import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0,str(Path(__file__).parents[1]))
import soak_mapping_retention as r


class MappingRetentionTests(unittest.TestCase):
    def fixture(self, folder):
        (folder/'native').mkdir()
        raw='1000-3000 rw-p 00000000 00:00 0\nSize: 8 kB\nRss: 8 kB\nPss: 8 kB\nAnonymous: 8 kB\nPrivate_Dirty: 8 kB\nSwap: 0 kB\n'
        memory={k:8192 if k in ('Rss','Pss','Anonymous','Private_Dirty') else 0
                for k in r.rollup.REQUIRED}
        resources=dict(rss=8192,os_memory=dict(bytes=memory,
            smaps_rollup_raw='00000000-7fffffffffff ---p 00000000 00:00 0 [rollup]\n'+
                ''.join(f'{k}: {v//1024} kB\n' for k,v in memory.items())))
        gc=[dict(phase='poststop_gc',at_seconds=float(i),resources=resources) for i in range(0,121,5)]
        scavenged=dict(phase='poststop_go_scavenge',at_seconds=120.1,
            resources=resources,go_scavenge_seconds=.01)
        report=dict(settings=dict(duration_seconds=180,post_stop_observe_seconds=120,
            diagnostic_go_scavenge=True,post_stop_observer_ack=True),post_stop_observation=gc+[scavenged],
            points=[dict(phase='measured',at_seconds=180,resources={'rss':999999})],
            counts={},warmup_counts={},idle_baseline={},after_stop={'rss':777777},
            measured_seconds=180,scheduler_timing={},stop_seconds=.1)
        sha=r.mappings.load_evidence_hash(report)
        records=[]
        for i,point in enumerate(report['post_stop_observation']):
            path=folder/f'{i}.gz'
            with gzip.open(path,'wt') as stream:stream.write(raw)
            records.append(dict(key=[point['phase'],point['at_seconds']],source_field='post_stop_observation',
                point=point,point_sha256=r.ledger.point_sha(point),file=path.name,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),read_start_monotonic_ns=1000+i*100,
                read_end_monotonic_ns=1010+i*100,checkpoint_age_seconds=.01,
                pid=42,start_ticks='123',load_evidence_sha256=sha))
        capture=dict(format_version=1,clock='CLOCK_MONOTONIC',records=records)
        r.context.dump(folder/'retention-snapshots.json',capture)
        r.context.dump(folder/'execution.json',dict(target_identity_verified=True,group_gone=True,
            target_identity=dict(pid=42,start_ticks=123)))
        r.acknowledge(folder,dict(report,post_stop_observation=gc),records[:-1])
        parsed=dict(native_pid=42,target_exec_ns=1,calls=[dict(call='mmap',tid=42,id='42:1',
            start_ns=2,end_ns=3,args=[0,8192,3,34,0,0],value=0x1000,contexts=[[1,1]],owner='trace_switch')])
        return parsed,report,capture

    def test_same_process_complete_retention_and_raw_mapping_attribution(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);parsed,report,_=self.fixture(folder)
            out=r.audit_retention(folder,parsed,report)
            self.assertEqual(out['gc_samples'],25)
            self.assertEqual(out['selected']['go_scavenge']['family']['groups_rss_bytes'],
                {'observed_race_runtime':8192})
            self.assertEqual(report['points'][0]['resources']['rss'],999999)
            self.assertEqual(report['after_stop']['rss'],777777)

    def test_retention_rejects_missing_reordered_point_hash_identity_and_clock(self):
        mutations=[lambda c:c['records'].pop(),lambda c:c['records'].reverse(),
            lambda c:c.update(clock='CLOCK_BOOTTIME'),
            lambda c:c['records'][0].update(pid=99),
            lambda c:c['records'][0].update(start_ticks='999'),
            lambda c:c['records'][0].update(point_sha256='bad'),
            lambda c:c['records'][0].update(sha256='bad'),
            lambda c:c['records'][0].update(read_start_monotonic_ns=0),
            lambda c:c['records'][0].update(checkpoint_age_seconds=.101)]
        for mutate in mutations:
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as temp:
                folder=Path(temp);parsed,report,capture=self.fixture(folder)
                mutate(capture);r.context.dump(folder/'retention-snapshots.json',capture)
                with self.assertRaises(ValueError):r.audit_retention(folder,parsed,report)

    def test_changed_load_or_original_after_stop_cannot_be_hidden(self):
        for key in ('points','after_stop'):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temp:
                folder=Path(temp);parsed,report,_=self.fixture(folder)
                if key=='points':report[key][0]['resources']['rss']=1
                else:report[key]['rss']=1
                with self.assertRaisesRegex(ValueError,'point/load evidence changed'):
                    r.audit_retention(folder,parsed,report)

    def test_wrong_or_stale_pre_scavenge_acknowledgment_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);parsed,report,_=self.fixture(folder)
            ack=folder/'native/post-stop-observer-ack.json'
            data=json.loads(ack.read_text());data['mapping_sha256']='old'
            r.context.dump(ack,data)
            with self.assertRaisesRegex(ValueError,'acknowledgment mismatch'):
                r.audit_retention(folder,parsed,report)

    def test_ack_requires_complete_prefix_and_timely_final_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);_,report,capture=self.fixture(folder)
            report['post_stop_observation'].pop();records=capture['records'][:-1]
            ack=folder/'native/post-stop-observer-ack.json';ack.unlink()
            with self.assertRaisesRegex(ValueError,'missing pre-scavenge'):
                r.acknowledge(folder,report,records[1:])
            self.assertFalse(ack.exists())
            records[-1]['checkpoint_age_seconds']=.101
            with self.assertRaisesRegex(ValueError,'timing failure'):
                r.acknowledge(folder,report,records)
            self.assertFalse(ack.exists())

    def test_live_collector_persists_raw_maps_before_final_ack_and_freezes_load(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);_,report,_=self.fixture(folder)
            (folder/'native/post-stop-observer-ack.json').unlink()
            native=folder/'native/report.json'
            all_points=report['post_stop_observation']
            # /proc/self also works in hosts whose procfs uses a different PID namespace.
            active=MagicMock(pid='self',start=r.mappings.pid_identity('self'),verified=True)
            with patch.object(r.ledger,'Collector',return_value=active):
                collector=r.Collector(folder,Path('/proc/self/exe'))
            for i in range(25):
                report['post_stop_observation']=all_points[:i+1]
                r.context.dump(native,report)
                collector()
                self.assertEqual((folder/'native/post-stop-observer-ack.json').exists(),i==24)
            capture=json.loads((folder/'retention-snapshots.json').read_text())
            ack=json.loads((folder/'native/post-stop-observer-ack.json').read_text())
            self.assertEqual(ack['mapping_sha256'],capture['records'][-1]['sha256'])
            for record in capture['records']:
                raw=folder/record['file']
                self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(),record['sha256'])
                self.assertTrue(gzip.open(raw,'rt').read())
            report['post_stop_observation']=all_points
            report['after_stop']['rss']=1
            r.context.dump(native,report)
            with self.assertRaisesRegex(ValueError,'original load/after_stop changed'):
                collector()

    def test_address_reuse_with_new_generation_is_not_same_retained_vma(self):
        v=dict(start=4096,end=8192,generations=['1'],owner='observed_race_runtime',rss=4096)
        a=dict(key=['measured',180],point={'resources':{'rss':8192}},read_end_monotonic_ns=10,
            family=dict(unnamed_vmas=[v],groups_rss_bytes={'observed_race_runtime':4096}))
        b=copy.deepcopy(a);b['key']=['poststop_gc',0];b['read_end_monotonic_ns']=20
        b['family']['unnamed_vmas'][0]['generations']=['2']
        result=r.compare_maps(a,b,[{'call':'munmap','end_ns':15}])
        self.assertEqual(result['same_bounds_generations_owner_rss_delta'],0)
        self.assertEqual(len(result['changed_or_removed_vmas']),1)
        self.assertEqual(len(result['changed_or_added_vmas']),1)
        self.assertEqual(result['memory_syscalls'],{'munmap':1})

    def test_resource_failure_preserves_load_and_post_stop_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'out';binary=root/'probe';control=root/'control'
            parsed={'native_pid':42};info={'build_info':'pinned'}
            post=dict(status='retention_audit_passed',selected={'last_gc':{'proof':'retained'}})
            def launch(target,folder,symbols,args,timeout,tracer,**kwargs):
                if target==binary:
                    self.assertEqual(timeout,450)
                    self.assertIn('--post-stop-observer-ack',args)
                    self.assertEqual(args[args.index('--duration')+1],'180s')
                    self.assertEqual(args[args.index('--post-stop-observe')+1],'120s')
                    native=folder/'native';native.mkdir(parents=True)
                    (native/'report.json').write_text(json.dumps(dict(build_info='pinned',settings={'pid':42})))
                return parsed
            with patch.object(sys,'argv',['retention','--binary',str(binary),'--control',str(control),
                    '--tracer','/tracer','--artifacts',str(out)]),\
                 patch.object(r.os,'sysconf',return_value=4096),\
                 patch.object(r.ledger,'Collector'),patch.object(r,'Collector'),\
                 patch.object(r.context,'launch',side_effect=launch),\
                 patch.object(r.subprocess,'check_output',return_value=json.dumps(info).encode()),\
                 patch.object(r.mappings,'supported',return_value=True),\
                 patch.object(r.ledger,'audit_snapshots',return_value=[{'proof':'active'}]),\
                 patch.object(r,'audit_retention',return_value=post),\
                 patch.object(r,'add_load_comparisons'),\
                 patch.object(r.verify,'validate_events',return_value=1919),\
                 patch.object(r.verify,'validate_engine_logs'),\
                 patch.object(r.verify,'validate_report',side_effect=ValueError('active resource bound: rss')):
                self.assertEqual(r.main(),1)
            result=json.loads((out/'experiment.json').read_text())
            self.assertEqual(result['status'],'failed')
            self.assertFalse(result['qualifies_24h'])
            self.assertEqual(result['events'],1919)
            self.assertEqual(result['retention'],post)
            self.assertEqual(result['pilot']['snapshots'],[{'proof':'active'}])
            self.assertEqual(result['error'],'ValueError: active resource bound: rss')
            self.assertNotIn('acceptance',result)


if __name__=='__main__':unittest.main()
