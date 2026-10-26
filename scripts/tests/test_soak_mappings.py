import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('soak_mappings',Path(__file__).parents[1]/'soak_mappings.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class MappingsTests(unittest.TestCase):
    def vma(self,start,end,path=''):
        return f'{start:x}-{end:x} rw-p 00000000 00:00 0 {path}\n'+''.join(f'{k}: 4 kB\n' for k in m.FIELDS)

    def test_real_format_and_exclusive_buckets(self):
        lo,hi=m.RANGES['race_shadow']
        raw=self.vma(lo,lo+4096)+self.vma(hi,hi+4096)
        parsed=m.parse_smaps(raw,True)
        self.assertEqual(parsed['groups']['race_shadow']['Rss'],4096)
        self.assertEqual(parsed['groups']['other_anonymous']['Rss'],4096)
        self.assertNotIn('race_shadow',m.parse_smaps(raw,False)['groups'])
        self.assertEqual(m.classify(lo-4096,lo+4096,'',True),'boundary_crossing')

    def test_reject_corruption_and_unsupported_ownership(self):
        raw=self.vma(4096,8192)
        for bad in ('',raw.replace('Rss: 4 kB\n',''),raw+'Rss: 4 kB\n',
                    raw.replace('4 kB','-1 kB',1),raw+raw,
                    raw.replace('4 kB','18014398509481984 kB',1)):
            with self.subTest(raw=bad),self.assertRaises(ValueError):m.parse_smaps(bad,True)
        with self.assertRaises(ValueError):
            m.supported(dict(go_version='go1.27.0',goos='linux',goarch='amd64',build_info=''))


if __name__=='__main__':unittest.main()
