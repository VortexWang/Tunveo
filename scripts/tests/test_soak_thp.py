import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
import soak_thp as thp


class THPTests(unittest.TestCase):
    def raw(self, extra='AnonHugePages: 0 kB\nTHPeligible: 0\nVmFlags: rd wr nh\n'):
        return ('c000000000-c000400000 rw-p 00000000 00:00 0 [anon: Go: heap]\n'
                'Size: 4096 kB\nRss: 20 kB\nPss: 20 kB\nAnonymous: 20 kB\n'
                'Private_Dirty: 20 kB\nSwap: 0 kB\n'+extra)

    def test_absence_of_thp_fields_cannot_be_reported_as_zero(self):
        for raw in (self.raw(''), self.raw('AnonHugePages: 0 kB\n'),
                    self.raw().replace('AnonHugePages: 0', 'AnonHugePages: -1'),
                    self.raw()+'AnonHugePages: 0 kB\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                thp.heap_pages(raw, False)

    def test_whole_mapping_accounting_and_intervention_flags(self):
        p = thp.heap_pages(self.raw(), True)
        self.assertEqual(p['rss'], 20*1024)
        self.assertTrue(p['all_no_hugepage'])
        p = thp.heap_pages(self.raw().replace('0 kB\nTHPeligible', '2048 kB\nTHPeligible').replace('rd wr nh', 'rd wr hg'), False)
        self.assertEqual(p['anon_huge_pages'], 2048*1024)
        self.assertFalse(p['all_no_hugepage'])

    def test_ambient_debug_does_not_contaminate_either_arm(self):
        original = {'GODEBUG': 'disablethp=1,gctrace=1', 'GOGC': '80', 'GOMEMLIMIT': '1GiB'}
        a = thp.runtime_environment('default', original)
        b = thp.runtime_environment('disablethp', original)
        self.assertNotIn('GODEBUG', a)
        self.assertEqual(b['GODEBUG'], 'disablethp=1')
        self.assertEqual({k:v for k,v in b.items() if k!='GODEBUG'}, a)
        self.assertEqual(original['GODEBUG'], 'disablethp=1,gctrace=1')


if __name__ == '__main__': unittest.main()
