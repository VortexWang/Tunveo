import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('audit_soak_os_memory', Path(__file__).parents[1] / 'audit_soak_os_memory.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class RollupEvidenceTests(unittest.TestCase):
    def test_source_conversion_and_corruption(self):
        raw = '1000-2000 ---p 00000000 00:00 0 [rollup]\n' + ''.join(f'{k}: 17 kB\n' for k in sorted(audit.REQUIRED))
        self.assertEqual(audit.parse_rollup(raw)['Rss'], 17*1024)
        for bad in (raw.replace('[rollup]', '[heap]'), raw.replace('17 kB', '-1 kB', 1),
                    raw.replace('17 kB', '17 MB', 1), raw+'Rss: 17 kB\n',
                    raw.replace('Rss: 17 kB\n', ''),
                    raw.replace('17 kB', '18014398509481984 kB', 1)):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                audit.parse_rollup(bad)

    def test_missing_optional_fields_remain_absent(self):
        raw = '1000-2000 ---p 00000000 00:00 0 [rollup]\n' + ''.join(f'{k}: 0 kB\n' for k in sorted(audit.REQUIRED))
        self.assertNotIn('Pss_Anon', audit.parse_rollup(raw))


if __name__ == '__main__':
    unittest.main()
