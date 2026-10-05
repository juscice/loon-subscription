import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import update

class UpdaterTests(unittest.TestCase):
    def test_reference_sites_only(self):
        s='# https://example.org/x.js\n[Script]\nresponse if ${url} ~= /test/ then script("https://example.org/x.js") with enable=true\n[Plugin]\nhttps://example.org/a.lpx, enabled=true\n'
        self.assertEqual(update.references(s),{'https://example.org/x.js':'scripts','https://example.org/a.lpx':'plugins'})
        rendered=update.render(s,{'https://example.org/x.js':'https://mirror.org/x.js'})
        self.assertTrue(rendered.startswith('# https://example.org/x.js'))
        self.assertIn('script("https://mirror.org/x.js")',rendered)
    def test_bad_sources(self):
        for text,kind in [('<html>Error</html>','rules'),('ca-p12 = secret','plugins'),('BROKEN,line','rules'),('const = ;','scripts')]:
            with self.assertRaises(ValueError): update.validate(text,kind)
    def test_failure_keeps_valid_cache(self):
        with tempfile.TemporaryDirectory() as d,patch.object(update,'ROOT',Path(d)),patch.object(update.urllib.request,'urlopen',side_effect=OSError('offline')):
            url='https://example.org/a.js';p=Path(d)/update.relative(url,'scripts');p.parent.mkdir(parents=True);p.write_text('$done({});')
            report,body=update.refresh((url,'scripts'))
            self.assertEqual(report['status'],'fallback');self.assertEqual(body,'$done({});');self.assertEqual(p.read_text(),body)
            report,body=update.refresh(('https://example.org/missing.js','scripts'))
            self.assertEqual(report['status'],'unavailable');self.assertIsNone(body)
    def test_private_certificate_rejected(self):
        s=(update.ROOT/'profiles/loon.conf').read_text();update.validate_config(s)
        with self.assertRaises(ValueError): update.validate_config(s+'\nca-p12=private\n')

if __name__=='__main__': unittest.main()
