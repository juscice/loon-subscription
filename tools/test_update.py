import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import update
import io, urllib.error

class UpdaterTests(unittest.TestCase):
    def tearDown(self): update.BLOCKED_HOSTS.clear()
    def test_ling_ai_policy_and_ipv6_conversion(self):
        rows=update.ling_rules('# > Claude\nDOMAIN-SUFFIX,claude.ai\n# > ChatGPT\nIP-CIDR,2403:300::/32,no-resolve\n','AI.list')
        self.assertEqual(rows[0][2],'Claude');self.assertEqual(rows[1],('IP-CIDR6','2403:300::/32','ChatGPT',['no-resolve']))
        with self.assertRaises(ValueError):update.ling_rules('UNKNOWN,example.org','AI.list')
    def test_ling_dedup_and_priority(self):
        body='DOMAIN-SUFFIX,example.org\nDOMAIN,api.example.org\nDOMAIN-SUFFIX,new.org\nDOMAIN-SUFFIX,new.org\n'
        def mock_refresh(item,offline):
            return {'url':item[0],'kind':'rules','status':'ok'},body if item[0].endswith('Apple.list') else ''
        source='[Rule]\nDOMAIN-SUFFIX,example.org,Apple服务\nDOMAIN-SUFFIX,apple.com,Apple服务\nFINAL,FINAL\n[Remote Rule]\n'
        with tempfile.TemporaryDirectory() as d,patch.object(update,'ROOT',Path(d)),patch.object(update,'refresh',side_effect=mock_refresh):
            text,report=update.integrate_ling(source)
        self.assertEqual(report['added'],1);self.assertEqual(report['duplicates_removed'],3)
        self.assertEqual(text.count('DOMAIN-SUFFIX,new.org,Apple服务'),1)
        self.assertLess(text.index('new.org'),text.index('apple.com'))
    def test_catalog_filters_and_deduplicates(self):
        import json
        u='loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/Test.lpx'
        body=json.dumps({'lists':[{'url':u,'tag':['去广告']},{'url':u,'tag':['功能增强']},{'url':u,'tag':['签到']}]})
        entries=update.catalog_entries(body)
        self.assertEqual(len(entries),1)
        with self.assertRaises(ValueError):update.catalog_entries(body.replace('kelee.one','untrusted.org'))
    def test_catalog_adds_enabled_preserves_existing_disabled(self):
        import json
        a='https://kelee.one/Tool/Loon/Lpx/A.lpx';b='https://kelee.one/Tool/Loon/Lpx/B.lpx'
        body=json.dumps({'lists':[{'url':'loon://import?plugin='+u,'tag':['去广告']} for u in [a,b,b]]})
        source='[Plugin]\n'+a+', enabled=false\n[Mitm]\nhostname = example.org\n'
        with tempfile.TemporaryDirectory() as d,patch.object(update,'ROOT',Path(d)),patch.object(update,'download',return_value=body):
            text,report=update.integrate_catalog(source)
            self.assertIn(a+', enabled=false',text);self.assertIn(b+', enabled=true',text)
            self.assertEqual(report['added'],1);self.assertEqual(text.count(b),1)
            with patch.object(update,'download',side_effect=OSError('offline')):
                fallback,r=update.integrate_catalog(source)
            self.assertEqual(r['status'],'fallback');self.assertEqual(text,fallback)
    def test_cloudflare_block_is_classified(self):
        e=urllib.error.HTTPError('https://kelee.one/a.lpx',403,'Forbidden',{},io.BytesIO(b'<title>Attention Required! | Cloudflare</title>Sorry, you have been blocked'))
        with patch.object(update.urllib.request,'urlopen',side_effect=e):
            with self.assertRaisesRegex(ValueError,'Cloudflare access block'):update.download('https://kelee.one/a.lpx')
        self.assertIn('kelee.one',update.BLOCKED_HOSTS)
    def test_blocked_host_uses_cache_without_retry(self):
        with tempfile.TemporaryDirectory() as d,patch.object(update,'ROOT',Path(d)),patch.object(update.urllib.request,'urlopen') as request:
            u='https://kelee.one/a.lpx';p=Path(d)/update.relative(u,'plugins');p.parent.mkdir(parents=True);p.write_text('[Rule]\nDOMAIN,example.org,REJECT\n')
            update.BLOCKED_HOSTS['kelee.one']='Cloudflare access block'
            report,body=update.refresh((u,'plugins'))
            self.assertEqual(report['status'],'fallback');self.assertTrue(report['blocked']);self.assertIn('[Rule]',body);request.assert_not_called()
    def test_rendered_plugin_dependency_uses_rendered_target(self):
        source='[Plugin]\nhttps://example.org/a.lpx, enabled=true\n'
        self.assertIn('/dist/plugins/a.lpx',update.render(source,{'https://example.org/a.lpx':'https://mirror.org/dist/plugins/a.lpx'}))
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
