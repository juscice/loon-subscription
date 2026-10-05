#!/usr/bin/env python3
"""Refresh actual Loon references. Validate downloads; never execute upstream JS."""
import argparse, concurrent.futures, hashlib, ipaddress, json, os, re, subprocess, tempfile, urllib.request, urllib.error, urllib.parse
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BLOCKED_HOSTS = {}
CATALOG_URL = 'https://hub.kelee.one/list.json'
LING_BASE='https://raw.githubusercontent.com/LingJingMaster/Shadowrocket-Rules/main/'
LING_POLICIES={'HSBC_HK.list':'汇丰香港','HK_Banks_Direct.list':'香港银行','HK_Broker.list':'券商服务','Mail.list':'邮件服务','ApplePush.list':'苹果推送','AI.list':'AI服务','Google.list':'Google','Apple.list':'Apple服务'}

def ling_rules(body, filename):
    policy=LING_POLICIES[filename]; rows=[]
    for line in body.splitlines():
        line=line.strip()
        if not line: continue
        if line.startswith('#'):
            if filename=='AI.list' and line.startswith('# > '):
                section=line[4:].strip()
                policy='ChatGPT' if section=='ChatGPT' else 'Claude' if section=='Claude' else 'AI服务'
            if filename=='Google.list' and line=='# > Google AI (from AI.list)':policy='Gemini'
            continue
        # AI supplement in Google.list ends before the ordinary Google list.
        if filename=='Google.list' and line=='DOMAIN,voice.telephony.goog':policy='Google'
        parts=[x.strip() for x in line.split(',')]
        if len(parts) not in (2,3) or (len(parts)==3 and parts[2]!='no-resolve'):raise ValueError('unsupported LingJing rule')
        kind,value=parts[:2]
        if kind=='URL-REGEX':continue # Path-specific bank URL matching requires separate HTTPS handling.
        if kind not in {'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','USER-AGENT','IP-CIDR','IP-CIDR6'}:raise ValueError('unsupported LingJing rule type')
        if kind in {'IP-CIDR','IP-CIDR6'}:
            net=ipaddress.ip_network(value,strict=False);value=str(net);kind='IP-CIDR6' if net.version==6 else 'IP-CIDR'
        if kind.startswith('DOMAIN'):value=value.lower().rstrip('.')
        if not value:raise ValueError('empty LingJing rule')
        rows.append((kind,value,policy,parts[2:]));
    return rows

def integrate_ling(text,offline=False):
    existing=set();section=''
    for line in text.splitlines():
        if line.startswith('['):section=line
        if section=='[Rule]' and line and not line.startswith(('#','[')):
            p=line.split(',')
            if len(p)>=3:existing.add((p[0],p[1].lower(),p[2]))
    # Compare against active baseline rule sets, respecting their assigned policies.
    section=''
    for line in text.splitlines():
        if line.startswith('['):section=line
        if section!='[Remote Rule]' or not line.startswith('https://') or 'enabled=false' in line:continue
        m=re.search(r'policy=([^,]+)',line)
        path=ROOT/relative(line.split(',')[0],'rules')
        if m and path.exists():
            for row in path.read_text().splitlines():
                p=row.strip().split(',')
                if len(p)>=2 and not p[0].startswith('#'):existing.add((p[0],p[1].lower(),m[1].strip()))
    additions=[];reports=[];duplicates=0;skipped=0;bank_exclusions=set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        downloaded=list(pool.map(lambda filename:refresh((LING_BASE+filename,'rules'),offline),LING_POLICIES))
    for filename,(r,body) in zip(LING_POLICIES,downloaded):
        reports.append(r)
        if body is None:continue
        for kind,value,policy,flags in ling_rules(body,filename):
            if filename in {'HSBC_HK.list','HK_Banks_Direct.list'} and kind in {'DOMAIN','DOMAIN-SUFFIX'}:
                bank_exclusions.add('-'+value)
                if kind=='DOMAIN-SUFFIX':bank_exclusions.add('-*.'+value)
            # Keep explicit user policies. Preserve intentional service overrides of broad baseline sets.
            signature=(kind,value.lower(),policy)
            if filename in {'Google.list','Apple.list'} and policy in {'Google','Apple服务'} and any(k==kind and v==value.lower() for k,v,p in existing):
                duplicates+=1;continue
            if signature in existing:
                duplicates+=1;continue
            if kind in {'DOMAIN','DOMAIN-SUFFIX'} and any(('DOMAIN-SUFFIX',suffix,policy) in existing for suffix in [value.lower()]+['.'.join(value.lower().split('.')[i:]) for i in range(1,len(value.split('.')))]):
                duplicates+=1;continue
            existing.add(signature);additions.append(','.join([kind,value,policy]+flags))
        skipped+=sum(l.strip().startswith('URL-REGEX,') for l in body.splitlines())
    block=['# LingJingMaster/Shadowrocket-Rules supplements (MIT, Copyright 2026 Ling_Jing).','# Attribution and full license: README.md; generated from eight source lists.']+additions
    # Supplemental service rules must precede broad local Apple / Microsoft / Google rules.
    text=text.replace('[Rule]\n','[Rule]\n'+'\n'.join(block)+'\n',1)
    lines=text.splitlines();section=''
    for i,line in enumerate(lines):
        if line.startswith('['):section=line
        if section.lower()=='[mitm]' and re.match(r'hostname\s*=',line):
            values=[v.strip() for v in line.split('=',1)[1].split(',') if v.strip()]
            lines[i]='hostname = '+','.join(values+sorted(bank_exclusions-set(values)))
    text='\n'.join(lines)+'\n'
    return text,{'added':len(additions),'duplicates_removed':duplicates,'unsupported_url_rules_skipped':skipped,'sources':reports}

def catalog_entries(body):
    data=json.loads(body)
    if not isinstance(data,dict) or not isinstance(data.get('lists'),list) or not 1 <= len(data['lists']) <= 1500:
        raise ValueError('invalid plugin catalog')
    entries={}
    for item in data['lists']:
        if not isinstance(item,dict) or not isinstance(item.get('tag'),list): raise ValueError('invalid catalog entry')
        if not {'去广告','功能增强'}.intersection(item['tag']): continue
        parsed=urllib.parse.urlsplit(item.get('url',''))
        if parsed.scheme!='loon' or parsed.netloc!='import': raise ValueError('invalid import URL')
        urls=urllib.parse.parse_qs(parsed.query).get('plugin',[])
        if len(urls)!=1: raise ValueError('invalid plugin URL')
        url=urls[0]; p=urllib.parse.urlsplit(url)
        if p.scheme!='https' or p.hostname!='kelee.one' or p.username or p.password or p.query or p.fragment or not p.path.startswith('/Tool/Loon/Lpx/') or not p.path.endswith('.lpx') or any(c in url for c in ',\r\n '):
            raise ValueError('unexpected plugin source')
        entries[url]={'url':url,'tags':sorted(set(item['tag']).intersection({'去广告','功能增强'}))}
    if not entries: raise ValueError('empty selected catalog')
    return list(entries.values())

def integrate_catalog(text, offline=False):
    cache=ROOT/'upstream/catalog.json'; entries=[]; status='cached'; error=None
    try:
        if not offline:
            entries=catalog_entries(download(CATALOG_URL))
            cache.parent.mkdir(parents=True,exist_ok=True)
            cache.write_text(json.dumps(entries,ensure_ascii=False,indent=2)+'\n')
            status='ok'
        else:
            entries=json.loads(cache.read_text())
    except Exception as e:
        error=str(e)
        if cache.exists(): entries=json.loads(cache.read_text());status='fallback'
        else: status='unavailable'
    # Revalidate cached URLs with the same policy as newly downloaded entries.
    if entries:
        entries=catalog_entries(json.dumps({'lists':[{'url':'loon://import?plugin='+urllib.parse.quote(e['url'],safe=''),'tag':e['tags']} for e in entries]}))
    existing={u for u,k in references(text).items() if k=='plugins'}
    additions=[e['url'] for e in entries if e['url'] not in existing]
    if additions:
        lines=text.splitlines(); start=lines.index('[Plugin]')+1
        end=next((i for i in range(start,len(lines)) if re.fullmatch(r'\[[^]]+\]',lines[i].strip())),len(lines))
        lines[end:end]=['# Automatically added from PluginHub: ads and enhancements']+[u+', enabled=true' for u in additions]
        text='\n'.join(lines)+'\n'
    return text,{'url':CATALOG_URL,'status':status,'selected':len(entries),'added':len(additions),'existing':len(entries)-len(additions),'error':error}

def download(url):
    req = urllib.request.Request(url, headers={'User-Agent':'Loon-subscription-updater/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r: body=r.read(8*1024*1024+1)
    except urllib.error.HTTPError as e:
        body=e.read(65536).decode('utf-8',errors='replace')
        if e.code==403 and ('Sorry, you have been blocked' in body or 'Attention Required! | Cloudflare' in body or e.headers.get('cf-mitigated')=='challenge'):
            host=urllib.parse.urlsplit(url).hostname
            BLOCKED_HOSTS[host]='Cloudflare access block; upstream file was not returned'
            raise ValueError(BLOCKED_HOSTS[host]) from e
        raise
    if len(body)>8*1024*1024: raise ValueError('source too large')
    return body.decode('utf-8-sig')

def references(text):
    refs = {}; section = ''
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//')): continue
        if re.fullmatch(r'\[[^]]+\]', line): section = line.lower(); continue
        if section in ('[plugin]', '[remote rule]', '[remote script]'):
            m = re.match(r'(https://[^,\s]+)', line)
            if m: refs[m[1]] = {'[plugin]':'plugins','[remote rule]':'rules','[remote script]':'scripts'}[section]
        if section == '[script]':
            for m in re.finditer(r'(?:script-path\s*=\s*|script\(\s*["\x27])(https://[^,\s"\x27)]+)', line): refs[m[1]] = 'scripts'
        if section == '[rule]':
            m = re.match(r'(?:RULE-SET|DOMAIN-SET),\s*(https://[^,\s]+)',line)
            if m: refs[m[1]] = 'rules'
    return refs

def relative(url, kind):
    return 'upstream/' + kind + '/' + hashlib.sha256(url.encode()).hexdigest()[:20] + {'plugins':'.lpx','scripts':'.js','rules':'.list'}[kind]

def validate(text, kind):
    if not text.strip() or re.match(r'\s*(?:<!doctype|<html)', text, re.I): raise ValueError('empty source or HTML response')
    if re.search(r'(?im)^\s*ca-(?:p12|passphrase)\s*=\s*\S',text): raise ValueError('source contains certificate material')
    if kind == 'scripts':
        with tempfile.NamedTemporaryFile(suffix='.js', mode='w', encoding='utf-8') as f:
            f.write(text); f.flush()
            r = subprocess.run(['node','--check',f.name],capture_output=True,timeout=20)
            if r.returncode: raise ValueError('JavaScript syntax check failed')
    elif kind == 'plugins':
        if not re.search(r'(?im)^\[(?:Rule|Script|Rewrite|Remote Script|Remote Rule|Host|Mitm)\]',text): raise ValueError('missing plugin sections')
    elif kind == 'rules':
        rows=[l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith(('#','//'))]
        allowed={'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-WILDCARD','IP-CIDR','IP-CIDR6','IP-ASN','GEOIP','URL-REGEX','USER-AGENT','AND','OR','NOT','PROCESS-NAME','DEST-PORT','SRC-IP','SRC-PORT','IN-PORT','PROTOCOL','NETWORK','DOMAIN-SET','RULE-SET','IP-CIDR6','FINAL'}
        if not rows or any(l.split(',')[0].strip() not in allowed for l in rows): raise ValueError('unsupported rule format')

def refresh(item, offline=False, candidate=None):
    url,kind=item; rel=relative(url,kind); path=ROOT/rel
    status='cached'; error=None
    try:
        if not offline:
            host=urllib.parse.urlsplit(url).hostname
            if host in BLOCKED_HOSTS: raise ValueError(BLOCKED_HOSTS[host])
            text=candidate if candidate is not None else download(url)
            validate(text,kind)
            path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text); status='ok'
        if not path.exists(): raise ValueError('no validated cache')
        text=path.read_text(); validate(text,kind)
    except Exception as e:
        error=str(e)
        if path.exists():
            text=path.read_text(); validate(text,kind); status='fallback'
        else: text=None; status='unavailable'
    return {'url':url,'kind':kind,'path':rel,'status':status,'error':error,'blocked':urllib.parse.urlsplit(url).hostname in BLOCKED_HOSTS,'sha256':hashlib.sha256(text.encode()).hexdigest() if text else None},text

def render(text, mapping):
    # Only replace URLs at actual active reference sites, never regex bodies or comments.
    lines=[]; section=''
    for line in text.splitlines():
        stripped=line.strip()
        if re.fullmatch(r'\[[^]]+\]',stripped): section=stripped.lower()
        if stripped and not stripped.startswith(('#','//')) and section in ('[plugin]','[remote rule]','[remote script]','[script]','[rule]'):
            for url in references(section+'\n'+line):
                if url in mapping: line=line.replace(url,mapping[url])
        lines.append(line)
    return '\n'.join(lines)+'\n'

def validate_config(text):
    if re.search(r'(?im)^\s*ca-(?:p12|passphrase)\s*=',text): raise ValueError('private CA in published profile')
    if not all('['+s+']' in text for s in ['General','Remote Proxy','Proxy Group','Rule','Script','Plugin','Mitm']): raise ValueError('incomplete config')
    if '-*.icbc.com.cn' not in text or 'DOMAIN-SUFFIX,icbc.com.cn,DIRECT' not in text: raise ValueError('bank exclusion lost')
    wx=next(l for l in text.splitlines() if 'tag="微信读书旧版"' in l)
    if 'enable=true' not in wx: raise ValueError('WeRead disabled')
    urls=[];section=''
    for l in text.splitlines():
        if l.startswith('['): section=l
        if section=='[Plugin]' and l.startswith('https://'): urls.append(l.split(',')[0])
    if not 271 <= len(urls) <= 1500 or len(set(urls))!=len(urls): raise ValueError('plugin count or dedup changed')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--offline',action='store_true');args=ap.parse_args()
    text=(ROOT/'profiles/loon.conf').read_text(); validate_config(text)
    text,catalog=integrate_catalog(text,args.offline);validate_config(text)
    queue=references(text); done={}; contents={}
    candidates={}
    # Check a protected host once before scheduling hundreds of downloads.
    # A confirmed Cloudflare block is not a missing plugin and must not be retried as one.
    if not args.offline:
        protected=sorted(u for u in queue if urllib.parse.urlsplit(u).hostname=='kelee.one')
        if protected:
            try: candidates[protected[0]]=download(protected[0])
            except Exception: pass
    for depth in range(5):
        pending=sorted((u,k) for u,k in queue.items() if u not in done)
        if not pending: break
        if len(done)+len(pending)>1500: raise ValueError('resource count guard')
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            for report,body in pool.map(lambda item:refresh(item,args.offline,candidates.pop(item[0],None)),pending):
                done[report['url']]=report
                if body is not None:
                    contents[report['url']]=body
                    if report['kind']=='plugins': queue.update(references(body))
    text,ling=integrate_ling(text,args.offline)
    for r in ling['sources']:done[r['url']]=r
    repo=os.environ.get('GITHUB_REPOSITORY','juscice/loon-subscription')
    raw='https://raw.githubusercontent.com/'+repo+'/main/'
    mapping={u:raw+(d['path'].replace('upstream/','dist/') if d['kind']=='plugins' else d['path']) for u,d in done.items() if u in contents}
    dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    full=render(text,mapping);validate_config(full)
    (dist/'loon.conf').write_text(full)
    # Keep downloaded originals separate from rendered plugins to avoid parsing our mirror as upstream.
    for u,body in contents.items():
        if done[u]['kind']=='plugins':
            rel=done[u]['path'].replace('upstream/','dist/')
            p=ROOT/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(render(body,mapping))
    validate_config(full);(dist/'loon.conf').write_text(full)
    missing=[r for r in done.values() if r['status']=='unavailable']
    plugins=[r for r in done.values() if r['kind']=='plugins']
    report={'build_status':'degraded' if missing or catalog['status']=='unavailable' else 'complete','catalog':catalog,'lingjing':ling,'blocked_hosts':BLOCKED_HOSTS,'plugins':{'total':len(plugins),'mirrored':sum(r['url'] in contents for r in plugins),'unmirrored':sum(r['url'] not in contents for r in plugins)},'resources':list(done.values()),'counts':{s:sum(r['status']==s for r in done.values()) for s in ['ok','cached','fallback','unavailable']},'runtime_tested':False}
    (dist/'update-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report['counts']))
    if missing: print('::warning::Subscription build is degraded: '+str(len(missing))+' references have no validated cache. Original URLs were retained.')
    summary=os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a') as f:
            f.write('## Loon resource synchronization\n\nBuild: **'+report['build_status']+'**\n\nPlugins mirrored: '+str(report['plugins']['mirrored'])+'/'+str(len(plugins))+'\n\nMissing references: '+str(len(missing))+'\n\n')
            f.write('PluginHub catalog: '+catalog['status']+'; selected: '+str(catalog['selected'])+'; added: '+str(catalog['added'])+'; already present: '+str(catalog['existing'])+'\n\n')
            f.write('LingJing supplements: '+str(ling['added'])+'; duplicate rules removed: '+str(ling['duplicates_removed'])+'; source lists: '+str(len(ling['sources']))+'\n\n')
            for host,reason in BLOCKED_HOSTS.items(): f.write('- '+host+': '+reason+'\n')

if __name__=='__main__': main()
