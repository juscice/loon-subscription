#!/usr/bin/env python3
"""Refresh actual Loon references. Validate downloads; never execute upstream JS."""
import argparse, concurrent.futures, hashlib, json, os, re, subprocess, tempfile, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

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

def refresh(item, offline=False):
    url,kind=item; rel=relative(url,kind); path=ROOT/rel
    status='cached'; error=None
    try:
        if not offline:
            req=urllib.request.Request(url,headers={'User-Agent':'Loon-subscription-updater/1.0'})
            with urllib.request.urlopen(req, timeout=15) as r: b=r.read(8*1024*1024+1)
            if len(b)>8*1024*1024: raise ValueError('source too large')
            text=b.decode('utf-8-sig'); validate(text,kind)
            path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text); status='ok'
        if not path.exists(): raise ValueError('no validated cache')
        text=path.read_text(); validate(text,kind)
    except Exception as e:
        error=str(e)
        if path.exists():
            text=path.read_text(); validate(text,kind); status='fallback'
        else: text=None; status='unavailable'
    return {'url':url,'kind':kind,'path':rel,'status':status,'error':error,'sha256':hashlib.sha256(text.encode()).hexdigest() if text else None},text

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
    if len(urls)!=271 or len(set(urls))!=271: raise ValueError('plugin count or dedup changed')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--offline',action='store_true');args=ap.parse_args()
    text=(ROOT/'profiles/loon.conf').read_text(); validate_config(text)
    queue=references(text); done={}; contents={}
    for depth in range(5):
        pending=sorted((u,k) for u,k in queue.items() if u not in done)
        if not pending: break
        if len(done)+len(pending)>1500: raise ValueError('resource count guard')
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            for report,body in pool.map(lambda item:refresh(item,args.offline),pending):
                done[report['url']]=report
                if body is not None:
                    contents[report['url']]=body
                    if report['kind']=='plugins': queue.update(references(body))
    repo=os.environ.get('GITHUB_REPOSITORY','juscice/loon-subscription')
    raw='https://raw.githubusercontent.com/'+repo+'/main/'
    mapping={u:raw+d['path'] for u,d in done.items() if u in contents}
    dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    full=render(text,mapping);validate_config(full)
    (dist/'loon.conf').write_text(full)
    # Keep downloaded originals separate from rendered plugins to avoid parsing our mirror as upstream.
    for u,body in contents.items():
        if done[u]['kind']=='plugins':
            rel=done[u]['path'].replace('upstream/','dist/')
            p=ROOT/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(render(body,mapping))
            full=full.replace(raw+done[u]['path'],raw+rel)
    validate_config(full);(dist/'loon.conf').write_text(full)
    report={'resources':list(done.values()),'counts':{s:sum(r['status']==s for r in done.values()) for s in ['ok','cached','fallback','unavailable']},'runtime_tested':False}
    (dist/'update-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report['counts']))

if __name__=='__main__': main()
