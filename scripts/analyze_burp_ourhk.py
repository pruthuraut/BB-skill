#!/usr/bin/env python3
import hashlib, json, re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path('burp_capture_tmp')
OUT = Path('ourhkfoundation_analysis')
HOST = 'ourhkfoundation.org.hk'

def split_http(message):
    head, sep, body = message.partition('\r\n\r\n')
    lines = head.split('\r\n')
    first = lines[0] if lines else ''
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return first, headers, body if sep else ''

def flatten_json(obj, prefix=''):
    out=[]
    if isinstance(obj, dict):
        for k,v in obj.items(): out += flatten_json(v, f'{prefix}.{k}' if prefix else k)
    elif isinstance(obj, list):
        for i,v in enumerate(obj): out += flatten_json(v, f'{prefix}[{i}]')
    else: out.append((prefix, str(obj)))
    return out

OUT.mkdir(exist_ok=True)
(OUT/'burp').mkdir(exist_ok=True)
(OUT/'js_raw').mkdir(exist_ok=True)
items=[]
for page in sorted(Path('burp_capture_single').glob('single_*.jsonl')):
    for line in page.read_text(errors='ignore').splitlines():
        if line.strip(): items.append(json.loads(line))

# Large Burp records are capped by the connector at 5,015 characters. Recover
# every request from the original paginated payload even where the response was
# truncated. JSON-decode the captured request string so CRLF/body data survive.
request_records=[]
request_pat=re.compile(r'\{"request":"((?:\\.|[^"\\])*)","response":',re.S)
for page in sorted(ROOT.glob('page_*.jsonl')):
    raw=page.read_text(errors='ignore')
    for m in request_pat.finditer(raw):
        try: request_records.append(json.loads('"'+m.group(1)+'"'))
        except Exception: pass

exact=[]; external=[]; rows=[]; params=[]; endpoints=set(); js_urls=set(); js_manifest=[]
methods=Counter(); statuses=Counter(); content_types=Counter()
for idx,item in enumerate(items):
    req=item.get('request',''); resp=item.get('response','')
    first,hdrs,body=split_http(req)
    parts=first.split(' ')
    method,target=(parts[0],parts[1]) if len(parts)>=2 else ('','')
    host=hdrs.get('host','').split(':')[0].lower()
    if host != HOST:
        external.append(item); continue
    exact.append(item); methods[method]+=1
    rfirst,rhdrs,rbody=split_http(resp)
    sm=re.match(r'HTTP/\S+\s+(\d+)',rfirst)
    status=int(sm.group(1)) if sm else None
    if status: statuses[str(status)]+=1
    ctype=rhdrs.get('content-type','').split(';')[0].strip().lower()
    if ctype: content_types[ctype]+=1
    parsed=urlsplit(target)
    endpoint=parsed.path or '/'; endpoints.add(endpoint)
    rows.append({'index':idx,'method':method,'target':target,'path':endpoint,'status':status,
                 'content_type':ctype,'referer':hdrs.get('referer','')})
    for key,vals in parse_qs(parsed.query,keep_blank_values=True).items():
        for val in vals: params.append({'source':'query','method':method,'path':endpoint,'name':key,'value':val})
    bctype=hdrs.get('content-type','').lower()
    if body:
        if 'application/json' in bctype:
            try:
                for key,val in flatten_json(json.loads(body)):
                    params.append({'source':'json','method':method,'path':endpoint,'name':key,'value':val})
            except Exception: pass
        elif 'application/x-www-form-urlencoded' in bctype:
            for key,vals in parse_qs(body,keep_blank_values=True).items():
                for val in vals: params.append({'source':'form','method':method,'path':endpoint,'name':key,'value':val})
    is_js = bool(re.search(r'\.(?:js|mjs)(?:$|\?)', target, re.I)) or ctype in {'application/javascript','text/javascript'}
    if is_js:
        url='https://'+HOST+target
        js_urls.add(url)
        if status == 200 and rbody:
            digest=hashlib.sha256(url.encode()).hexdigest()[:12]
            base=Path(parsed.path).name or 'index.js'
            base=re.sub(r'[^A-Za-z0-9._-]+','_',base)
            name=f'{digest}_{base}'
            dest=OUT/'js_raw'/name
            if not dest.exists() or len(rbody)>dest.stat().st_size: dest.write_text(rbody,errors='ignore')
            js_manifest.append({'url':url,'file':name,'bytes':len(rbody),'status':status,'source':'burp_response'})

# Add all requests (including those whose large responses were connector-capped)
# to the attack-surface index. De-duplicate by exact raw request.
seen_requests={x.get('request','') for x in items}
for req in request_records:
    if req in seen_requests: continue
    seen_requests.add(req)
    first,hdrs,body=split_http(req); parts=first.split(' ')
    method,target=(parts[0],parts[1]) if len(parts)>=2 else ('','')
    host=hdrs.get('host','').split(':')[0].lower()
    if host != HOST: continue
    parsed=urlsplit(target); endpoint=parsed.path or '/'; endpoints.add(endpoint); methods[method]+=1
    rows.append({'index':None,'method':method,'target':target,'path':endpoint,'status':None,
                 'content_type':None,'referer':hdrs.get('referer',''),'response_truncated_by_connector':True})
    for key,vals in parse_qs(parsed.query,keep_blank_values=True).items():
        for val in vals: params.append({'source':'query','method':method,'path':endpoint,'name':key,'value':val})
    bctype=hdrs.get('content-type','').lower()
    if body and 'application/json' in bctype:
        try:
            for key,val in flatten_json(json.loads(body)):
                params.append({'source':'json','method':method,'path':endpoint,'name':key,'value':val})
        except Exception: pass
    elif body and 'application/x-www-form-urlencoded' in bctype:
        for key,vals in parse_qs(body,keep_blank_values=True).items():
            for val in vals: params.append({'source':'form','method':method,'path':endpoint,'name':key,'value':val})
    if re.search(r'\.(?:js|mjs)(?:$|\?)',target,re.I): js_urls.add('https://'+HOST+target)

def jsonl(path,data):
    path.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in data))
jsonl(OUT/'burp'/'history_full_entries_under_connector_cap.jsonl',items)
jsonl(OUT/'burp'/'history_exact_host.jsonl',exact)
jsonl(OUT/'burp'/'history_external_references.jsonl',external)
jsonl(OUT/'request_index.jsonl',rows)
jsonl(OUT/'parameter_observations.jsonl',params)
jsonl(OUT/'js_manifest.jsonl',sorted({(x['url'],x['file']):x for x in js_manifest}.values(),key=lambda x:x['url']))
(OUT/'endpoints.txt').write_text('\n'.join(sorted(endpoints))+'\n')
(OUT/'js_urls.txt').write_text('\n'.join(sorted(js_urls))+'\n')
param_summary=defaultdict(lambda:{'count':0,'values':set(),'paths':set(),'sources':set()})
for p in params:
    d=param_summary[p['name']]; d['count']+=1; d['values'].add(p['value']); d['paths'].add(p['path']); d['sources'].add(p['source'])
summary=[]
for name,d in sorted(param_summary.items()):
    summary.append({'name':name,'count':d['count'],'sources':sorted(d['sources']),'paths':sorted(d['paths']),
                    'values':sorted(d['values'])[:100],'distinct_values':len(d['values'])})
(OUT/'parameters_summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
stats={'burp_total_matches':295,'full_entries_under_connector_cap':len(items),
       'requests_recovered_from_all_pages':len(request_records),'exact_host_full_entries':len(exact),'external_reference_full_entries':len(external),
       'methods':dict(methods),'statuses':dict(statuses),'content_types':dict(content_types),
       'unique_endpoints':len(endpoints),'parameter_observations':len(params),'unique_parameter_names':len(param_summary),
       'unique_js_urls':len(js_urls),'js_files_recovered':len(list((OUT/'js_raw').iterdir()))}
(OUT/'stats.json').write_text(json.dumps(stats,indent=2)+'\n')
print(json.dumps(stats,indent=2))
