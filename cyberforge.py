
#!/usr/bin/env python3
"""CyberForge v5 - Authorized Security Assessment Suite."""
import argparse, hashlib, html, ipaddress, json, math, re, shutil, socket, ssl
import subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "5.1.0"
BASE = Path(__file__).resolve().parent
REPORTS = BASE / "reports"
TIMEOUT = 8
MAX_REQUESTS = 50
MIN_DELAY = 0.20
UA = "CyberForge/5.0 (Authorized Security Assessment)"

DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,445,587,993,995,3306,3389,5432,6379,8080,8443]

SECURITY_HEADERS = {
    "strict-transport-security":"HSTS",
    "content-security-policy":"CSP",
    "x-content-type-options":"X-Content-Type-Options",
    "x-frame-options":"X-Frame-Options",
    "referrer-policy":"Referrer-Policy",
    "permissions-policy":"Permissions-Policy",
    "cross-origin-opener-policy":"COOP",
    "cross-origin-resource-policy":"CORP",
}

SENSITIVE_PATHS = [
    ".env", ".git/HEAD", ".git/config", "config.php", "wp-config.php",
    "database.yml", "docker-compose.yml", "backup.zip", "backup.tar.gz",
    "backup.sql", "dump.sql", "debug.log", "error.log", ".DS_Store"
]

ERROR_PATTERNS = [
    r"traceback \(most recent call last\)", r"stack trace", r"fatal error",
    r"sql syntax", r"uncaught exception", r"exception in thread"
]

TECH_PATTERNS = {
    "WordPress":[r"/wp-content/",r"/wp-includes/",r"wp-json"],
    "React":[r"react(?:\.production)?\.min\.js",r"data-reactroot"],
    "Next.js":[r"/_next/",r"__NEXT_DATA__"],
    "Vue":[r"vue(?:\.min)?\.js",r"data-v-"],
    "Angular":[r"ng-version",r"angular(?:\.min)?\.js"],
    "jQuery":[r"jquery(?:\.min)?\.js"],
    "Bootstrap":[r"bootstrap(?:\.min)?\.(?:css|js)"],
    "Cloudflare":[r"cf-ray",r"cloudflare"],
}

def stamp():
    return datetime.now(timezone.utc).isoformat()

def clear():
    print("\033[2J\033[H", end="")

def banner():
    print("\033[1;36m╔════════════════════════════════════════════════════════════╗")
    print("║\033[1;97m              CYBERFORGE by  Furkan                      \033[1;36m║")
    print("║\033[1;33m             AUTHORIZED SECURITY ASSESSMENT              \033[1;36m║")
    print("╚════════════════════════════════════════════════════════════╝\033[0m")
    print("\033[0;90m Safe-by-design: network actions require explicit scope.\033[0m")

def save_report(name, data):
    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / (datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + name + ".json")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\033[1;32m[+] Report:\033[0m", path.relative_to(BASE))
    return path

def normalize_url(value):
    value = value.strip()
    if not urllib.parse.urlparse(value).scheme:
        value = "https://" + value
    p = urllib.parse.urlparse(value)
    if p.scheme not in ("http","https") or not p.hostname:
        raise ValueError("Only valid http/https URLs are supported.")
    return value

def scope_entries(path):
    p = Path(path)
    if not p.exists():
        raise ValueError("Scope file not found: " + str(p))
    return [
        x.split("#",1)[0].strip().lower().rstrip(".")
        for x in p.read_text(errors="ignore").splitlines()
        if x.strip() and not x.lstrip().startswith("#")
    ]

def host_ok(host, entries):
    host = host.lower().rstrip(".")
    try:
        hip = ipaddress.ip_address(host)
    except ValueError:
        hip = None
    for entry in entries:
        if entry == "*":
            return True
        if entry.startswith("*.") and (host == entry[2:] or host.endswith("." + entry[2:])):
            return True
        if host == entry:
            return True
        try:
            if hip and hip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False

def require_scope(target, scope):
    if not scope:
        raise PermissionError("Network action blocked. Add --scope scope.txt")
    entries = scope_entries(scope)
    u = urllib.parse.urlparse(target if "://" in target else "//" + target)
    host = u.hostname or target.split("/")[0].split(":")[0]
    if not host_ok(host, entries):
        raise PermissionError(f"Target '{host}' is not in {scope}")
    return host

def fetch(url, method="GET", timeout=TIMEOUT, max_bytes=300000):
    req = urllib.request.Request(url, method=method, headers={"User-Agent":UA,"Accept":"*/*"})
    r = urllib.request.urlopen(req, timeout=timeout)
    body = b"" if method == "HEAD" else r.read(max_bytes)
    return r, body

def finding(severity, title, evidence, remediation):
    return {"severity":severity,"title":title,"evidence":evidence,"remediation":remediation}

def risk(findings):
    weights = {"critical":10,"high":7,"medium":4,"low":1,"info":0}
    score = sum(weights.get(x["severity"].lower(),0) for x in findings)
    level = "CRITICAL" if score >= 20 else "HIGH" if score >= 12 else "MEDIUM" if score >= 6 else "LOW" if score else "INFO"
    return score, level

def hashes(path):
    p = Path(path)
    if not p.is_file():
        raise ValueError("File not found: " + str(p))
    hs = {x:hashlib.new(x) for x in ("md5","sha1","sha256","sha512")}
    total = 0
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            total += len(chunk)
            for h in hs.values():
                h.update(chunk)
    return {"file":str(p),"size":total,**{k:v.hexdigest() for k,v in hs.items()}}

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def malware_analyze(path):
    p = Path(path)
    meta = hashes(p)
    raw = p.read_bytes()[:2000000]
    low = raw.lower()
    indicators = []
    if raw[:2] == b"MZ": indicators.append("PE executable signature")
    if raw[:4] == b"\x7fELF": indicators.append("ELF executable signature")
    if len(raw) > 4096 and entropy(raw) > 7.2: indicators.append("high entropy content")
    for token in (b"powershell -enc",b"eval(",b"base64_decode(",b"cmd.exe /c",b"wget http",b"curl http"):
        if token in low: indicators.append(token.decode(errors="ignore"))
    meta["entropy"] = round(entropy(raw),4)
    meta["indicators"] = sorted(set(indicators))
    meta["risk"] = "HIGH" if len(indicators)>=3 else "MEDIUM" if indicators else "LOW"
    meta["yara_available"] = bool(shutil.which("yara"))
    print("\n\033[1;36mMalware & Suspicious File Analysis\033[0m")
    for k,v in meta.items(): print(f" {k}: {v}")
    save_report("malware_analysis",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"analysis":meta})

def dns(host, scope):
    host = require_scope(host,scope)
    ips = sorted({x[4][0] for x in socket.getaddrinfo(host,None)})
    rows = []
    for ip in ips:
        try: rev = socket.gethostbyaddr(ip)[0]
        except Exception: rev = None
        rows.append({"ip":ip,"reverse_dns":rev})
    print("\n\033[1;36mDNS / Address Resolution\033[0m",host)
    for row in rows: print(" ",row["ip"],"->",row["reverse_dns"] or "no PTR")
    return save_report("dns",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":host,"addresses":ips,"details":rows})

def geoip(host, scope):
    host = require_scope(host,scope)
    ip = socket.gethostbyname(host)
    data = {"ip":ip}
    try:
        _, body = fetch("https://ipwho.is/" + urllib.parse.quote(ip),timeout=6,max_bytes=30000)
        obj = json.loads(body.decode("utf-8","replace"))
        conn = obj.get("connection") or {}
        data.update(country=obj.get("country"),region=obj.get("region"),city=obj.get("city"),
                    latitude=obj.get("latitude"),longitude=obj.get("longitude"),
                    isp=conn.get("isp"),organization=conn.get("org"),asn=conn.get("asn"))
    except Exception as e:
        data["lookup_error"] = str(e)
    data["note"] = "GeoIP is approximate; it is not precise real-time physical tracking."
    for k,v in data.items(): print(f" {k}: {v}")
    return save_report("geoip",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":host,"result":data})

def tls(host, scope, port=443):
    host = require_scope(host,scope)
    data = {"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":host,"port":port}
    findings = []
    print("\n\033[1;36mTLS / HTTPS Security Audit\033[0m",host)
    try:
        with socket.create_connection((host,port),TIMEOUT) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as s:
                cert = s.getpeercert()
                data.update(tls_version=s.version(),cipher=s.cipher(),subject=cert.get("subject"),
                    issuer=cert.get("issuer"),san=cert.get("subjectAltName"),
                    not_before=cert.get("notBefore"),not_after=cert.get("notAfter"),
                    fingerprint=hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest())
                print(" TLS:",s.version()," Cipher:",s.cipher()[0] if s.cipher() else "unknown")
                if s.version() in ("TLSv1","TLSv1.1"):
                    findings.append(finding("high","Legacy TLS version",s.version(),"Disable legacy TLS."))
    except Exception as e:
        data["error"]=str(e)
        findings.append(finding("high","TLS connection failed",str(e),"Review HTTPS/TLS configuration."))
        print("\033[1;31m Error:\033[0m",e)
    data["findings"]=findings
    return save_report("tls",data)

def tech_detect(headers, body):
    hay = body.decode("utf-8","replace").lower() + "\n" + "\n".join(f"{k}:{v}" for k,v in headers.items()).lower()
    found = []
    for tech,pats in TECH_PATTERNS.items():
        if any(re.search(p,hay,re.I) for p in pats): found.append(tech)
    return sorted(set(found))

def parse_links(base, body):
    text = body.decode("utf-8","replace")
    links = set()
    pattern = r'(?:href|src)\s*=\s*["\']([^"\']+)["\']'
    for m in re.finditer(pattern,text,re.I):
        u = urllib.parse.urljoin(base,m.group(1))
        if urllib.parse.urlparse(u).scheme in ("http","https"): links.add(u)
    return sorted(links)

def header_findings(headers, https):
    result, findings = {}, []
    for key,label in SECURITY_HEADERS.items():
        ok = key in headers
        result[label] = ok
        if not ok:
            sev = "medium" if label in ("HSTS","CSP") and https else "low"
            findings.append(finding(sev,"Missing "+label,"Response header not present","Configure "+label+"."))
    return result,findings

def cookie_findings(headers):
    raw = headers.get("set-cookie","")
    if not raw: return []
    out=[]
    if "secure" not in raw.lower(): out.append(finding("medium","Cookie without Secure","Set-Cookie lacks Secure","Set Secure on security-sensitive cookies."))
    if "httponly" not in raw.lower(): out.append(finding("medium","Cookie without HttpOnly","Set-Cookie lacks HttpOnly","Set HttpOnly on session cookies where appropriate."))
    if "samesite" not in raw.lower(): out.append(finding("low","Cookie without SameSite","Set-Cookie lacks SameSite","Set an appropriate SameSite policy."))
    return out

def web_audit(url, scope, deep=True):
    url = normalize_url(url)
    require_scope(url,scope)
    findings=[]
    data={"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":url}
    print("\n\033[1;36mAdvanced Web Security Audit\033[0m",url)
    try:
        r,body = fetch(url)
        headers={k.lower():v for k,v in r.headers.items()}
        final=r.geturl()
        data.update(status=r.status,final_url=final,headers=dict(headers),
                    content_type=headers.get("content-type"),technologies=tech_detect(headers,body))
        sh,f = header_findings(headers,urllib.parse.urlparse(final).scheme=="https")
        data["security_headers"]=sh
        findings += f + cookie_findings(headers)
        for pat in ERROR_PATTERNS:
            if re.search(pat,body.decode("utf-8","replace"),re.I):
                findings.append(finding("medium","Verbose error information indicator",pat,"Disable verbose errors in production."))
        links=parse_links(final,body)
        host=urllib.parse.urlparse(final).hostname
        same=[x for x in links if urllib.parse.urlparse(x).hostname==host]
        data["links_sample"]=same[:100]
        print(" HTTP status:",r.status)
        print(" Final URL:",final)
        print(" Technologies:",", ".join(data["technologies"]) or "not detected")
        print(" Same-origin links:",len(same))
        for label,ok in sh.items():
            print(f" {label:28}", "\033[1;32mOK\033[0m" if ok else "\033[1;33mMISSING\033[0m")
        if "server" in headers: data["server_header"]=headers["server"]
        if deep:
            for name,path in (("robots","/robots.txt"),("sitemap","/sitemap.xml")):
                try:
                    rr,bb=fetch(urllib.parse.urljoin(final,path),timeout=5,max_bytes=10000)
                    data[name]={"status":rr.status,"size":len(bb),"preview":bb.decode("utf-8","replace")[:5000]}
                except Exception:
                    data[name]={"status":"unavailable"}
            checks=[]
            for name in SENSITIVE_PATHS:
                u=urllib.parse.urljoin(final,"/"+name)
                try:
                    rr,_=fetch(u,method="HEAD",timeout=4,max_bytes=0)
                    checks.append({"url":u,"status":rr.status})
                    if rr.status < 400:
                        findings.append(finding("medium","Potentially sensitive public resource",u,"Restrict or remove if not intentionally public."))
                except urllib.error.HTTPError as e:
                    checks.append({"url":u,"status":e.code})
                except Exception:
                    pass
                time.sleep(MIN_DELAY)
            data["sensitive_resource_checks"]=checks
            health=[]
            for link in same[:30]:
                try:
                    rr,_=fetch(link,method="HEAD",timeout=4,max_bytes=0)
                    health.append({"url":link,"status":rr.status})
                    if rr.status >= 500:
                        findings.append(finding("medium","Server error on public endpoint",f"{rr.status} {link}","Review application/server error handling."))
                except Exception as e:
                    health.append({"url":link,"error":str(e)[:120]})
                time.sleep(MIN_DELAY)
            data["endpoint_health"]=health
    except urllib.error.HTTPError as e:
        data["status"]=e.code
        findings.append(finding("medium","HTTP error response",str(e),"Review endpoint and error handling."))
    except Exception as e:
        data["error"]=str(e)
        findings.append(finding("high","Web audit failed",str(e),"Verify target, DNS, TLS and scope."))
    score,level=risk(findings)
    data["findings"]=findings
    data["risk_score"]=score
    data["risk"]=level
    save_report("web_audit",data)
    return data



def fetch_text(url, scope, max_bytes=300000, timeout=TIMEOUT):
    url = normalize_url(url)
    require_scope(url, scope)
    r, body = fetch(url, timeout=timeout, max_bytes=max_bytes)
    return r, body

def subdomain_intelligence(url, scope):
    url = normalize_url(url); host = require_scope(url, scope)
    data = {"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":url,"host":host,"subdomains":[],"sources":[]}
    candidates = set()
    try:
        r, body = fetch(url, timeout=6, max_bytes=200000)
        text = body.decode("utf-8","replace")
        for m in re.findall(r"(?:https?:)?//([A-Za-z0-9.-]+)", text):
            h = m.lower().rstrip('.')
            if h == host or h.endswith('.' + host): candidates.add(h)
        data["sources"].append("page_links")
        cert = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=host)
        cert.settimeout(TIMEOUT); cert.connect((host,443)); obj=cert.getpeercert(); cert.close()
        for kind,name in obj.get("subjectAltName",[]):
            if kind == "DNS" and (name.lower().rstrip('.') == host or name.lower().endswith('.'+host)):
                candidates.add(name.lower().lstrip('*.').rstrip('.'))
        data["sources"].append("tls_certificate_san")
    except Exception as e:
        data["errors"]=[str(e)]
    entries=scope_entries(scope)
    data["subdomains"] = sorted(x for x in candidates if host_ok(x, entries))
    print("\n\033[1;36mSubdomain Intelligence\033[0m",host)
    for x in data["subdomains"]: print(" ",x)
    if not data["subdomains"]: print("  No in-scope subdomains discovered from passive sources.")
    return save_report("subdomain_intelligence",data)

def api_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r, body = fetch(url, timeout=TIMEOUT, max_bytes=300000)
    headers={k.lower():v for k,v in r.headers.items()}
    text=body.decode('utf-8','replace')
    endpoints=[]
    for u in parse_links(r.geturl(), body):
        path=urllib.parse.urlparse(u).path.lower()
        if any(x in path for x in ('/api/','/graphql','/rest/','/v1/','/v2/')):
            endpoints.append(u)
    endpoints=sorted(set(endpoints))[:50]
    findings=[]
    if 'authorization' not in headers and any(x in text.lower() for x in ('/api/','graphql')):
        findings.append(finding('info','API indicators detected','Page references API-style endpoints','Review authentication and authorization controls for each API.'))
    if 'access-control-allow-origin' in headers and headers['access-control-allow-origin'].strip() == '*':
        findings.append(finding('medium','Permissive API CORS policy','Access-Control-Allow-Origin: *','Restrict origins where sensitive API data is exposed.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'status':r.status,'api_endpoints':endpoints,'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mAPI Security Audit\033[0m",url)
    print(' API-style endpoints:',len(endpoints)); print(' CORS:',headers.get('access-control-allow-origin','not advertised'))
    return save_report('api_security',data)

def cookie_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100)
    headers={k.lower():v for k,v in r.headers.items()}
    raw=r.headers.get_all('Set-Cookie') or []
    findings=[]; rows=[]
    for c in raw:
        low=c.lower(); name=c.split('=',1)[0].strip()
        row={'name':name,'secure':'secure' in low,'httponly':'httponly' in low,'samesite':re.search(r'samesite=([^;]+)',low).group(1) if re.search(r'samesite=([^;]+)',low) else None}
        rows.append(row)
        if not row['secure']: findings.append(finding('medium','Cookie missing Secure',name,'Use Secure for cookies carrying sensitive state over HTTPS.'))
        if not row['httponly']: findings.append(finding('medium','Cookie missing HttpOnly',name,'Use HttpOnly for session cookies when JavaScript access is unnecessary.'))
        if not row['samesite']: findings.append(finding('low','Cookie missing SameSite',name,'Set an appropriate SameSite policy.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'cookies':rows,'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCookie Security Audit\033[0m",url)
    print(' Cookies:',len(rows))
    for x in rows: print(' ',x['name'], 'Secure='+str(x['secure']), 'HttpOnly='+str(x['httponly']), 'SameSite='+str(x['samesite']))
    return save_report('cookie_security',data)

def cors_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100)
    h={k.lower():v for k,v in r.headers.items()}; findings=[]
    origin=h.get('access-control-allow-origin')
    creds=h.get('access-control-allow-credentials','').lower()
    if origin=='*': findings.append(finding('medium','Wildcard CORS origin','Access-Control-Allow-Origin: *','Restrict cross-origin access for sensitive resources.'))
    if origin and origin!='*' and creds=='true': findings.append(finding('info','Credentialed CORS enabled',f'{origin} with credentials=true','Ensure the allowed origin is a trusted application origin.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'cors':{k:v for k,v in h.items() if k.startswith('access-control-')},'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCORS Security Audit\033[0m",url)
    print(' Allow-Origin:',origin or 'not advertised'); print(' Allow-Credentials:',creds or 'not advertised')
    return save_report('cors_security',data)

def javascript_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); links=parse_links(r.geturl(),body)
    text=body.decode('utf-8','replace'); scripts=[]
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)',text,re.I):
        u=urllib.parse.urljoin(r.geturl(),m.group(1));
        if urllib.parse.urlparse(u).scheme in ('http','https') and host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)): scripts.append(u)
    indicators=[]
    for pat,label in [(r'(?i)sourceMappingURL=','source map reference'),(r'(?i)(api[_-]?key|client[_-]?secret)\s*[:=]','possible exposed configuration key'),(r'(?i)eval\s*\(','eval usage indicator')]:
        if re.search(pat,text): indicators.append(label)
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'scripts':sorted(set(scripts))[:100],'indicators':indicators,'findings':[]}
    if 'source map reference' in indicators: data['findings'].append(finding('low','Source map reference detected','JavaScript references a source map','Review whether production source maps should be publicly accessible.'))
    if 'possible exposed configuration key' in indicators: data['findings'].append(finding('medium','Possible exposed client configuration','JavaScript contains a key-like configuration pattern','Verify no secret credential is embedded in client-side code.'))
    score,level=risk(data['findings']); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mJavaScript Security Audit\033[0m",url); print(' Scripts:',len(data['scripts'])); print(' Indicators:',', '.join(indicators) or 'none')
    return save_report('javascript_security',data)

def cloud_exposure_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); text=body.decode('utf-8','replace')
    patterns=[r'https?://[A-Za-z0-9._-]+\.s3(?:[-.][A-Za-z0-9.-]+)?\.amazonaws\.com[^\s"\']*',r'https?://storage\.googleapis\.com/[^\s"\']+',r'https?://[A-Za-z0-9.-]+\.blob\.core\.windows\.net[^\s"\']*']
    matches=[]
    for pat in patterns: matches += re.findall(pat,text,re.I)
    findings=[]
    if matches: findings.append(finding('medium','Public cloud resource reference detected',', '.join(sorted(set(matches))[:10]),'Verify referenced cloud objects are intentionally public and access-controlled.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'cloud_references':sorted(set(matches))[:50],'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCloud Exposure Audit\033[0m",url); print(' Cloud references:',len(data['cloud_references']))
    return save_report('cloud_exposure',data)

def waf_cdn_detection(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100); h={k.lower():v for k,v in r.headers.items()}
    signals=[]
    if 'cf-ray' in h or 'cloudflare' in h.get('server','').lower(): signals.append('Cloudflare')
    if 'x-amz-cf-id' in h or 'cloudfront' in h.get('via','').lower(): signals.append('Amazon CloudFront')
    if 'x-sucuri-id' in h or 'sucuri' in h.get('server','').lower(): signals.append('Sucuri')
    if 'akamai' in h.get('server','').lower() or 'akamai' in h.get('via','').lower(): signals.append('Akamai')
    if 'x-cache' in h: signals.append('Generic cache/CDN signal')
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'detected':sorted(set(signals)),'evidence':{k:v for k,v in h.items() if k in ('server','via','cf-ray','x-amz-cf-id','x-sucuri-id','x-cache')}}
    print("\n\033[1;36mWAF / CDN Detection\033[0m",url); print(' Detected:',', '.join(data['detected']) or 'not detected')
    return save_report('waf_cdn',data)

def authentication_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); text=body.decode('utf-8','replace'); findings=[]
    forms=re.findall(r'<form\b[^>]*>(.*?)</form>',text,re.I|re.S)
    password_forms=sum(1 for f in forms if re.search(r'type=["\']password["\']',f,re.I))
    auth_links=[x for x in parse_links(r.geturl(),body) if re.search(r'(login|signin|auth|account|session)',x,re.I)][:30]
    if password_forms and urllib.parse.urlparse(r.geturl()).scheme!='https': findings.append(finding('high','Password form served over HTTP','Password input detected on non-HTTPS page','Serve authentication forms only over HTTPS.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'password_forms':password_forms,'auth_links':auth_links,'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mAuthentication Security Audit\033[0m",url); print(' Password forms:',password_forms); print(' Auth-related links:',len(auth_links))
    return save_report('authentication_security',data)

def api_endpoint_discovery(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,body=fetch(url,timeout=TIMEOUT,max_bytes=500000); base=r.geturl(); text=body.decode('utf-8','replace')
    endpoints=set()
    for u in parse_links(base,body):
        if host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)) and re.search(r'/(api|graphql|rest|v\d+)(?:/|$)',urllib.parse.urlparse(u).path,re.I): endpoints.add(u)
    for m in re.findall(r'["\']((?:/|https?://)[A-Za-z0-9_./?=&%-]*(?:api|graphql|rest|v1|v2)[A-Za-z0-9_./?=&%-]*)["\']',text,re.I):
        u=urllib.parse.urljoin(base,m)
        if host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)): endpoints.add(u)
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'endpoints':sorted(endpoints)[:100]}
    print("\n\033[1;36mAPI Endpoint Discovery\033[0m",url); print(' Endpoints:',len(data['endpoints']))
    for x in data['endpoints'][:30]: print(' ',x)
    return save_report('api_endpoints',data)

def dependency_cve_intelligence(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); h={k.lower():v for k,v in r.headers.items()}; text=body.decode('utf-8','replace')
    candidates=[]
    patterns=[('WordPress',r'(?i)wp(?:-|_)?version["\']?\s*[:=]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),('jQuery',r'(?i)jquery(?:-|\.)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),('Bootstrap',r'(?i)bootstrap(?:-|\.)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)')]
    for name,pat in patterns:
        for v in re.findall(pat,text): candidates.append({'component':name,'version':v,'cve_lookup':'recommended'})
    if 'x-powered-by' in h: candidates.append({'component':'X-Powered-By','version':h['x-powered-by'],'cve_lookup':'recommended'})
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'detected_components':candidates,'note':'This module identifies version candidates; verify against a trusted CVE database before treating a CVE as confirmed.'}
    print("\n\033[1;36mDependency / CVE Intelligence\033[0m",url)
    for x in candidates: print(' ',x['component'],x['version'])
    if not candidates: print(' No reliable component versions detected.')
    return save_report('dependency_cve',data)

def http_method_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,method='OPTIONS',timeout=TIMEOUT,max_bytes=2000); h={k.lower():v for k,v in r.headers.items()}; allow=h.get('allow','')
    methods=[x.strip().upper() for x in allow.split(',') if x.strip()]
    findings=[]
    unusual=[x for x in methods if x not in ('GET','HEAD','POST','OPTIONS')]
    if any(x in methods for x in ('TRACE','CONNECT')): findings.append(finding('medium','Potentially unnecessary HTTP method advertised',', '.join(methods),'Disable methods not required by the application.'))
    if unusual: findings.append(finding('low','Additional HTTP methods advertised',', '.join(unusual),'Review whether each method is necessary and properly authorized.'))
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':url,'status':r.status,'allow':allow,'methods':methods,'findings':findings}
    score,level=risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mHTTP Method Security Audit\033[0m",url); print(' Allow:',allow or 'not advertised')
    return save_report('http_methods',data)

def risk_scoring_engine(target=None):
    files=sorted(REPORTS.glob('*.json'))[-100:]; selected=[]
    for f in files:
        try:
            d=json.loads(f.read_text(encoding='utf-8'))
            if target and d.get('target') and d.get('target') != target: continue
            selected.append((f,d))
        except Exception: pass
    findings=[]
    for _,d in selected: findings.extend(d.get('findings',[]))
    score,level=risk(findings)
    counts={k:sum(1 for x in findings if x.get('severity','').lower()==k) for k in ('critical','high','medium','low','info')}
    normalized=min(100,score*4)
    grade='A' if normalized<=10 else 'B' if normalized<=25 else 'C' if normalized<=50 else 'D' if normalized<=75 else 'F'
    data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':target,'reports_considered':len(selected),'finding_counts':counts,'risk_score':score,'risk_level':level,'security_score':max(0,100-normalized),'grade':grade,'top_findings':findings[:20]}
    print("\n\033[1;35mCYBERFORGE SECURITY SCORE\033[0m")
    print(' Overall Score:',data['security_score'],'/ 100'); print(' Grade:',grade); print(' Risk:',level); print(' Critical:',counts['critical'],'High:',counts['high'],'Medium:',counts['medium'],'Low:',counts['low'])
    return save_report('risk_score',data)

def nmap_scan(host, scope, profile="quick"):
    host=require_scope(host,scope)
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is not installed. Install it first.")
    profiles={
        "quick":["-T2","--top-ports","20","-sV","--version-light"],
        "service":["-T2","-p-","-sV","--version-light"],
        "os":["-T2","-sV","-O","--osscan-limit"],
        "common":["-T2","-p",",".join(map(str,DEFAULT_PORTS)),"-sV","--version-light"],
    }
    cmd=["nmap",*profiles[profile],host]
    print("\n\033[1;36mNmap Network Scanner\033[0m",host)
    print(" Command:"," ".join(cmd))
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
    out=(p.stdout or "")[-20000:]
    err=(p.stderr or "")[-5000:]
    print(out)
    if err: print("\033[1;33mNmap notes:\033[0m",err)
    return save_report("nmap",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),
        "target":host,"profile":profile,"returncode":p.returncode,"stdout":out,"stderr":err})

def ports(host,scope,plist=None):
    host=require_scope(host,scope)
    plist=plist or DEFAULT_PORTS
    if len(plist)>50: raise ValueError("Maximum 50 ports per run")
    rows=[]
    print("\n\033[1;36mPort Audit\033[0m",host)
    for port in plist:
        with socket.socket() as s:
            s.settimeout(.8); t=time.perf_counter()
            try: state="open" if s.connect_ex((host,int(port)))==0 else "closed/filtered"
            except OSError: state="error"
            ms=round((time.perf_counter()-t)*1000,2)
        print(f" {int(port):5} {state:16} {ms:8.2f} ms")
        rows.append({"port":int(port),"state":state,"latency_ms":ms})
    save_report("ports",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":host,"results":rows})

def load_check(url,scope,count=10,delay=.5):
    url=normalize_url(url); require_scope(url,scope)
    if not 1<=count<=MAX_REQUESTS: raise ValueError(f"count must be 1-{MAX_REQUESTS}")
    if delay<MIN_DELAY: raise ValueError(f"delay must be >= {MIN_DELAY}s")
    rows=[]
    for i in range(1,count+1):
        t=time.perf_counter(); status=None; err=None
        try: r,_=fetch(url,max_bytes=64); status=r.status
        except Exception as e: err=str(e)
        ms=round((time.perf_counter()-t)*1000,2)
        print(f" {i:02}/{count} status={status} {ms:8.2f} ms")
        rows.append({"request":i,"status":status,"latency_ms":ms,"error":err})
        if i<count: time.sleep(delay)
    save_report("load_check",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":url,"count":count,"delay":delay,"results":rows})

def file_hash(path):
    data=hashes(path)
    print(json.dumps(data,indent=2))
    save_report("file_hash",{"tool":"CyberForge","version":VERSION,"timestamp":stamp(),**data})

def reports_list():
    REPORTS.mkdir(exist_ok=True)
    for f in sorted(REPORTS.glob("*.json"))[-30:]: print(" ",f.name)

def export_html():
    files=sorted(REPORTS.glob("*.json"))
    if not files: raise ValueError("No JSON reports available.")
    sections=[]
    for f in files[-50:]:
        try:
            d=json.loads(f.read_text(encoding="utf-8"))
            sections.append("<h2>"+html.escape(f.name)+"</h2><pre>"+html.escape(json.dumps(d,indent=2,ensure_ascii=False))+"</pre>")
        except Exception: pass
    out=REPORTS/(datetime.now().strftime("%Y%m%d_%H%M%S")+"_cyberforge_report.html")
    out.write_text("<!doctype html><html><meta charset='utf-8'><title>CyberForge v5 Report</title><style>body{font-family:monospace;background:#07120a;color:#7cff7c;padding:24px}pre{white-space:pre-wrap}</style><h1>CYBERFORGE v5</h1>"+''.join(sections)+"</html>",encoding="utf-8")
    print("[+] HTML report:",out.relative_to(BASE))

def deep_analysis(target,scope):
    url=normalize_url(target); host=require_scope(url,scope)
    print("\n\033[1;35m=== DEEP SECURITY ANALYSIS ===\033[0m")
    web=web_audit(url,scope,True)
    tls_result=tls(host,scope,443)
    dns_result=dns(host,scope)
    try: geo=geoip(host,scope)
    except Exception as e: geo={"error":str(e)}
    try: nm=nmap_scan(host,scope,"quick")
    except Exception as e: nm={"error":str(e)}
    try: pr=ports(host,scope)
    except Exception as e: pr={"error":str(e)}
    findings=web.get("findings",[])+tls_result.get("findings",[])
    score,level=risk(findings)
    data={"tool":"CyberForge","version":VERSION,"timestamp":stamp(),"target":url,
          "summary":{"finding_count":len(findings),"risk_score":score,"risk":level},
          "modules":{"web":web,"tls":tls_result,"dns":dns_result,"geoip":geo,"nmap":nm,"ports":pr}}
    print(f"\n\033[1;32mDeep Analysis Complete\033[0m | Findings: {len(findings)} | Risk: {level}")
    save_report("deep_analysis",data)
    return data

def scope_check(scope):
    entries=scope_entries(scope)
    if not entries: raise ValueError("Scope file is empty.")
    print("\n\033[1;36mAuthorized Scope\033[0m")
    for e in entries: print(" -",e)

def interactive(scope_default=None):
    while True:
        clear(); banner()
        print("""
 [1]  Advanced Web Security Audit
 [2]  Nmap Network Scanner
 [3]  TLS / HTTPS Security Audit
 [4]  Port & Service Enumeration
 [5]  DNS / IP Intelligence
 [6]  Security Headers Audit
 [7]  Web Technology Fingerprinting
 [8]  Vulnerability Assessment
 [9]  Broken Link & Endpoint Audit
 [10] Sensitive File / Object Detection
 [11] Malware & Suspicious File Analysis
 [12] Error & Misconfiguration Detection
 [13] Security Configuration Audit
 [14] IP / ASN / GeoIP Intelligence
 [15] SSL Certificate Intelligence
 [16] Robots.txt / Sitemap Analysis
 [17] URL / Redirect Security Audit
 [18] File Hash & Integrity Analysis
 [19] Deep Security Analysis
 [20] Scope / Authorization Check
 [21] Scan History
 [22] Generate HTML Report

 [23] Subdomain Intelligence
 [24] API Security Audit
 [25] Cookie Security Audit
 [26] CORS Security Audit
 [27] JavaScript Security Audit
 [28] Cloud Exposure Audit
 [29] WAF / CDN Detection
 [30] Authentication Security Audit
 [31] API Endpoint Discovery
 [32] Dependency / CVE Intelligence
 [33] HTTP Method Security Audit
 [34] Security Risk Scoring Engine
 [0]  Exit
""")
        c=input(" CyberForge > ").strip()
        try:
            if c=="0": return
            if c=="11": malware_analyze(input(" Local file > ").strip())
            elif c=="18": file_hash(input(" Local file > ").strip())
            elif c=="21": reports_list()
            elif c=="22": export_html()
            elif c=="34": risk_scoring_engine(input(" Target URL [optional] > ").strip() or None)
            elif c=="20": scope_check(input(" Scope file > ").strip() or scope_default or "scope.txt")
            else:
                s=input(f" Scope file [{scope_default or 'scope.txt'}] > ").strip() or scope_default or "scope.txt"
                if c=="1": web_audit(input(" URL > ").strip(),s,True)
                elif c=="2": nmap_scan(input(" Host > ").strip(),s,input(" Profile [quick/service/os/common] > ").strip() or "quick")
                elif c=="3": tls(input(" Host > ").strip(),s)
                elif c=="4":
                    h=input(" Host > ").strip(); q=input(" Ports [default] > ").strip(); ports(h,s,[int(x) for x in q.split(",")] if q else None)
                elif c=="5": dns(input(" Host > ").strip(),s)
                elif c=="6":
                    d=web_audit(input(" URL > ").strip(),s,False); print("\nSecurity Headers:"); [print(f" {k}: {'OK' if v else 'MISSING'}") for k,v in d.get('security_headers',{}).items()]
                elif c=="7":
                    u=input(" URL > ").strip(); d=web_audit(u,s,False); print(" Technologies:",", ".join(d.get('technologies',[])) or 'not detected')
                elif c=="8": web_audit(input(" URL > ").strip(),s,True)
                elif c=="9": web_audit(input(" URL > ").strip(),s,True)
                elif c=="10": web_audit(input(" URL > ").strip(),s,True)
                elif c=="12": web_audit(input(" URL > ").strip(),s,True)
                elif c=="13": web_audit(input(" URL > ").strip(),s,True)
                elif c=="14": geoip(input(" Host > ").strip(),s)
                elif c=="15": tls(input(" Host > ").strip(),s)
                elif c=="16":
                    u=normalize_url(input(" URL > ").strip()); require_scope(u,s); r,_=fetch(u); base=r.geturl();
                    rows=[]
                    for path in ('/robots.txt','/sitemap.xml'):
                        try: rr,bb=fetch(urllib.parse.urljoin(base,path),timeout=5,max_bytes=20000); rows.append({'url':rr.geturl(),'status':rr.status,'preview':bb.decode('utf-8','replace')[:5000]})
                        except Exception as e: rows.append({'url':urllib.parse.urljoin(base,path),'error':str(e)})
                    print(json.dumps(rows,indent=2)); save_report('robots_sitemap',{'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':u,'results':rows})
                elif c=="17":
                    u=normalize_url(input(" URL > ").strip()); require_scope(u,s); r,_=fetch(u,timeout=TIMEOUT,max_bytes=100); data={'tool':'CyberForge','version':VERSION,'timestamp':stamp(),'target':u,'final_url':r.geturl(),'redirected':r.geturl()!=u,'status':r.status}; print(' Final URL:',r.geturl()); save_report('redirect_audit',data)
                elif c=="19": deep_analysis(input(" URL > ").strip(),s)
                elif c=="23": subdomain_intelligence(input(" URL > ").strip(),s)
                elif c=="24": api_security_audit(input(" URL > ").strip(),s)
                elif c=="25": cookie_security_audit(input(" URL > ").strip(),s)
                elif c=="26": cors_security_audit(input(" URL > ").strip(),s)
                elif c=="27": javascript_security_audit(input(" URL > ").strip(),s)
                elif c=="28": cloud_exposure_audit(input(" URL > ").strip(),s)
                elif c=="29": waf_cdn_detection(input(" URL > ").strip(),s)
                elif c=="30": authentication_security_audit(input(" URL > ").strip(),s)
                elif c=="31": api_endpoint_discovery(input(" URL > ").strip(),s)
                elif c=="32": dependency_cve_intelligence(input(" URL > ").strip(),s)
                elif c=="33": http_method_security_audit(input(" URL > ").strip(),s)
                else: print(" Unknown option.")
        except (KeyboardInterrupt,EOFError): return
        except Exception as e: print("\033[1;31m[!]\033[0m",e)
        input("\n Press Enter to continue...")

def main():
    p=argparse.ArgumentParser(description="CyberForge v5 - authorized defensive security assessment toolkit")
    p.add_argument("--scope")
    sub=p.add_subparsers(dest="cmd")
    q=sub.add_parser("file-hash"); q.add_argument("path")
    q=sub.add_parser("malware-analyze"); q.add_argument("path")
    q=sub.add_parser("web-audit"); q.add_argument("url")
    q=sub.add_parser("deep-audit"); q.add_argument("url")
    q=sub.add_parser("tls"); q.add_argument("host"); q.add_argument("--port",type=int,default=443)
    q=sub.add_parser("nmap"); q.add_argument("host"); q.add_argument("--profile",choices=["quick","service","os","common"],default="quick")
    q=sub.add_parser("ports"); q.add_argument("host"); q.add_argument("--ports")
    q=sub.add_parser("dns"); q.add_argument("host")
    q=sub.add_parser("geoip"); q.add_argument("host")
    q=sub.add_parser("load-check"); q.add_argument("url"); q.add_argument("--count",type=int,default=10); q.add_argument("--delay",type=float,default=.5)
    q=sub.add_parser("subdomain-intel"); q.add_argument("url")
    q=sub.add_parser("api-audit"); q.add_argument("url")
    q=sub.add_parser("cookie-audit"); q.add_argument("url")
    q=sub.add_parser("cors-audit"); q.add_argument("url")
    q=sub.add_parser("javascript-audit"); q.add_argument("url")
    q=sub.add_parser("cloud-audit"); q.add_argument("url")
    q=sub.add_parser("waf-cdn"); q.add_argument("url")
    q=sub.add_parser("auth-audit"); q.add_argument("url")
    q=sub.add_parser("api-endpoints"); q.add_argument("url")
    q=sub.add_parser("dependency-intel"); q.add_argument("url")
    q=sub.add_parser("http-methods"); q.add_argument("url")
    q=sub.add_parser("risk-score"); q.add_argument("--target")
    sub.add_parser("html-report")
    a=p.parse_args()
    try:
        if not a.cmd: interactive(a.scope); return
        if a.cmd=="file-hash": file_hash(a.path)
        elif a.cmd=="malware-analyze": malware_analyze(a.path)
        elif a.cmd=="web-audit": web_audit(a.url,a.scope,True)
        elif a.cmd=="deep-audit": deep_analysis(a.url,a.scope)
        elif a.cmd=="tls": tls(a.host,a.scope,a.port)
        elif a.cmd=="nmap": nmap_scan(a.host,a.scope,a.profile)
        elif a.cmd=="ports": ports(a.host,a.scope,[int(x) for x in a.ports.split(",")] if a.ports else None)
        elif a.cmd=="dns": dns(a.host,a.scope)
        elif a.cmd=="geoip": geoip(a.host,a.scope)
        elif a.cmd=="load-check": load_check(a.url,a.scope,a.count,a.delay)
        elif a.cmd=="subdomain-intel": subdomain_intelligence(a.url,a.scope)
        elif a.cmd=="api-audit": api_security_audit(a.url,a.scope)
        elif a.cmd=="cookie-audit": cookie_security_audit(a.url,a.scope)
        elif a.cmd=="cors-audit": cors_security_audit(a.url,a.scope)
        elif a.cmd=="javascript-audit": javascript_security_audit(a.url,a.scope)
        elif a.cmd=="cloud-audit": cloud_exposure_audit(a.url,a.scope)
        elif a.cmd=="waf-cdn": waf_cdn_detection(a.url,a.scope)
        elif a.cmd=="auth-audit": authentication_security_audit(a.url,a.scope)
        elif a.cmd=="api-endpoints": api_endpoint_discovery(a.url,a.scope)
        elif a.cmd=="dependency-intel": dependency_cve_intelligence(a.url,a.scope)
        elif a.cmd=="http-methods": http_method_security_audit(a.url,a.scope)
        elif a.cmd=="risk-score": risk_scoring_engine(a.target)
        elif a.cmd=="html-report": export_html()
    except Exception as e:
        print("\033[1;31m[!]\033[0m",e); sys.exit(2)

if __name__=="__main__":
    main()
