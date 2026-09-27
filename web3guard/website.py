"""Bounded passive web reconnaissance for authorized targets."""
from __future__ import annotations
import json, re, urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag
from web3guard.utils.fetch import FetchError, _OPENER, _assert_public_host
from web3guard.utils.secrets import iter_secret_matches, redact_sensitive_text

_ENDPOINT_RE = re.compile(r'(?:(?:https?:)?//[^"\'\\s<>]+|/(?:api|graphql|rest|v[0-9]+)/[^"\'\\s<>]+)', re.I)

@dataclass
class WebsitePage:
    url: str
    status: int
    content_type: str
    depth: int
    title: str = ""
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict[str, object]] = field(default_factory=list)
    findings: list[dict[str, object]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

@dataclass
class WebsiteReport:
    target: str
    pages: list[WebsitePage] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secret_findings: list[dict[str, object]] = field(default_factory=list)
    security_findings: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    def to_dict(self): return asdict(self)

class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.links=[]; self.scripts=[]; self.forms=[]; self.title_parts=[]; self._title=False; self._form=None
    def handle_starttag(self, tag, attrs):
        a={k.lower():(v or "") for k,v in attrs}; t=tag.lower()
        if t=="a" and a.get("href"): self.links.append(a["href"])
        elif t=="script" and a.get("src"): self.scripts.append(a["src"])
        elif t=="title": self._title=True
        elif t=="form": self._form={"action":a.get("action",""),"method":a.get("method","GET").upper(),"inputs":[]}
        elif t in {"input","textarea","select","button"} and self._form is not None: self._form["inputs"].append({"tag":t,"name":a.get("name",""),"type":a.get("type","")})
    def handle_endtag(self, tag):
        if tag.lower()=="title": self._title=False
        elif tag.lower()=="form" and self._form is not None: self.forms.append(self._form); self._form=None
    def handle_data(self, data):
        if self._title: self.title_parts.append(data)

def _same_origin(a,b):
    x,y=urlparse(a),urlparse(b); px=x.port or (443 if x.scheme=="https" else 80); py=y.port or (443 if y.scheme=="https" else 80)
    return (x.scheme,x.hostname,px)==(y.scheme,y.hostname,py)

def _normalize(base,href):
    u=urldefrag(urljoin(base,href))[0]; p=urlparse(u)
    return u if p.scheme in {"http","https"} and p.hostname else None

def _get(url,max_bytes,timeout):
    _assert_public_host(url)
    req=urllib.request.Request(url,headers={"User-Agent":"Web3Guard-WebRecon/1.0","Accept":"text/html,application/javascript,*/*;q=0.8","Accept-Encoding":"identity"})
    with _OPENER.open(req,timeout=timeout) as resp:
        data=resp.read(max_bytes+1)
        if len(data)>max_bytes: raise FetchError("response exceeded byte cap")
        return int(resp.status),resp.headers.get("content-type",""),{k.lower():v for k,v in resp.headers.items()},data

def _header_findings(headers,https):
    out=[]
    if https and "strict-transport-security" not in headers: out.append({"id":"missing-hsts","severity":"MEDIUM","description":"HSTS header is absent."})
    for h,i,s,d in (("content-security-policy","missing-csp","LOW","Content-Security-Policy is absent."),("x-content-type-options","missing-nosniff","LOW","X-Content-Type-Options is missing."),("referrer-policy","missing-referrer-policy","LOW","Referrer-Policy is absent.")):
        if h not in headers or (h=="x-content-type-options" and headers.get(h,"").lower()!="nosniff"): out.append({"id":i,"severity":s,"description":d})
    return out

def scan_website(target,max_pages=25,max_depth=2,max_total_bytes=32*1024*1024,timeout=15):
    p=urlparse(target)
    if p.scheme not in {"http","https"} or not p.hostname: raise FetchError("website target must be an http(s) URL")
    _assert_public_host(target); target=urldefrag(target)[0]
    report=WebsiteReport(target); q=deque([(target,0)]); seen=set(); scripts=set(); total=0
    while q and len(report.pages)<max_pages:
        current,depth=q.popleft()
        if current in seen: continue
        seen.add(current)
        try: status,ctype,headers,body=_get(current,4*1024*1024,timeout)
        except Exception as exc: report.warnings.append(f"{current}: {type(exc).__name__}: {exc}"); continue
        total+=len(body)
        if total>max_total_bytes: report.warnings.append("total response-byte cap reached"); break
        page=WebsitePage(current,status,ctype,depth,headers=headers); page.findings.extend(_header_findings(headers,p.scheme=="https"))
        text=body.decode("utf-8",errors="replace")
        if p.scheme=="http": page.findings.append({"id":"cleartext-http","severity":"MEDIUM","description":"The target URL uses HTTP."})
        for m in iter_secret_matches(text):
            item={"kind":m.kind,"file":current,"line":m.line,"snippet":f"<redacted:{m.kind}>"}; page.findings.append({"id":"secret-leak","severity":"CRITICAL","description":f"Potential {m.kind} exposed in page source."}); report.secret_findings.append(item)
        if "text/html" in ctype.lower() or "<html" in text[:1024].lower():
            parser=_PageParser(); parser.feed(text); page.title=" ".join(" ".join(parser.title_parts).split())[:300]; page.forms=parser.forms
            for link in parser.links:
                u=_normalize(current,link)
                if u and _same_origin(target,u): page.links.append(u); report.discovered_urls.append(u); depth<max_depth and q.append((u,depth+1))
            for src in parser.scripts[:50]:
                u=_normalize(current,src)
                if u and _same_origin(target,u): page.scripts.append(u)
        for raw in _ENDPOINT_RE.findall(text):
            u=_normalize(current,raw)
            if u and _same_origin(target,u): report.endpoints.append(u[:500])
        for script in page.scripts:
            if script in scripts or len(scripts)>=50: continue
            scripts.add(script)
            try: _,_,_,js=_get(script,2*1024*1024,timeout)
            except Exception as exc: report.warnings.append(f"{script}: {type(exc).__name__}"); continue
            total+=len(js); jst=js.decode("utf-8",errors="replace")
            for m in iter_secret_matches(jst): report.secret_findings.append({"kind":m.kind,"file":script,"line":m.line,"snippet":f"<redacted:{m.kind}>"})
            for raw in _ENDPOINT_RE.findall(jst):
                u=_normalize(script,raw)
                if u and _same_origin(target,u): report.endpoints.append(u[:500])
        report.pages.append(page)
    report.discovered_urls=sorted(set(report.discovered_urls)); report.endpoints=sorted(set(report.endpoints)); return report

def write_website_report(report,out_dir):
    out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    paths={"json":out_dir/"WEB3GUARD_WEBSITE_REPORT.json","md":out_dir/"WEB3GUARD_WEBSITE_REPORT.md","txt":out_dir/"WEB3GUARD_WEBSITE_REPORT.txt"}
    paths["json"].write_text(json.dumps(report.to_dict(),indent=2)+"\n",encoding="utf-8")
    lines=["# Web3Guard Website Reconnaissance","",f"Target: `{report.target}`",f"Pages crawled: {len(report.pages)}",f"URLs discovered: {len(report.discovered_urls)}","","## Findings"]
    findings=report.security_findings+[ {"severity":"CRITICAL","description":f"Potential {x['kind']} in {x['file']} line {x['line']} (value redacted)."} for x in report.secret_findings ]
    lines += (["- No passive security findings detected."] if not findings else [f"- **{f.get('severity','INFO')}** — {redact_sensitive_text(str(f.get('description','')))}" for f in findings])
    lines += ["","## Endpoints",*(f"- `{x}`" for x in report.endpoints[:200])]
    md="\n".join(lines)+"\n"; paths["md"].write_text(md,encoding="utf-8"); paths["txt"].write_text(re.sub(r"[*`]","",md),encoding="utf-8"); return paths
