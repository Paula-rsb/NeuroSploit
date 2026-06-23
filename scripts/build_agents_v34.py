#!/usr/bin/env python3
"""
NeuroSploit v3.4.x — recon + whitebox(code) agent builder.

Emits two new categories the Rust harness loads:
  agents_md/recon/  — information-gathering specialists
  agents_md/code/   — white-box source-code (SAST) review specialists

Usage: python3 scripts/build_agents_v34.py
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def render(a, code=False):
    L = [f"# {a['title']} Agent\n", "## User Prompt"]
    if code:
        L.append(f"You are reviewing the source code of **{{target}}** for {a['for']}.\n")
        L.append("**Recon Context:**\n{recon_json}\n")
        L.append("The relevant source files are provided to you below the methodology.\n")
    else:
        L.append(f"You are performing reconnaissance on **{{target}}** to {a['for']}.\n")
        L.append("**Recon Context:**\n{recon_json}\n")
    L.append("**METHODOLOGY:**\n")
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L.append(f"### {n}. Report Format")
    L.append("For each CONFIRMED finding:")
    L.append("```")
    L.append("FINDING:")
    L.append(f"- Title: {a['title']} at [{'file:line' if code else 'asset/endpoint'}]")
    L.append(f"- Severity: {a['sev']}")
    L.append(f"- CWE: {a['cwe']}")
    L.append(f"- Endpoint: [{'file:line' if code else 'URL/host'}]")
    L.append("- Vector: [what/where]")
    L.append("- Payload: [PoC / vulnerable code snippet]")
    L.append("- Evidence: [proof / exact code quoted]")
    L.append(f"- Impact: {a['impact']}")
    L.append(f"- Remediation: {a['fix']}")
    L.append("```\n")
    L.append("## System Prompt")
    L.append(a["system"])
    return "\n".join(L) + "\n"


RECON = [
{"name":"subdomain_enum","title":"Subdomain Enumeration Specialist","for":"discover all subdomains and expand the attack surface","sev":"Info","cwe":"CWE-200","impact":"Wider attack surface, forgotten/staging hosts","fix":"Inventory and decommission stale DNS records",
 "steps":[("Passive sources",["Query crt.sh, certificate transparency, Shodan, and passive DNS","Run `subfinder -d {target}` and `amass enum -passive -d {target}`"]),
 ("Active resolution",["Resolve and probe with `httpx -title -tech-detect -status-code`","Bruteforce with a curated wordlist where in scope"]),
 ("Triage",["Flag dev/staging/admin/api hosts and dangling CNAMEs (subdomain takeover candidates)"])],
 "system":"You are a recon specialist. Report only resolvable, in-scope subdomains you actually observed, with the resolution evidence. Do not invent hosts."},
{"name":"tech_fingerprint","title":"Technology Fingerprinting Specialist","for":"identify the full technology stack and versions","sev":"Info","cwe":"CWE-200","impact":"Targeted exploitation of known-vulnerable components","fix":"Hide version banners; keep components patched",
 "steps":[("Fingerprint",["Inspect headers, cookies, error pages, favicon hash","Run `whatweb`, `nuclei -t technologies`, and Wappalyzer-style detection"]),
 ("Version map",["Map server, framework, language, CMS, JS libs and their versions"]),
 ("CVE correlation",["Correlate detected versions to known CVEs for later exploitation"])],
 "system":"You are a fingerprinting specialist. Report only technologies you positively detected with the supporting evidence (header/banner/hash). Mark version guesses as uncertain."},
{"name":"js_analysis","title":"JavaScript Analysis Specialist","for":"extract endpoints, secrets and logic from client-side JS","sev":"Low","cwe":"CWE-200","impact":"Hidden endpoints and leaked secrets in bundles","fix":"Strip secrets from client code; restrict sourcemaps",
 "steps":[("Collect",["Gather all JS bundles and sourcemaps; `katana`/`gau` for URLs"]),
 ("Extract",["Regex for API paths, fetch/axios calls, API keys (sk-, AIza, nvapi-), tokens"]),
 ("Map",["Build an endpoint + parameter inventory from the JS for downstream agents"])],
 "system":"You are a JS-recon specialist. Report only endpoints/secrets actually present in the served JS, quoting the snippet. Validated secrets only; never invent."},
{"name":"api_discovery","title":"API Surface Discovery Specialist","for":"enumerate REST/GraphQL/gRPC/WebSocket surfaces","sev":"Info","cwe":"CWE-200","impact":"Undocumented API endpoints widen attack surface","fix":"Gate non-public APIs; remove exposed schemas",
 "steps":[("Find specs",["Probe /openapi.json, /swagger, /graphql, /.well-known, /v1 /v2 prefixes"]),
 ("Enumerate",["Introspect GraphQL; enumerate REST routes; check gRPC reflection"]),
 ("Catalog",["Record methods, params, auth requirements per endpoint"])],
 "system":"You are an API-recon specialist. Report only endpoints you confirmed respond, with method and a sample response signature. No speculation."},
{"name":"secret_scanning","title":"Exposed Secret Scanning Specialist","for":"find leaked credentials and keys across exposed assets","sev":"High","cwe":"CWE-522","impact":"Credential/key exposure enabling account or cloud takeover","fix":"Rotate exposed secrets; remove from public assets",
 "steps":[("Sweep",["Scan JS, .env, .git, backups, CI logs, comments with trufflehog-style regex"]),
 ("Validate",["Confirm key format and (in scope) liveness without abusing it"]),
 ("Classify",["Tag provider and privilege of each secret"])],
 "system":"You are a secret-scanning specialist. Report only real, validly-formatted secrets you actually found, quoting location. Never abuse keys beyond a minimal validity check."},
{"name":"dns_recon","title":"DNS Reconnaissance Specialist","for":"map DNS records and infrastructure relationships","sev":"Info","cwe":"CWE-200","impact":"Infra mapping; zone/record misconfig discovery","fix":"Harden DNS; disable zone transfers",
 "steps":[("Records",["Enumerate A/AAAA/CNAME/MX/TXT/NS/SOA; check SPF/DMARC/DKIM"]),
 ("Misconfig",["Test zone transfer (AXFR), wildcard records, dangling CNAMEs"]),
 ("Relate",["Cluster shared infrastructure and providers"])],
 "system":"You are a DNS-recon specialist. Report only records you actually resolved, with the query evidence."},
{"name":"content_discovery","title":"Content & Path Discovery Specialist","for":"discover hidden files, directories and backups","sev":"Low","cwe":"CWE-538","impact":"Exposure of admin panels, backups, configs","fix":"Remove sensitive files from web root; enforce authz",
 "steps":[("Crawl",["Spider with katana; parse robots.txt/sitemap.xml/.well-known"]),
 ("Fuzz",["`ffuf` directories/files with sensible wordlists and extensions (.bak,.old,.zip,.sql)"]),
 ("Triage",["Flag admin, backup, config, and source-leak paths"])],
 "system":"You are a content-discovery specialist. Report only paths that returned a meaningful status/body, with the evidence. No 404s as findings."},
{"name":"parameter_discovery","title":"Parameter Discovery Specialist","for":"enumerate hidden request parameters and inputs","sev":"Info","cwe":"CWE-200","impact":"Hidden params enable injection/logic attacks","fix":"Validate and document all accepted parameters",
 "steps":[("Mine",["Extract params from JS, forms, history (gau), and docs"]),
 ("Bruteforce",["Use arjun/param-miner style discovery with reflection detection"]),
 ("Hand off",["Provide the param inventory to injection specialists"])],
 "system":"You are a parameter-discovery specialist. Report only parameters you confirmed the app accepts/reflects, with evidence."},
{"name":"waf_cdn_detection","title":"WAF/CDN Detection Specialist","for":"identify WAF/CDN and inform evasion strategy","sev":"Info","cwe":"CWE-200","impact":"Informs bypass strategy; reveals origin exposure","fix":"Ensure origin is not directly reachable",
 "steps":[("Detect",["Fingerprint WAF/CDN via headers, cookies, block pages, `wafw00f`"]),
 ("Origin",["Search for origin IP leaks (DNS history, SSL SANs, headers)"]),
 ("Strategy",["Note effective encodings/paths for later, in-scope testing"])],
 "system":"You are a WAF/CDN specialist. Report only positively-identified protections and any verified origin exposure, with evidence."},
{"name":"cloud_asset_discovery","title":"Cloud Asset Discovery Specialist","for":"discover cloud buckets, functions and metadata surfaces","sev":"Low","cwe":"CWE-200","impact":"Exposed cloud assets and SSRF/metadata vectors","fix":"Lock down public cloud assets; enforce IMDSv2",
 "steps":[("Discover",["Find S3/GCS/Azure references; permutate bucket names; detect cloud provider"]),
 ("Probe",["Check public list/read on storage; note SSRF-to-metadata potential"]),
 ("Catalog",["Record provider, asset, and access level"])],
 "system":"You are a cloud-recon specialist. Report only assets you confirmed exist with their observed access level. No guessed buckets."},
{"name":"graphql_discovery","title":"GraphQL Discovery Specialist","for":"map the GraphQL schema and sensitive operations","sev":"Low","cwe":"CWE-200","impact":"Schema exposure aids targeted attacks","fix":"Disable introspection/suggestions in production",
 "steps":[("Locate",["Find /graphql endpoints and test introspection"]),
 ("Map",["If introspection off, use field-suggestion (clairvoyance) to reconstruct types"]),
 ("Flag",["Mark mutations and sensitive queries for the API agents"])],
 "system":"You are a GraphQL-recon specialist. Report only schema elements you actually recovered, with the query/response evidence."},
{"name":"osint_employee","title":"OSINT & Exposure Mapping Specialist","for":"map public exposure (leaked creds, repos, docs) for the target org","sev":"Low","cwe":"CWE-200","impact":"Public exposure enabling targeted attacks","fix":"Monitor and remediate public exposure",
 "steps":[("Sources",["Search public code (GitHub), paste sites, breach indices (in scope)"]),
 ("Correlate",["Link leaked emails/creds/repos to the target's assets"]),
 ("Report",["Summarize exposure relevant to the engagement"])],
 "system":"You are an OSINT specialist operating strictly within authorized scope. Report only verifiable public exposure tied to the target, citing the source. No private data harvesting."},
]


def _code(name, title, vc, cwe, sev, patterns, fix, impact):
    return {"name": name, "title": title, "for": f"{vc} in the source code", "sev": sev, "cwe": cwe,
            "impact": impact, "fix": fix,
            "steps": [("Locate sinks/sources", patterns),
                      ("Trace dataflow", ["Trace user-controlled input from source to the dangerous sink",
                                          "Confirm the path is reachable and lacks sanitization/validation"]),
                      ("Confirm exploitability", ["Quote the exact vulnerable lines (file:line)",
                                                  "Explain the concrete exploit and why existing controls don't stop it"])],
            "system": f"You are a white-box source reviewer for {vc}. Report ONLY issues you can prove in the PROVIDED code by quoting the exact vulnerable lines (file:line) and a reachable dataflow from untrusted input. Never report sanitized, unreachable, or hypothetical code. If the snippet is insufficient, say so rather than guess."}


CODE = [
_code("code_sqli","Source SQL Injection Reviewer","SQL injection","CWE-89","Critical",
 ["String concatenation/interpolation into SQL (f-strings, +, .format) passed to execute()","Raw queries bypassing the ORM; `.raw(`, `cursor.execute(... % ...)`"],
 "Use parameterized queries / ORM bindings","Database compromise, data exfiltration"),
_code("code_command_injection","Source Command Injection Reviewer","OS command injection","CWE-78","Critical",
 ["`os.system`, `subprocess(..., shell=True)`, `exec`, backticks with user input","Unsanitized input concatenated into shell strings"],
 "Avoid shells; pass argument arrays; validate input","Remote code execution on the host"),
_code("code_path_traversal","Source Path Traversal Reviewer","path traversal / arbitrary file access","CWE-22","High",
 ["User input in file paths (open/read/sendFile) without normalization","Missing checks for `../` and absolute paths"],
 "Canonicalize and confine paths to a safe base directory","Arbitrary file read/write"),
_code("code_ssrf","Source SSRF Reviewer","server-side request forgery","CWE-918","High",
 ["User-controlled URLs passed to HTTP clients (requests/fetch/curl)","No allowlist or scheme/host validation"],
 "Allowlist destinations; block internal ranges and redirects","Internal network access, cloud metadata theft"),
_code("code_xss","Source XSS Reviewer","cross-site scripting (output encoding)","CWE-79","High",
 ["Unescaped user input rendered to HTML (innerHTML, dangerouslySetInnerHTML, `|safe`, `v-html`)","Template autoescaping disabled"],
 "Context-aware output encoding; keep autoescaping on; CSP","Session theft, account takeover"),
_code("code_insecure_deserialization","Source Insecure Deserialization Reviewer","unsafe deserialization","CWE-502","Critical",
 ["`pickle.loads`, `yaml.load` (unsafe), Java/PHP native deserialization on untrusted data","Object deserialization of request data"],
 "Use safe formats/loaders; never deserialize untrusted data","Remote code execution"),
_code("code_hardcoded_secrets","Source Hardcoded Secrets Reviewer","hardcoded credentials/keys","CWE-798","High",
 ["API keys, passwords, tokens, private keys committed in source/config","High-entropy strings assigned to credential-like names"],
 "Move secrets to a vault/env; rotate exposed values","Credential/key compromise"),
_code("code_weak_crypto","Source Weak Cryptography Reviewer","weak or misused cryptography","CWE-327","Medium",
 ["MD5/SHA1 for passwords; ECB mode; static IV/salt; hardcoded keys","Custom/rolled crypto; weak random for security tokens"],
 "Use vetted algorithms (bcrypt/argon2, AES-GCM), random IVs, CSPRNG","Data exposure, token forgery"),
_code("code_auth_flaws","Source Authentication/Authorization Reviewer","broken authentication/authorization","CWE-287","High",
 ["Missing auth checks on sensitive routes; client-trusted role flags","Comparisons of secrets without constant-time; weak session handling"],
 "Enforce server-side authz on every action; harden sessions","Privilege escalation, account takeover"),
_code("code_idor_access","Source IDOR / Access Control Reviewer","insecure direct object references","CWE-639","High",
 ["Object lookups by user-supplied id without ownership checks","Direct DB fetch on `request.id` with no scoping"],
 "Enforce per-object ownership/authorization checks","Cross-account data access"),
_code("code_xxe","Source XXE Reviewer","XML external entity processing","CWE-611","High",
 ["XML parsers with external entities/DTDs enabled on untrusted input","`resolve_entities=True`, default-config parsers"],
 "Disable DTDs/external entities; use hardened parsers","File disclosure, SSRF"),
_code("code_open_redirect","Source Open Redirect Reviewer","open redirect","CWE-601","Medium",
 ["Redirects built from user input (redirect(request.param))","No allowlist of redirect destinations"],
 "Allowlist redirect targets; use relative paths","Phishing, OAuth token theft"),
_code("code_template_injection","Source Template Injection Reviewer","server-side template injection","CWE-1336","Critical",
 ["User input concatenated into template strings then rendered","`render_template_string`, dynamic template construction"],
 "Never render user input as templates; sandbox","Remote code execution"),
_code("code_race_condition","Source Race Condition Reviewer","TOCTOU / concurrency flaws","CWE-362","Medium",
 ["Check-then-act on shared state without locking","Non-atomic balance/quota/idempotency updates"],
 "Use atomic operations, locks, or transactions","Double-spend, state corruption"),
_code("code_unsafe_eval","Source Unsafe Eval Reviewer","dynamic code evaluation","CWE-95","Critical",
 ["`eval`, `exec`, `Function()`, `setTimeout(string)` on user input","Dynamic import/require of user-controlled names"],
 "Eliminate dynamic eval; use safe parsers/dispatch tables","Remote code execution"),
_code("code_csrf_missing","Source CSRF Protection Reviewer","missing CSRF protection","CWE-352","Medium",
 ["State-changing POST/PUT/DELETE without CSRF tokens","CSRF protection globally disabled"],
 "Enable anti-CSRF tokens / SameSite cookies","Unauthorized state-changing actions"),
_code("code_insecure_random","Source Insecure Randomness Reviewer","predictable randomness for security","CWE-330","Medium",
 ["`random`/`Math.random` used for tokens, IDs, passwords, OTPs","Seeded or time-based randomness for secrets"],
 "Use a CSPRNG (secrets, crypto.randomBytes)","Token/session prediction"),
_code("code_logging_sensitive","Source Sensitive Logging Reviewer","sensitive data in logs","CWE-532","Low",
 ["Logging passwords, tokens, PII, full requests","Debug logging of secrets in production paths"],
 "Redact sensitive fields; scope debug logging","Credential/PII exposure via logs"),
_code("code_sql_orm_raw","Source ORM Raw-Query Reviewer","unsafe raw ORM queries","CWE-89","High",
 ["`.raw()`, `.extra()`, query builders with string interpolation","Raw fragments mixing user input"],
 "Use parameter binding even in raw queries","SQL injection via ORM"),
_code("code_file_upload","Source File Upload Reviewer","insecure file upload handling","CWE-434","High",
 ["No type/extension/content validation; user-controlled filenames/paths","Uploads served from executable directories"],
 "Validate type/size; randomize names; store outside webroot","Webshell upload, RCE"),
_code("code_mass_assignment","Source Mass Assignment Reviewer","mass assignment / over-binding","CWE-915","High",
 ["Binding whole request body to models (`Model(**request)`, `update_attributes`)","No allowlist of bindable fields"],
 "Allowlist bindable fields; use DTOs","Privilege escalation via hidden fields"),
_code("code_jwt_misuse","Source JWT Misuse Reviewer","JWT verification flaws","CWE-347","High",
 ["`verify=False`, alg `none` accepted, secret not validated","Algorithm not pinned; weak/hardcoded secret"],
 "Pin algorithm; verify signature; strong secret/keys","Token forgery, auth bypass"),
_code("code_cors_misconfig","Source CORS Misconfiguration Reviewer","permissive CORS","CWE-942","Medium",
 ["`Access-Control-Allow-Origin: *` with credentials; reflecting Origin","Wildcard or unchecked origin allowlists"],
 "Strict origin allowlist; never reflect Origin with credentials","Cross-origin data theft"),
_code("code_ssrf_redirect","Source SSRF-via-Redirect Reviewer","SSRF through redirect following","CWE-918","Medium",
 ["HTTP clients following redirects to user-controlled URLs","No re-validation of redirect targets against allowlist"],
 "Disable/limit redirects; re-validate each hop","Internal access via redirect"),
]


def main():
    rdir = os.path.join(ROOT, "agents_md", "recon")
    cdir = os.path.join(ROOT, "agents_md", "code")
    os.makedirs(rdir, exist_ok=True)
    os.makedirs(cdir, exist_ok=True)
    for a in RECON:
        open(os.path.join(rdir, a["name"] + ".md"), "w").write(render(a, code=False))
    for a in CODE:
        open(os.path.join(cdir, a["name"] + ".md"), "w").write(render(a, code=True))
    print(f"recon agents: {len(RECON)}  |  code agents: {len(CODE)}")


if __name__ == "__main__":
    main()
