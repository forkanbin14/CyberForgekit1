# CyberForge v5.1 — Authorized Security Assessment Suite

Developed by MR. ERROR FK

CyberForge v5.1 is a modular, safe-by-design terminal toolkit for authorized defensive security assessment on Termux and Kali Linux.

## 34 Modules

### Core assessment
1. Advanced Web Security Audit
2. Nmap Network Scanner
3. TLS / HTTPS Security Audit
4. Port & Service Enumeration
5. DNS / IP Intelligence
6. Security Headers Audit
7. Web Technology Fingerprinting
8. Vulnerability Assessment
9. Broken Link & Endpoint Audit
10. Sensitive File / Object Detection
11. Malware & Suspicious File Analysis
12. Error & Misconfiguration Detection
13. Security Configuration Audit
14. IP / ASN / GeoIP Intelligence
15. SSL Certificate Intelligence
16. Robots.txt / Sitemap Analysis
17. URL / Redirect Security Audit
18. File Hash & Integrity Analysis
19. Deep Security Analysis
20. Scope / Authorization Check
21. Scan History
22. Generate HTML Report

### Advanced modules
23. Subdomain Intelligence — passive, in-scope discovery from page references and TLS certificate SANs
24. API Security Audit — API indicators, endpoint inventory and basic CORS/authentication signals
25. Cookie Security Audit — Secure, HttpOnly and SameSite checks
26. CORS Security Audit — response CORS policy review
27. JavaScript Security Audit — script inventory and non-destructive exposure indicators
28. Cloud Exposure Audit — public cloud resource references in page content
29. WAF / CDN Detection — common WAF/CDN header fingerprinting
30. Authentication Security Audit — authentication-page and transport-security indicators
31. API Endpoint Discovery — in-scope API-style endpoint inventory
32. Dependency / CVE Intelligence — technology/version candidates for follow-up against trusted CVE sources
33. HTTP Method Security Audit — OPTIONS/Allow policy review
34. Security Risk Scoring Engine — aggregates findings into score, grade and severity counts

## Install

### Termux
--- 
git clone https://github.com/ahmadfurqan26/CyberForgekit.git

cd CyberForgeKit

ls

bash install-termux.sh

python3 cyberforge.py




 For nmap :  pkg install nmap



## Scope

Copy the example scope and add only domains/IPs/CIDRs you are authorized to assess


# Scope Setup
cp scope.txt.example scope.txt
nano scope.txt
Example:
(example.com
api.example.com)

# View the reports: 

Open a other page. And type cat and then put the report json address. as like
cat reports/20260813_190534_malware_analysis.json

Examples:
```text
example.com
*.example.com
192.168.1.0/24
```

Network actions require an explicit scope. Keep scope limited to assets you own or have permission to assess.

## CLI examples

```bash
./cyberforge --help
./cyberforge --scope scope.txt web-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt subdomain-intel https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt api-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt cookie-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt cors-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt javascript-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt cloud-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt waf-cdn https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt auth-audit https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt api-endpoints https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt dependency-intel https://YOUR-AUTHORIZED-DOMAIN
./cyberforge --scope scope.txt http-methods https://YOUR-AUTHORIZED-DOMAIN
./cyberforge risk-score --target https://YOUR-AUTHORIZED-DOMAIN
./cyberforge html-report
```

GeoIP is approximate and is not precise real-time physical tracking. The assessment modules are designed to be non-destructive: they do not brute-force, exploit, delete remote files, steal credentials, or establish persistence.
