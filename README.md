# CyberForge v6.2 — Adaptive Technology Website Security Analyzer

CyberForge is an authorized defensive assessment toolkit. It performs passive and low-impact checks only and requires explicit scope for network actions.

## Core capability
CyberForge now uses **Adaptive Technology Intelligence**. It first fingerprints the target stack, then selects relevant passive checks for the detected technologies. Unknown stacks still receive generic HTTP/TLS/API/configuration analysis.

### Technology coverage
- CMS/e-commerce: WordPress, WooCommerce, Drupal, Joomla, Magento/Adobe Commerce, Shopify, PrestaShop
- Frontend: React, Next.js, Vue, Nuxt, Angular, Svelte/SvelteKit, Astro, Ember, Backbone, jQuery, Bootstrap, Tailwind, TypeScript
- Backend: Node/Express, NestJS, Django, Flask, FastAPI, Laravel, Symfony, Rails, Spring Boot, ASP.NET/.NET, PHP, Go, Rust
- API/realtime: GraphQL, WebSocket, gRPC
- Cloud/CDN/edge: Cloudflare, AWS, Azure, Google Cloud, Vercel, Netlify, Render
- Web servers: Nginx, Apache, IIS, Caddy

Detection is evidence-based; a fingerprint is not treated as proof of a backend implementation.

## Adaptive analysis
```bash
./cyberforge --scope scope.txt adaptive-analysis https://YOUR-AUTHORIZED-DOMAIN
```

The adaptive engine:
1. Fetches the authorized target.
2. Detects technologies from HTML, script paths, cookies and response headers.
3. Records evidence for every fingerprint.
4. Selects technology-specific, scope-safe paths where applicable.
5. Falls back to generic analysis when the stack is unknown.

## Deep analysis
```bash
./cyberforge --scope scope.txt deep-audit https://YOUR-AUTHORIZED-DOMAIN
```

Deep analysis now includes the adaptive technology layer alongside web, TLS, DNS, GeoIP, Nmap/builtin fallback and port analysis.

## Module health
```bash
./cyberforge --scope scope.txt module-health
```

Current registry: **35/35 modules active**.

## Interactive mode
```bash
./cyberforge --scope scope.txt
```

Use option **35** for Adaptive Technology / Stack Analysis and **36** for Module Health Check.

## Scope
Create `scope.txt` with only assets you are authorized to assess:
```text
example.com
*.example.com
192.168.1.0/24
```

## Safety
CyberForge does not add credential attacks, brute force, exploitation, persistence, destructive actions or unauthorized access. Use it only on systems you own or have explicit permission to assess.


## Article-style text summaries
After `deep-audit` or `adaptive-analysis`, CyberForge automatically generates a readable Bengali text summary in `reports/` describing:
- overall risk and severity counts
- detected technology stack
- exactly what problem was found
- analysis module/area
- target/location where it was observed
- evidence
- recommended remediation
- prioritized remediation plan

You can also generate it manually:
```bash
./cyberforge article-summary --target https://YOUR-AUTHORIZED-DOMAIN
```


## Final result model
Every finding includes evidence, confidence, verification status, module/area, and remediation. Risk is independently recalculated per analysis and the article summary explains the score and finding contributions.


## Startup Safety Warning
CyberForge displays an authorization and limitations warning before every run. Use it only on assets you own or are explicitly authorized to assess. Automated findings require appropriate verification.
