# Subdomain Enumeration: 50-Item Master Audit Checklist

This checklist tracks execution progress across all 50 enumeration vectors. It maps directly into the 6 specialized subagents to guarantee zero omissions, maximum granularity, and high-fidelity output.

**Progress:** `[ 0 / 50 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Command / Method | Status |
|---|-------------------|----------|------------------|--------|
| **01** | Use subfinder for passive subdomain enumeration | Subagent 01 | `subfinder -d <target> -all -cs -o subfinder.txt` | `[ ]` |
| **02** | Use amass for deep subdomain discovery with OSINT integration | Subagent 01 | `amass enum -passive -d <target> -o amass.txt` | `[ ]` |
| **03** | Use assetfinder to find subdomains from various data sources | Subagent 01 | `assetfinder --subs-only <target> > assetfinder.txt` | `[ ]` |
| **04** | Use Findomain for fast subdomain enumeration with CT | Subagent 01 | `findomain -t <target> -u findomain.txt` | `[ ]` |
| **05** | Use knockpy for subdomain enumeration with DNS zone transfer checks | Subagent 03 | `knockpy <target> --dns <resolvers> -o knockpy/` | `[ ]` |
| **06** | Use DNSdumpster for DNS recon and visual subdomain mapping | Subagent 01 | `python3 dnsdumpster.py -d <target>` | `[ ]` |
| **07** | Query crt.sh certificate transparency logs | Subagent 01 | `curl -s "https://crt.sh/?q=%25.<target>&output=json" \| jq -r '.[].name_value'` | `[ ]` |
| **08** | Use SecurityTrails API for historical and current DNS records | Subagent 01 | `curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/<target>/subdomains"` | `[ ]` |
| **09** | Use wayback machine CDX API for discovering old subdomains | Subagent 01 | `curl -s "http://web.archive.org/cdx/search/cdx?url=*.<target>/*&output=text&fl=original&collapse=urlkey"` | `[ ]` |
| **10** | Use VirusTotal domain report for passive DNS subdomains | Subagent 01 | `curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" "https://www.virustotal.com/api/v3/domains/<target>/subdomains"` | `[ ]` |
| **11** | Use Shodan for subdomain and open port discovery via internet scanning | Subagent 01 | `shosubgo -d <target> -s $SHODAN_API_KEY` / `shodan search hostname:<target>` | `[ ]` |
| **12** | Use Censys for certificate-based subdomain discovery at scale | Subagent 01 | `censys subdomains <target>` / Censys Search API query | `[ ]` |
| **13** | Use Facebook CT logs (ct.facebook.com) for CT search | Subagent 01 | Graph API / CT Facebook endpoint querying `<target>` | `[ ]` |
| **14** | Use Google dorking: `site:target.com -www` to find subdomains | Subagent 02 | Google search queries recursively subtracting discovered subdomains | `[ ]` |
| **15** | Use Bing dorking: `site:target.com` for additional subdomain results | Subagent 02 | Bing API / automated scraper: `site:<target> -www` | `[ ]` |
| **16** | Use Yahoo and DuckDuckGo for search engine diversity | Subagent 02 | Scrape Yahoo & DDG search SERPs with negative host filters | `[ ]` |
| **17** | Perform DNS brute force with dnsrecon or dnscan using wordlists | Subagent 03 | `dnsrecon -d <target> -D commonspeak2.txt -t brt` | `[ ]` |
| **18** | Use massdns for fast DNS resolution of discovered subdomains | Subagent 03 | `massdns -r resolvers.txt -t A -o S all_candidates.txt -w massdns.out` | `[ ]` |
| **19** | Check for wildcard DNS responses to filter false positives | Subagent 03 | `dnsx -l candidates.txt -wd <target> -r resolvers.txt -o resolved.txt` | `[ ]` |
| **20** | Attempt DNS zone transfer (AXFR) on all authoritative nameservers | Subagent 03 | `dig axfr @<nameserver> <target>` / `dnsrecon -d <target> -t axfr` | `[ ]` |
| **21** | Enumerate subdomains from JavaScript files on the main domain | Subagent 04 | `SubDomainizer -u https://<target> -l 3` / Katana JS extraction | `[ ]` |
| **22** | Extract subdomains from SPF records via include mechanisms | Subagent 05 | `dig +short TXT <target> \| grep "v=spf1"` (parse `include:` and `a:`) | `[ ]` |
| **23** | Extract subdomains from DMARC aggregate reports (`rua` tag) | Subagent 05 | `dig +short TXT _dmarc.<target>` (extract mailbox hostnames in `rua=mailto:`) | `[ ]` |
| **24** | Use Google Transparency Report for certificate search | Subagent 01 | Scrape / API query Google CT report for `<target>` | `[ ]` |
| **25** | Check for subdomain takeover vulnerability on all discovered subdomains | Subagent 06 | `nuclei -l live_subs.txt -t http/takeovers/ -o takeovers.txt` | `[ ]` |
| **26** | Verify DNSSEC configuration and look for misconfigurations | Subagent 03 | `delv <target>` / `ldns-walk @<nameserver> <target>` (NSEC zone walking) | `[ ]` |
| **27** | Use nmap DNS brute script for additional subdomain enumeration | Subagent 03 | `nmap --script dns-brute --script-args dns-brute.domain=<target>` | `[ ]` |
| **28** | Check for dangling CNAME records pointing to expired services | Subagent 06 | `dnsx -l live_subs.txt -cname -resp` (cross-reference against `can-i-take-over-xyz`) | `[ ]` |
| **29** | Look for internal IP address leaks in DNS records | Subagent 05 | Filter `A` records matching `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | `[ ]` |
| **30** | Use sublist3r with all search engine modules enabled | Subagent 02 | `python3 sublist3r.py -d <target> -t 10 -v -o sublist3r.txt` | `[ ]` |
| **31** | Check for subdomains in robots.txt and sitemap.xml files | Subagent 04 | Parse `Disallow:`, `Allow:`, `<loc>` URLs from `robots.txt` & `sitemap.xml` | `[ ]` |
| **32** | Search GitHub/GitLab repositories for subdomain references in code | Subagent 02 | `python3 github-subdomains.py -d <target> -t $GITHUB_TOKEN` | `[ ]` |
| **33** | Check Stack Overflow and developer forums for subdomain leaks | Subagent 02 | Google Dork: `site:stackoverflow.com "<target>"` | `[ ]` |
| **34** | Use Chaos dataset from ProjectDiscovery for community subdomains | Subagent 01 | `chaos -d <target> -key $CHAOS_KEY -silent` | `[ ]` |
| **35** | Check for subdomains embedded in Android/iOS app APKs/IPAs | Subagent 04 | `apktool d app.apk; grep -Eroh "([a-zA-Z0-9_\-]+\.)+<target>" app/` | `[ ]` |
| **36** | Use Rapid7 Open Data (Project Sonar) for forward DNS lookup | Subagent 05 | Query FDNS datasets / Rapid7 FDNS extracts for `.<target>` | `[ ]` |
| **37** | Enumerate cloud subdomains (AWS S3, Azure Blob, GCP Storage) | Subagent 05 | `cloudlist -d <target>` / Cloud range cert correlation (Haddix slide 41) | `[ ]` |
| **38** | Check for subdomains leaked in email headers (SPF/DKIM/DMARC) | Subagent 05 | Inspect `Authentication-Results`, `Received:`, and DKIM selectors (`default._domainkey.<target>`) | `[ ]` |
| **39** | Use Recon.dev API for subdomain enumeration from recon data | Subagent 01 | `curl -s -H "Authorization: Bearer $RECON_DEV_KEY" "https://recon.dev/api/search?key=<target>"` | `[ ]` |
| **40** | Check for Punycode/IDN subdomain variants for homograph attacks | Subagent 05 | Convert target domain to IDN variants; query DNS for existing registrations | `[ ]` |
| **41** | Search for subdomains in Internet Archive Wayback CDX API | Subagent 04 | `gau --subs <target> \| unfurl -u domains \| grep "<target>"` | `[ ]` |
| **42** | Look for subdomains in technology detection tools (Wappalyzer) | Subagent 04 | Correlate Ad/Analytics IDs across BuiltWith & Wappalyzer (Haddix slide 18) | `[ ]` |
| **43** | Use BufferOver.run for subdomain data from Rapid7 Sonar | Subagent 01 | `curl -s "https://dns.bufferover.run/dns?q=.<target>" \| jq -r .FDNS_A[]` | `[ ]` |
| **44** | Check for subdomains in Common Crawl data index | Subagent 01 | Query `index.commoncrawl.org` for `*.target/*` and extract hostnames | `[ ]` |
| **45** | Use DNSrecon for SRV record enumeration | Subagent 03 | `dnsrecon -d <target> -t srv` (uncovers `_sip`, `_autodiscover`, `_kerberos` hosts) | `[ ]` |
| **46** | Check for subdomains via HTTP certificate parsing (`openssl s_client`) | Subagent 05 | `echo \| openssl s_client -connect <target>:443 2>/dev/null \| openssl x509 -noout -text \| grep "DNS:"` | `[ ]` |
| **47** | Use CertSpotter API for certificate transparency monitoring | Subagent 01 | `curl -s "https://api.certspotter.com/v1/issuances?domain=<target>&include_subdomains=true&expand=dns_names"` | `[ ]` |
| **48** | Search for subdomains in FOFA search engine | Subagent 02 | FOFA CLI / API query: `domain="<target>"` | `[ ]` |
| **49** | Check for subdomains in ZoomEye search engine | Subagent 02 | `zoomeye search "site:<target>" -num 500` | `[ ]` |
| **50** | Use DorkAssistant for automated Google dork subdomain enumeration | Subagent 02 | Automated search engine dorking script using negative filtering loop | `[ ]` |
