# Crawling, Parameter Fuzzing, Virtual Hosts, Methods, and WebSockets (extension)

Class key: `passive` = archives and static analysis. `bounded` = rate-limited requests on in-scope hosts. Keep fuzzing rates at the program limit.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LP-URL-001 | JS crawl | Endpoints extracted from JS files | passive | `katana -js-crawl -silent \| tee js-endpoints.txt` |
| LP-URL-002 | JS files | Discover JS URLs from historical archives | passive | `gau --subs <t> \| grep '\.js' \| sort -u` |
| LP-URL-003 | Historical | Wayback and passive URL collection | passive | `waybackurls <t> \| sort -u`; `katana -passive` |
| LP-URL-004 | Active | Spider live hosts depth 3 | bounded | `katana -u https://<h> -d 3 -silent`; `gospider -s https://<h> -c 5 -d 2 --sitemap --robots` |
| LP-URL-005 | Active | hakrawler plain crawl | bounded | `hakrawler -url https://<h> -depth 3 -plain` |
| LP-FUZZ-001 | Directories | Directory and file fuzzing with status filters | bounded | `ffuf -u https://<h>/FUZZ -w directory-list-2.3-medium.txt -t 20 -rate 50 -mc 200,204,301,302,403` |
| LP-FUZZ-002 | Files | Raft-large-files fuzzing | bounded | `ffuf -u https://<h>/FUZZ -w raft-large-files.txt -t 20 -rate 50 -mc 200,204,301,302,403` |
| LP-FUZZ-003 | Parameters | Hidden GET/POST parameter discovery | bounded | `arjun -u https://<h>/<path> -t 10`; `x8 -u <url> -w burp-parameter-names.txt` |
| LP-FUZZ-004 | Parameters | Response-size differential on fuzzed names | bounded | `ffuf -u 'https://<h>/<path>?FUZZ=1' -w params.txt -fs <baseline>` |
| LP-VHOST-001 | Virtual hosts | Host-header fuzzing for hidden vhosts | bounded | `ffuf -u https://<ip> -H 'Host: FUZZ.<t>' -w subdomains.txt -fc 200,301,302` (in-scope IP only) |
| LP-VHOST-002 | Virtual hosts | Host header replaces internal name | bounded | `ffuf -u https://<t> -H 'Host: FUZZ' -w subdomains.txt -fc 200` |
| LP-METHOD-001 | Methods | Content-Type fuzzing on JSON endpoints | bounded | `ffuf -u <api> -X POST -H 'Content-Type: FUZZ' -w content-types.txt -d 'test=1'` |
| LP-METHOD-002 | Methods | OPTIONS and Allow header review | passive | `curl -X OPTIONS -v <url>` |
| WS-LP-001 | WebSocket | Endpoint discovery in JS (ws://, wss://, socket.io, signalr) | passive | Grep JS for websocket URLs |
| WS-LP-002 | WebSocket | Authentication on handshake only, not per message | bounded | Own two accounts; replay messages |
| WS-LP-003 | WebSocket | Cross-site hijacking via Origin check | bounded | Handshake with foreign Origin |
| WS-LP-004 | WebSocket | Message injection into rendered output | bounded | Own marker message |
