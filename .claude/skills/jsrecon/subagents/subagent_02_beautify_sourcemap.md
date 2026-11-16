# Subagent 02: Automated De-Minification & Source Map (.map) Reconstruction

## Role & Mission
Responsible for preprocessing minified JavaScript: beautifying/formatting dense bundles using `js-beautify`, actively detecting exposed Source Map files (`.js.map`), and reconstructing the developer's original, unminified source code tree (including TypeScript, JSX, comments, and private functions).

---

## 1. Automated JavaScript Beautification (De-Minification)

Minified code is virtually impossible for manual review or regex engines to parse reliably due to concatenated single-line strings. Beautification expands the code into readable, structured syntax:

```bash
mkdir -p artifacts/js_recon/js_beautified/

# 1. Beautify all downloaded raw JS files using js-beautify
for f in artifacts/js_recon/js_raw/*.js; do
  fname=$(basename "$f")
  if command -v js-beautify >/dev/null 2>&1; then
    js-beautify "$f" > "artifacts/js_recon/js_beautified/${fname}"
  else
    # Python fallback if js-beautify npm package is not installed
    python3 -c "
import jsbeautifier
opts = jsbeautifier.default_options()
opts.indent_size = 2
with open('$f', errors='ignore') as infile:
    res = jsbeautifier.beautify(infile.read(), opts)
with open('artifacts/js_recon/js_beautified/${fname}', 'w', errors='ignore') as outfile:
    outfile.write(res)
" 2>/dev/null || cp "$f" "artifacts/js_recon/js_beautified/${fname}"
  fi
done
```

---

## 2. Source Map (.map) Discovery & Detection

Source maps are the single highest-value target in frontend reconnaissance. When developers compile TypeScript, React, or Vue apps with Webpack/Vite, `.map` files map compiled bundles back to the original source.

### Detection Methods
1. **Direct Map Appending:** Test `{bundle_url}.map` (e.g. `https://target.com/static/js/main.123.js.map`).
2. **Comment Header Extraction:** Search for `//# sourceMappingURL=` comments at the bottom of the bundle:
   ```bash
   grep -roE "sourceMappingURL=([^\s]+)" artifacts/js_recon/js_beautified/ > artifacts/js_recon/sourcemap_links.txt
   ```
3. **HTTP Header Response:** Check for `SourceMap:` or `X-SourceMap:` HTTP response headers:
   ```bash
   cat artifacts/js_recon/live_js_urls.txt | while read url; do
     curl -sI -A "Mozilla/5.0" "$url" | grep -iE "(sourcemap|x-sourcemap)"
   done
   ```
4. **Common Static Asset Map Paths:**
   - `/static/js/main.js.map`
   - `/static/js/bundle.js.map`
   - `/js/app.js.map`
   - `/assets/vendor.js.map`
   - `/build/index.js.map`

---

## 3. Reconstructing Original Source Code from `.map` Files

When a `.js.map` is downloaded, it contains the full JSON source map schema:
- `sources`: Array of original file paths (e.g., `webpack:///src/auth/cognitoService.ts`).
- `sourcesContent`: Array of raw unminified source code strings corresponding to each file.

### Complete Extraction & Unpacking Workflow
```bash
mkdir -p artifacts/js_recon/js_maps/
mkdir -p artifacts/js_recon/source_unpacked/

# 1. Download confirmed source maps
cat artifacts/js_recon/live_js_urls.txt | head -n 100 | while read url; do
  map_url="${url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    h=$(printf '%s' "$url" | sha1sum | cut -c1-10)
    curl -sSL -o "artifacts/js_recon/js_maps/${h}.map" "$map_url"
  fi
done

# 2. Extract original function names and source filenames
for map_file in artifacts/js_recon/js_maps/*.map; do
  [ -f "$map_file" ] || continue
  # Extract original function names
  grep -oE "\"name\":\"[^\"]+\"" "$map_file" | sed 's/"name":"//;s/"//' >> artifacts/js_recon/original_functions.txt
  # Extract original source filenames
  grep -oE "\"file\":\"[^\"]+\"" "$map_file" | sed 's/"file":"//;s/"//' >> artifacts/js_recon/original_source_files.txt
done
sort -u artifacts/js_recon/original_functions.txt -o artifacts/js_recon/original_functions.txt
sort -u artifacts/js_recon/original_source_files.txt -o artifacts/js_recon/original_source_files.txt

# 3. Fully unpack source trees using Python
python3 -c "
import json, os, glob

for map_path in glob.glob('artifacts/js_recon/js_maps/*.map'):
    try:
        with open(map_path, 'r', errors='ignore') as f:
            data = json.load(f)
        sources = data.get('sources', [])
        contents = data.get('sourcesContent', [])
        for src, code in zip(sources, contents):
            if not code: continue
            clean_path = src.replace('webpack://', '').replace('../', '').lstrip('/\\\\')
            dest = os.path.join('artifacts/js_recon/source_unpacked', clean_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, 'w', errors='ignore') as out:
                out.write(code)
    except Exception as e:
        pass
"
```

---

## 4. Mining Developer Notes, TODOs & Dependencies
Once beautified and unpacked, search for internal developer comments and configurations:

```bash
# 1. Search for TODO and FIXME comments
grep -roiE "(//\s*TODO|//\s*FIXME|/\*\s*TODO|/\*\s*FIXME).*" artifacts/js_recon/js_beautified/ > artifacts/js_recon/developer_todos.txt

# 2. Search for package.json dependencies and versions
grep -roiE "\"dependencies\"\s*:\s*\{[^}]+\}" artifacts/js_recon/source_unpacked/ > artifacts/js_recon/identified_dependencies.txt
```

---

## Output Artifacts
- `artifacts/js_recon/js_beautified/` — Directory of de-minified, formatted JavaScript files.
- `artifacts/js_recon/js_maps/` — Downloaded `.js.map` JSON files.
- `artifacts/js_recon/source_unpacked/` — Reconstructed original application source code tree.
- `artifacts/js_recon/original_functions.txt` — Harvested internal unminified function names.
- `artifacts/js_recon/developer_todos.txt` — Developer notes, comments, and forgotten debugging instructions.
