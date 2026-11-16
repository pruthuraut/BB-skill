# Frontend Library Version Triage and Client Secrets (extension)

Class key: `passive` for every row. Versions come from script URLs, banners, or `package.json` if exposed. Compare with the advisory, do not exploit.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| JSL-001 | jQuery | Version and known XSS fixed-release comparison | passive | Grep script URL and banner for jQuery version |
| JSL-002 | Bootstrap | Version and data-attribute XSS (3.x tooltips, 4.x collapse data-parent; fixed in 4.3.1) | passive | Grep banner |
| JSL-003 | Angular / AngularJS | Version and sandbox escape history; CSTI when user input is compiled | passive | Grep ng-version or angular.version; check input rendering |
| JSL-004 | Vue.js / Vuetify | Version and template injection through user-compiled templates | passive | Grep Vue banner and compile usage |
| JSL-005 | React / React Router / Radix UI / MUI / Headless UI | Dev build markers and dangerouslySetInnerHTML use | passive | Grep for react-dom.development and dangerouslySetInnerHTML |
| JSL-006 | Lodash / Moment / Underscore | Prototype pollution and deprecated versions | passive | Grep version banner |
| JSL-007 | Handlebars / Mustache / lodash templates | Template XSS with raw output | passive | Grep for triple-stash and raw template use |
| JSL-008 | Chart.js / Highcharts / ECharts / Plotly / Recharts / Rickshaw / amCharts / FusionCharts / Highcharts | Version and HTML label injection | passive | Grep version banner; check label formatting with user data |
| JSL-009 | Highlight.js | Autoescape disabled leading to XSS | passive | Grep config |
| JSL-010 | Froala / TinyMCE / Tiptap / Quill / CKEditor / Summernote | Version and stored XSS via HTML content | passive | Grep editor version and sanitizer config |
| JSL-011 | DOMPurify / sanitize-html | Version (mXSS bypass history) | passive | Grep banner |
| JSL-012 | PDF.js | Version and XSS or RCE history | passive | Grep pdf.js version |
| JSL-013 | Polyfill.io / polyfill CDN | Supply-chain risk when script host is third-party | passive | Grep for polyfill.io hosts |
| JSL-014 | Unpkg / jsDelivr / cdnjs | Script loaded without SRI | passive | Grep script tags without integrity attribute |
| JSL-015 | Polymer / Stimulus / Riot / Knockout / Backbone / Marionette / Ember / Aurelia / Meteor / Svelte / Solid / Qwik / Preact / Phaser / Three.js / Unity WebGL / Raphael / Cufon / Modernizr / NProgress / Swiper / Glide / Flickity / OWL Carousel / Isotope / Hammer / Headroom / Materialize / Pure CSS / Foundation / MathJax / Reveal.js / Rxjs / Turbolinks / Vaadin / Zone.js / Dart / Ruffle | Version disclosure and outdated release | passive | Grep version banner; compare with release notes |
| JSL-016 | Redux / Redux DevTools / MobX / Pinia | DevTools hook enabled in production | passive | Grep __REDUX_DEVTOOLS_EXTENSION__ |
| JSL-017 | Source maps | `.js.map` exposing original source and comments | passive | GET `<bundle>.js.map`; check sourcesContent presence |
| JSL-018 | Bundles | Secret strings in bundles (AKIA, sk_live_, AIza, xox, ghp_) | passive | Regex sweep; redact and classify |
| JSL-019 | Webpack / Vite / Next / Nuxt | Build config and env embedding (NEXT_PUBLIC_, GATSBY_, VITE_) | passive | Grep env prefixes with secret-looking values |
| JSL-020 | Storybook / Storybook addons | Storybook deployed to production | passive | GET /storybook/ or iframe.html |
| JSL-021 | Gulp / Grunt / Gruntfile | Build files exposed | passive | GET /gulpfile.js, /Gruntfile.js status |
| JSL-022 | Typescript | Source maps and .ts exposed | passive | GET .ts paths listed in sourcemaps |
| JSL-023 | Lottie / Rive / Spline | Animation JSON or .riv files expose internal design data | passive | Grep for asset URLs |
| JSL-024 | Google Tag Manager / analytics containers | Container IDs (public) and injected tags | passive | Grep GTM-, G- IDs; review injected tags list |
