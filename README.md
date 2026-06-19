# tool-url

A URL allowlist footgun inspector. Paste an untrusted URL and an optional
allowlist host, and the page shows you what the browser's real parser
actually resolves, where a naive string check would disagree, and whether
your allowlist is being bypassed.

Live: https://truffle.ghostwright.dev/public/tools/url/

## What it does

Every URL on the page is parsed with the platform's own WHATWG `URL`
constructor, the same parser the browser's network stack uses to decide
where a request goes. The tool then contrasts that authoritative result
with the shortcuts people reach for when they write their own validation:
`url.includes(host)`, `hostname.endsWith(host)`, splitting on `://` and
`@` by hand. When the two disagree, that gap is the bug, and the tool
names it.

## The footguns it encodes

- **Userinfo confusion.** `https://example.com@evil.example.net/` connects
  to `evil.example.net`. The host is whatever follows the *last* `@`, not
  the friendly-looking string before it.
- **Backslash normalization.** For http(s) and other special schemes the
  parser rewrites `\` to `/`, so `https://example.com\@evil.net/` has host
  `example.com` and `@evil.net` is just path. A backslash-blind splitter
  reads a different host than the browser.
- **IPv4 canonicalization.** `http://2130706433/`, `http://0177.0.0.1/`,
  `http://0x7f.1/`, and `http://127.1/` all resolve to `127.0.0.1`. An
  allowlist that blocks the dotted-quad string still lets these through.
- **Punycode homographs.** An IDN host is stored in its ASCII `xn--` form.
  A Cyrillic lookalike domain is a different host than it appears.
- **Trailing dot.** `example.com.` reaches the same site as `example.com`
  but is a different string, so an exact-match allowlist misses it.
- **Allowlist boundary bugs.** `endsWith("example.com")` also matches
  `notexample.com`; `includes("example.com")` matches
  `example.com.evil.net`. The safe check is `h === allow ||
  h.endsWith("." + allow)` on the *parsed* hostname.

For each input the tool renders the verdict (allowed, denied, or bypass
risk), a step-by-step trace, and a full table of the parsed components so
you can see exactly what the browser sees.

## What it does not do

No network requests. No redirect following. It does not fetch the URL or
tell you where a server-side redirect would land; it inspects the string
you give it with the parser the browser already ships. It is a teaching
and auditing surface for one decision: does this URL go where you think it
goes.

## Correctness

The in-page engine is exposed for testing (`globalThis.__URLTOOL`) and
cross-checked against Node's own `URL` (the same WHATWG implementation)
across parsing, userinfo extraction, backslash normalization, IPv4 and
IPv6 notations, punycode, trailing dots, and every allowlist branch:
86 assertions, all green. Run it with `node test.mjs`; the test extracts
the engine from `index.html`, runs it in a headless `vm`, and asserts the
parsed result equals what Node's `URL` produces on adversarial input.

## Shape

One HTML file. Inline CSS, inline JS, no build step, no dependencies, no
trackers. Works offline after first load. State lives in the URL hash, so
a link preserves exactly what you were looking at.

## License

MIT. See [LICENSE](LICENSE).
