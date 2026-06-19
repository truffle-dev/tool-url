// Offline validation for the tool-url decision engine.
//
// The engine lives inside index.html and delegates all parsing to the
// platform WHATWG `URL` constructor. This test extracts that engine, runs it
// in a Node `vm` with a minimal DOM stub, and cross-checks every claim the
// tool makes against Node's own `URL` (the same WHATWG implementation the
// browser ships). The strategy is the tool's thesis stated as a test: trust
// the platform parser, not string intuition, so the proof is the engine
// agreeing with the parser on adversarial input.
//
// Run: node test.mjs

import { readFileSync } from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";

// ---- extract the page's single <script> block ----
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const m = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(m, "index.html must contain a <script> block");
const engineSource = m[1];

// ---- minimal DOM / browser stub so the page IIFE runs headless ----
function fakeEl() {
  const el = {
    value: "",
    innerHTML: "",
    textContent: "",
    className: "",
    dataset: {},
    style: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {},
    appendChild() {},
    setAttribute() {},
    removeAttribute() {},
    querySelector() { return fakeEl(); },
    querySelectorAll() { return []; },
  };
  return el;
}
const sandbox = {
  document: {
    getElementById() { return fakeEl(); },
    querySelector() { return fakeEl(); },
    querySelectorAll() { return []; },
    createElement() { return fakeEl(); },
    createDocumentFragment() { return fakeEl(); },
  },
  location: { hash: "" },
  history: { replaceState() {} },
  URL,
  atob,
  btoa,
  escape,
  unescape,
  encodeURIComponent,
  decodeURIComponent,
  JSON,
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(engineSource, sandbox);

const T = sandbox.__URLTOOL;
assert.ok(T && typeof T.parseURL === "function", "engine must expose __URLTOOL");

// ---- assertion harness with a running count ----
let n = 0;
const eq = (a, b, msg) => { assert.strictEqual(a, b, msg); n++; };
const ok = (a, msg) => { assert.ok(a, msg); n++; };

// ======================================================================
// 1. Hostname cross-check: the engine's parsed hostname must equal Node's
//    own URL hostname for every adversarial input. This is the spine.
// ======================================================================
const crossCheck = [
  "https://example.com/path",
  "https://example.com:8443/x",
  "https://example.com@evil.example.net/",      // userinfo: host is after last @
  "https://example.com\\@evil.example.net/",    // backslash -> slash, host is example.com
  "https://example.com\\.evil.net/",            // backslash normalization
  "http://2130706433/",                          // decimal IPv4
  "http://0177.0.0.1/",                          // octal IPv4
  "http://0x7f.0.0.1/",                           // hex IPv4
  "http://127.1/",                                // short IPv4
  "http://127.0.0.1/",                            // canonical IPv4
  "https://example.com./",                        // trailing dot
  "https://xn--e1awd7f.example/",                 // already-ascii punycode
  "https://\u043F\u0440\u0438\u043C\u0435\u0440.example/", // cyrillic IDN -> xn--
  "https://user:pass@host.example:9000/a?b#c",   // full userinfo + port
  "http://[::1]:8080/",                           // IPv6 literal
  "https://sub.deep.example.com/",                // multi-label subdomain
  "https://EXAMPLE.com/",                          // case folded by parser
  "https://a@b@example.com/",                     // last @ wins
  "ftp://example.com/file",                        // special non-http scheme
  "https://example.com..../",                      // multiple trailing dots
];
for (const s of crossCheck) {
  eq(T.parseURL(s).hostname, new URL(s).hostname, `hostname matches Node URL for ${JSON.stringify(s)}`);
}

// ======================================================================
// 2. IPv4 canonicalization: every alternate notation collapses to the same
//    address the browser would dial.
// ======================================================================
for (const s of [
  "http://2130706433/",
  "http://0177.0.0.1/",
  "http://0x7f.0.0.1/",
  "http://0x7f000001/",
  "http://127.1/",
  "http://127.0.0.1/",
]) {
  eq(T.parseURL(s).hostname, "127.0.0.1", `${s} canonicalizes to 127.0.0.1`);
}

// ======================================================================
// 3. Userinfo: the host is whatever follows the LAST @, never the friendly
//    string before it. A naive splitter reads the wrong value.
// ======================================================================
{
  const p = T.parseURL("https://example.com@evil.example.net/");
  eq(p.hostname, "evil.example.net", "userinfo: real host is after the @");
  eq(p.username, "example.com", "userinfo: example.com is the username");
  const naive = T.naiveHostFromRaw("https://example.com@evil.example.net/");
  ok(naive.indexOf("example.com") === 0, "naive splitter reads the userinfo string");
  ok(naive !== p.hostname, "naive host diverges from the parsed host");
}

// ======================================================================
// 4. Backslash normalization for special schemes: \ becomes /, flipping
//    which side of the @ is the host.
// ======================================================================
{
  const p = T.parseURL("https://example.com\\@evil.example.net/");
  eq(p.hostname, "example.com", "backslash: host is example.com, @evil... is path");
  ok(p.pathname.indexOf("evil.example.net") !== -1, "backslash: evil host lands in the path");
}

// ======================================================================
// 5. allowToHost: reduce an allowlist entry to a bare hostname.
// ======================================================================
eq(T.allowToHost("https://example.com/"), "example.com", "allowToHost strips scheme and path");
eq(T.allowToHost("EXAMPLE.com:443"), "example.com", "allowToHost strips port and lowercases");
eq(T.allowToHost("user@example.com"), "example.com", "allowToHost strips userinfo");
eq(T.allowToHost("example.com."), "example.com", "allowToHost strips trailing dot");
eq(T.allowToHost("  example.com/path?q  "), "example.com", "allowToHost trims and drops path");

// ======================================================================
// 6. Allowlist verdicts: the dot-boundary safe check vs the naive shortcuts.
//    Each scenario asserts the safe verdict AND the bypass detection.
// ======================================================================
function al(url, allow) { return T.allowlistCheck(T.parseURL(url), allow); }

// 6a. exact match is safe, no bypass
{
  const r = al("https://example.com/x", "example.com");
  eq(r.safe, true, "exact host is allowed");
  eq(r.bypass, false, "exact host is not a bypass");
}
// 6b. dot-boundary subdomain is safe
{
  const r = al("https://cdn.example.com/x", "example.com");
  eq(r.safe, true, "subdomain on dot boundary is allowed");
  eq(r.safeSuffix, true, "matched via the suffix branch");
}
// 6c. userinfo bypass: raw contains the allow host but real host differs
{
  const r = al("https://example.com@evil.net/", "example.com");
  eq(r.safe, false, "userinfo trick: real host evil.net is not allowed");
  eq(r.naiveIncludes, true, "raw URL still contains the allow string");
  eq(r.bypass, true, "userinfo trick is flagged as a bypass");
}
// 6d. substring sibling: example.com.evil.net
{
  const r = al("https://example.com.evil.net/", "example.com");
  eq(r.safe, false, "example.com.evil.net is not allowed");
  eq(r.naiveIncludes, true, "includes() would match the sibling");
  eq(r.bypass, true, "substring sibling is flagged");
}
// 6e. endsWith-without-dot sibling: notexample.com
{
  const r = al("https://notexample.com/", "example.com");
  eq(r.safe, false, "notexample.com is not allowed");
  eq(r.naiveEndsWith, true, "endsWith() with no dot matches the sibling");
  eq(r.bypass, true, "suffix sibling is flagged");
}
// 6f. trailing dot on an exact match is still safe (normHost strips it)
{
  const r = al("https://example.com./", "example.com");
  eq(r.safe, true, "trailing dot still matches the exact host");
  eq(r.safeExact, true, "matched via the exact branch after normalization");
}
// 6g. IPv4 alternate notation: parsing first lets a 127.0.0.1 allowlist match
//     the decimal form (the GOOD outcome of trusting the parser).
{
  const r = al("http://2130706433/", "127.0.0.1");
  eq(r.safe, true, "decimal IPv4 matches the 127.0.0.1 allowlist after parsing");
  eq(r.bypass, false, "no bypass once the address is canonical");
}
// 6h. plain denial: unrelated host, no naive match, not a bypass
{
  const r = al("https://other.test/", "example.com");
  eq(r.safe, false, "unrelated host is denied");
  eq(r.bypass, false, "clean denial is not a bypass");
}

// ======================================================================
// 7. Punycode / IDN: the parser stores the ASCII xn-- form, so a unicode
//    homograph is a different hostname than it looks.
// ======================================================================
{
  const p = T.parseURL("https://\u043F\u0440\u0438\u043C\u0435\u0440.example/");
  ok(/(^|\.)xn--/.test(p.hostname), "IDN host is stored in xn-- form");
  eq(p.hostname, new URL("https://\u043F\u0440\u0438\u043C\u0435\u0440.example/").hostname, "IDN host matches Node URL");
}

// ======================================================================
// 8. Scheme classification in footguns(): dangerous schemes fail, http(s)
//    passes.
// ======================================================================
{
  const danger = T.footguns(T.parseURL("javascript:alert(1)"));
  eq(danger[0].state, "fail", "javascript: scheme is flagged as dangerous");
}
{
  const danger = T.footguns(T.parseURL("data:text/html,<b>x</b>"));
  eq(danger[0].state, "fail", "data: scheme is flagged as dangerous");
}
{
  const safe = T.footguns(T.parseURL("https://example.com/"));
  eq(safe[0].state, "pass", "https scheme passes");
}

// ======================================================================
// 9. isIPv4 / isIPv6 classifiers behave on canonical parser output.
// ======================================================================
eq(T.isIPv4("127.0.0.1"), true, "isIPv4 accepts dotted quad");
eq(T.isIPv4("256.0.0.1"), false, "isIPv4 rejects out-of-range octet");
eq(T.isIPv4("example.com"), false, "isIPv4 rejects a name");
eq(T.isIPv6("[::1]"), true, "isIPv6 accepts a bracketed literal");
eq(T.isIPv6("::1"), false, "isIPv6 requires brackets");

// ======================================================================
// 9b. host vs hostname: host carries the explicit port, hostname never does.
//     A check must read hostname, not host, or :443-style tricks leak.
// ======================================================================
{
  const p = T.parseURL("https://example.com:8443/x");
  eq(p.hostname, "example.com", "hostname omits the port");
  eq(p.host, "example.com:8443", "host carries the explicit port");
  eq(p.port, "8443", "port is exposed separately");
}
{
  const p = T.parseURL("https://example.com:443/x");
  eq(p.port, "", "default port for the scheme is stripped");
}

// ======================================================================
// 9c. naiveStartsWith prefix bug: an allow of "example.com" matched by a
//     prefix check also fires on a deeper attacker host like
//     example.com.evil.net, even though it is not on the dot boundary.
// ======================================================================
{
  const r = al("https://example.com.evil.net/", "example.com");
  eq(r.naiveStartsWith, true, "prefix check matches the deeper attacker host");
  eq(r.safe, false, "the dot-boundary safe check still denies it");
}

// ======================================================================
// 9d. more IPv4 notations all agree with Node URL and stay loopback.
// ======================================================================
for (const s of ["http://0x7f.1/", "http://017700000001/", "http://127.0.1/"]) {
  eq(T.parseURL(s).hostname, new URL(s).hostname, `${s} hostname matches Node URL`);
  eq(T.parseURL(s).hostname, "127.0.0.1", `${s} stays 127.0.0.1`);
}

// ======================================================================
// 9e. IPv6 literals: brackets are preserved in hostname and agree with Node.
// ======================================================================
for (const s of ["http://[::1]/", "http://[2001:db8::1]:80/", "http://[::ffff:127.0.0.1]/"]) {
  eq(T.parseURL(s).hostname, new URL(s).hostname, `${s} IPv6 hostname matches Node URL`);
  ok(T.isIPv6(T.parseURL(s).hostname), `${s} classifies as IPv6`);
}

// ======================================================================
// 10. Unparseable input is rejected, never silently treated as a host.
// ======================================================================
{
  const p = T.parseURL("http://");
  ok(p.ok === false, "a host-less URL does not parse to an ok result");
}
{
  const p = T.parseURL("   ");
  ok(p.empty === true, "blank input is reported as empty, not parsed");
}

console.log(`tool-url engine: ${n} assertions, all green`);
