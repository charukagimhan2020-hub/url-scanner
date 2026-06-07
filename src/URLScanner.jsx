import { useState, useEffect } from "react";

// ── Heuristic Engine ────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  ".xyz",".tk",".pw",".cc",".top",".gq",".ml",".cf",".ga",".men",
  ".work",".click",".link",".loan",".win",".bid",".download",".stream",
  ".racing",".accountant",".party",".trade",".review",".science",".date",
];

const POPULAR_BRANDS = [
  "google","facebook","paypal","amazon","apple","microsoft","netflix","instagram",
  "twitter","linkedin","dropbox","github","yahoo","outlook","gmail","chase",
  "wellsfargo","bankofamerica","citibank","ebay","walmart","steam","discord",
];

const SUSPICIOUS_KEYWORDS = [
  "login","signin","verify","secure","update","confirm","account","banking",
  "password","credential","alert","suspend","unusual","activity","validate",
  "recover","unlock","restore","limited","urgent","free","prize","winner",
  "click","redirect","offer","deal","bonus","reward",
];

const HOMOGLYPHS = { "0":"o","1":"l","3":"e","4":"a","5":"s","@":"a","vv":"w" };

function parseURL(raw) {
  try {
    const url = raw.startsWith("http") ? raw : "https://" + raw;
    return new URL(url);
  } catch {
    return null;
  }
}

function entropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((e, f) => {
    const p = f / str.length;
    return e - p * Math.log2(p);
  }, 0);
}

function runChecks(raw) {
  const parsed = parseURL(raw);
  if (!parsed) return null;

  const host     = parsed.hostname.toLowerCase();
  const fullURL  = parsed.href;
  const tld      = "." + host.split(".").slice(-1)[0];
  const subparts = host.split(".");
  const checks   = [];
  let score      = 0;

  if (parsed.protocol === "http:") {
    checks.push({ id:"http", label:"No HTTPS (HTTP only)", severity:"high", detail:"Connection is unencrypted. Credentials can be intercepted." });
    score += 30;
  } else {
    checks.push({ id:"https", label:"HTTPS enabled", severity:"safe", detail:"Connection is encrypted." });
  }

  if (SUSPICIOUS_TLDS.includes(tld)) {
    checks.push({ id:"tld", label:`Suspicious TLD: ${tld}`, severity:"high", detail:"This top-level domain is commonly used in phishing and spam campaigns." });
    score += 25;
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    checks.push({ id:"ip", label:"IP address used as hostname", severity:"high", detail:"Legitimate sites use domain names. IP-based URLs are a common phishing tactic." });
    score += 35;
  }

  const typo = POPULAR_BRANDS.find(brand => {
    if (host.includes(brand)) return false;
    const distance = levenshtein(host.replace(/\.[^.]+$/, "").split(".").pop(), brand);
    return distance === 1 || distance === 2;
  });
  if (typo) {
    checks.push({ id:"typo", label:`Possible typosquatting of "${typo}"`, severity:"high", detail:`The domain closely resembles "${typo}" with a small spelling difference — a classic impersonation technique.` });
    score += 30;
  }

  const rootDomain = subparts.slice(-2).join(".");
  const brandInSub = POPULAR_BRANDS.find(b => host.includes(b) && !rootDomain.includes(b));
  if (brandInSub) {
    checks.push({ id:"brandsub", label:`Brand "${brandInSub}" in subdomain only`, severity:"high", detail:`The subdomain contains "${brandInSub}" but the actual domain is different — a known phishing pattern.` });
    score += 35;
  }

  if (subparts.length > 4) {
    checks.push({ id:"subdomains", label:`Excessive subdomains (${subparts.length - 2})`, severity:"medium", detail:"Legitimate sites rarely use more than 2-3 subdomain levels." });
    score += 15;
  }

  const foundKw = SUSPICIOUS_KEYWORDS.filter(kw => fullURL.toLowerCase().includes(kw));
  if (foundKw.length >= 2) {
    checks.push({ id:"keywords", label:`Suspicious keywords: ${foundKw.slice(0,4).join(", ")}`, severity:"medium", detail:"Multiple security-sensitive keywords in the URL are associated with phishing lures." });
    score += 20;
  } else if (foundKw.length === 1) {
    checks.push({ id:"keywords1", label:`Suspicious keyword: "${foundKw[0]}"`, severity:"low", detail:"Contains a keyword commonly used in social engineering attacks." });
    score += 8;
  }

  const encodedCount = (fullURL.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encodedCount > 5) {
    checks.push({ id:"encoded", label:`Heavy URL encoding (${encodedCount} sequences)`, severity:"high", detail:"Excessive URL encoding is used to obfuscate malicious content from scanners." });
    score += 25;
  } else if (encodedCount > 0) {
    checks.push({ id:"encoded1", label:`URL-encoded characters (${encodedCount})`, severity:"low", detail:"Some encoded characters present — minor obfuscation." });
    score += 5;
  }

  let homoFound = null;
  for (const [fake, real] of Object.entries(HOMOGLYPHS)) {
    if (host.includes(fake)) { homoFound = { fake, real }; break; }
  }
  if (homoFound) {
    checks.push({ id:"homo", label:`Lookalike character "${homoFound.fake}" → "${homoFound.real}"`, severity:"high", detail:"Homograph attack detected. Characters that look like real letters used to impersonate domains." });
    score += 30;
  }

  if (parsed.port && !["80","443",""].includes(parsed.port)) {
    checks.push({ id:"port", label:`Non-standard port: ${parsed.port}`, severity:"medium", detail:"Legitimate websites almost always use port 80 or 443." });
    score += 15;
  }

  if (fullURL.length > 150) {
    checks.push({ id:"length", label:`Unusually long URL (${fullURL.length} chars)`, severity:"medium", detail:"Very long URLs are often used to hide the true destination or stuff keywords." });
    score += 15;
  } else if (fullURL.length > 100) {
    checks.push({ id:"length1", label:`Long URL (${fullURL.length} chars)`, severity:"low", detail:"Above-average URL length." });
    score += 5;
  }

  const domainEntropy = parseFloat(entropy(host).toFixed(2));
  if (domainEntropy > 4.2) {
    checks.push({ id:"entropy", label:`High domain entropy (${domainEntropy})`, severity:"medium", detail:"High character randomness suggests a machine-generated or DGA domain." });
    score += 15;
  }

  const redirectCount = (fullURL.match(/https?:\/\//g) || []).length - 1;
  if (redirectCount > 0) {
    checks.push({ id:"redirect", label:`Embedded redirect URL detected`, severity:"high", detail:"The URL contains another URL inside it — a common open redirect / redirect chaining technique." });
    score += 30;
  }

  if (raw.trim().startsWith("data:")) {
    checks.push({ id:"data", label:"Data URI scheme", severity:"high", detail:"data: URIs can be used to execute arbitrary HTML/JS — a phishing and XSS vector." });
    score += 40;
  }

  const isClean = checks.every(c => c.severity === "safe");
  if (isClean) {
    checks.push({ id:"clean", label:"No suspicious indicators found", severity:"safe", detail:"Heuristic scan found no red flags. Always verify with a live reputation service for certainty." });
  }

  const capped = Math.min(score, 100);
  let verdict, color;
  if (capped >= 55)      { verdict = "DANGEROUS";    color = "var(--red)";   }
  else if (capped >= 25) { verdict = "SUSPICIOUS";   color = "var(--amber)"; }
  else                   { verdict = "LIKELY SAFE";   color = "var(--green)"; }

  return {
    parsed,
    host,
    protocol: parsed.protocol,
    path: parsed.pathname,
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    score: capped,
    verdict,
    color,
    checks,
    entropy: domainEntropy,
    length: fullURL.length,
  };
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

// ── Sample URLs ─────────────────────────────────────────────────────────────
const SAMPLE_GROUPS = [
  {
    group: "🎣 Phishing (PayPal)",
    color: "var(--red)",
    variants: [
      { label: "Classic paypa1 lure",      url: "http://paypa1-secure-login.verify-account.tk/update/credentials?redirect=https://paypal.com" },
      { label: "Brand-in-subdomain",        url: "http://paypal.com.secure-account-update.xyz/signin?token=abc123&verify=true" },
      { label: "Homoglyph paypаl (Cyrillic)",url: "http://www.paypаl-secure.com/login/confirm?user=victim@email.com" },
      { label: "Open redirect chain",       url: "http://paypal-login.tk/redirect?url=https://paypal.com&next=http://evil.pw/steal" },
      { label: "Encoded credentials path",  url: "http://secure-paypal.men/%6C%6F%67%69%6E%2F%76%65%72%69%66%79?account=suspend&action=confirm" },
    ],
  },
  {
    group: "🕵️ Suspicious subdomain",
    color: "var(--amber)",
    variants: [
      { label: "Google account verify",     url: "http://google.com.account-verify.xyz/signin?user=admin" },
      { label: "Apple ID reset",            url: "http://appleid.apple.com.password-reset.cc/update?token=xf91k&redirect=appleid.apple.com" },
      { label: "Microsoft in subdomain",    url: "http://microsoft.com.support-center.top/login/secure?session=expired" },
      { label: "Amazon order alert",        url: "http://amazon.com.order-alert.pw/account/verify?order=112-fake&action=confirm" },
      { label: "Netflix billing subdomain", url: "http://netflix.com.billing-update.stream/payment/method?suspended=true&next=signin" },
    ],
  },
  {
    group: "✅ Clean site",
    color: "var(--green)",
    variants: [
      { label: "GitHub repo",               url: "https://github.com/torvalds/linux" },
      { label: "Wikipedia article",         url: "https://en.wikipedia.org/wiki/Phishing" },
      { label: "MDN Web Docs",              url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview" },
      { label: "Anthropic homepage",        url: "https://www.anthropic.com" },
      { label: "npm package",               url: "https://www.npmjs.com/package/react" },
    ],
  },
  {
    group: "📡 IP-based URL",
    color: "var(--red)",
    variants: [
      { label: "Router admin login",        url: "http://192.168.1.1/login?next=/admin" },
      { label: "Public IP phishing page",   url: "http://203.0.113.42/paypal/signin?verify=account&suspend=true" },
      { label: "Non-standard port",         url: "http://198.51.100.7:8080/update/credentials?redirect=paypal.com" },
      { label: "Localhost abuse",           url: "http://127.0.0.1:3000/login?next=/dashboard&token=eyJhbGciOiJIUzI1" },
      { label: "Class A internal IP",       url: "http://10.0.0.1/admin/login?username=root&redirect=http://evil.xyz" },
    ],
  },
  {
    group: "🤫 Encoded obfuscation",
    color: "var(--amber)",
    variants: [
      { label: "PayPal login path encoded", url: "https://example.com/%70%61%79%70%61%6C%2F%6C%6F%67%69%6E%2F%76%65%72%69%66%79" },
      { label: "Heavy keyword encoding",    url: "http://totally-safe.xyz/%73%69%67%6E%69%6E%2F%76%65%72%69%66%79%2F%61%63%63%6F%75%6E%74?%70%61%73%73%77%6F%72%64=reset" },
      { label: "Double-encoded slash",      url: "http://redirect-me.cc/go?url=https%3A%2F%2Fpaypal.com%2Flogin%26next%3Dhttp%3A%2F%2Fevil.pw" },
      { label: "Mixed encoding + keywords", url: "https://secure-verify.men/%63%6F%6E%66%69%72%6D?account=%73%75%73%70%65%6E%64&action=validate&urgent=1" },
      { label: "Path traversal encoded",    url: "http://legit-looking.work/%2E%2E%2F%2E%2E%2Fadmin%2Flogin?redirect=%2F%70%61%79%70%61%6C" },
    ],
  },
];

// ── Styles ──────────────────────────────────────────────────────────────────
const css = `
@import url('https://fonts.googleapis.com/css2?family=Bangers&family=Nunito:wght@400;700;900&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --bg: #fffdf5;
  --bg2: #fff8e1;
  --bg3: #fff3cc;
  --outline: #111111;
  --outline-w: 2.5px;
  --shadow: 4px 4px 0px #111;
  --shadow-sm: 3px 3px 0px #111;
  --green: #1db954;
  --green-bg: #d4f5e1;
  --red: #e8002d;
  --red-bg: #ffd6dd;
  --amber: #d97706;
  --amber-bg: #fef3c7;
  --blue: #2563eb;
  --blue-bg: #dbeafe;
  --text: #111;
  --muted: #555;
  --muted2: #888;
  --display: 'Bangers', cursive;
  --body: 'Nunito', sans-serif;
  --radius: 10px;
}

body {
  background: var(--bg);
  background-image:
    radial-gradient(circle, #ddd 1px, transparent 1px);
  background-size: 24px 24px;
  color: var(--text);
  font-family: var(--body);
  min-height: 100vh;
}

.app {
  max-width: 900px;
  margin: 0 auto;
  padding: 2rem 1.5rem 3rem;
}

/* ── Header ── */
.header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 2rem;
  background: #111;
  border-radius: var(--radius);
  border: var(--outline-w) solid var(--outline);
  padding: 1.25rem 1.5rem;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
.header::before {
  content: '';
  position: absolute;
  inset: 0;
  background: repeating-linear-gradient(
    -45deg,
    transparent,
    transparent 8px,
    rgba(255,255,255,0.03) 8px,
    rgba(255,255,255,0.03) 16px
  );
}
.header-icon { font-size: 2.2rem; position: relative; z-index: 1; }
.header-title {
  font-family: var(--display);
  font-size: 2.2rem;
  letter-spacing: 0.06em;
  color: #fff;
  line-height: 1;
  position: relative; z-index: 1;
}
.header-title span { color: #ffd700; }
.header-sub {
  font-size: 11px;
  color: #aaa;
  letter-spacing: .12em;
  text-transform: uppercase;
  margin-top: 4px;
  position: relative; z-index: 1;
  font-weight: 700;
}
.badge {
  margin-left: auto;
  background: #ffd700;
  color: #111;
  border: var(--outline-w) solid #111;
  border-radius: 6px;
  padding: 5px 12px;
  font-size: 11px;
  font-weight: 900;
  letter-spacing: .1em;
  box-shadow: var(--shadow-sm);
  position: relative; z-index: 1;
  transform: rotate(1.5deg);
}

/* ── Scan box ── */
.scan-box {
  background: #fff;
  border: var(--outline-w) solid var(--outline);
  border-radius: var(--radius);
  padding: 1.25rem;
  margin-bottom: 1rem;
  box-shadow: var(--shadow);
}
.scan-row { display: flex; gap: 8px; }
.scan-input {
  flex: 1;
  background: var(--bg);
  border: var(--outline-w) solid var(--outline);
  border-radius: 7px;
  padding: 10px 14px;
  color: var(--text);
  font-family: var(--body);
  font-size: 13px;
  font-weight: 700;
  outline: none;
  transition: box-shadow .15s;
  box-shadow: 2px 2px 0 #111;
}
.scan-input:focus {
  box-shadow: 3px 3px 0 var(--blue);
  border-color: var(--blue);
}
.scan-input::placeholder { color: var(--muted2); font-weight: 400; }

.btn {
  padding: 10px 18px;
  border-radius: 7px;
  font-family: var(--body);
  font-size: 13px;
  font-weight: 900;
  letter-spacing: .04em;
  cursor: pointer;
  border: var(--outline-w) solid var(--outline);
  transition: all .1s;
  box-shadow: var(--shadow-sm);
}
.btn:active { transform: translate(2px, 2px); box-shadow: 1px 1px 0 #111; }
.btn-primary { background: #111; color: #ffd700; }
.btn-primary:hover { background: #333; }
.btn-clear { background: var(--bg); color: var(--muted); }
.btn-clear:hover { background: var(--bg3); }

.samples { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.sample-btn {
  background: var(--bg2);
  border: var(--outline-w) solid var(--outline);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 11px;
  font-weight: 700;
  color: var(--text);
  cursor: pointer;
  font-family: var(--body);
  transition: all .1s;
  box-shadow: 2px 2px 0 #111;
}
.sample-btn:hover {
  background: #111;
  color: #ffd700;
  transform: translate(-1px, -1px);
  box-shadow: 3px 3px 0 #555;
}
.sample-btn:active { transform: translate(1px, 1px); box-shadow: 1px 1px 0 #111; }

/* ── Verdict box ── */
.verdict-box {
  background: #fff;
  border-radius: var(--radius);
  padding: 1.5rem;
  margin-bottom: 1rem;
  border: var(--outline-w) solid var(--outline);
  display: flex;
  align-items: center;
  gap: 1.5rem;
  box-shadow: var(--shadow);
}
.verdict-score { text-align: center; flex-shrink: 0; }
.score-ring {
  width: 84px;
  height: 84px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 4px solid;
  box-shadow: 4px 4px 0 #111;
}
.score-num {
  font-family: var(--display);
  font-size: 2rem;
  line-height: 1;
  letter-spacing: .04em;
}
.score-lbl {
  font-size: 9px;
  color: var(--muted);
  letter-spacing: .12em;
  margin-top: 2px;
  font-weight: 900;
  text-transform: uppercase;
}
.verdict-label {
  font-family: var(--display);
  font-size: 1.8rem;
  letter-spacing: .06em;
  line-height: 1;
}
.verdict-url {
  font-size: 11px;
  color: var(--muted);
  margin-top: 5px;
  word-break: break-all;
  font-weight: 700;
}

/* ── Severity badges ── */
.sev-badge {
  flex-shrink: 0;
  padding: 3px 9px;
  border-radius: 5px;
  font-size: 10px;
  font-weight: 900;
  letter-spacing: .1em;
  text-transform: uppercase;
  margin-top: 2px;
  border: var(--outline-w) solid #111;
  font-family: var(--body);
}
.sev-high    { background: var(--red-bg);   color: var(--red);   box-shadow: 2px 2px 0 #111; }
.sev-medium  { background: var(--amber-bg); color: var(--amber); box-shadow: 2px 2px 0 #111; }
.sev-low     { background: var(--blue-bg);  color: var(--blue);  box-shadow: 2px 2px 0 #111; }
.sev-safe    { background: var(--green-bg); color: var(--green); box-shadow: 2px 2px 0 #111; }

/* ── Meta grid ── */
.meta-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 1rem;
}
.meta-card {
  background: #fff;
  border: var(--outline-w) solid var(--outline);
  border-radius: var(--radius);
  padding: 12px 14px;
  box-shadow: var(--shadow-sm);
}
.meta-val {
  font-family: var(--display);
  font-size: 1.15rem;
  color: var(--text);
  line-height: 1;
  word-break: break-all;
  letter-spacing: .04em;
}
.meta-lbl {
  font-size: 9px;
  color: var(--muted2);
  margin-top: 4px;
  letter-spacing: .1em;
  text-transform: uppercase;
  font-weight: 900;
}

/* ── Score bar ── */
.score-section {
  background: #fff;
  border: var(--outline-w) solid var(--outline);
  border-radius: var(--radius);
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
  box-shadow: var(--shadow-sm);
}
.score-section-header {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 8px;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .08em;
}
.prog-bar-bg {
  background: var(--bg3);
  border-radius: 6px;
  height: 12px;
  overflow: hidden;
  border: var(--outline-w) solid var(--outline);
}
.prog-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width .5s cubic-bezier(.34,1.56,.64,1);
}
.score-labels {
  display: flex;
  justify-content: space-between;
  font-size: 9px;
  color: var(--muted2);
  margin-top: 5px;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .06em;
}

/* ── Checks ── */
.checks-wrap {
  background: #fff;
  border: var(--outline-w) solid var(--outline);
  border-radius: var(--radius);
  overflow: hidden;
  margin-bottom: 1rem;
  box-shadow: var(--shadow);
}
.checks-header {
  padding: 10px 1.25rem;
  border-bottom: var(--outline-w) solid var(--outline);
  font-size: 11px;
  color: #fff;
  background: #111;
  letter-spacing: .15em;
  text-transform: uppercase;
  font-weight: 900;
  font-family: var(--body);
  display: flex;
  align-items: center;
  gap: 8px;
}
.checks-header-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #ffd700;
  border: 1.5px solid #555;
  display: inline-block;
}
.check-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px 1.25rem;
  border-bottom: 1.5px solid #eee;
  transition: background .1s;
}
.check-item:last-child { border-bottom: none; }
.check-item:hover { background: var(--bg); }
.check-label {
  font-size: 12px;
  color: var(--text);
  font-weight: 900;
  margin-bottom: 2px;
  font-family: var(--body);
}
.check-detail {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.6;
  font-family: var(--body);
}

/* ── Empty state ── */
.empty-state {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--muted);
  font-size: 13px;
  font-weight: 700;
}
.empty-icon { font-size: 3rem; margin-bottom: 1rem; }

/* ── Scanning ── */
.scanning-box {
  background: #fff;
  border: var(--outline-w) solid var(--outline);
  border-radius: var(--radius);
  padding: 2rem;
  text-align: center;
  margin-bottom: 1rem;
  box-shadow: var(--shadow);
}
.scanning-text {
  font-family: var(--display);
  font-size: 1.3rem;
  letter-spacing: .1em;
  color: #111;
  margin-bottom: 14px;
}
@keyframes scanpulse {
  0%   { width: 0%; }
  60%  { width: 90%; }
  100% { width: 100%; }
}
.prog-bar-anim {
  animation: scanpulse 0.55s ease-out forwards;
  background: #111 !important;
}

/* ── Disclaimer ── */
.disclaimer {
  font-size: 10px;
  color: var(--muted2);
  border-top: var(--outline-w) solid #ddd;
  padding-top: 1rem;
  margin-top: .5rem;
  line-height: 1.7;
  text-align: center;
  font-weight: 700;
}
.disclaimer strong { color: var(--amber); }

@media (max-width: 600px) {
  .meta-grid { grid-template-columns: repeat(2, 1fr); }
  .header-title { font-size: 1.6rem; }
  .badge { display: none; }
}
`;

// ── Component ────────────────────────────────────────────────────────────────
export default function URLScanner() {
  const [input, setInput]         = useState("");
  const [result, setResult]       = useState(null);
  const [error, setError]         = useState("");
  const [scanning, setScanning]   = useState(false);
  const [openGroup, setOpenGroup] = useState(null);

  useEffect(() => {
    const tag = document.createElement("style");
    tag.textContent = css;
    document.head.appendChild(tag);
    return () => document.head.removeChild(tag);
  }, []);

  function scan(url) {
    const raw = (url || input).trim();
    if (!raw) { setError("Please enter a URL."); return; }
    setError("");
    setScanning(true);
    setResult(null);
    setTimeout(() => {
      const r = runChecks(raw);
      if (!r) { setError("Invalid URL — make sure it starts with http:// or https://"); setScanning(false); return; }
      setResult(r);
      setScanning(false);
    }, 600);
  }

  const highCount = result?.checks.filter(c => c.severity === "high").length   || 0;
  const medCount  = result?.checks.filter(c => c.severity === "medium").length  || 0;
  const lowCount  = result?.checks.filter(c => c.severity === "low").length     || 0;

  return (
    <>
      <div className="app">

        {/* Header */}
        <div className="header">
          <div className="header-icon">🔍</div>
          <div>
            <div className="header-title">URL <span>Security</span> Scanner</div>
            <div className="header-sub">Heuristic Analysis · Local Only · No API Required</div>
          </div>
          <div className="badge">⚡ INSTANT SCAN</div>
        </div>

        {/* Input */}
        <div className="scan-box">
          <div className="scan-row">
            <input
              className="scan-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && scan()}
              placeholder="Paste any URL to scan — e.g. https://example.com/login"
            />
            <button className="btn btn-primary" onClick={() => scan()}>
              {scanning ? "Scanning…" : "▶ Scan"}
            </button>
            <button className="btn btn-clear" onClick={() => { setInput(""); setResult(null); setError(""); }}>
              ✕
            </button>
          </div>
          {error && <div style={{ color: "var(--red)", fontSize: "12px", marginTop: "8px", fontWeight: 900 }}>{error}</div>}
          <div className="samples">
            <span style={{ fontSize: "11px", color: "var(--muted)", alignSelf: "center", fontWeight: 700, flexShrink: 0 }}>Try:</span>
            {SAMPLE_GROUPS.map(g => (
              <div key={g.group} style={{ position: "relative", display: "inline-block" }}>
                <button
                  className="sample-btn"
                  style={{ borderColor: openGroup === g.group ? "#111" : undefined, background: openGroup === g.group ? "#111" : undefined, color: openGroup === g.group ? "#ffd700" : undefined }}
                  onClick={() => setOpenGroup(openGroup === g.group ? null : g.group)}
                >
                  {g.group} {openGroup === g.group ? "▲" : "▼"}
                </button>
                {openGroup === g.group && (
                  <div style={{
                    position: "absolute", top: "calc(100% + 6px)", left: 0, zIndex: 50,
                    background: "#fff", border: "2.5px solid #111", borderRadius: "8px",
                    boxShadow: "4px 4px 0 #111", minWidth: "260px", overflow: "hidden",
                  }}>
                    {g.variants.map((v, i) => (
                      <button
                        key={v.label}
                        onClick={() => { setInput(v.url); scan(v.url); setOpenGroup(null); }}
                        style={{
                          display: "block", width: "100%", textAlign: "left",
                          padding: "8px 14px", background: "transparent",
                          border: "none", borderBottom: i < g.variants.length - 1 ? "1.5px solid #eee" : "none",
                          cursor: "pointer", fontFamily: "var(--body)", fontSize: "11px",
                          fontWeight: 700, color: "#111",
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = "#fffdf5"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                      >
                        <span style={{ display: "block", color: "#111" }}>{v.label}</span>
                        <span style={{ display: "block", color: "#999", fontSize: "10px", marginTop: "1px", fontWeight: 400, wordBreak: "break-all", whiteSpace: "normal" }}>{v.url.length > 55 ? v.url.slice(0, 55) + "…" : v.url}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Scanning */}
        {scanning && (
          <div className="scanning-box">
            <div className="scanning-text">🔎 Running heuristic checks…</div>
            <div className="prog-bar-bg" style={{ maxWidth: "320px", margin: "0 auto" }}>
              <div className="prog-bar-fill prog-bar-anim" style={{ width: "0%" }} />
            </div>
          </div>
        )}

        {/* Results */}
        {result && !scanning && (
          <>
            {/* Verdict */}
            <div className="verdict-box" style={{ borderColor: result.color, borderWidth: "3px" }}>
              <div className="verdict-score">
                <div className="score-ring" style={{ borderColor: result.color, background: result.color + "18" }}>
                  <div>
                    <div className="score-num" style={{ color: result.color }}>{result.score}</div>
                    <div className="score-lbl">RISK</div>
                  </div>
                </div>
              </div>
              <div style={{ flex: 1 }}>
                <div className="verdict-label" style={{ color: result.color }}>{result.verdict}</div>
                <div className="verdict-url">{result.parsed.href}</div>
                <div style={{ display: "flex", gap: "8px", marginTop: "10px", flexWrap: "wrap" }}>
                  {highCount > 0 && <span className="sev-badge sev-high">{highCount} HIGH</span>}
                  {medCount  > 0 && <span className="sev-badge sev-medium">{medCount} MEDIUM</span>}
                  {lowCount  > 0 && <span className="sev-badge sev-low">{lowCount} LOW</span>}
                </div>
              </div>
            </div>

            {/* Meta */}
            <div className="meta-grid">
              {[
                { val: result.protocol.replace(":",""), lbl: "Protocol" },
                { val: result.host, lbl: "Hostname" },
                { val: result.port, lbl: "Port" },
                { val: result.length, lbl: "URL Length" },
              ].map(({ val, lbl }) => (
                <div className="meta-card" key={lbl}>
                  <div className="meta-val" style={{ fontSize: String(val).length > 14 ? "0.78rem" : undefined }}>{val}</div>
                  <div className="meta-lbl">{lbl}</div>
                </div>
              ))}
            </div>

            {/* Score bar */}
            <div className="score-section">
              <div className="score-section-header">
                <span>Risk Score</span>
                <span style={{ color: result.color }}>{result.score} / 100</span>
              </div>
              <div className="prog-bar-bg">
                <div className="prog-bar-fill" style={{ width: `${result.score}%`, background: result.color }} />
              </div>
              <div className="score-labels">
                <span>Safe</span><span>Suspicious</span><span>Dangerous</span>
              </div>
            </div>

            {/* Checks */}
            <div className="checks-wrap">
              <div className="checks-header">
                <span className="checks-header-dot" />
                Check Results ({result.checks.length})
              </div>
              {result.checks
                .sort((a, b) => {
                  const order = { high: 0, medium: 1, low: 2, safe: 3 };
                  return order[a.severity] - order[b.severity];
                })
                .map(c => (
                  <div className="check-item" key={c.id}>
                    <span className={`sev-badge sev-${c.severity}`}>{c.severity}</span>
                    <div>
                      <div className="check-label">{c.label}</div>
                      <div className="check-detail">{c.detail}</div>
                    </div>
                  </div>
                ))}
            </div>
          </>
        )}

        {!result && !scanning && (
          <div className="empty-state">
            <div className="empty-icon">🔗</div>
            <div>Paste a URL above and hit <strong>Scan</strong> — or try one of the sample URLs.</div>
          </div>
        )}

        <div className="disclaimer">
          <strong>⚠ EDUCATIONAL USE ONLY.</strong> This scanner uses local heuristics only — no live threat intelligence.
          It may produce false positives and cannot replace a real reputation service like VirusTotal or Google Safe Browsing.
        </div>
      </div>
    </>
  );
}
