/** TrueClick analyzer — same pipeline as analyzer.py, for the Node server. */
import dns from "node:dns/promises";
import net from "node:net";
import { load as loadHtml } from "cheerio";

const UA = "Mozilla/5.0 (compatible; TrueClickBot/1.0)";
const MAX_BYTES = 2_000_000;

export const OFFICIAL = {
  amazon: ["amazon.in", "amazon.com"],
  flipkart: ["flipkart.com"],
  paytm: ["paytm.com"],
  phonepe: ["phonepe.com"],
  sbi: ["sbi.co.in", "onlinesbi.sbi"],
  hdfc: ["hdfcbank.com"],
  icici: ["icicibank.com"],
  google: ["google.com", "google.co.in"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  netflix: ["netflix.com"],
};
export const SUGGEST = {
  shop: [
    ["Amazon.in", "https://www.amazon.in"],
    ["Flipkart", "https://www.flipkart.com"],
    ["Myntra", "https://www.myntra.com"],
  ],
  fin: [
    ["SBI", "https://sbi.co.in"],
    ["HDFC Bank", "https://www.hdfcbank.com"],
    ["RBI: check a lender is registered", "https://www.rbi.org.in"],
  ],
  job: [
    ["National Career Service (Govt.)", "https://www.ncs.gov.in"],
    ["Naukri", "https://www.naukri.com"],
    ["LinkedIn Jobs", "https://www.linkedin.com/jobs"],
  ],
  tech: [
    ["Apple India", "https://www.apple.com/in"],
    ["Croma", "https://www.croma.com"],
    ["Amazon.in", "https://www.amazon.in"],
  ],
  gen: [["Search the brand name and open the official site", "https://www.google.com"]],
};
const STOP = new Set("the and for you your our with get now from this that are can will has have not all any".split(" "));
const RISKY_CLAIMS = [
  [/guaranteed|100% ?(safe|sure|approval)|risk[- ]?free/i, "guarantee"],
  [/no (documents?|kyc|credit check|fees?)/i, "'no checks' promise"],
  [/double your|earn \d+.{0,20}(day|hour)/i, "unrealistic earnings"],
  [/free (iphone|gift|recharge|laptop)/i, "free luxury giveaway"],
  [/limited time|only \d+ left|act now|hurry/i, "pressure tactic"],
  [/9\d% off/i, "extreme discount"],
];
const CTA_WORDS = [
  "apply now", "buy now", "sign up", "get started", "shop now",
  "learn more", "book now", "register", "download", "start free trial",
];

export function hostOf(url) {
  try {
    const full = /^https?:\/\//i.test(url) ? url : "https://" + url;
    const u = new URL(full);
    return (u.hostname || "").toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

function isDomain(h, d) {
  return h === d || h.endsWith("." + d);
}

function isBadIp(ip) {
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  const v = net.isIP(ip);
  if (v === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    return false;
  }
  if (v === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) return true;
    if (lower.startsWith("ff")) return true;
    return false;
  }
  return true;
}

export async function isSafePublicUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (!["http:", "https:"].includes(u.protocol) || !u.hostname) return false;
  try {
    const answers = await dns.lookup(u.hostname, { all: true });
    if (!answers.length) return false;
    return answers.every((a) => !isBadIp(a.address));
  } catch {
    return false;
  }
}

export async function fetchPage(url) {
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  if (!(await isSafePublicUrl(url))) return [null, "Link could not be resolved or points to a private address."];
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": UA },
      signal: AbortSignal.timeout(10000),
      redirect: "follow",
    });
    if ([401, 403, 429].includes(r.status)) {
      return [null, `Site blocked automated access (HTTP ${r.status}). Paste the page HTML instead.`];
    }
    const buf = Buffer.from(await r.arrayBuffer()).subarray(0, MAX_BYTES);
    return [buf.toString("utf8"), null];
  } catch (e) {
    return [null, `Could not fetch page: ${e?.name || "Error"}`];
  }
}

export function parseBlocks(htmlOrText) {
  if (!/<\s*(html|body|div|p|h1|section)\b/i.test(htmlOrText)) {
    const lines = htmlOrText.split(/(?<=[.!?])\s+|\n+/).map((l) => l.trim()).filter(Boolean);
    return [lines.map((t, i, arr) => blockMeta(t, false, i, arr.length)), []];
  }
  const $ = loadHtml(htmlOrText);
  $("script, style, noscript, svg, template").remove();
  const raw = [];
  const ctas = [];
  const title = $("title").first().text().replace(/\s+/g, " ").trim();
  if (title) raw.push([title, false]);
  const md = $('meta[name="description"]').attr("content");
  if (md && md.trim()) raw.push([md.trim(), false]);
  $("h1, h2, h3, h4, p, li, a, button, td, span, label").each((_, el) => {
    const name = el.tagName?.toLowerCase();
    if (["span", "label", "td"].includes(name) && $(el).find("p, li, a, button").length) return;
    const t = $(el).text().replace(/\s+/g, " ").trim();
    if (t.length < 3) return;
    const inFooter = $(el).parents("footer").length > 0;
    raw.push([t, inFooter]);
    if (name === "a" || name === "button") ctas.push(t.toLowerCase());
  });
  const seen = new Set();
  const blocks = [];
  for (const [t0, inFooter] of raw) {
    const t = t0.replace(/\s+/g, " ");
    if (seen.has(t)) continue;
    seen.add(t);
    blocks.push({ text: t, footer: inFooter });
  }
  const n = blocks.length;
  blocks.forEach((b, i) => {
    b.id = i;
    const footer = b.footer || i >= n * 0.85;
    delete b.footer;
    b.pos = footer ? "footer" : i < Math.max(3, n * 0.15) ? "hero" : "body";
  });
  return [blocks, ctas];
}

function blockMeta(t, inFooter, i, n) {
  return {
    text: t.replace(/\s+/g, " "),
    id: i,
    pos: inFooter || i >= n * 0.85 ? "footer" : i < Math.max(3, n * 0.15) ? "hero" : "body",
  };
}

function norm(s) {
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

export function verifyQuote(quote, blocks) {
  const q = norm(quote).replace(/^[\s"'.]+|[\s"'.]+$/g, "");
  if (q.length < 4) return null;
  for (const b of blocks) {
    if (norm(b.text).includes(q)) return b;
  }
  return null;
}

export function adClaims(adText) {
  const parts = adText.split(/(?<=[.!?])\s+|\n+|\|/).map((p) => p.replace(/^[ .!?]+|[ .!?]+$/g, ""));
  return parts.filter((p) => p.split(/\s+/).length >= 2 && !CTA_WORDS.includes(p.toLowerCase())).slice(0, 8);
}

function tokens(s) {
  const out = new Set();
  for (const m of s.toLowerCase().match(/[a-z0-9]+(?:\.\d+)?/g) || []) {
    out.add(m.length > 3 && m.endsWith("s") ? m.slice(0, -1) : m);
  }
  return out;
}

export function keywordMatch(claims, blocks) {
  const out = [];
  for (const c of claims) {
    const kw = new Set([...tokens(c)].filter((w) => w.length > 2 && !STOP.has(w)));
    const nums = new Set(c.match(/\d+(?:\.\d+)?/g) || []);
    if (!kw.size) continue;
    let best = 0;
    let bb = null;
    for (const b of blocks) {
      const bt = tokens(b.text);
      let cov = [...kw].filter((w) => bt.has(w)).length / kw.size;
      if (nums.size && ![...nums].every((n) => bt.has(n))) cov = 0;
      if (cov > best) {
        best = cov;
        bb = b;
      }
    }
    const need = kw.size >= 3 ? 0.75 : 1.0;
    if (bb && best >= need) {
      out.push({ claim: c, status: "supported", quote: bb.text.slice(0, 160), fix: "" });
    } else {
      out.push({
        claim: c,
        status: "unsupported",
        quote: "",
        fix: `Add a clear line near the top of the page that says: "${c}", or remove this promise from the ad.`,
      });
    }
  }
  return out;
}

export async function llmMatch(claims, blocks, adText) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  const page = blocks.slice(0, 150).map((b) => `[${b.id}] (${b.pos}) ${b.text}`).join("\n").slice(0, 14000);
  const prompt =
    "You audit message match between an ad and its landing page.\n" +
    "Use ONLY the numbered page blocks below. Never invent page content.\n" +
    "For each ad claim return: claim, status (supported | partial | unsupported), " +
    "quote (an EXACT copy of text from ONE page block, empty if unsupported), " +
    "block_id (number or null), fix (a concrete fix, empty if supported).\n" +
    'Reply with ONLY JSON: {"findings":[...]}\n\n' +
    `AD TEXT:\n${adText}\n\nCLAIMS:\n` +
    claims.map((c) => `- ${c}`).join("\n") +
    `\n\nPAGE BLOCKS:\n${page}`;
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5",
        max_tokens: 1500,
        messages: [{ role: "user", content: prompt }],
      }),
      signal: AbortSignal.timeout(40000),
    });
    const data = await r.json();
    let text = data.content[0].text.trim().replace(/^```(?:json)?|```$/gm, "").trim();
    return JSON.parse(text).findings;
  } catch {
    return null;
  }
}

export async function analyze(url, adText = "", pageInput = null, boost = 0, reviews = null, openComplaints = 0) {
  const ev = [];
  let score = 50;
  const add = (kind, msg, pts, quote = "", pos = "", fix = "") => {
    score += pts;
    ev.push({ type: kind, message: msg, quote, position: pos, fix });
  };

  const full = /^https?:\/\//i.test(url) ? url : "https://" + url;
  let u;
  try {
    u = new URL(full);
  } catch {
    u = { protocol: "", hostname: "" };
  }
  const h = hostOf(url);
  if (!h || !h.includes(".")) {
    return {
      score: 0,
      label: "Not suggested",
      risk: "Critical",
      host: url.slice(0, 80),
      category: "gen",
      evidence: [{ type: "bad", message: "This is not a valid link, so it cannot be verified.", quote: "", position: "", fix: "" }],
      suggestions: SUGGEST.gen,
      mode: "none",
      fixes: [],
    };
  }
  const low = full.toLowerCase();

  if (u.protocol === "https:") add("good", "Link uses HTTPS (encrypted connection).", 8);
  else add("bad", "Link uses plain HTTP, so data is not encrypted.", -15);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) add("bad", "Link points to a raw IP address instead of a brand name.", -25);
  if (/(^|\.)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy)$/.test(h)) {
    add("bad", "Shortened link hides the real destination.", -15);
  }
  if (/\.(xyz|top|click|loan|work|gq|tk|ml|cf|icu|buzz|rest)$/.test(h)) {
    add("bad", "Domain ending is often used by throwaway scam sites.", -18);
  }
  if (/\.(gov\.in|nic\.in|ac\.in|edu|gov)$/.test(h)) add("good", "Government or education domain.", 15);
  if ((h.match(/-/g) || []).length >= 3) add("bad", "Domain has many hyphens, a common trick in fake sites.", -10);
  if (h.split(".").length > 4) add("bad", "Domain has too many sub-domains.", -8);
  if (h.includes("xn--") || low.includes("@")) {
    add("bad", "Link uses look-alike characters or an '@' to disguise the destination.", -20);
  }
  const m = low.match(/free-?gift|winner|lottery|prize|giveaway|claim|bonus|refund|kyc|verify|login-?update/);
  if (m) add("bad", `Link contains the scam-style word '${m[0]}'.`, -15);

  let official = null;
  let fake = null;
  for (const [brand, doms] of Object.entries(OFFICIAL)) {
    if (doms.some((d) => isDomain(h, d))) official = brand;
    else if (h.includes(brand) && !fake) fake = brand;
  }
  if (official) add("good", `Official domain of ${official}.`, 12);
  else if (fake) add("bad", `Domain imitates '${fake}' but is not its official site.`, -30);
  else add("info", "Domain is not in our trusted list, so there is no reputation data for it.", 0);

  let pen = 0;
  for (const [pat, name] of RISKY_CLAIMS) {
    const mm = (adText || "").match(pat);
    if (mm && pen > -32) {
      pen -= 8;
      add("bad", `Ad uses a risky claim (${name}).`, -8, mm[0]);
    }
  }

  let mode = "none";
  let err = null;
  let html = pageInput;
  if (html) {
    mode = "snapshot";
  } else {
    [html, err] = await fetchPage(url);
    mode = html ? "live" : "none";
  }
  const [blocks, ctas] = html ? parseBlocks(html) : [[], []];
  if (adText && blocks.length) {
    const claims = adClaims(adText);
    const raw = await llmMatch(claims, blocks, adText);
    const usedLlm = raw != null;
    const findings = usedLlm ? raw : keywordMatch(claims, blocks);
    for (const f of findings) {
      let claim = String(f.claim || "").slice(0, 120);
      let status = f.status || "unsupported";
      let quote = String(f.quote || "");
      if (status === "supported" || status === "partial") {
        const blk = verifyQuote(quote, blocks);
        if (!blk) {
          status = "unsupported";
          quote = "";
        } else {
          const w = { hero: 6, body: 3, footer: 1 }[blk.pos];
          const where = {
            hero: "near the top of the page",
            body: "in the page body",
            footer: "only in the footer",
          }[blk.pos];
          add(
            "good",
            `Ad promises "${claim}". The page backs it up ${where}.`,
            status === "supported" ? w : Math.floor(w / 2),
            blk.text.slice(0, 200),
            blk.pos,
          );
          continue;
        }
      }
      add(
        "bad",
        `Ad promises "${claim}" but no matching text was found on the page.`,
        -12,
        "",
        "",
        f.fix || `Add a visible line near the top of the page covering: "${claim}", or remove it from the ad.`,
      );
    }
    mode += usedLlm ? "+llm" : "+rules";
    const adCta = CTA_WORDS.find((c) => adText.toLowerCase().includes(c));
    if (adCta && ctas.length) {
      if (ctas.some((c) => c.includes(adCta))) add("good", `Call-to-action "${adCta}" appears on the page as well.`, 2);
      else {
        add(
          "bad",
          `Ad says "${adCta}" but no button or link on the page uses that wording.`,
          -4,
          "",
          "",
          `Use the same call-to-action text ("${adCta}") on the page button.`,
        );
      }
    }
  } else if (adText && !blocks.length) {
    add("info", err || "Page content could not be read, so ad-to-page match was not checked.", 0);
  } else {
    add("info", "No ad text was given, so ad-to-page message match was not checked.", 0);
  }

  reviews = reviews || [];
  const mis = reviews.filter((r) => r === "Misleading").length;
  const gen = reviews.length - mis;
  if (mis > gen) add("bad", `${mis} user review(s) call this link misleading (vs ${gen} genuine).`, -Math.min(30, 10 * (mis - gen)));
  else if (gen > mis) add("good", `${gen} user review(s) say this link is genuine (vs ${mis} misleading).`, Math.min(12, 4 * (gen - mis)));
  if (openComplaints) add("bad", `${openComplaints} open complaint(s) filed against this link.`, -Math.min(15, 5 * openComplaints));
  if (boost) add("good", "Advertiser updated the page and resolved the reported issues (demo).", boost);

  score = Math.max(0, Math.min(100, score));
  const label = score >= 80 ? "Excellent" : score >= 60 ? "Good" : score >= 40 ? "Moderate" : "Not suggested";
  const risk = score >= 80 ? "Low" : score >= 60 ? "Medium" : score >= 40 ? "High" : "Critical";
  const tx = `${adText || ""} ${low}`.toLowerCase();
  const cat = /loan|credit|emi|insurance|bank|invest/.test(tx)
    ? "fin"
    : /\bjob|earn|work from home|hiring/.test(tx)
      ? "job"
      : /iphone|laptop|mobile|phone|\btv\b/.test(tx)
        ? "tech"
        : /sale|offer|discount|shop|deal|% off/.test(tx)
          ? "shop"
          : "gen";
  const order = { bad: 0, good: 1, info: 2 };
  ev.sort((a, b) => order[a.type] - order[b.type]);
  return {
    score,
    label,
    risk,
    host: h,
    category: cat,
    evidence: ev,
    suggestions: score < 60 ? SUGGEST[cat] : [],
    mode,
    fixes: ev.filter((e) => e.fix).map((e) => e.fix),
  };
}
