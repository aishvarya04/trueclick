"""TrueClick analyzer.

Pipeline:
  1. fetch_page()      -> download the landing page safely (or use pasted HTML snapshot)
  2. parse_blocks()    -> split visible text into blocks tagged hero / body / footer
  3. url_signals()     -> rule-based checks on the link itself
  4. match_claims()    -> compare ad claims with page (LLM if API key, else keyword matcher)
  5. verify_quote()    -> EVERY quote must really exist in the page text, or the finding is dropped
  6. combine into score, label, risk, evidence, fixes
"""
import ipaddress
import json
import os
import re
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (compatible; TrueClickBot/1.0)"
MAX_BYTES = 2_000_000

OFFICIAL = {
    "amazon": ["amazon.in", "amazon.com"], "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"], "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"], "google": ["google.com", "google.co.in"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"],
}
SUGGEST = {
    "shop": [("Amazon.in", "https://www.amazon.in"), ("Flipkart", "https://www.flipkart.com"), ("Myntra", "https://www.myntra.com")],
    "fin": [("SBI", "https://sbi.co.in"), ("HDFC Bank", "https://www.hdfcbank.com"), ("RBI: check a lender is registered", "https://www.rbi.org.in")],
    "job": [("National Career Service (Govt.)", "https://www.ncs.gov.in"), ("Naukri", "https://www.naukri.com"), ("LinkedIn Jobs", "https://www.linkedin.com/jobs")],
    "tech": [("Apple India", "https://www.apple.com/in"), ("Croma", "https://www.croma.com"), ("Amazon.in", "https://www.amazon.in")],
    "gen": [("Search the brand name and open the official site", "https://www.google.com")],
}
STOP = set("the and for you your our with get now from this that are can will has have not all any".split())
RISKY_CLAIMS = [
    (r"guaranteed|100% ?(safe|sure|approval)|risk[- ]?free", "guarantee"),
    (r"no (documents?|kyc|credit check|fees?)", "'no checks' promise"),
    (r"double your|earn \d+.{0,20}(day|hour)", "unrealistic earnings"),
    (r"free (iphone|gift|recharge|laptop)", "free luxury giveaway"),
    (r"limited time|only \d+ left|act now|hurry", "pressure tactic"),
    (r"9\d% off", "extreme discount"),
]
CTA_WORDS = ["apply now", "buy now", "sign up", "get started", "shop now", "learn more", "book now", "register", "download", "start free trial"]


def host_of(url):
    try:
        u = urlparse(url if re.match(r"^https?://", url, re.I) else "https://" + url)
        return (u.hostname or "").lower().removeprefix("www.")
    except Exception:
        return ""


def is_domain(h, d):
    return h == d or h.endswith("." + d)


# ---------------------------------------------------------------- fetching
def is_safe_public_url(url):
    """Block localhost / private networks so the server cannot be abused (SSRF)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    try:
        for info in socket.getaddrinfo(u.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
    except Exception:
        return False
    return True


def fetch_page(url):
    """Returns (html, error_message). Live fetch; JS-heavy pages may come back thin."""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    if not is_safe_public_url(url):
        return None, "Link could not be resolved or points to a private address."
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=10, stream=True)
        if r.status_code in (401, 403, 429):
            return None, f"Site blocked automated access (HTTP {r.status_code}). Paste the page HTML instead."
        data = r.raw.read(MAX_BYTES, decode_content=True)
        r.close()
        return data.decode(r.encoding or "utf-8", errors="replace"), None
    except Exception as e:
        return None, f"Could not fetch page: {type(e).__name__}"


# ---------------------------------------------------------------- parsing
def parse_blocks(html_or_text):
    """Return (blocks, ctas). Each block: {id, text, pos} with pos in hero/body/footer."""
    if not re.search(r"<\s*(html|body|div|p|h1|section)\b", html_or_text, re.I):
        lines = [l.strip() for l in re.split(r"(?<=[.!?])\s+|\n+", html_or_text) if l.strip()]
        raw = [(l, False) for l in lines]
        ctas = []
    else:
        soup = BeautifulSoup(html_or_text, "html.parser")
        for t in soup(["script", "style", "noscript", "svg", "template"]):
            t.decompose()
        raw, ctas = [], []
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        if title:
            raw.append((title, False))
        md = soup.find("meta", attrs={"name": "description"})
        if md and md.get("content"):
            raw.append((md["content"].strip(), False))
        for el in soup.find_all(["h1", "h2", "h3", "h4", "p", "li", "a", "button", "td", "span", "label"]):
            if el.name in ("span", "label", "td") and el.find(["p", "li", "a", "button"]):
                continue
            t = el.get_text(" ", strip=True)
            if len(t) < 3:
                continue
            in_footer = el.find_parent("footer") is not None
            raw.append((t, in_footer))
            if el.name in ("a", "button"):
                ctas.append(t.lower())
    seen, blocks = set(), []
    for t, in_footer in raw:
        t = re.sub(r"\s+", " ", t)
        if t in seen:
            continue
        seen.add(t)
        blocks.append({"text": t, "footer": in_footer})
    n = len(blocks)
    for i, b in enumerate(blocks):
        b["id"] = i
        b["pos"] = "footer" if b.pop("footer") or i >= n * 0.85 else ("hero" if i < max(3, n * 0.15) else "body")
    return blocks, ctas


def norm(s):
    return re.sub(r"\s+", " ", s.lower()).strip()


def verify_quote(quote, blocks):
    """The anti-hallucination gate. Returns the block containing the quote, or None."""
    q = norm(quote).strip(" \"'.")
    if len(q) < 4:
        return None
    for b in blocks:
        if q in norm(b["text"]):
            return b
    return None


# ---------------------------------------------------------------- claim matching
def ad_claims(ad_text):
    """Split ad text into claims. Decimals like 11.5% stay intact; bare call-to-actions are not claims."""
    parts = [p.strip(" .!?") for p in re.split(r"(?<=[.!?])\s+|\n+|\|", ad_text)]
    return [p for p in parts if len(p.split()) >= 2 and p.lower() not in CTA_WORDS][:8]


def _tokens(s):
    """Lower-case words with a crude plural strip: 'days' -> 'day'."""
    return {w[:-1] if len(w) > 3 and w.endswith("s") else w for w in re.findall(r"[a-z0-9]+(?:\.\d+)?", s.lower())}


def keyword_match(claims, blocks):
    """Fallback matcher (no API key). Strict on purpose: all numbers in the claim must appear on the page."""
    out = []
    for c in claims:
        kw = {w for w in _tokens(c) if len(w) > 2 and w not in STOP}
        nums = set(re.findall(r"\d+(?:\.\d+)?", c))
        if not kw:
            continue
        best, bb = 0.0, None
        for b in blocks:
            bt = _tokens(b["text"])
            cov = len(kw & bt) / len(kw)
            if nums and not nums <= bt:
                cov = 0
            if cov > best:
                best, bb = cov, b
        need = 0.75 if len(kw) >= 3 else 1.0
        if bb and best >= need:
            out.append({"claim": c, "status": "supported", "quote": bb["text"][:160], "fix": ""})
        else:
            out.append({"claim": c, "status": "unsupported", "quote": "",
                        "fix": f'Add a clear line near the top of the page that says: "{c}", or remove this promise from the ad.'})
    return out


def llm_match(claims, blocks, ad_text):
    """Ask Claude for structured JSON. Returns list or None (falls back to keyword matcher)."""
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    page = "\n".join(f"[{b['id']}] ({b['pos']}) {b['text']}" for b in blocks[:150])[:14000]
    prompt = (
        "You audit message match between an ad and its landing page.\n"
        "Use ONLY the numbered page blocks below. Never invent page content.\n"
        "For each ad claim return: claim, status (supported | partial | unsupported), "
        "quote (an EXACT copy of text from ONE page block, empty if unsupported), "
        "block_id (number or null), fix (a concrete fix, empty if supported).\n"
        'Reply with ONLY JSON: {"findings":[...]}\n\n'
        f"AD TEXT:\n{ad_text}\n\nCLAIMS:\n" + "\n".join(f"- {c}" for c in claims) + f"\n\nPAGE BLOCKS:\n{page}"
    )
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"), "max_tokens": 1500,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=40,
        )
        text = r.json()["content"][0]["text"]
        text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
        return json.loads(text)["findings"]
    except Exception:
        return None


# ---------------------------------------------------------------- scoring
def analyze(url, ad_text="", page_input=None, boost=0, reviews=None, open_complaints=0):
    """Main entry. page_input: pasted HTML/text snapshot, or None to fetch live."""
    ev = []  # evidence items
    score = 50

    def add(kind, msg, pts, quote="", pos="", fix=""):
        nonlocal score
        score += pts
        ev.append({"type": kind, "message": msg, "quote": quote, "position": pos, "fix": fix})

    full = url if re.match(r"^https?://", url, re.I) else "https://" + url
    u = urlparse(full)
    h = host_of(url)
    if not h or "." not in h:
        return {"score": 0, "label": "Not suggested", "risk": "Critical", "host": url[:80], "category": "gen",
                "evidence": [{"type": "bad", "message": "This is not a valid link, so it cannot be verified.", "quote": "", "position": "", "fix": ""}],
                "suggestions": SUGGEST["gen"], "mode": "none"}
    low = full.lower()

    # --- link signals
    if u.scheme == "https":
        add("good", "Link uses HTTPS (encrypted connection).", 8)
    else:
        add("bad", "Link uses plain HTTP, so data is not encrypted.", -15)
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h):
        add("bad", "Link points to a raw IP address instead of a brand name.", -25)
    if re.search(r"(^|\.)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy)$", h):
        add("bad", "Shortened link hides the real destination.", -15)
    if re.search(r"\.(xyz|top|click|loan|work|gq|tk|ml|cf|icu|buzz|rest)$", h):
        add("bad", "Domain ending is often used by throwaway scam sites.", -18)
    if re.search(r"\.(gov\.in|nic\.in|ac\.in|edu|gov)$", h):
        add("good", "Government or education domain.", 15)
    if h.count("-") >= 3:
        add("bad", "Domain has many hyphens, a common trick in fake sites.", -10)
    if len(h.split(".")) > 4:
        add("bad", "Domain has too many sub-domains.", -8)
    if "xn--" in h or "@" in low:
        add("bad", "Link uses look-alike characters or an '@' to disguise the destination.", -20)
    m = re.search(r"free-?gift|winner|lottery|prize|giveaway|claim|bonus|refund|kyc|verify|login-?update", low)
    if m:
        add("bad", f"Link contains the scam-style word '{m.group(0)}'.", -15)
    official = fake = None
    for brand, doms in OFFICIAL.items():
        if any(is_domain(h, d) for d in doms):
            official = brand
        elif brand in h and not fake:
            fake = brand
    if official:
        add("good", f"Official domain of {official}.", 12)
    elif fake:
        add("bad", f"Domain imitates '{fake}' but is not its official site.", -30)
    else:
        add("info", "Domain is not in our trusted list, so there is no reputation data for it.", 0)

    # --- ad wording
    pen = 0
    for pat, name in RISKY_CLAIMS:
        mm = re.search(pat, ad_text or "", re.I)
        if mm and pen > -32:
            pen -= 8
            add("bad", f"Ad uses a risky claim ({name}).", -8, quote=mm.group(0))

    # --- page content
    mode, err = "none", None
    html = page_input
    if html:
        mode = "snapshot"
    else:
        html, err = fetch_page(url)
        mode = "live" if html else "none"
    blocks, ctas = parse_blocks(html) if html else ([], [])
    if ad_text and blocks:
        claims = ad_claims(ad_text)
        raw = llm_match(claims, blocks, ad_text)
        used_llm = raw is not None
        findings = raw if used_llm else keyword_match(claims, blocks)
        for f in findings:
            claim, status = str(f.get("claim", ""))[:120], f.get("status", "unsupported")
            quote = str(f.get("quote", ""))
            if status in ("supported", "partial"):
                blk = verify_quote(quote, blocks)
                if blk is None:  # hallucinated quote -> do NOT report it as a match
                    status, quote = "unsupported", ""
                else:
                    w = {"hero": 6, "body": 3, "footer": 1}[blk["pos"]]
                    where = {"hero": "near the top of the page", "body": "in the page body", "footer": "only in the footer"}[blk["pos"]]
                    add("good", f'Ad promises "{claim}". The page backs it up {where}.', w if status == "supported" else w // 2,
                        quote=blk["text"][:200], pos=blk["pos"])
                    continue
            add("bad", f'Ad promises "{claim}" but no matching text was found on the page.', -12,
                fix=f.get("fix") or f'Add a visible line near the top of the page covering: "{claim}", or remove it from the ad.')
        mode += "+llm" if used_llm else "+rules"
        # CTA consistency
        ad_cta = next((c for c in CTA_WORDS if c in ad_text.lower()), None)
        if ad_cta and ctas:
            if any(ad_cta in c for c in ctas):
                add("good", f'Call-to-action "{ad_cta}" appears on the page as well.', 2)
            else:
                add("bad", f'Ad says "{ad_cta}" but no button or link on the page uses that wording.', -4,
                    fix=f'Use the same call-to-action text ("{ad_cta}") on the page button.')
    elif ad_text and not blocks:
        add("info", err or "Page content could not be read, so ad-to-page match was not checked.", 0)
    else:
        add("info", "No ad text was given, so ad-to-page message match was not checked.", 0)

    # --- community signals
    reviews = reviews or []
    mis = sum(1 for r in reviews if r == "Misleading")
    gen = len(reviews) - mis
    if mis > gen:
        add("bad", f"{mis} user review(s) call this link misleading (vs {gen} genuine).", -min(30, 10 * (mis - gen)))
    elif gen > mis:
        add("good", f"{gen} user review(s) say this link is genuine (vs {mis} misleading).", min(12, 4 * (gen - mis)))
    if open_complaints:
        add("bad", f"{open_complaints} open complaint(s) filed against this link.", -min(15, 5 * open_complaints))
    if boost:
        add("good", "Advertiser updated the page and resolved the reported issues (demo).", boost)

    score = max(0, min(100, score))
    label = "Excellent" if score >= 80 else "Good" if score >= 60 else "Moderate" if score >= 40 else "Not suggested"
    risk = "Low" if score >= 80 else "Medium" if score >= 60 else "High" if score >= 40 else "Critical"
    tx = ((ad_text or "") + " " + low).lower()
    cat = ("fin" if re.search(r"loan|credit|emi|insurance|bank|invest", tx) else
           "job" if re.search(r"\bjob|earn|work from home|hiring", tx) else
           "tech" if re.search(r"iphone|laptop|mobile|phone|\btv\b", tx) else
           "shop" if re.search(r"sale|offer|discount|shop|deal|% off", tx) else "gen")
    order = {"bad": 0, "good": 1, "info": 2}
    ev.sort(key=lambda e: order[e["type"]])
    return {"score": score, "label": label, "risk": risk, "host": h, "category": cat, "evidence": ev,
            "suggestions": SUGGEST[cat] if score < 60 else [], "mode": mode,
            "fixes": [e["fix"] for e in ev if e["fix"]]}
