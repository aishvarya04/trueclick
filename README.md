# TrueClick - Ad Link Verifier (Flask + SQLite)

Checks whether an ad's link and landing page are genuine. Gives a score, evidence with exact page quotes, risk level, safer alternatives, watchlist alerts, a complaint portal and a community review portal.

## Run on Windows (recommended: Node.js)

Python is optional. If `python` is not installed, use Node (v22+):

```
npm install
npm start
```

Then open http://127.0.0.1:5000 in any browser. On the Check a link page, press **Load sample ad** then **Check this link**.

### Or with Python

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Works immediately in **rule-based mode**. For AI claim-matching, copy `.env.example` to `.env`, paste your `ANTHROPIC_API_KEY`, and restart.

## Demo script (hackathon)

1. Sign up as **Ad viewer**. Paste link `https://quickcash-loans.xyz/apply`.
2. Paste the text from `samples/ad_text.txt` into the ad box. Open "Offline snapshot" and upload `samples/loan_page_snapshot.html`.
3. Result: ad says "Same-day approval", page footer says "2 to 3 working days" -> flagged, with a fix. Risky claim "Guaranteed" flagged.
4. Press "Watch this link". In Watchlist press "Demo: next day, advertiser fixed page" -> alert appears.
5. File a complaint: choose the government authority and type your own issue. Log out, sign up as **Government officer** with another email, open Complaints, mark it under review or resolved with a reply. Log back in as the viewer: the alert shows the reply.
6. Post a "Misleading" review, check the link again: score drops.

## How the anti-hallucination check works

Every finding that says the page supports a claim must include an exact quote. `analyzer.verify_quote()` searches the real page text for that quote. If it is not found, the finding is dropped and reported as unsupported. This applies to both the LLM path and the rule-based path.

## Files

- `app.py` - Flask routes, login (hashed passwords), SQLite tables, 24-hour background re-check
- `analyzer.py` - safe page fetch (blocks private addresses), page parsing (hero / body / footer), link rules, claim matching, quote verification, scoring
- `templates/index.html`, `static/app.js`, `static/style.css` - frontend
- `samples/` - ad text and offline page snapshot for the demo

## Scoring

Starts at 50. Link signals, risky ad wording, ad-to-page match (hero quotes count more than footer quotes), reviews and complaints add or subtract. 80+ Excellent (Low risk), 60-79 Good (Medium), 40-59 Moderate (High), below 40 Not suggested (Critical).

## Limits to be honest about

- Rule-based scoring is a heuristic, not a guarantee. Always tell users to verify before paying.
- Live fetching fails on sites that block bots or need JavaScript. Use the snapshot upload for those.
- SQLite and the Flask dev server are fine for a demo, not for production.
