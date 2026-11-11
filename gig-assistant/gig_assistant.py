#!/usr/bin/env python3
"""Gig assistant: triage a job post you found yourself.

Paste a job post in (or pass a file). It will:
  1. flag common scam signals,
  2. score how well the job fits AI-assisted work,
  3. draft a reply for YOU to review, edit and send.

It does not browse, scrape, apply, or message anyone. Standard library only.

Usage:
    python3 gig_assistant.py post.txt
    python3 gig_assistant.py            # then paste, finish with Ctrl-D
    python3 gig_assistant.py post.txt --name "Sam" --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# (label, weight, regex) -- weight 3 = walk away, 2 = serious, 1 = be careful
SCAM_SIGNALS = [
    ("Asks you to cash/deposit a check and send money on", 3,
     r"(cash|deposit)\w*\s+(a|the|our|my)?\s*(cashier'?s?\s+)?che(ck|que)|overpay|send (back )?the (difference|remainder|balance)"),
    ("Payment processing / moving money for someone (money-mule pattern)", 3,
     r"payment processing agent|process(ing)? payments? (for|on behalf)|receive (funds|payments?) (and|then) (forward|transfer|send)|money transfer agent|use your (own |personal )?bank account"),
    ("Reshipping / package forwarding", 3,
     r"re-?ship|package (forward|handl|inspect)|receive (packages|parcels) at (your )?home|shipping coordinator from home"),
    ("Gift cards, crypto or wire as part of the job", 3,
     r"gift ?cards?|western union|moneygram|bitcoin atm|(buy|purchase|send)\w* (crypto|bitcoin|usdt)|wire (the|us|me) (money|funds)"),
    ("Asks you to pay to start (fee, kit, training, equipment)", 3,
     r"(registration|training|starter|activation|processing|background check) fee|pay (for|a) (your )?(kit|training|equipment|software)|refundable deposit|buy (your|the) (own )?equipment (from|through) (our|the) vendor"),
    ("Asks for bank login, SSN or card details up front", 3,
     r"(bank|online banking) (login|username|password|credentials)|routing (and|&) account number|social security|\bssn\b|credit card (number|details)|copy of (your )?(id|driver'?s licen[sc]e|passport)"),
    ("Car wrap / mystery shopper / personal assistant to a traveling boss", 2,
     r"car wrap|wrap your (car|vehicle)|mystery shopp|secret shopp|(i am|i'm) (currently )?(out of|traveling|abroad|overseas)|run (personal )?errands for me"),
    ("Moves you off-platform to Telegram/WhatsApp/Signal right away", 2,
     r"telegram|whats ?app|signal app|text (me|us) (at|on)|contact (the )?(hr|hiring) manager (on|via)"),
    ("Pay is unrealistic for the work described", 2,
     r"\$\s?[2-9]\d{2,}\s?(/|per|a)\s?(hr|hour|day)|\$\s?\d{1,2},?\d{3}\s?(/|per|a)\s?week|earn up to \$|make \$\d+k? (a|per) (day|week) (from home)?|no experience (needed|required|necessary)"),
    ("Hired without an interview / instant start", 2,
     r"no interview|hired (immediately|instantly|on the spot)|start (today|immediately)|immediate hire|guaranteed (income|job|pay)"),
    ("Pressure and urgency", 1,
     r"act (now|fast)|limited (spots|slots|positions)|urgent(ly)?\b|respond (asap|immediately)|only \d+ (spots|positions) left"),
    ("Free 'test' work that is really the whole job", 1,
     r"unpaid (trial|test|sample)|(complete|do) (a|the) (full|whole) (project|article|design) (as|for) (a )?(test|sample)|sample (must|should) be original and unpublished"),
    ("Vague about what the work actually is", 1,
     r"simple tasks|easy (money|work|tasks)|data entry (clerk )?(from home|remote).*\$|work from (home|anywhere).*(no skills|anyone can)"),
]

# (category, fit 0-10, regex) -- fit = how much of the job AI help can carry
FIT_CATEGORIES = [
    ("Writing / copy / blog posts", 9, r"blog|article|copywrit|content writ|newsletter|product description|ghostwrit|web copy|press release"),
    ("Editing / proofreading", 9, r"proofread|copy ?edit|\bedit(ing|or)?\b|grammar|rewrit"),
    ("Resume / cover letter", 9, r"r[ée]sum[ée]|cover letter|\bcv\b|linkedin profile"),
    ("Spreadsheets / data cleanup", 9, r"spreadsheet|\bexcel\b|google sheets|\bcsv\b|data (clean|entry|cleanup)|pivot table|vlookup|formulas?"),
    ("Small coding / scripts / website fixes", 8, r"python|javascript|\bhtml\b|\bcss\b|wordpress|\bscripts?\b|web ?site (fix|update|bug)|bug ?fix|automation|\bapi\b|\bsql\b|shopify"),
    ("Research / summaries", 8, r"research|summar(y|ize|ise)|literature review|market analysis|competitor|fact.?check"),
    ("Translation / localization", 7, r"translat|locali[sz]"),
    ("Transcription (from text or clean audio)", 6, r"transcri"),
    ("Tutoring / lesson material", 6, r"tutor|lesson plan|study guide|curriculum|worksheet"),
    ("Social media / marketing copy", 7, r"social media|instagram captions?|ad copy|seo|email campaign|marketing"),
    ("Admin / virtual assistant", 4, r"virtual assistant|\bva\b|inbox|scheduling|calendar|customer (service|support)"),
    ("Design / video / audio production", 3, r"logo|graphic design|photoshop|illustrat|video edit|voice ?over|animation|photograph"),
    ("Phone / in-person / physical work", 1, r"phone calls?|cold call|\bon.?site\b|in person|delivery driver|\bdriv(er|ing)\b|warehouse|must be local|lifting"),
]

# Things that make a legit job a bad fit, or that you must not do.
CAUTIONS = [
    ("Looks like someone else's graded schoolwork or exam -- don't take it (academic cheating)",
     r"(write|do|complete|take) my (essay|homework|assignment|exam|quiz|class|course|dissertation|thesis)|online (class|course|exam) (for me|taker)"),
    ("Fake reviews / fake accounts / astroturfing -- don't take it",
     r"(write|post|leave) (positive |5.star |fake )?reviews|fake (reviews|accounts|followers)|upvotes?|create (multiple )?accounts"),
    ("Says no AI allowed -- respect that, or ask first",
     r"no (ai|chatgpt|gpt)|ai.?(free|generated content (is )?not)|human.?written only|will (be )?check(ed)? (for|with) ai"),
    ("Needs a licence or credential (legal, medical, tax, accounting)",
     r"attorney|lawyer|\bcpa\b|licensed|certified (public|translator)|medical (advice|coding)|notar"),
    ("Needs live calls or meetings you'd have to do yourself",
     r"zoom|video call|daily stand.?up|phone interview|available (during|between) .*(am|pm)"),
]


def find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    return m.group(0).strip()[:80] if m else None


def analyze(post: str) -> dict:
    scams = [{"signal": label, "weight": w, "matched": hit}
             for label, w, pat in SCAM_SIGNALS if (hit := find(pat, post))]
    scam_score = sum(s["weight"] for s in scams)
    worst = max((s["weight"] for s in scams), default=0)
    if worst == 3 or scam_score >= 5:
        risk = "HIGH"
    elif scam_score >= 2:
        risk = "MEDIUM"
    elif scam_score == 1:
        risk = "LOW-MEDIUM"
    else:
        risk = "LOW"

    cats = [{"category": c, "fit": f, "matched": hit}
            for c, f, pat in FIT_CATEGORIES if (hit := find(pat, post))]
    cats.sort(key=lambda c: -c["fit"])
    cautions = [{"caution": label, "matched": hit}
                for label, pat in CAUTIONS if (hit := find(pat, post))]

    if not cats:
        fit = None
    else:
        # Mostly the best match, pulled down by any poor-fit requirement.
        fit = round(0.7 * cats[0]["fit"] + 0.3 * min(c["fit"] for c in cats))
    blocked = any("don't take it" in c["caution"] for c in cautions)

    if risk == "HIGH":
        verdict = "SKIP -- strong scam signals. Do not reply or share any details."
    elif blocked:
        verdict = "SKIP -- this is work you shouldn't take (see cautions)."
    elif fit is None:
        verdict = "UNCLEAR -- can't tell what the work is. Ask for a concrete scope before anything else."
    elif fit >= 7 and risk == "LOW":
        verdict = "GOOD CANDIDATE -- review the draft reply, edit it, and send it yourself."
    elif fit >= 7:
        verdict = "MAYBE -- good fit, but check the flagged signals before replying."
    elif fit >= 4:
        verdict = "PARTIAL FIT -- AI can help with parts; you'd carry the rest."
    else:
        verdict = "POOR FIT -- mostly work that needs you in person or on calls."

    return {"risk": risk, "scam_score": scam_score, "scam_signals": scams,
            "fit": fit, "categories": cats, "cautions": cautions, "verdict": verdict}


def draft_reply(post: str, result: dict, name: str) -> str | None:
    if result["verdict"].startswith(("SKIP", "POOR")):
        return None
    cats = result["categories"]
    skill = cats[0]["category"].lower() if cats else "this kind of work"
    title = next((ln.strip() for ln in post.splitlines() if ln.strip()), "your post")[:70]
    lines = [
        f"Hi,",
        "",
        f"I saw your post (\"{title}\") and I'd like to help. I do {skill} "
        "and can turn this around quickly.",
        "",
        "A few questions so I can give you an accurate quote:",
        "  - What exactly is the deliverable, and in what format?",
        "  - What's the deadline?",
        "  - Do you have an example of what 'good' looks like?",
        "",
        "[ADD: one or two sentences about relevant work you've done, with a link or sample.]",
        "[ADD: your rate or a fixed price, and how you'd like to be paid -- "
        "PayPal/Venmo/Zelle invoice or a freelance platform. Never share bank logins.]",
        "",
        "I use AI tools as part of my workflow and review everything myself before delivering.",
        "",
        "Thanks,",
        name,
    ]
    if result["risk"] != "LOW":
        lines.insert(8, "  - Can you confirm the company name and who I'd be working with?")
    return "\n".join(lines)


def render(result: dict, reply: str | None) -> str:
    out = ["=" * 60, f"VERDICT: {result['verdict']}", "=" * 60, "",
           f"Scam risk: {result['risk']}  (score {result['scam_score']})"]
    for s in result["scam_signals"]:
        out.append(f"  [{'!' * s['weight']:<3}] {s['signal']}\n         matched: \"{s['matched']}\"")
    if not result["scam_signals"]:
        out.append("  No known scam patterns matched. That is not proof it's safe -- see CHECKLIST.md.")
    fit = "?" if result["fit"] is None else result["fit"]
    out += ["", f"AI-fit score: {fit}/10"]
    for c in result["categories"]:
        out.append(f"  {c['fit']:>2}/10  {c['category']}  (\"{c['matched']}\")")
    if result["cautions"]:
        out += ["", "Cautions:"]
        out += [f"  - {c['caution']}  (\"{c['matched']}\")" for c in result["cautions"]]
    if reply:
        out += ["", "-" * 60, "DRAFT REPLY -- edit the [ADD: ...] lines, then send it yourself:",
                "-" * 60, reply]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage a job post: scam flags, AI-fit score, draft reply.")
    ap.add_argument("file", nargs="?", help="text file with the job post (default: read stdin)")
    ap.add_argument("--name", default="[Your name]", help="name to sign the draft reply with")
    ap.add_argument("--json", action="store_true", help="output JSON instead of text")
    args = ap.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            post = f.read()
    else:
        if sys.stdin.isatty():
            print("Paste the job post, then press Ctrl-D (Ctrl-Z then Enter on Windows):\n", file=sys.stderr)
        post = sys.stdin.read()
    if not post.strip():
        print("No job post given.", file=sys.stderr)
        return 1

    result = analyze(post)
    reply = draft_reply(post, result, args.name)
    if args.json:
        print(json.dumps({**result, "draft_reply": reply}, indent=2))
    else:
        print(render(result, reply))
    return 0


if __name__ == "__main__":
    sys.exit(main())
