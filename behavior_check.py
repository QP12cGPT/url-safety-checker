# filename: behavior_check.py
import asyncio, json, re, sys, os, datetime
from urllib.parse import urlparse, parse_qsl
from pathlib import Path

import tldextract
from playwright.async_api import async_playwright

# ====== 設定 ======
TIMEOUT_MS = 35_000
DWELL_MS   = 12_000
AUTO_SCROLL = True
SCROLL_STEPS = 10

PSP_ALLOW = {
    "stripe.com", "adyen.com", "paypal.com", "braintreepayments.com",
    "amazonpay.com", "checkout.com", "squareup.com", "apple.com", "google.com",
    "pay.jp", "sbpayment.jp", "veritrans.co.jp", "gmo-pg.com", "zeus.co.jp",
}

THIRD_PARTY_SOFT_ALLOW = {
    "akamaihd.net", "akamai.net", "cloudflare.com", "cloudfront.net",
    "fastly.net", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "mixpanel.com", "branch.io", "adjust.com",
    "appsflyer.com", "sentry.io"
}

PII_KEYS = [
    "email", "e-mail", "mail",
    "phone", "tel",
    "name", "first_name", "last_name", "fullname",
    "address", "addr", "postcode", "zip", "city", "state", "prefecture",
    "country",
    "card", "cc", "pan", "cvv", "cvc", "expiry", "exp_month", "exp_year"
]

CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

def reg_domain(host: str) -> str:
    ext = tldextract.extract(host or "")
    return ".".join([p for p in [ext.domain, ext.suffix] if p]).lower()

def mask_pan(s: str) -> str:
    def repl(m):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) < 13:
            return m.group(0)
        return digits[:6] + "*" * (len(digits)-10) + digits[-4:]
    return CARD_PATTERN.sub(repl, s)

def kv_extract_from_body(body: bytes, content_type: str):
    preview = body[:4096].decode("utf-8", errors="replace")
    out = {"raw_preview": mask_pan(preview), "pairs": []}
    try:
        if "application/json" in content_type:
            data = json.loads(preview)
            if isinstance(data, dict):
                for k, v in list(data.items())[:40]:
                    out["pairs"].append([k, mask_pan(str(v))[:200]])
        elif "application/x-www-form-urlencoded" in content_type:
            pairs = parse_qsl(preview, keep_blank_values=True)
            for k, v in pairs[:40]:
                out["pairs"].append([k, mask_pan(v)[:200]])
    except Exception:
        pass
    return out

async def analyze(url: str):
    norm = url.split("#")[0]
    rep = {
        "input_url": url,
        "normalized": norm,
        "when": datetime.datetime.utcnow().isoformat() + "Z",
        "target_domain": "",
        "target_reg_domain": "",
        "security_headers": {},
        "forms": {"has_card_like_field": False, "card_fields": [], "psp_iframes": [], "first_party_card_field": False},
        "network": {"requests": [], "summary": {"post_total":0,"post_to_psp":0,"post_to_3p":0,"post_with_pii":0}},
        "score": 0,
        "verdict": "PASS",
        "reasons": []
    }

    pr = urlparse(norm)
    rep["target_domain"] = pr.hostname or ""
    rep["target_reg_domain"] = reg_domain(rep["target_domain"])

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(ignore_https_errors=False)
        page = await ctx.new_page()

        async def on_request(req):
            method = req.method.upper()
            url = req.url
            rd = reg_domain(urlparse(url).hostname or "")
            ct = req.headers.get("content-type","")
            entry = {
                "method": method,
                "url": url,
                "reg_domain": rd,
                "content_type": ct,
                "kind": "first_party" if rd==rep["target_reg_domain"] else ("psp" if rd in PSP_ALLOW else ("soft_allow" if rd in THIRD_PARTY_SOFT_ALLOW else "third_party")),
                "pii_keys_detected": [],
                "body_preview": None
            }
            if method in ("POST","PUT","PATCH"):
                try:
                    body = await req.post_data_buffer()
                except Exception:
                    body = b""
                bp = kv_extract_from_body(body, ct)
                entry["body_preview"] = bp
                pii_keys = set()
                for k, v in bp.get("pairs", []):
                    lk = (k or "").lower()
                    if any(h in lk for h in PII_KEYS):
                        pii_keys.add(lk)
                if CARD_PATTERN.search(bp.get("raw_preview","")):
                    pii_keys.add("card_number_like")
                entry["pii_keys_detected"] = sorted(pii_keys)

                rep["network"]["summary"]["post_total"] += 1
                if entry["kind"] == "psp":
                    rep["network"]["summary"]["post_to_psp"] += 1
                elif entry["kind"] != "first_party":
                    rep["network"]["summary"]["post_to_3p"] += 1
                if entry["pii_keys_detected"]:
                    rep["network"]["summary"]["post_with_pii"] += 1

            rep["network"]["requests"].append(entry)

        page.on("request", on_request)

        resp = await page.goto(norm, timeout=TIMEOUT_MS, wait_until="domcontentloaded")
        if resp:
            headers = {k.lower(): v for k,v in (resp.headers or {}).items()}
            for k in ["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy","permissions-policy","cross-origin-opener-policy","cross-origin-resource-policy"]:
                if k in headers:
                    rep["security_headers"][k] = headers[k]

        if AUTO_SCROLL:
            for _ in range(SCROLL_STEPS):
                await page.mouse.wheel(0, 2000)
                await page.wait_for_timeout(500)
        await page.wait_for_timeout(DWELL_MS)

        card_like_selectors = [
            'input[autocomplete="cc-number"]',
            'input[name*="card"]',
            'input[id*="card"]',
            'input[name*="cc"]'
        ]
        card_fields = []
        for sel in card_like_selectors:
            els = await page.query_selector_all(sel)
            for el in els:
                try:
                    box = await el.bounding_box()
                    if box:
                        card_fields.append({"selector": sel, "pos": box})
                except Exception:
                    pass
        rep["forms"]["card_fields"] = card_fields
        rep["forms"]["has_card_like_field"] = bool(card_fields)

        iframes = page.frames
        psp_ifr = []
        for fr in iframes:
            try:
                urlf = fr.url
                if not urlf:
                    continue
                rd = reg_domain(urlparse(urlf).hostname or "")
                if rd in PSP_ALLOW:
                    psp_ifr.append({"url": urlf, "reg_domain": rd})
            except Exception:
                pass
        rep["forms"]["psp_iframes"] = psp_ifr
        rep["forms"]["first_party_card_field"] = rep["forms"]["has_card_like_field"] and len(psp_ifr)==0

        await ctx.close()
        await browser.close()

    if rep["forms"]["first_party_card_field"]:
        rep["score"] += 5
        rep["reasons"].append("カード番号らしき入力欄が同一生成元（PSP iFrameが見当たらない）")

    for rq in rep["network"]["requests"]:
        if rq["method"] in ("POST","PUT","PATCH") and rq["kind"] == "third_party" and rq["pii_keys_detected"]:
            rep["score"] += 5
            rep["reasons"].append(f"第三者({rq['reg_domain']})へPII含む送信: {','.join(rq['pii_keys_detected'])}")
            break

    must_headers = ["content-security-policy","strict-transport-security","x-frame-options"]
    missing = [h for h in must_headers if h not in rep["security_headers"]]
    if missing:
        rep["score"] += 1
        rep["reasons"].append(f"重要セキュリティヘッダー不足: {', '.join(missing)}")

    if rep["score"] >= 5:
        rep["verdict"] = "BLOCK"
    elif rep["score"] >= 2:
        rep["verdict"] = "WARN"
    else:
        rep["verdict"] = "PASS"

    return rep

def save_report(rep: dict, outdir="reports"):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rd = rep.get("target_reg_domain","site")
    base = Path(outdir) / f"{ts}_{rd}"
    json_path = str(base.with_suffix(".json"))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    md_path = str(base.with_suffix(".md"))
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Behavior Report: {rep['normalized']}\n\n")
        f.write(f"- Verdict: **{rep['verdict']}** (score={rep['score']})\n")
        if rep["reasons"]:
            f.write(f"- Reasons: {', '.join(rep['reasons'])}\n")
        f.write("\n## Security Headers\n")
        for k,v in rep["security_headers"].items():
            f.write(f"- {k}: `{v}`\n")
        f.write("\n## PSP iframes\n")
        for it in rep["forms"]["psp_iframes"]:
            f.write(f"- {it['reg_domain']} → {it['url']}\n")
        f.write("\n## POST Requests (Top 20)\n")
        cnt = 0
        for rq in rep["network"]["requests"]:
            if rq["method"] in ("POST","PUT","PATCH"):
                cnt += 1
                f.write(f"- **{rq['method']}** to `{rq['reg_domain']}` ({rq['kind']})\n")
                if rq["pii_keys_detected"]:
                    f.write(f"  - PII keys: {', '.join(rq['pii_keys_detected'])}\n")
                if rq["body_preview"]:
                    f.write(f"  - body preview: `{rq['body_preview'].get('raw_preview','')[:300]}`\n")
                if cnt >= 20:
                    break
    return json_path, md_path

async def main():
    if len(sys.argv) < 2:
        print("Usage: python behavior_check.py <url>")
        sys.exit(2)
    url = sys.argv[1]
    rep = await analyze(url)
    jp, mp = save_report(rep)
    print(json.dumps({"verdict": rep["verdict"], "score": rep["score"], "reasons": rep["reasons"], "json": jp, "md": mp}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
