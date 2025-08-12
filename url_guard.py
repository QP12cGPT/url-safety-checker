# filename: url_guard.py
import os, re, sys, json, socket, ssl, datetime, ipaddress
from urllib.parse import urlparse

# --- .env を確実に読み込む（このファイルと同じフォルダの .env を想定） ---
try:
    from dotenv import load_dotenv
    from pathlib import Path
    load_dotenv(dotenv_path=Path(__file__).with_name(".env"))
except Exception:
    pass

import httpx
import tldextract
import dns.resolver

# ===== 設定 =====
TIMEOUT = 8.0
MAX_REDIRECTS = 5
STRICT_HTTPS_ONLY = True
ALWAYS_RUN_GSB = True              # ← ホワイトリストでも/HTTPでも必ずGSBを走らせる
STRIP_QUERY = True                 # ← Trueで広告・追跡クエリを削除して検査（再現性＆軽量化）
MAX_BYTES = 200_000                # ← 取得本文の最大読み込みバイト数（ストリーミング）
DEBUG_PRINT = False

GSB_API_KEY = os.getenv("GSB_API_KEY")

WHITELIST = {
    "apple.com","icloud.com","mzstatic.com",
    "google.com","youtube.com","android.com",
    "openai.com",
    "microsoft.com","github.com",
    "amazon.co.jp","amazon.com"
}

SUSPICIOUS_TLDS = {"zip","mov","tk","top","xyz","gq","work","rest","country","mom"}
BINARY_EXT = (".exe",".scr",".bat",".msi",".apk",".dmg",".pkg",".iso",".js")

def dprint(*a):
    if DEBUG_PRINT: print(*a)

def norm_url(u: str) -> str:
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    # クエリを削って再現性と負荷を低減（必要なら False に）
    if STRIP_QUERY:
        pr = urlparse(u)
        u = f"{pr.scheme}://{pr.netloc}{pr.path}"
    return u

def parse_domain(host: str):
    ext = tldextract.extract(host or "")
    reg = ".".join([p for p in [ext.domain, ext.suffix] if p])
    return ext, reg.lower()

def is_puny_or_nonascii(host: str) -> bool:
    try:
        (host or "").encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def looks_homoglyphy(host: str) -> bool:
    # 誤検知を抑えた簡易版
    host = (host or "").lower()
    suspicious_pairs = [("0","o"), ("1","l"), ("3","e"), ("5","s")]
    return any(a in host and b in host for (a,b) in suspicious_pairs)

def dns_resolves(host: str) -> bool:
    try:
        dns.resolver.resolve(host, "A", lifetime=TIMEOUT)
        return True
    except Exception:
        return False

def is_private_ip(netloc: str) -> bool:
    try:
        host = (netloc or "").split(":")[0]
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def get_tls_info(host: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                nb = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                na = datetime.datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
                return {
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject_cn": subject.get("commonName"),
                    "not_before": nb.isoformat(),
                    "not_after":  na.isoformat()
                }
    except Exception:
        return None

def suspicious_content_heuristics(text: str, headers: dict) -> int:
    score = 0
    if len(text) > 0 and text.count("<script") > 50:
        score += 2
    if "application/octet-stream" in headers.get("content-type",""):
        score += 2
    return score

# ---- Google Safe Browsing ----
def check_gsb(url: str, api_key: str):
    """危険なら True（ヒットあり）。ヒットなしは False。未実行は None。"""
    if not api_key:
        return None
    try:
        payload = {
          "client": {"clientId": "url_guard", "clientVersion": "1.0"},
          "threatInfo": {
            "threatTypes": [
              "MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
          }
        }
        r = httpx.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload, timeout=TIMEOUT
        )
        dprint("GSB status:", r.status_code, "resp:", r.text[:200])
        if r.status_code != 200:
            return None
        data = r.json()
        return bool(data.get("matches"))
    except Exception as e:
        dprint("GSB error:", e)
        return None

def check_url(u: str):
    report = {
        "input": u,
        "normalized": None,
        "status": "PASS",
        "score": 0,
        "reasons": [],
        "final_url": None,
        "redirects": [],
        "domain": None,
        "registered_domain": None,
        "tls": None,
        "gsb": None
    }

    # 正規化（HTTPS付与・クエリ除去）
    norm = norm_url(u)
    report["normalized"] = norm
    pr = urlparse(norm)
    ext, reg = parse_domain(pr.hostname)
    report["domain"] = pr.hostname
    report["registered_domain"] = reg

    # 先にGSB（常に実行）
    gsb_res = check_gsb(norm, GSB_API_KEY)
    report["gsb"] = gsb_res
    if gsb_res is True:
        report["score"] += 5
        report["reasons"].append("Google Safe Browsing: 危険ヒット")

    # HTTPS必須（ただしGSBは上で既に実行済み）
    if STRICT_HTTPS_ONLY and pr.scheme != "https":
        report["status"] = "BLOCK"; report["score"] = max(report["score"], 5)
        report["reasons"].append("HTTPのみは不可（HTTPS必須）")
        return report

    # ホワイトリスト
    if reg in WHITELIST:
        report["reasons"].append("公式ホワイトリスト一致")

    # TLD/文字列チェック
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    if tld in SUSPICIOUS_TLDS and reg not in WHITELIST:
        report["score"] += 1
        report["reasons"].append(f"懸念TLD: .{tld}")
    if is_puny_or_nonascii(pr.hostname or ""):
        report["score"] += 1
        report["reasons"].append("IDN/非ASCIIドメイン")
    if looks_homoglyphy(pr.hostname or ""):
        report["score"] += 1
        report["reasons"].append("紛らわしい文字の組合せ疑い")

    # DNS
    if not dns_resolves(pr.hostname or ""):
        report["status"] = "BLOCK"; report["score"] = max(report["score"], 5)
        report["reasons"].append("DNS解決不可")
        return report

    # プライベートIP
    if is_private_ip(pr.netloc):
        report["score"] += 2
        report["reasons"].append("プライベートIPに解決（社内向け/フィッシング疑い）")

    # TLS
    tls = get_tls_info(pr.hostname or "")
    if not tls:
        report["score"] += 2
        report["reasons"].append("TLS証明書情報取得不可/不正")
    else:
        report["tls"] = tls
        not_after = datetime.datetime.fromisoformat(tls["not_after"])
        if not_after < datetime.datetime.utcnow():
            report["score"] += 3
            report["reasons"].append("証明書期限切れ")

    # リダイレクト追跡 + 最終GET（ストリーミングで軽量化）
    try:
        redirects = []
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT, verify=True, http2=True) as client:
            cur = norm
            for _ in range(MAX_REDIRECTS):
                r = client.head(cur)
                if r.status_code in (301,302,303,307,308) and "location" in r.headers:
                    nxt = str(httpx.URL(cur).join(r.headers["location"]))
                    redirects.append({"from": cur, "to": nxt, "status": r.status_code})
                    cur = nxt
                else:
                    break
            report["redirects"] = redirects
            report["final_url"] = cur

            with client.stream("GET", cur) as r:
                ctype = r.headers.get("content-type","")
                if any(cur.lower().endswith(ext) for ext in BINARY_EXT) or "application/octet-stream" in ctype:
                    report["score"] += 3
                    report["reasons"].append("実行ファイル配布/バイナリ直配の疑い")

                collected = bytearray()
                for chunk in r.iter_bytes():
                    collected.extend(chunk)
                    if len(collected) >= MAX_BYTES:
                        break

                try:
                    text = collected.decode(r.encoding or "utf-8", errors="replace")
                except Exception:
                    text = collected.decode("utf-8", errors="replace")

                add = suspicious_content_heuristics(text, r.headers)
                if add:
                    report["score"] += add
                    report["reasons"].append("コンテンツ構造が不自然（ヒューリスティクス）")

    except httpx.RequestError:
        report["score"] += 2
        report["reasons"].append("HTTP到達不可/タイムアウト")

    # ステータス決定
    if report["score"] >= 5:
        report["status"] = "BLOCK"
    elif report["score"] >= 2:
        report["status"] = "WARN"
    else:
        report["status"] = "PASS"

    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python url_guard.py <url>")
        sys.exit(2)
    res = check_url(sys.argv[1])
    print(json.dumps(res, ensure_ascii=False, indent=2))
    sys.exit(1 if res["status"] in ("WARN","BLOCK") else 0)

