"""
PHONE NUMBER EXPOSURE CHECKER (no API keys, no prompts)

Scans YOUR OWN Gmail (read-only, Google sign-in) to estimate how
widely your phone number is stored. It never asks for your number
and does not search other websites.

Services that hold your number AND handle money or logins (banks,
payment apps, big accounts) raise the risk most, because a leaked
or hijacked number can be used for SIM-swap and OTP fraud.

SETUP
  py -m pip install google-api-python-client google-auth-oauthlib
  Put credentials.json in the same folder as this file.
"""

import os
import sys
from collections import Counter
from email.utils import parseaddr

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
except ImportError:
    print("Run: py -m pip install google-api-python-client google-auth-oauthlib")
    sys.exit(1)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CREDS_FILE = "credentials.json"
TOKEN_FILE = "token.json"
MAX_MESSAGES = 500

PHONE_KEYWORDS = [
    "verify your phone", "confirm your phone", "mobile number",
    "verify your mobile", "sms verification", "verification code",
    "security code", "one-time password", "otp", "your code is",
]
CHANGE_KEYWORDS = [
    "phone number added", "phone number was changed",
    "phone number has been", "mobile number updated",
    "recovery phone", "number was removed",
]
SECURITY_KEYWORDS = [
    "new sign-in", "new login", "security alert", "suspicious",
    "two-factor", "2-step", "password reset",
]

# Services where a stolen number can lead to money or account loss
HIGH_RISK = {
    "google.com", "accounts.google.com", "microsoft.com", "apple.com",
    "paypal.com", "paytm.com", "phonepe.com", "razorpay.com",
    "coinbase.com", "binance.com", "wise.com", "revolut.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "amazon.in", "amazon.com", "flipkart.com",
    "facebookmail.com", "instagram.com", "whatsapp.com", "telegram.org",
    "linkedin.com", "twitter.com", "x.com",
}

MULTI_TLDS = {"co.uk", "co.in", "com.au", "com.br", "co.jp", "co.nz"}


def root_domain(host):
    parts = host.lower().strip().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def sign_in():
    creds = None
    try:
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        if not creds or not creds.valid:
            if not os.path.exists(CREDS_FILE):
                print("credentials.json not found in this folder.")
                return None, None
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
        svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
        email = svc.users().getProfile(userId="me").execute()["emailAddress"]
        return svc, email
    except Exception as e:
        print("Google sign-in failed:", e)
        return None, None


def list_ids(svc, keywords):
    query = " OR ".join('subject:"' + k + '"' for k in keywords)
    ids = []
    token = None
    while len(ids) < MAX_MESSAGES:
        resp = svc.users().messages().list(
            userId="me", q=query, maxResults=100, pageToken=token
        ).execute()
        ids += [m["id"] for m in resp.get("messages", [])]
        token = resp.get("nextPageToken")
        if not token:
            break
    return ids[:MAX_MESSAGES]


def sender_counts(svc, ids):
    counts = Counter()
    total = len(ids)
    for i, mid in enumerate(ids, 1):
        try:
            msg = svc.users().messages().get(
                userId="me", id=mid, format="metadata",
                metadataHeaders=["From"]
            ).execute()
            for h in msg.get("payload", {}).get("headers", []):
                if h["name"].lower() == "from":
                    addr = parseaddr(h["value"])[1]
                    if "@" in addr:
                        counts[root_domain(addr.split("@")[-1])] += 1
                    break
        except Exception:
            continue
        if i % 25 == 0 or i == total:
            print("  processed", i, "of", total)
    return counts


def main():
    print("=" * 56)
    print("     PHONE NUMBER EXPOSURE CHECKER (no API keys)")
    print("=" * 56)

    svc, email = sign_in()
    if not svc:
        return
    print("Signed in as:", email)

    try:
        print("\nScanning for phone verification emails...")
        phone = sender_counts(svc, list_ids(svc, PHONE_KEYWORDS))
        print("\nScanning for phone number change emails...")
        changes = sender_counts(svc, list_ids(svc, CHANGE_KEYWORDS))
        print("\nScanning for security alert emails...")
        security = sender_counts(svc, list_ids(svc, SECURITY_KEYWORDS))
    except Exception as e:
        print("Scan error:", e)
        return

    holding = set(phone) | set(changes)
    high = {d for d in holding if d in HIGH_RISK}
    normal = holding - high
    sms_2fa = {d for d in security if d in holding}

    risk = 0
    risk += len(high) * 9        # money or login services hold your number
    risk += len(normal) * 4      # other services hold your number
    risk += len(changes) * 3     # number was added or changed somewhere
    risk += len(sms_2fa) * 2     # also sends security alerts: likely SMS 2FA
    risk = min(risk, 100)

    if risk <= 15:
        level = "LOW"
    elif risk <= 40:
        level = "MODERATE"
    elif risk <= 70:
        level = "HIGH"
    else:
        level = "VERY HIGH"

    print("\n" + "=" * 56)
    print("         PHONE NUMBER EXPOSURE REPORT")
    print("=" * 56)
    print("Account scanned:", email)

    print("\n[HIGH-RISK SERVICES HOLDING YOUR NUMBER] (%d)" % len(high))
    print("  (money, logins, big accounts)")
    for d in sorted(high):
        n = phone.get(d, 0) + changes.get(d, 0)
        print("  %-30s %d email(s)" % (d, n))

    print("\n[OTHER SERVICES HOLDING YOUR NUMBER] (%d)" % len(normal))
    for d in sorted(normal):
        n = phone.get(d, 0) + changes.get(d, 0)
        print("  %-30s %d email(s)" % (d, n))

    print("\n[NUMBER ADDED OR CHANGED] (%d)" % len(changes))
    for d in sorted(changes):
        print("  %-30s %d email(s)" % (d, changes[d]))

    print("\n[LIKELY USING SMS FOR SECURITY] (%d)" % len(sms_2fa))
    for d in sorted(sms_2fa):
        print("  " + d)

    print("\n" + "-" * 56)
    print("Services holding your number : %d" % len(holding))
    print("High-risk services           : %d" % len(high))
    print("PHONE NUMBER EXPOSURE RISK   : %d%%  [%s]" % (risk, level))
    print("-" * 56)

    print("\nHOW TO REDUCE EXPOSURE")
    print("1. Ask your carrier for a SIM lock or port-out PIN.")
    print("2. Use an authenticator app instead of SMS codes.")
    print("3. Remove your number from services you no longer use.")
    print("4. Never share OTP codes with anyone.")
    print("5. Use a second number for non-essential signups.")
    print("6. Hide your number on WhatsApp and Telegram.")
    print("\nNote: results come from email keywords and are approximate.")
    print("Deleted emails and services that never email you are invisible.")


if __name__ == "__main__":
    main()
