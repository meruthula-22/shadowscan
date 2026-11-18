"""
ShadowScan - Phone Number Exposure Checker (Streamlit web version)

Scans YOUR OWN Gmail (read-only) to estimate how widely your phone
number is stored. Never asks for your number. Nothing is saved.
"""

import os
from collections import Counter
from email.utils import parseaddr

import streamlit as st
from google.oauth2.credentials import Credentials  # noqa: F401
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

st.set_page_config(page_title="ShadowScan", page_icon="🕵️")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
MAX_MESSAGES = 200

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


def make_flow():
    cfg = {
        "web": {
            "client_id": st.secrets["client_id"],
            "client_secret": st.secrets["client_secret"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [st.secrets["redirect_uri"]],
        }
    }
    return Flow.from_client_config(
        cfg,
        scopes=SCOPES,
        redirect_uri=st.secrets["redirect_uri"],
        autogenerate_code_verifier=False,
    )


def list_ids(svc, keywords):
    query = " OR ".join('subject:"' + k + '"' for k in keywords)
    ids, token = [], None
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

    def cb(_req_id, resp, exc):
        if exc or not resp:
            return
        for h in resp.get("payload", {}).get("headers", []):
            if h["name"].lower() == "from":
                addr = parseaddr(h["value"])[1]
                if "@" in addr:
                    counts[root_domain(addr.split("@")[-1])] += 1
                break

    for i in range(0, len(ids), 50):
        batch = svc.new_batch_http_request(callback=cb)
        for mid in ids[i:i + 50]:
            batch.add(
                svc.users().messages().get(
                    userId="me", id=mid, format="metadata",
                    metadataHeaders=["From"],
                )
            )
        batch.execute()
    return counts


def run_scan(svc):
    bar = st.progress(0, text="Phone verification emails scan pannuren...")
    phone = sender_counts(svc, list_ids(svc, PHONE_KEYWORDS))
    bar.progress(35, text="Number change emails scan pannuren...")
    changes = sender_counts(svc, list_ids(svc, CHANGE_KEYWORDS))
    bar.progress(70, text="Security alert emails scan pannuren...")
    security = sender_counts(svc, list_ids(svc, SECURITY_KEYWORDS))
    bar.progress(100, text="Mudinjidichu")
    bar.empty()

    holding = set(phone) | set(changes)
    high = {d for d in holding if d in HIGH_RISK}
    normal = holding - high
    sms_2fa = {d for d in security if d in holding}

    risk = min(
        len(high) * 9 + len(normal) * 4 + len(changes) * 3 + len(sms_2fa) * 2,
        100,
    )
    if risk <= 15:
        level = "LOW"
    elif risk <= 40:
        level = "MODERATE"
    elif risk <= 70:
        level = "HIGH"
    else:
        level = "VERY HIGH"

    st.metric("Phone number exposure risk", f"{risk}%  [{level}]")
    c1, c2 = st.columns(2)
    c1.metric("Services holding your number", len(holding))
    c2.metric("High-risk services", len(high))

    def show(title, domains, counter=None):
        st.subheader(f"{title} ({len(domains)})")
        if not domains:
            st.caption("Onnum illa")
        for d in sorted(domains):
            n = (phone.get(d, 0) + changes.get(d, 0)) if counter is None else counter[d]
            st.write(f"- **{d}** : {n} email(s)")

    show("High-risk services (money, logins)", high)
    show("Other services", normal)
    show("Number added / changed", set(changes), changes)
    st.subheader(f"Likely using SMS for security ({len(sms_2fa)})")
    for d in sorted(sms_2fa):
        st.write(f"- {d}")

    st.subheader("How to reduce exposure")
    st.markdown(
        "1. Carrier-kitta SIM lock / port-out PIN kelunga\n"
        "2. SMS-ku badhula authenticator app use pannunga\n"
        "3. Use panna services-la irundhu number remove pannunga\n"
        "4. OTP yaarukum share pannaadhinga\n"
        "5. Non-essential signup-ku second number use pannunga\n"
        "6. WhatsApp / Telegram-la number hide pannunga"
    )
    st.caption(
        "Results email keywords-la irundhu varudhu, so approximate dhaan. "
        "Delete panna emails, email anuppaadha services theriyaadhu."
    )


st.title("🕵️ ShadowScan")
st.write("Un Gmail-la (read-only) un phone number evlo places-la irukkunu estimate pannum. "
         "Number-a kekkaadhu, edhuvum save pannaadhu.")

code = st.query_params.get("code")
if code and "creds" not in st.session_state:
    try:
        flow = make_flow()
        flow.fetch_token(code=code)
        st.session_state["creds"] = flow.credentials
    except Exception as e:
        st.error(f"Google sign-in fail aagiduchu: {e}")
    st.query_params.clear()

if "creds" not in st.session_state:
    flow = make_flow()
    url, _ = flow.authorization_url(prompt="consent", access_type="online")
    st.link_button("🔐 Sign in with Google", url)
    st.stop()

try:
    svc = build("gmail", "v1", credentials=st.session_state["creds"],
                cache_discovery=False)
    email = svc.users().getProfile(userId="me").execute()["emailAddress"]
except Exception as e:
    st.error(f"Gmail connect aagala: {e}")
    st.session_state.pop("creds", None)
    st.stop()

st.success(f"Signed in as {email}")
if st.button("Scan my Gmail", type="primary"):
    try:
        run_scan(svc)
    except Exception as e:
        st.error(f"Scan error: {e}")
