"""
Vouch Slack Bot
================
Brings Vouch's verify endpoints into Slack so anyone can paste a
suspicious email/recruiter/offer straight into a channel or DM and get
a verdict without leaving Slack.

Three ways to use it once installed:

1. Slash command:      /vouch <paste text, email address, or raw email source>
2. Message shortcut:   right-click / "More actions" -> "Verify with Vouch"
                        on any message (checks its text, and any PDF
                        attached to it, against Vouch).
3. Mention:            @Vouch <text> in any channel it's been added to.

Run with (Socket Mode, no public URL / ngrok needed for the demo):

    pip install -r ../requirements.txt -r requirements.txt
    export SLACK_BOT_TOKEN=xoxb-...
    export SLACK_APP_TOKEN=xapp-...
    export VOUCH_API_BASE=http://localhost:8000   # your uvicorn backend
    python app.py
"""
import os
import re
import requests

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

VOUCH_API_BASE = os.environ.get("VOUCH_API_BASE", "http://localhost:8000")
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_APP_TOKEN = os.environ["SLACK_APP_TOKEN"]

app = App(token=SLACK_BOT_TOKEN)

VERDICT_STYLE = {
    "verified": ("✅", "Verified", "#2eb67d"),
    "scam": ("🚫", "Scam", "#e01e5a"),
    "unverifiable": ("❓", "Can't Verify", "#ecb22e"),
}

EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
RAW_EMAIL_HINT_RE = re.compile(r"^(From:|Received:|Return-Path:)", re.IGNORECASE | re.MULTILINE)


def call_vouch_verify(raw_text: str) -> dict:
    """Route free-form Slack input to the right Vouch endpoint."""
    text = raw_text.strip()
    if not text:
        return {"verdict": "unverifiable", "reasons": ["Nothing to check."]}

    if RAW_EMAIL_HINT_RE.search(text):
        # Looks like a full pasted email source (headers included).
        resp = requests.post(f"{VOUCH_API_BASE}/api/verify/email", json={"raw_email": text}, timeout=15)
    elif EMAIL_RE.match(text):
        # Just a bare address, e.g. someone checking a recruiter's email.
        resp = requests.post(f"{VOUCH_API_BASE}/api/verify/email", json={"sender_address": text}, timeout=15)
    else:
        # Plain message text (an offer message, a DM, a text pasted in).
        resp = requests.post(f"{VOUCH_API_BASE}/api/verify/text", json={"text": text}, timeout=15)

    resp.raise_for_status()
    return resp.json()


def call_vouch_verify_pdf(file_bytes: bytes, filename: str) -> dict:
    files = {"file": (filename, file_bytes, "application/pdf")}
    resp = requests.post(f"{VOUCH_API_BASE}/api/verify/pdf", files=files, timeout=30)
    resp.raise_for_status()
    return resp.json()


def build_verdict_blocks(result: dict, source_label: str) -> list:
    verdict = result.get("verdict", "unverifiable")
    emoji, label, _color = VERDICT_STYLE.get(verdict, VERDICT_STYLE["unverifiable"])
    reasons = result.get("reasons") or result.get("flags") or ["No details returned."]

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *{label}* — checked {source_label} with Vouch",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(f"• {r}" for r in reasons[:8]),
            },
        },
    ]
    extra = []
    if result.get("company"):
        extra.append(f"Company: *{result['company']}*")
    if result.get("from_domain"):
        extra.append(f"Sender domain: `{result['from_domain']}`")
    if extra:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(extra)}]})
    return blocks


@app.command("/vouch")
def handle_vouch_command(ack, respond, command):
    ack()
    text = command.get("text", "")
    try:
        result = call_vouch_verify(text)
        respond(blocks=build_verdict_blocks(result, "this"), response_type="ephemeral")
    except requests.RequestException as e:
        respond(f"⚠️ Couldn't reach Vouch backend at {VOUCH_API_BASE}: {e}")


@app.event("app_mention")
def handle_mention(event, say, client):
    text = re.sub(r"<@[^>]+>", "", event.get("text", "")).strip()
    try:
        result = call_vouch_verify(text) if text else {"verdict": "unverifiable", "reasons": ["Mention me with the text/email you want checked."]}
        say(blocks=build_verdict_blocks(result, "this message"), thread_ts=event.get("ts"))
    except requests.RequestException as e:
        say(f"⚠️ Couldn't reach Vouch backend at {VOUCH_API_BASE}: {e}", thread_ts=event.get("ts"))


@app.shortcut("verify_with_vouch")
def handle_message_shortcut(ack, shortcut, client, respond):
    ack()
    message = shortcut["message"]
    channel_id = shortcut["channel"]["id"]
    user_id = shortcut["user"]["id"]

    files = message.get("files") or []
    pdf_files = [f for f in files if f.get("filetype") == "pdf"]

    try:
        if pdf_files:
            f = pdf_files[0]
            file_bytes = requests.get(
                f["url_private"],
                headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
                timeout=30,
            ).content
            result = call_vouch_verify_pdf(file_bytes, f.get("name", "offer.pdf"))
            source_label = f"the attached PDF ({f.get('name')})"
        else:
            text = message.get("text", "")
            result = call_vouch_verify(text)
            source_label = "this message"

        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            blocks=build_verdict_blocks(result, source_label),
        )
    except requests.RequestException as e:
        client.chat_postEphemeral(channel=channel_id, user=user_id, text=f"⚠️ Couldn't reach Vouch backend: {e}")


if __name__ == "__main__":
    print(f"Vouch Slack bot starting -- talking to backend at {VOUCH_API_BASE}")
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
