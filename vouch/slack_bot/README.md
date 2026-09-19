# Vouch Slack Bot

Lets anyone verify a suspicious offer/recruiter/email right inside Slack,
without leaving the channel or DM they're already in. Calls your existing
Vouch FastAPI backend (`/api/verify/email`, `/api/verify/text`, `/api/verify/pdf`)
-- no new backend logic needed.

## Setup (5 minutes)

1. Go to https://api.slack.com/apps -> **Create New App** -> **From an app manifest**.
2. Pick your workspace, paste the contents of `manifest.yml`, create the app.
3. **Install to Workspace** (OAuth & Permissions tab) -> copy the **Bot User OAuth Token** (`xoxb-...`).
4. **Basic Information** -> **App-Level Tokens** -> **Generate Token**, add scope
   `connections:write`, copy the token (`xapp-...`).
5. Copy `.env.example` to `.env`, fill in both tokens (and `VOUCH_API_BASE` if your
   backend isn't on `localhost:8000`).
6. Make sure the Vouch backend is running (`uvicorn backend.main:app --reload --port 8000`
   from the project root).
7. Install deps and run:
   ```bash
   cd slack_bot
   pip install -r requirements.txt -r ../requirements.txt
   export $(cat .env | xargs)   # or use python-dotenv / direnv
   python app.py
   ```
8. In Slack, invite the bot to a channel and try:
   - `/vouch alex.rivera@northwind.xyz`
   - `/vouch` + paste a full raw email source (headers included) -> real DKIM/SPF/domain check
   - Right-click any message (with or without a PDF offer attached) -> **More actions** -> **Verify with Vouch**
   - `@Vouch is this offer real: <paste text>` in a channel it's in

## Demo tip

For the live pitch: paste a scam offer's raw text into a channel, then use the
message shortcut ("Verify with Vouch") right on that message -- it's a faster,
more visual beat on stage than typing a slash command, and it shows Vouch
working where recruiters/candidates actually talk (Slack, in a campus career
center, a bootcamp cohort channel, etc.) instead of only as a standalone web page.

## Notes

- Runs in Socket Mode, so no public URL / ngrok needed -- good for a hackathon demo on a laptop.
- The bot never stores anything itself; every check is a live call to your Vouch backend.
- If `VOUCH_API_BASE` points at `localhost`, only people on your machine can use it -- for
  a shared team channel over multiple days, deploy the backend somewhere reachable
  (Render/Railway/Fly all have free tiers) and point this at that URL instead.
