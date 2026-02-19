# Telegram Settings Bot

This bot lets each Telegram user store:

- a **username**
- a **forum URL** (supports `{username}` placeholder)
- a **line limit** (max lines exported, up to 2000)

Then `/export` downloads the URL and sends a `.txt` file containing up to the configured number of lines of visible page text.

## Setup

In PowerShell:

```powershell
cd c:\Users\depen\Downloads\.venv\telegram_bot
python -m pip install -r requirements.txt
```

Create a bot with BotFather, then set your token:

```powershell
$env:TELEGRAM_BOT_TOKEN="123456:abc..."
python .\bot.py
```

## Commands

- `/setusername <name>`
- `/seturl <url>` (example: `https://example.com/u/{username}`)
- `/setlimit <n>` (1..2000)
- `/show`
- `/export` (uses saved URL)
- `/export <url>` (export a one-off URL)

## Notes

- Only `http(s)` URLs are accepted.
- The bot blocks obvious local/loopback/private IP hostnames to reduce SSRF risk.

