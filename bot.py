import asyncio
import datetime as dt
import hashlib
import ipaddress
import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

import requests
from bs4 import BeautifulSoup
from telegram import (
    ForceReply,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("telegram_bot")

# Bot credentials — env vars take priority, fallback to hardcoded values
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8191911612:AAFZ1ZiBnIECFiTff813I8FRp1YhuXU8yEw")
OWNER_ID = int(os.environ.get("OWNER_ID", "7931350533"))
BOT_DB_PATH = os.environ.get("BOT_DB_PATH", "bot_data.sqlite3").strip() or "bot_data.sqlite3"
SCRAPER_UA = os.environ.get("SCRAPER_UA", "SettingsFetchBot/1.0 (contact: you@example.com)")

# ── MySQL / Railway config ────────────────────────────────────────────────────
MYSQL_HOST     = os.environ.get("MYSQLHOST", "")
MYSQL_PORT     = int(os.environ.get("MYSQLPORT", "3306"))
MYSQL_USER     = os.environ.get("MYSQLUSER", "")
MYSQL_PASSWORD = os.environ.get("MYSQLPASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQLDATABASE", "railway")
USE_MYSQL      = bool(MYSQL_AVAILABLE and MYSQL_HOST)

if USE_MYSQL:
    log_db = logging.getLogger("db")
    log_db.info("Using MySQL database at %s:%s/%s", MYSQL_HOST, MYSQL_PORT, MYSQL_DATABASE)
else:
    log_db = logging.getLogger("db")
    log_db.info("Using local SQLite database: %s", BOT_DB_PATH)
# ─────────────────────────────────────────────────────────────────────────────

HTTP_TIMEOUT_S = 25
FETCH_COOLDOWN_S = 5


@dataclass(frozen=True)
class UserSettings:
    telegram_user_id: int
    username: Optional[str]
    url: Optional[str]
    password_hash: Optional[str]
    forum_username: Optional[str] = None
    forum_password: Optional[str] = None
    forum_domain: Optional[str] = None
    forum_login_url: Optional[str] = None
    forum_login_page: Optional[str] = None
    is_subscribed: bool = False


# ── Database helpers ───────────────────────────────────────────────────────────

CREATE_TABLE_MYSQL = """
CREATE TABLE IF NOT EXISTS user_settings (
    telegram_user_id BIGINT PRIMARY KEY,
    username VARCHAR(255),
    url TEXT,
    password_hash TEXT,
    forum_username TEXT,
    forum_password TEXT,
    forum_domain VARCHAR(255),
    forum_login_url TEXT,
    forum_login_page TEXT,
    is_subscribed TINYINT(1) NOT NULL DEFAULT 0,
    updated_at VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

CREATE_TABLE_SQLITE = """
CREATE TABLE IF NOT EXISTS user_settings (
    telegram_user_id INTEGER PRIMARY KEY,
    username TEXT,
    url TEXT,
    password_hash TEXT,
    forum_username TEXT,
    forum_password TEXT,
    forum_domain TEXT,
    forum_login_url TEXT,
    forum_login_page TEXT,
    is_subscribed INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
)
"""


def _mysql_connect():
    """Return a MySQL connection from pool (Railway)."""
    conn = mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        autocommit=True,
        connection_timeout=10,
        charset="utf8mb4",
        pool_name="bot_pool",
        pool_size=5,
        pool_reset_session=True,
    )
    return conn


def _sqlite_connect() -> sqlite3.Connection:
    """Return a new SQLite connection (local fallback)."""
    conn = sqlite3.connect(BOT_DB_PATH)
    conn.execute(CREATE_TABLE_SQLITE)
    for col, ddl in [
        ("forum_username", "TEXT"),
        ("forum_password", "TEXT"),
        ("forum_domain", "TEXT"),
        ("forum_login_url", "TEXT"),
        ("forum_login_page", "TEXT"),
        ("is_subscribed", "INTEGER NOT NULL DEFAULT 0"),
        ("password_hash", "TEXT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE user_settings ADD COLUMN {col} {ddl}")
        except sqlite3.OperationalError:
            pass
    return conn


def _init_db() -> None:
    """Create tables on startup."""
    if USE_MYSQL:
        conn = _mysql_connect()
        cur = conn.cursor()
        cur.execute(CREATE_TABLE_MYSQL)
        cur.close()
        conn.close()
    else:
        with _sqlite_connect():
            pass


_SELECT_COLS = "username, url, password_hash, forum_username, forum_password, forum_domain, forum_login_url, forum_login_page, is_subscribed"

# ── Fast in-memory settings cache (30s TTL) ─────────────────────────────────
import time as _time

_settings_cache: dict[int, tuple[float, "UserSettings"]] = {}
_CACHE_TTL = 30  # seconds


def _cache_get(uid: int):
    entry = _settings_cache.get(uid)
    if entry and (_time.time() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def _cache_set(uid: int, s):
    _settings_cache[uid] = (_time.time(), s)


def _cache_invalidate(uid: int):
    _settings_cache.pop(uid, None)


def get_settings(telegram_user_id: int) -> UserSettings:
    cached = _cache_get(telegram_user_id)
    if cached is not None:
        return cached

    if USE_MYSQL:
        conn = _mysql_connect()
        cur = conn.cursor()
        cur.execute(
            f"SELECT {_SELECT_COLS} FROM user_settings WHERE telegram_user_id = %s",
            (telegram_user_id,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
    else:
        with _sqlite_connect() as conn:
            row = conn.execute(
                f"SELECT {_SELECT_COLS} FROM user_settings WHERE telegram_user_id = ?",
                (telegram_user_id,),
            ).fetchone()

    if row is None:
        result = UserSettings(
            telegram_user_id=telegram_user_id,
            username=None,
            url=None,
            password_hash=None,
        )
        _cache_set(telegram_user_id, result)
        return result

    username, url, password_hash, f_user, f_pass, f_domain, f_l_url, f_l_page, is_sub = row
    result = UserSettings(
        telegram_user_id=telegram_user_id,
        username=username,
        url=url,
        password_hash=password_hash,
        forum_username=f_user,
        forum_password=f_pass,
        forum_domain=f_domain,
        forum_login_url=f_l_url,
        forum_login_page=f_l_page,
        is_subscribed=bool(is_sub),
    )
    _cache_set(telegram_user_id, result)
    return result


def upsert_settings(
    telegram_user_id: int,
    *,
    username: Optional[str] = None,
    url: Optional[str] = None,
    password_hash: Optional[str] = None,
    forum_username: Optional[str] = None,
    forum_password: Optional[str] = None,
    forum_domain: Optional[str] = None,
    forum_login_url: Optional[str] = None,
    forum_login_page: Optional[str] = None,
    is_subscribed: Optional[bool] = None,
) -> UserSettings:
    _cache_invalidate(telegram_user_id)
    current = get_settings(telegram_user_id)
    next_settings = UserSettings(
        telegram_user_id=telegram_user_id,
        username=username if username is not None else current.username,
        url=url if url is not None else current.url,
        password_hash=password_hash if password_hash is not None else current.password_hash,
        forum_username=forum_username if forum_username is not None else current.forum_username,
        forum_password=forum_password if forum_password is not None else current.forum_password,
        forum_domain=forum_domain if forum_domain is not None else current.forum_domain,
        forum_login_url=forum_login_url if forum_login_url is not None else current.forum_login_url,
        forum_login_page=forum_login_page if forum_login_page is not None else current.forum_login_page,
        is_subscribed=is_subscribed if is_subscribed is not None else current.is_subscribed,
    )
    now = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    if USE_MYSQL:
        conn = _mysql_connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_settings
                (telegram_user_id, username, url, password_hash,
                 forum_username, forum_password, forum_domain,
                 forum_login_url, forum_login_page, is_subscribed, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                username=VALUES(username),
                url=VALUES(url),
                password_hash=VALUES(password_hash),
                forum_username=VALUES(forum_username),
                forum_password=VALUES(forum_password),
                forum_domain=VALUES(forum_domain),
                forum_login_url=VALUES(forum_login_url),
                forum_login_page=VALUES(forum_login_page),
                is_subscribed=VALUES(is_subscribed),
                updated_at=VALUES(updated_at)
            """.strip(),
            (
                next_settings.telegram_user_id,
                next_settings.username,
                next_settings.url,
                next_settings.password_hash,
                next_settings.forum_username,
                next_settings.forum_password,
                next_settings.forum_domain,
                next_settings.forum_login_url,
                next_settings.forum_login_page,
                int(next_settings.is_subscribed),
                now,
            ),
        )
        cur.close()
        conn.close()
    else:
        with _sqlite_connect() as conn:
            conn.execute(
                """
                INSERT INTO user_settings
                    (telegram_user_id, username, url, password_hash,
                     forum_username, forum_password, forum_domain,
                     forum_login_url, forum_login_page, is_subscribed, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(telegram_user_id) DO UPDATE SET
                    username=excluded.username,
                    url=excluded.url,
                    password_hash=excluded.password_hash,
                    forum_username=excluded.forum_username,
                    forum_password=excluded.forum_password,
                    forum_domain=excluded.forum_domain,
                    forum_login_url=excluded.forum_login_url,
                    forum_login_page=excluded.forum_login_page,
                    is_subscribed=excluded.is_subscribed,
                    updated_at=excluded.updated_at
                """.strip(),
                (
                    next_settings.telegram_user_id,
                    next_settings.username,
                    next_settings.url,
                    next_settings.password_hash,
                    next_settings.forum_username,
                    next_settings.forum_password,
                    next_settings.forum_domain,
                    next_settings.forum_login_url,
                    next_settings.forum_login_page,
                    int(next_settings.is_subscribed),
                    now,
                ),
            )

    _cache_set(telegram_user_id, next_settings)
    return next_settings


def normalize_username(raw: str) -> str:
    u = raw.strip()
    if u.startswith("@"):
        u = u[1:]
    u = re.sub(r"\s+", "", u)
    if not u:
        raise ValueError("Username cannot be empty.")
    return u


def _is_disallowed_host(host: str) -> bool:
    h = host.strip().lower()
    if not h:
        return True
    if h in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def validate_http_url(url: str) -> str:
    u = url.strip()
    p = urlparse(u)
    if p.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")
    if not p.netloc:
        raise ValueError("URL must include a hostname.")
    if _is_disallowed_host(p.hostname or ""):
        raise ValueError("That hostname is not allowed.")
    return u


def build_effective_url(settings: UserSettings, override_url: Optional[str] = None) -> str:
    url_template = override_url.strip() if override_url else (settings.url or "").strip()
    if not url_template:
        raise ValueError("No forum URL set. Use /seturl first (or pass a URL to /export).")
    url_template = validate_http_url(url_template)

    username = (settings.username or "").strip()
    if "{username}" in url_template and not username:
        raise ValueError("URL requires {username}, but no username is set. Use /setusername first.")

    return url_template.replace("{username}", username)


def html_to_lines(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    raw = soup.get_text("\n", strip=True)
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for line in raw.split("\n"):
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    return lines


def fetch_lines(url: str) -> list[str]:
    r = requests.get(
        url,
        headers={"User-Agent": SCRAPER_UA},
        timeout=HTTP_TIMEOUT_S,
    )
    r.raise_for_status()
    return html_to_lines(r.text)


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with salt."""
    salt = "telegram_bot_salt_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return hash_password(password) == password_hash


def is_authenticated(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Check if user is authenticated (has password or no password required)."""
    settings = get_settings(user_id)
    if not settings.password_hash:
        return True
    return context.user_data.get("authenticated", False)


HELP_TEXT = (
    "Commands:\n"
    "/subscribe           - Request subscription ($20 for 30 days)\n"
    "/setup_creds         - Setup forum credentials (interactive)\n"
    "/start_scrape        - Verify credentials and start scraping\n"
    "/setusername <name>  - store your bot username\n"
    "/seturl <url>        - store a forum URL (supports {username} placeholder)\n"
    "/setup_creds         - Setup forum credentials (interactive)\n"
    "/start_scrape        - Verify credentials and start scraping\n"
    "/setusername <name>  - store your bot username\n"
    "/seturl <url>        - store a forum URL (supports {username} placeholder)\n"
    "/setpassword <pw>    - set a password to protect the bot\n"
    "/login <password>    - login to use password-protected features\n"
    "/logout              - logout from current session\n"
    "/show                - view your saved settings\n"
    "\n"
    "Owner Commands:\n"
    "/approve <user_id>   - Approve a subscription\n"
)


def _fmt_settings(s: UserSettings) -> str:
    username = s.username or "(not set)"
    url = s.url or "(not set)"
    password_status = "🔒 Protected" if s.password_hash else "🔓 No password"
    sub_status = "✅ Active" if s.is_subscribed else "❌ Inactive"
    return (
        "*Your settings*\n"
        "*Your settings*\n"
        f"- *username*: `{username}`\n"
        f"- *forum_url*: `{url}`\n"
        f"- *security*: {password_status}\n"
        f"- *Subscription*: {sub_status}\n"
        f"- *Forum User*: `{s.forum_username or 'Not set'}`\n"
        f"- *Forum Domain*: `{s.forum_domain or 'Not set'}`"
    )

CB_SET_FORUM_URL = "setup:set_forum_url"
CB_SET_USERNAME = "setup:set_username"
CB_SET_PASSWORD = "setup:set_password"
CB_EXPORT = "setup:export"
CB_HELP = "setup:help"

def _setup_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Set forum URL", callback_data=CB_SET_FORUM_URL),
            ],
            [InlineKeyboardButton("Set username", callback_data=CB_SET_USERNAME)],
            [InlineKeyboardButton("Set password", callback_data=CB_SET_PASSWORD)],
            [InlineKeyboardButton("Export to .txt", callback_data=CB_EXPORT)],
            [InlineKeyboardButton("Help", callback_data=CB_HELP)],
        ]
    )


async def _send_setup_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user:
        return
    s = get_settings(user.id)
    text = _fmt_settings(s) + "\n\nTap a button to edit."

    if update.callback_query:
        await update.callback_query.answer()
        if update.callback_query.message:
            await update.callback_query.message.reply_text(
                text,
                reply_markup=_setup_keyboard(),
                parse_mode=ParseMode.MARKDOWN,
            )
        return

    if update.message:
        await update.message.reply_text(
            text,
            reply_markup=_setup_keyboard(),
            parse_mode=ParseMode.MARKDOWN,
        )


async def setup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authenticated(update.effective_user.id, context):
        await update.message.reply_text("🔒 Please login with /login <password> to use this command.")
        return
    await _send_setup_menu(update, context)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    
    user_id = update.effective_user.id
    settings = get_settings(user_id)
    
    if settings.password_hash and not context.user_data.get("authenticated"):
        await update.message.reply_text(
            "🔒 This bot is password protected. Use /login <password> to access it.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if settings.is_subscribed:
        # Already subscribed — show setup/scrape button
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔑 Setup Credentials & Start Scraping", callback_data="action:setup_creds")],
            [InlineKeyboardButton("ℹ️ Help", callback_data="setup:help")],
        ])
        await update.message.reply_text(
            f"👋 Welcome back, *{update.effective_user.first_name}*!\n"
            f"✅ Your subscription is *active*.\n\n"
            f"Tap the button below to configure your credentials and begin scraping.",
            reply_markup=keyboard,
            parse_mode=ParseMode.MARKDOWN,
        )
    else:
        # Not subscribed — show subscribe button
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("💳 Subscribe ($20/month)", callback_data="action:subscribe")],
        ])
        await update.message.reply_text(
            f"👋 Hello, *{update.effective_user.first_name}*!\n\n"
            f"Welcome to the CC Scraper Bot.\n"
            f"To use this bot, you need an active subscription.\n"
            f"💰 Price: *$20 / month*\n\n"
            f"Tap the button below to request a subscription.",
            reply_markup=keyboard,
            parse_mode=ParseMode.MARKDOWN,
        )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(HELP_TEXT)


async def show(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not is_authenticated(update.effective_user.id, context):
        await update.message.reply_text("🔒 Please login with /login <password> to use this command.")
        return
    s = get_settings(update.effective_user.id)
    await update.message.reply_text(_fmt_settings(s), parse_mode=ParseMode.MARKDOWN)


async def setusername(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not is_authenticated(update.effective_user.id, context):
        await update.message.reply_text("🔒 Please login with /login <password> to use this command.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /setusername <name>")
        return
    raw = " ".join(context.args)
    try:
        username = normalize_username(raw)
        s = upsert_settings(update.effective_user.id, username=username)
        await update.message.reply_text(_fmt_settings(s), parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


async def seturl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not is_authenticated(update.effective_user.id, context):
        await update.message.reply_text("🔒 Please login with /login <password> to use this command.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /seturl <url>")
        return
    raw = " ".join(context.args)
    try:
        url = validate_http_url(raw)
        s = upsert_settings(update.effective_user.id, url=url)
        await update.message.reply_text(_fmt_settings(s), parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


async def setpassword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not context.args:
        await update.message.reply_text("Usage: /setpassword <password>")
        return
    password = " ".join(context.args)
    if len(password) < 4:
        await update.message.reply_text("Password must be at least 4 characters long.")
        return
    
    password_hash = hash_password(password)
    s = upsert_settings(update.effective_user.id, password_hash=password_hash)
    await update.message.reply_text(
        "Password set successfully! You will need to login with /login to use the bot.",
        parse_mode=ParseMode.MARKDOWN
    )


async def login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not context.args:
        await update.message.reply_text("Usage: /login <password>")
        return
    
    user_id = update.effective_user.id
    settings = get_settings(user_id)
    
    if not settings.password_hash:
        await update.message.reply_text("No password is set for this account. Use /setpassword to add one.")
        return
    
    password = " ".join(context.args)
    if verify_password(password, settings.password_hash):
        context.user_data["authenticated"] = True
        await update.message.reply_text("✅ Login successful! You can now use the bot.")
    else:
        await update.message.reply_text("❌ Incorrect password. Please try again.")


async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    
    context.user_data["authenticated"] = False
    await update.message.reply_text("Logged out successfully.")


async def export_txt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    if not is_authenticated(update.effective_user.id, context):
        await update.message.reply_text("🔒 Please login with /login <password> to use this command.")
        return

    s = get_settings(update.effective_user.id)
    override_url = " ".join(context.args).strip() if context.args else None

    now = asyncio.get_running_loop().time()
    last_t = context.user_data.get("last_fetch_ts")
    if isinstance(last_t, (int, float)) and now - last_t < FETCH_COOLDOWN_S:
        wait = int(FETCH_COOLDOWN_S - (now - last_t) + 0.999)
        await update.message.reply_text(f"Please wait {wait}s before fetching again.")
        return

    try:
        effective_url = build_effective_url(s, override_url=override_url)
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")
        return

    context.user_data["last_fetch_ts"] = now
    await update.message.reply_text(f"Fetching: `{effective_url}`", parse_mode=ParseMode.MARKDOWN)

    try:
        lines = await asyncio.to_thread(fetch_lines, effective_url)
        if not lines:
            await update.message.reply_text("No text found on the page.")
            return

        out_name = f"export_{update.effective_user.id}.txt"
        out_path = os.path.join(os.path.dirname(__file__), out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

        await update.message.reply_document(
            document=open(out_path, "rb"),
            filename="forum_export.txt",
            caption=f"{len(lines)} lines exported.",
        )
    except Exception as e:
        log.exception("Fetch failed")
        await update.message.reply_text(f"Export error: {type(e).__name__}: {e}")

async def setup_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not update.effective_user:
        return

    data = q.data or ""
    if data == CB_HELP:
        await q.answer()
        if q.message:
            await q.message.reply_text(HELP_TEXT)
        return

    if data == CB_EXPORT:
        await q.answer()
        if q.message:
            await q.message.reply_text("Run: /export")
        return

    if data == CB_SET_FORUM_URL:
        context.user_data["awaiting_field"] = "forum_url"
        await q.answer()
        if q.message:
            await q.message.reply_text(
                "Send the forum URL (must start with http(s)).",
                reply_markup=ForceReply(selective=True),
            )
        return

    if data == CB_SET_USERNAME:
        context.user_data["awaiting_field"] = "username"
        await q.answer()
        if q.message:
            await q.message.reply_text(
                "Send your username.",
                reply_markup=ForceReply(selective=True),
            )
        return

    if data == CB_SET_PASSWORD:
        context.user_data["awaiting_field"] = "password"
        await q.answer()
        if q.message:
            await q.message.reply_text(
                "Send your password (min 4 characters).",
                reply_markup=ForceReply(selective=True),
            )
        return

    await q.answer()


async def setup_field_reply(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message or not update.message.text:
        return

    # Handle Step-by-step credential wizard
    cred_step = context.user_data.get("cred_step")
    if cred_step:
        raw = update.message.text.strip()
        user_id = update.effective_user.id

        if cred_step == "username":
            context.user_data["cred_username"] = raw
            context.user_data["cred_step"] = "password"
            await update.message.reply_text(
                "🔒 *Step 2/5* \u2014 Enter your forum *password*:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=ForceReply(selective=True),
            )

        elif cred_step == "password":
            context.user_data["cred_password"] = raw
            context.user_data["cred_step"] = "login_url"
            await update.message.reply_text(
                "🔗 *Step 3/5* \u2014 Enter the *Login POST URL*:\n"
                "_(URL the form submits to, e.g. `https://forum.com/login/login`)_",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=ForceReply(selective=True),
            )

        elif cred_step == "login_url":
            context.user_data["cred_login_url"] = raw
            context.user_data["cred_step"] = "login_page"
            await update.message.reply_text(
                "📄 *Step 4/5* \u2014 Enter the *Login Page URL*:\n"
                "_(The page that shows the login form, e.g. `https://forum.com/login`)_",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=ForceReply(selective=True),
            )

        elif cred_step == "login_page":
            context.user_data["cred_login_page"] = raw
            context.user_data["cred_step"] = "forum_url"
            await update.message.reply_text(
                "🌐 *Step 5/5* \u2014 Enter the *Forum Scrape URL*:\n"
                "_(The forum section to scrape, e.g. `https://forum.com/forums/cc.86/`)_",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=ForceReply(selective=True),
            )

        elif cred_step == "forum_url":
            forum_url = raw
            username   = context.user_data.pop("cred_username", "")
            password   = context.user_data.pop("cred_password", "")
            login_url  = context.user_data.pop("cred_login_url", "")
            login_page = context.user_data.pop("cred_login_page", "")
            context.user_data.pop("cred_step", None)

            # Extract domain from forum_url
            from urllib.parse import urlparse as _urlparse
            try:
                _parsed = _urlparse(forum_url)
                domain = _parsed.hostname or "unknown"
            except Exception:
                domain = "unknown"

            try:
                upsert_settings(
                    user_id,
                    forum_username=username,
                    forum_password=password,
                    forum_domain=domain,
                    forum_login_url=login_url,
                    forum_login_page=login_page,
                )
                upsert_settings(user_id, url=forum_url)

                await update.message.reply_text(
                    "✅ *Credentials saved!* Verifying login and starting scraper...",
                    parse_mode=ParseMode.MARKDOWN,
                )
                await _run_scraper_logic(update, context, user_id)
            except Exception as e:
                await update.message.reply_text(f"Error saving settings: {e}")
        return

    field = context.user_data.get("awaiting_field")
    if field not in {"forum_url", "username", "password"}:
        return

    raw = update.message.text.strip()
    try:
        if field == "forum_url":
            url = validate_http_url(raw)
            upsert_settings(update.effective_user.id, url=url)
        elif field == "username":
            name = normalize_username(raw) if raw else ""
            upsert_settings(update.effective_user.id, username=name or None)
        elif field == "password":
            if len(raw) < 4:
                await update.message.reply_text("Password must be at least 4 characters long.")
                return
            password_hash = hash_password(raw)
            upsert_settings(update.effective_user.id, password_hash=password_hash)
            await update.message.reply_text(
                "Password set! You'll need to login with /login to continue using the bot."
            )
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")
        return
    finally:
        context.user_data.pop("awaiting_field", None)

    await _send_setup_menu(update, context)


async def post_init(app: Application) -> None:
    await app.bot.set_my_commands([
        ("start", "Start the bot"),
        ("subscribe", "Request a $20 subscription"),
        ("setup_creds", "Configure forum credentials"),
        ("start_scrape", "Start scraping cards"),
        ("help", "Show help message"),
        ("setusername", "Set bot username"),
        ("login", "Login to the bot"),
        ("logout", "Logout of the bot"),
    ])


def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is required (set it in your environment).")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("setup", setup_cmd))
    app.add_handler(CallbackQueryHandler(stop_scrape_button, pattern="^stop_scraping$"))
    app.add_handler(CallbackQueryHandler(action_button_handler, pattern=r"^action:"))
    app.add_handler(CallbackQueryHandler(action_button_handler, pattern=r"^admin:"))
    app.add_handler(CallbackQueryHandler(setup_button, pattern=r"^setup:"))
    app.add_handler(MessageHandler(filters.REPLY & filters.TEXT & ~filters.COMMAND, setup_field_reply))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("show", show))
    app.add_handler(CommandHandler("setusername", setusername))
    app.add_handler(CommandHandler("seturl", seturl))
    app.add_handler(CommandHandler("setpassword", setpassword))
    app.add_handler(CommandHandler("login", login))
    app.add_handler(CommandHandler("logout", logout))
    app.add_handler(CommandHandler("export", export_txt))
    app.add_handler(CommandHandler("subscribe", subscribe))
    app.add_handler(CommandHandler("approve", approve))
    app.add_handler(CommandHandler("setup_creds", setup_creds))


    _init_db()
    app.run_polling(allowed_updates=Update.ALL_TYPES)



async def subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles both /subscribe command and the button callback."""
    # Support being called from a callback query OR a command
    if update.callback_query:
        q = update.callback_query
        await q.answer()
        user = q.from_user
        user_id = user.id
        reply = q.message.reply_text
    elif update.effective_user and update.message:
        user = update.effective_user
        user_id = user.id
        reply = update.message.reply_text
    else:
        return

    s = get_settings(user_id)
    if s.is_subscribed:
        await reply("✅ You already have an active subscription.")
        return

    await reply("⏳ Sending subscription request to owner... Please wait for approval.\nPrice: $20 / month.")
    try:
        approve_keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton(f"✅ Approve {user.full_name}", callback_data=f"admin:approve:{user_id}")],
            [InlineKeyboardButton(f"❌ Reject", callback_data=f"admin:reject:{user_id}")],
        ])
        await context.bot.send_message(
            chat_id=OWNER_ID,
            text=f"🔔 <b>New Subscription Request!</b>\nUser: {user.mention_html()} (ID: <code>{user_id}</code>)\nPrice: $20/month",
            parse_mode=ParseMode.HTML,
            reply_markup=approve_keyboard,
        )
    except Exception as e:
        log.error(f"Failed to notify owner: {e}")
        await reply("❌ Error contacting the admin.")

async def approve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.message:
        return
    
    if update.effective_user.id != OWNER_ID:
        return

    if not context.args:
        await update.message.reply_text("Usage: /approve <user_id>")
        return

    try:
        target_id = int(context.args[0])
        upsert_settings(target_id, is_subscribed=True)
        await update.message.reply_text(f"✅ User {target_id} approved.")
        try:
            # Notify user with a button to set up credentials
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔑 Setup Credentials & Start Scraping", callback_data="action:setup_creds")],
            ])
            await context.bot.send_message(
                chat_id=target_id,
                text="✅ Your subscription has been approved!\n\nTap below to configure your credentials and the scraper will start automatically.",
                reply_markup=keyboard,
            )
        except:
            pass
    except ValueError:
        await update.message.reply_text("Invalid User ID.")


async def action_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles action: and admin: callback buttons."""
    q = update.callback_query
    if not q:
        return
    data = q.data or ""

    if data == "action:subscribe":
        await subscribe(update, context)
    elif data == "action:setup_creds":
        await q.answer()
        context.user_data["cred_step"] = "username"
        await q.message.reply_text(
            "👤 *Step 1/5* \u2014 Enter your forum *username*:",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=ForceReply(selective=True),
        )
    elif data.startswith("admin:approve:"):
        # Only owner can use
        if q.from_user.id != OWNER_ID:
            await q.answer("You are not the owner.", show_alert=True)
            return
        target_id = int(data.split(":")[2])
        try:
            upsert_settings(target_id, is_subscribed=True)
        except Exception as e:
            log.error("Failed to approve user %s: %s", target_id, e)
            await q.answer(f"❌ DB error: {e}", show_alert=True)
            return
        await q.answer("✅ Approved!")
        try:
            await q.edit_message_text(
                text=q.message.text + "\n\n✅ <b>APPROVED</b>",
                parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            log.warning("Could not edit approve message: %s", e)
        try:
            creds_keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔑 Setup Credentials & Start Scraping", callback_data="action:setup_creds")],
            ])
            await context.bot.send_message(
                chat_id=target_id,
                text="✅ Your subscription has been approved!\n\nTap below to configure your credentials and the scraper will start automatically.",
                reply_markup=creds_keyboard,
            )
        except Exception as e:
            log.warning("Could not notify approved user %s: %s", target_id, e)
    elif data.startswith("admin:reject:"):
        if q.from_user.id != OWNER_ID:
            await q.answer("You are not the owner.", show_alert=True)
            return
        target_id = int(data.split(":")[2])
        await q.answer("❌ Rejected.")
        await q.edit_message_text(
            text=q.message.text + "\n\n❌ <b>REJECTED</b>",
            parse_mode=ParseMode.HTML,
        )
        try:
            await context.bot.send_message(
                chat_id=target_id,
                text="❌ Your subscription request was rejected. Please contact the admin.",
            )
        except Exception:
            pass

async def setup_creds(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Start the step-by-step credential setup wizard."""
    context.user_data["cred_step"] = "username"
    await update.message.reply_text(
        "👤 *Step 1/5* \u2014 Enter your forum *username*:",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=ForceReply(selective=True),
    )

from scraper_lib import ForumScraper

async def _run_scraper_logic(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    s = get_settings(user_id)
    
    if not s.is_subscribed:
        await context.bot.send_message(chat_id=user_id, text="❌ Active subscription required ($20/mo). Use /subscribe.")
        return
    
    if not s.forum_username or not s.forum_password:
        await context.bot.send_message(chat_id=user_id, text="❌ Credentials not set. Use /setup_creds.")
        return

    # Use reply_text if possible (update has message), else send_message
    status_msg = await context.bot.send_message(chat_id=user_id, text="🚀 Initializing scraper...")

    async def status_callback(msg):
        try:
            # Edit message for status updates or send new ones for findings
            if "💳" in msg or "✅" in msg or "❌" in msg:
                 await context.bot.send_message(chat_id=user_id, text=msg)
            else:
                 pass 
        except Exception:
            pass

    scraper = ForumScraper(
        username=s.forum_username,
        password=s.forum_password,
        domain=s.forum_domain,
        login_url=s.forum_login_url,
        login_page=s.forum_login_page,
        start_url=s.url,  # The main forum URL to scrape
        status_callback=status_callback
    )

    # callback wrapper for the sync parts
    async def run_wrapper():
        # Scraper.start() handles login and loop
        await scraper.start()

    # Store scraper instance to control it later
    context.user_data["scraper_instance"] = scraper
    context.user_data["scraper_task"] = asyncio.create_task(run_wrapper())
    
    stop_keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🛑 Stop Scraping", callback_data="stop_scraping")]
    ])
    await context.bot.send_message(chat_id=user_id, text="✅ Scraper task started! Watch for updates.", reply_markup=stop_keyboard)


async def start_scrape(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user:
        return
    await _run_scraper_logic(update, context, update.effective_user.id)


async def stop_scrape_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    await q.answer()
    
    scraper = context.user_data.get("scraper_instance")
    if scraper:
        scraper.stop()
        await q.edit_message_text(text="🛑 Stop signal sent. Finishing last page...")
    else:
        await q.edit_message_text(text="❌ No active scraper found.")

if __name__ == "__main__":
    main()


