"""
================================================================================
 SCAM REPORT BOT - single-file build
================================================================================
Everything lives in this one file: configuration, database layer, and bot
logic. Edit the three values in the CONFIG section directly below, then run:

    pip install python-telegram-bot==21.6
    python3 scam_report_bot.py

Requires the bot to be an admin (with "Post Messages" permission) in your
scam-exposure channel.

NOTE: the bot's profile photo / "About" text (the horizontal banner shown
when someone first opens the bot's DM) is set via @BotFather
(/setuserpic, /setabouttext) - that's outside what a running script can do.

--------------------------------------------------------------------------------
HOW THE SCAMMER'S NUMERIC ID GETS ATTACHED
--------------------------------------------------------------------------------
Telegram's Bot API does not allow a bot to look up an arbitrary user's numeric
ID from just their @username unless the bot has already "seen" that user
somewhere. This is a platform restriction, not a bug in this script.

Because of that, reporters just submit the @username as text - no forwarding
required. When an admin taps Accept on a report, the bot asks the admin to
send the scammer's numeric ID directly (sourced however the admin likes -
their own lookup tools, a mutual group, etc). Only once a valid numeric ID is
supplied does the report get published to the channel.
================================================================================
"""

from __future__ import annotations

import os
import re
import sys
import html
import asyncio
import json
import base64
import zlib
import io
import sqlite3
import logging
import datetime
import unicodedata
from contextlib import contextmanager
from types import SimpleNamespace

from telegram import (
    Update,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ApplicationHandlerStop,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    CallbackQueryHandler,
    TypeHandler,
    filters,
)
from telegram.error import TelegramError, BadRequest

try:  # Bot API 7.0+ "select user" button (python-telegram-bot >= 21)
    from telegram import KeyboardButton, KeyboardButtonRequestUsers
except ImportError:  # older library: the report flow falls back to typing @username
    KeyboardButton = KeyboardButtonRequestUsers = None

# ==============================================================================
# CONFIG - edit these three values, nothing else needs to change
# ==============================================================================

# Token from @BotFather, e.g. "123456789:AAExampleTokenGoesHere"
BOT_TOKEN = "8859291508:AAGBkrMoyVbgRjZ0Mv1BzeGKYw-tJdIGX7E"

# Your scam-exposure channel's username, WITHOUT the @
CHANNEL_USERNAME = "worksafer"

# Your personal Telegram chat ID(s) - the "Prime Admins". Don't know your
# own ID? Run the bot once and DM it /id. You can list 1-4 (or more) IDs
# here; all of them have full prime-admin power (/admin, /rmadmin, /pfp,
# /pfp2, etc).
PRIME_ADMIN_IDS = [8519948652, 8421166266, 8358390340]   # e.g. [111111111, 222222222, 333333333]

# Text shown at the bottom of the welcome message.
POWERED_BY = "@vergenetworks"

# "Always Use Trusted Middleman" button on impersonator posts.
# Put your middleman channel/bot link here. Leave "" to hide the button.
MIDDLEMAN_URL = "https://t.me/middlemonsters"
MIDDLEMAN_TEXT = "Always Use Trusted Middleman"

# OPTIONAL - makes /check show ANY user's profile photo, display name and ID.
# Telegram bots can't look up accounts that never talked to them, so the bot
# signs in as a normal Telegram account too (use a spare one, not your main).
#   1) pip install telethon
#   2) get TG_API_ID / TG_API_HASH at https://my.telegram.org  ->  API development tools
#   3) run:  python scem_bot.py --make-session   and paste the result into TG_SESSION
# Keep TG_SESSION secret - anyone with it can use that account.
TG_API_ID = 0
TG_API_HASH = ""
TG_SESSION = ""

DB_PATH = "scam_bot.db"

# ==============================================================================
# Logging
# ==============================================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("scam_bot")


# ==============================================================================
# Database layer (SQLite)
# ==============================================================================

def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                reporter_username TEXT,
                report_type TEXT NOT NULL,        -- 'impersonation' or 'scam'
                target_username TEXT,
                target_id TEXT,
                original_username TEXT,           -- impersonation only
                original_id TEXT,                 -- impersonation only
                amount TEXT,                      -- scam only
                description TEXT,                 -- scam only
                proof_link TEXT,                  -- scam only
                status TEXT DEFAULT 'pending',    -- pending / approved / rejected
                admin_message_ids TEXT,           -- json [[chat_id, message_id], ...]
                decided_by INTEGER,
                decided_by_username TEXT,
                reject_reason TEXT,
                created_at TEXT,
                decided_at TEXT,
                photo_file_id TEXT,
                channel_message_id INTEGER
            )
        """)
        # Migration for DBs created before these columns existed.
        cols = [row["name"] for row in c.execute("PRAGMA table_info(reports)").fetchall()]
        if "photo_file_id" not in cols:
            c.execute("ALTER TABLE reports ADD COLUMN photo_file_id TEXT")
        if "channel_message_id" not in cols:
            c.execute("ALTER TABLE reports ADD COLUMN channel_message_id INTEGER")
        c.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                chat_id INTEGER PRIMARY KEY,
                added_by INTEGER,
                added_at TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS appeals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                reporter_id INTEGER NOT NULL,
                reporter_username TEXT,
                explanation TEXT,
                status TEXT DEFAULT 'pending',    -- pending / approved / rejected
                admin_message_ids TEXT,
                decided_by INTEGER,
                decided_by_username TEXT,
                created_at TEXT,
                decided_at TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS warns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER, user_id INTEGER, admin_id INTEGER,
                reason TEXT, created_at TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY,
                warn_limit INTEGER DEFAULT 3
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                chat_id INTEGER, word TEXT, added_by INTEGER,
                PRIMARY KEY (chat_id, word)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS seen_users (
                user_id TEXT PRIMARY KEY,
                username TEXT,                    -- lowercase, no @
                display_name TEXT,
                updated_at TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS verified_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,                    -- stored lowercase, no @
                user_id TEXT,
                display_name TEXT,
                vouch_link TEXT,
                added_by INTEGER,
                created_at TEXT
            )
        """)


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---- config (key/value) ----

def db_set_config(key: str, value: str):
    with _conn() as c:
        c.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def db_get_config(key: str, default=None):
    with _conn() as c:
        row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


# ---- admins ----

def db_add_admin(chat_id: int, added_by: int):
    with _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO admins (chat_id, added_by, added_at) VALUES (?, ?, ?)",
            (chat_id, added_by, datetime.datetime.utcnow().isoformat()),
        )


def db_remove_admin(chat_id: int):
    with _conn() as c:
        c.execute("DELETE FROM admins WHERE chat_id=?", (chat_id,))


def db_list_admins():
    with _conn() as c:
        rows = c.execute("SELECT chat_id FROM admins").fetchall()
        return [r["chat_id"] for r in rows]


def db_is_admin(chat_id: int) -> bool:
    if chat_id in PRIME_ADMIN_IDS:
        return True
    with _conn() as c:
        row = c.execute("SELECT 1 FROM admins WHERE chat_id=?", (chat_id,)).fetchone()
        return row is not None


# ---- reports ----

def db_has_pending_report(reporter_id: int) -> bool:
    with _conn() as c:
        row = c.execute(
            "SELECT 1 FROM reports WHERE reporter_id=? AND status='pending'",
            (reporter_id,),
        ).fetchone()
        return row is not None


def db_create_report(**fields) -> int:
    fields.setdefault("status", "pending")
    fields["created_at"] = datetime.datetime.utcnow().isoformat()
    cols = ", ".join(fields.keys())
    placeholders = ", ".join(["?"] * len(fields))
    with _conn() as c:
        cur = c.execute(
            f"INSERT INTO reports ({cols}) VALUES ({placeholders})",
            list(fields.values()),
        )
        return cur.lastrowid


def db_get_report(report_id: int):
    with _conn() as c:
        row = c.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        return dict(row) if row else None


def db_set_admin_message_ids(report_id: int, pairs: list):
    with _conn() as c:
        c.execute(
            "UPDATE reports SET admin_message_ids=? WHERE id=?",
            (json.dumps(pairs), report_id),
        )


def db_set_target_username(report_id: int, username: str):
    with _conn() as c:
        c.execute("UPDATE reports SET target_username=? WHERE id=?", (username, report_id))


def db_set_target_id(report_id: int, target_id: str):
    with _conn() as c:
        c.execute("UPDATE reports SET target_id=? WHERE id=?", (target_id, report_id))


def db_set_original_id(report_id: int, original_id: str):
    with _conn() as c:
        c.execute("UPDATE reports SET original_id=? WHERE id=?", (original_id, report_id))


def db_known_id_for_username(username: str) -> str | None:
    """A numeric ID the bot already stored for this @username in an earlier report."""
    q = (username or "").lstrip("@").lower()
    if not q:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT target_id FROM reports WHERE LOWER(LTRIM(target_username,'@')) = ? "
            "AND target_id GLOB '[0-9]*' ORDER BY id DESC LIMIT 1", (q,)
        ).fetchone()
        return row[0] if row else None


def db_set_channel_message_id(report_id: int, message_id: int):
    with _conn() as c:
        c.execute(
            "UPDATE reports SET channel_message_id=? WHERE id=?", (message_id, report_id)
        )


def db_get_report_by_channel_message(message_id: int):
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM reports WHERE channel_message_id=?", (message_id,)
        ).fetchone()
        return dict(row) if row else None


# ---- appeals ----

def db_create_appeal(**fields) -> int:
    fields.setdefault("status", "pending")
    fields["created_at"] = datetime.datetime.utcnow().isoformat()
    cols = ", ".join(fields.keys())
    placeholders = ", ".join(["?"] * len(fields))
    with _conn() as c:
        cur = c.execute(
            f"INSERT INTO appeals ({cols}) VALUES ({placeholders})",
            list(fields.values()),
        )
        return cur.lastrowid


def db_get_appeal(appeal_id: int):
    with _conn() as c:
        row = c.execute("SELECT * FROM appeals WHERE id=?", (appeal_id,)).fetchone()
        return dict(row) if row else None


def db_set_appeal_admin_message_ids(appeal_id: int, pairs: list):
    with _conn() as c:
        c.execute(
            "UPDATE appeals SET admin_message_ids=? WHERE id=?",
            (json.dumps(pairs), appeal_id),
        )


def db_decide_appeal(appeal_id: int, status: str, decided_by: int, decided_by_username: str):
    with _conn() as c:
        c.execute(
            "UPDATE appeals SET status=?, decided_by=?, decided_by_username=?, decided_at=? "
            "WHERE id=?",
            (status, decided_by, decided_by_username,
             datetime.datetime.utcnow().isoformat(), appeal_id),
        )


def db_decide_report(report_id: int, status: str, decided_by: int,
                      decided_by_username: str, reject_reason: str = None):
    with _conn() as c:
        c.execute(
            "UPDATE reports SET status=?, decided_by=?, decided_by_username=?, "
            "reject_reason=?, decided_at=? WHERE id=?",
            (status, decided_by, decided_by_username, reject_reason,
             datetime.datetime.utcnow().isoformat(), report_id),
        )


def db_find_reports_for_target(query: str):
    """Look up by @username (with or without @) or numeric id."""
    query = query.strip()
    if query.startswith("@"):
        query = query[1:]
    with _conn() as c:
        rows = c.execute(
            """
            SELECT * FROM reports
            WHERE target_username IN (?, ?) COLLATE NOCASE
               OR target_id = ?
               OR original_username IN (?, ?) COLLATE NOCASE
            ORDER BY created_at DESC
            """,
            (query, "@" + query, query, query, "@" + query),
        ).fetchall()
        return [dict(r) for r in rows]


def db_check_target(query: str):
    """All reports where this @username / numeric ID is the REPORTED account
    (scammer or impersonator) - not the real user being impersonated."""
    q = query.strip().lstrip("@")
    with _conn() as c:
        rows = c.execute(
            """
            SELECT * FROM reports
            WHERE target_username IN (?, ?) COLLATE NOCASE
               OR target_id = ?
            ORDER BY created_at DESC
            """,
            (q, "@" + q, q),
        ).fetchall()
        return [dict(r) for r in rows]


# ---- everyone who has talked to the bot (lets /check find their photo by @username) ----
def db_remember_user(user_id, username, display_name):
    with _conn() as c:
        c.execute(
            "INSERT INTO seen_users (user_id, username, display_name, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, "
            "display_name=excluded.display_name, updated_at=excluded.updated_at",
            (str(user_id), username.lower() if username else None, display_name,
             datetime.datetime.utcnow().isoformat()),
        )


def db_find_seen(query: str):
    q = (query or "").strip().lstrip("@").lower()
    if not q:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM seen_users WHERE user_id = ? OR username = ?", (q, q)
        ).fetchone()
        return dict(row) if row else None


# ---- verified users (shown as TRUSTED in /check) ----
def db_add_verified(username, user_id, display_name, vouch_link, added_by):
    username = username.lstrip("@").lower() if username else None
    with _conn() as c:
        c.execute(
            "DELETE FROM verified_users WHERE (username IS NOT NULL AND username = ?) "
            "OR (user_id IS NOT NULL AND user_id = ?)",
            (username, user_id),
        )
        c.execute(
            "INSERT INTO verified_users (username, user_id, display_name, vouch_link, added_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, user_id, display_name, vouch_link, added_by, datetime.datetime.utcnow().isoformat()),
        )


def db_find_verified(query: str):
    q = query.strip().lstrip("@").lower()
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM verified_users WHERE username = ? OR user_id = ?", (q, q)
        ).fetchone()
        return dict(row) if row else None


def db_remove_verified(query: str) -> int:
    q = query.strip().lstrip("@").lower()
    with _conn() as c:
        return c.execute(
            "DELETE FROM verified_users WHERE username = ? OR user_id = ?", (q, q)
        ).rowcount


def db_list_verified():
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM verified_users ORDER BY created_at").fetchall()]


# ==============================================================================
# Conversation states & static UI
# ==============================================================================

(
    LOOKUP_INPUT,
    IMP_ORIGINAL,
    IMP_IMPERSONATOR,
    SCAM_USERNAME,
    SCAM_AMOUNT,
    SCAM_DESC,
    SCAM_PROOF,
    REJECT_REASON,
    PFP_PHOTO,
    APPEAL_FORWARD,
    APPEAL_EXPLAIN,
) = range(11)

# Menus are INLINE buttons under the message (no keyboard stuck at the bottom).
MAIN_MENU = InlineKeyboardMarkup([
    [InlineKeyboardButton("📨 Submit a Report", callback_data="menu:report"),
     InlineKeyboardButton("🔎 Users Lookup", callback_data="menu:lookup")],
    [InlineKeyboardButton("⚖️ Submit Appeal", callback_data="menu:appeal")],
])
REPORT_MENU = InlineKeyboardMarkup([
    [InlineKeyboardButton("Scam Report", callback_data="menu:scam"),
     InlineKeyboardButton("Impersonation Report", callback_data="menu:imp")],
    [InlineKeyboardButton("⬅️ Back", callback_data="menu:back")],
])
CANCEL_MENU = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel Report", callback_data="cancel_report")]])


def shared_user(message):
    """(numeric_id, username_or_None, name_or_None) from a 'pick the account'
    reply, or None if the message isn't one."""
    shared = getattr(message, "users_shared", None)
    if not shared:
        return None
    users = getattr(shared, "users", None)
    if users:
        u = users[0]
        name = " ".join(x for x in (getattr(u, "first_name", None), getattr(u, "last_name", None)) if x) or None
        return str(u.user_id), getattr(u, "username", None), name
    ids = getattr(shared, "user_ids", None)
    if ids:
        return str(ids[0]), None, None
    return None

DIVIDER = "──────────────"

CURRENCY_RE = re.compile(
    r"^\s*(?:[₹€¥$¢]\s?\d+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?\s?[₹€¥$¢])\s*$"
)
INVITE_LINK_RE = re.compile(r"^https://t\.me/\+\S+$", re.IGNORECASE)

# Cross-conversation state for admins replying to a "reject reason" prompt
# or sending a new /pfp photo. Keyed by admin chat_id.
awaiting_reject_reason: dict[int, int] = {}   # admin_chat_id -> report_id
awaiting_accept_id: dict[int, int] = {}       # admin_chat_id -> report_id currently awaiting the scammer's ID
awaiting_pfp: set[int] = set()                # admin_chat_ids currently sending the default flagged-user photo
awaiting_pfp3: set[int] = set()               # admin_chat_ids currently sending the impersonator-alert banner
awaiting_pfp2: set[int] = set()               # admin_chat_ids currently sending the welcome-banner photo
awaiting_getid: set[int] = set()              # admin_chat_ids currently awaiting a username/forward for /getid


def build_welcome_text(bot_username: str | None) -> str:
    custom = db_get_config("welcome_text")
    if custom:
        return custom

    handle = f"@{bot_username}" if bot_username else "this bot"
    return (
        f"Welcome to {handle}\n\n"
        f"A specialized platform committed to reporting scammers!\n\n"
        f"All reports are reviewed by mods before being published.\n\n"
        f"Note: Your report will be rejected if you are not a member of "
        f"@{CHANNEL_USERNAME}!\n\n"
        f"⚡️ Powered By: {POWERED_BY}"
    )


def join_channel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(f"Join @{CHANNEL_USERNAME}", url=f"https://t.me/{CHANNEL_USERNAME}")]]
    )


def join_gate_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"Join @{CHANNEL_USERNAME}", url=f"https://t.me/{CHANNEL_USERNAME}")],
            [InlineKeyboardButton("I've Joined - Check Again", callback_data="check_membership")],
        ]
    )


REPORT_SUBMITTED_TEXT = (
    "<b>Your report has been submitted.</b>\n\n"
    "You will be notified once it is processed and, if approved, "
    "published on the scam exposure channel."
)

ALREADY_PENDING_TEXT = (
    "<b>You already have a pending report.</b>\n"
    "Please wait for it to be processed before submitting another."
)

APPEAL_INTRO_TEXT = (
    "If you find out that a report is fake or we made a mistake, you can appeal.\n\n"
    "Forward your report from the channel here."
)

APPEAL_NOT_A_MATCH_TEXT = (
    "That doesn't look like a forward of a report from our channel. "
    "Please forward the exact report post you want to appeal."
)

APPEAL_ASK_EXPLANATION_TEXT = (
    "Explain in detail why you aren't guilty of this."
)

APPEAL_SUBMITTED_TEXT = (
    "<b>APPEAL SUBMITTED!</b>\n\n"
    "Our admins will review your appeal and the report will be removed "
    "if you are found innocent."
)


# ==============================================================================
# Helpers
# ==============================================================================

def is_privileged(chat_id: int) -> bool:
    return db_is_admin(chat_id)


def username_or_id(user) -> str:
    return f"@{user.username}" if user.username else str(user.id)


async def try_resolve_user_id(bot, username: str) -> str | None:
    """
    Best-effort resolution of a public @username to a numeric id.
    NOTE: Telegram only lets a bot resolve accounts it has already
    "seen" (via a forwarded message, a shared group, or a DM to the bot).
    This will fail for most arbitrary usernames - that is a Telegram
    platform limitation, not a bug. Prefer capturing the ID from a
    forwarded message wherever possible (see extract_forward_identity).
    """
    username = username.lstrip("@")
    try:
        chat = await bot.get_chat(f"@{username}")
        return str(chat.id)
    except TelegramError:
        return None


async def resolve_target_id(bot, username: str) -> str | None:
    """Best-effort raw API lookup. Falls back to None if Telegram can't
    resolve it - in which case an admin should supply the ID manually at
    accept-time, or via /getid using a forwarded message."""
    return await try_resolve_user_id(bot, username)


def is_forwarded_message(message) -> bool:
    return getattr(message, "forward_origin", None) is not None or \
           getattr(message, "forward_date", None) is not None


def extract_forward_identity(message) -> tuple[str | None, str | None]:
    """
    If the given message is a forward from a user, return
    (username_or_None, numeric_id) for that user. Returns (None, None)
    if the message is not a forward, or the forward origin is hidden
    by the sender's privacy settings.
    """
    origin = getattr(message, "forward_origin", None)
    if origin is not None:
        sender_user = getattr(origin, "sender_user", None)
        if sender_user is not None:
            uname = f"@{sender_user.username}" if sender_user.username else None
            return uname, str(sender_user.id)
        return None, None

    # Fallback for older API versions without forward_origin
    fwd_user = getattr(message, "forward_from", None)
    if fwd_user is not None:
        uname = f"@{fwd_user.username}" if fwd_user.username else None
        return uname, str(fwd_user.id)

    return None, None


def normalize_username(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith("@"):
        raw = "@" + raw
    return raw


def profile_url(username: str | None, numeric_id: str | None, prefer_id: bool = False) -> str | None:
    """Clickable profile link. By default the @username link (works for everyone);
    with prefer_id=True the numeric-ID link is used when we know the ID, so the
    button keeps working after the person changes their @username."""
    has_id = bool(numeric_id) and str(numeric_id).lstrip("-").isdigit()
    if prefer_id and has_id:
        return f"tg://user?id={numeric_id}"
    if username:
        return f"https://t.me/{username.lstrip('@')}"
    if has_id:
        return f"tg://user?id={numeric_id}"
    return None


def id_link(user_id) -> str:
    """A numeric ID that opens that person's profile when tapped (HTML)."""
    return f'<a href="tg://user?id={user_id}">{user_id}</a>'


NO_USERNAME_HINT = "\n<i>No username? Send their numeric ID, or forward me one of their messages.</i>"


def read_target(message):
    """What the reporter sent -> (username_or_None, id_or_None, error_or_None).
    Accepts an @username (or t.me link), a numeric ID, or a message forwarded
    from the person (gives their ID even without a username)."""
    uname, uid = extract_forward_identity(message)
    if uid:
        return uname, uid, None
    if (getattr(message, "forward_origin", None) or getattr(message, "forward_from", None)
            or getattr(message, "forward_sender_name", None)):
        return None, None, ("That person hides their account when messages are forwarded, so I can't read "
                            "their ID. Send their @username or numeric ID instead.")
    text = (getattr(message, "text", None) or "").strip()
    if re.fullmatch(r"\d{5,15}", text):
        return None, text, None
    m = re.fullmatch(r"(?:https?://)?(?:t\.me/|telegram\.me/)?@?([A-Za-z][A-Za-z0-9_]{3,31})", text)
    if m:
        return f"@{m.group(1)}", None, None
    return None, None, "Please send a @username, a numeric ID, or forward one of their messages."


def format_report_card(r: dict) -> str:
    reporter = f"@{r['reporter_username']}" if r["reporter_username"] else f"id {r['reporter_id']}"
    created = r["created_at"].split(".")[0].replace("T", " ") + " UTC"
    kind = "IMPERSONATION REPORT" if r["report_type"] == "impersonation" else "SCAM REPORT"

    header = f"<b>{kind} - #{r['id']}</b>\n{DIVIDER}\n"

    if r["report_type"] == "impersonation":
        body = (
            f"<b>Original handle</b>\n{r['original_username']} "
            f"(<code>{r['original_id'] or 'ID not captured'}</code>)\n\n"
            f"<b>Impersonator</b>\n{r['target_username'] or 'N/A'} "
            f"(<code>{r['target_id'] or 'ID not captured'}</code>)\n"
        )
    else:
        desc = r["description"] or "N/A"
        body = (
            f"<b>Reported user</b>\n{r['target_username'] or 'N/A'}\n\n"
            f"<b>User ID</b>\n<code>{r['target_id'] or 'ID not captured'}</code>\n\n"
            f"<b>Amount scammed</b>\n{r['amount']}\n\n"
            f"<b>Description</b>\n{desc}\n\n"
            f"<b>Proof channel</b>\n{r['proof_link']}\n"
        )

    footer = (
        f"{DIVIDER}\n"
        f"<b>Reported by</b>  {reporter}  (<code>{r['reporter_id']}</code>)\n"
        f"<b>Submitted</b>  {created}"
    )
    return header + body + footer


def decision_keyboard(report_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Accept", callback_data=f"report:accept:{report_id}"),
                InlineKeyboardButton("Reject", callback_data=f"report:reject:{report_id}"),
            ]
        ]
    )


def appeal_decision_keyboard(appeal_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Accept Appeal", callback_data=f"appeal:accept:{appeal_id}"),
                InlineKeyboardButton("Reject Appeal", callback_data=f"appeal:reject:{appeal_id}"),
            ]
        ]
    )


# ==============================================================================
# Telegram Premium (custom) emoji
# Telegram only lets a bot use them in messages to private chats, groups and
# supergroups when the BOT OWNER has Telegram Premium (or the bot owns a
# Fragment username). Never in channels. If Telegram refuses, the normal emoji
# is sent instead - nothing breaks.
#   /setemoji ✅ <premium emoji>   map a normal emoji to a premium one
#   /emojis    /delemoji ✅         list / remove
# Everything the bot sends is converted automatically.
# ==============================================================================
_premium_cache: dict | None = None


def _norm_emoji(e: str) -> str:
    return (e or "").replace("\ufe0f", "").strip()


def premium_map() -> dict:
    global _premium_cache
    if _premium_cache is None:
        try:
            _premium_cache = json.loads(db_get_config("premium_emoji") or "{}")
        except ValueError:
            _premium_cache = {}
    return _premium_cache


def premium_save(mapping: dict):
    global _premium_cache
    db_set_config("premium_emoji", json.dumps(mapping, ensure_ascii=False))
    _premium_cache = mapping


def apply_premium(text: str, parse_mode, mapping: dict) -> tuple[str, bool]:
    """Wrap mapped emoji in <tg-emoji>. Returns (new_text, changed)."""
    mode = str(getattr(parse_mode, "value", parse_mode) or "").upper()
    if not mapping or mode not in ("", "NONE", "HTML") or "<tg-emoji" in text:
        return text, False
    html_mode = mode == "HTML"
    keys = sorted(mapping, key=len, reverse=True)
    pattern = re.compile("(" + "|".join(re.escape(k) for k in keys) + ")\ufe0f?")
    changed = False

    def wrap(m):
        nonlocal changed
        changed = True
        return f'<tg-emoji emoji-id="{mapping[m.group(1)]}">{m.group(1)}</tg-emoji>'

    # plain text must be escaped first; in HTML mode leave the tags alone
    parts = re.split(r"(<[^>]*>)", text) if html_mode else [html.escape(text, quote=False)]
    out = [p if (html_mode and p.startswith("<") and p.endswith(">")) else pattern.sub(wrap, p) for p in parts]
    return "".join(out), changed


def install_premium_emoji(bot_class=None):
    """Make every text/caption the bot sends use the premium emoji map."""
    if bot_class is None:
        from telegram.ext import ExtBot as bot_class
    fields = (("send_message", "text"), ("edit_message_text", "text"), ("send_photo", "caption"),
              ("edit_message_caption", "caption"), ("send_document", "caption"),
              ("send_video", "caption"), ("send_animation", "caption"))
    for name, field in fields:
        orig = getattr(bot_class, name, None)
        if orig is None or getattr(orig, "_premium_wrapped", False):
            continue

        def make(orig=orig, field=field):
            async def wrapper(self, *args, **kwargs):
                mapping = premium_map()
                text = kwargs.get(field)
                if mapping and isinstance(text, str) and not kwargs.get("entities") and not kwargs.get("caption_entities"):
                    new_text, changed = apply_premium(text, kwargs.get("parse_mode"), mapping)
                    if changed:
                        try:
                            return await orig(self, *args, **{**kwargs, field: new_text, "parse_mode": "HTML"})
                        except BadRequest as e:
                            log.info("Premium emoji rejected (%s) - sending the normal emoji instead", e)
                return await orig(self, *args, **kwargs)

            wrapper._premium_wrapped = True
            wrapper.__name__ = getattr(orig, "__name__", name)
            wrapper.__doc__ = getattr(orig, "__doc__", None)
            return wrapper

        setattr(bot_class, name, make())


def _premium_icon(text: str):
    """(custom_emoji_id, label_without_emoji) if the button text starts with a mapped emoji."""
    for key, cid in premium_map().items():
        m = re.match(re.escape(key) + "\ufe0f?\\s*", text)
        if m:
            return cid, (text[m.end():] or text)
    return None, text


async def cmd_setemoji(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    msg = update.message
    customs = [e for e in (msg.entities or []) if e.type == "custom_emoji"]
    target = _norm_emoji(context.args[0]) if context.args else ""
    if not customs or not target or target.isascii() or len(target) > 8:
        await msg.reply_text(
            "Usage: /setemoji ✅ <premium emoji>\n"
            "Type the normal emoji you want replaced, then a Telegram Premium emoji, in one message.\n"
            "Example: /setemoji ❌ (then add your premium ❌)"
        )
        return
    cid = customs[0].custom_emoji_id
    mapping = dict(premium_map())
    mapping[target] = cid
    premium_save(mapping)
    await msg.reply_text(
        f"✅ Saved: {target} → premium emoji <code>{cid}</code>\nSend /emojis to test it.",
        parse_mode=ParseMode.HTML,
    )


async def cmd_delemoji(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    target = _norm_emoji(context.args[0]) if context.args else ""
    mapping = dict(premium_map())
    if target == "all":
        premium_save({})
        await update.message.reply_text("Removed all premium emoji.")
    elif target in mapping:
        del mapping[target]
        premium_save(mapping)
        await update.message.reply_text(f"Removed {target}.")
    else:
        await update.message.reply_text("Usage: /delemoji ✅   (or /delemoji all)")


async def cmd_emojis(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List the mapping and test whether Telegram really shows the premium emoji."""
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    mapping = premium_map()
    if not mapping:
        await update.message.reply_text(
            "No premium emoji set yet.\n\n"
            "1) Send /setemoji ✅ followed by a premium emoji, in one message.\n"
            "2) Repeat for each emoji you want replaced (✅ ❌ 🚫 🤝 ⏳ 🔎 📌 ⚡ ...).\n"
            "The bot then uses them everywhere automatically."
        )
        return
    lines = [f"{k} → <code>{v}</code>" for k, v in mapping.items()]
    sent = await update.message.reply_text("Premium emoji:\n" + "\n".join(lines), parse_mode=ParseMode.HTML)
    shown = any(e.type == "custom_emoji" for e in (getattr(sent, "entities", None) or []))
    await update.message.reply_text(
        "✅ Telegram is showing them as premium emoji." if shown else
        "⚠️ Telegram turned them back into normal emoji. Bots can only use premium emoji when the bot's "
        "OWNER (the account that created it in @BotFather) has Telegram Premium, or the bot owns a "
        "Fragment username. They never work in channels."
    )


async def on_custom_emoji_ids(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Prime admin sends premium emoji to the bot in private -> reply with their IDs."""
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        return
    msg = update.message
    lines = []
    for e in msg.entities or []:
        if e.type == "custom_emoji":
            lines.append(f"{msg.parse_entity(e)} → <code>{e.custom_emoji_id}</code>")
    if lines:
        await msg.reply_text("Premium emoji IDs:\n" + "\n".join(lines) +
                             "\n\nTo use one: /setemoji ✅ <that premium emoji>", parse_mode=ParseMode.HTML)


def _styled_button(text: str, url: str, style: str | None, colored: bool) -> InlineKeyboardButton:
    """URL button. When `colored`: adds Telegram's button `style` (primary = blue,
    success = green, danger = red) and a premium-emoji icon if the button text
    starts with a mapped emoji. The plain fallback has neither."""
    if colored:
        extra = {}
        if style:
            extra["style"] = style
        icon, label = _premium_icon(text)
        if icon:
            extra["icon_custom_emoji_id"] = icon
            text = label
        if extra:
            return InlineKeyboardButton(text, url=url, api_kwargs=extra)
    return InlineKeyboardButton(text, url=url)


def _ibutton(text: str, *, url: str | None = None, data: str | None = None,
             style: str | None = None, colored: bool = True) -> InlineKeyboardButton:
    """Inline button (link or callback). When `colored`: button style + premium-emoji icon."""
    extra = {}
    if colored:
        if style:
            extra["style"] = style
        icon, label = _premium_icon(text)
        if icon:
            extra["icon_custom_emoji_id"] = icon
            text = label
    kwargs = {"url": url} if url else {"callback_data": data}
    if extra:
        kwargs["api_kwargs"] = extra
    return InlineKeyboardButton(text, **kwargs)


def welcome_keyboard(bot_username: str | None, colored: bool = True) -> InlineKeyboardMarkup:
    """The /start menu, attached to the welcome message."""
    rows = [
        [_ibutton("📨 Submit a Report", data="menu:report", style="danger", colored=colored),
         _ibutton("🔎 Users Lookup", data="menu:lookup", style="primary", colored=colored)],
    ]
    second = [_ibutton("⚖️ Submit Appeal", data="menu:appeal", colored=colored)]
    if bot_username:
        second.append(_ibutton("➕ Add Bot to Group", url=f"https://t.me/{bot_username}?startgroup=true", colored=colored))
    rows.append(second)
    if MIDDLEMAN_URL:
        rows.append([_ibutton("🤝 Use a Middleman", url=MIDDLEMAN_URL, style="success", colored=colored)])
    rows.append([_ibutton(f"Join @{CHANNEL_USERNAME}", url=f"https://t.me/{CHANNEL_USERNAME}", colored=colored)])
    return InlineKeyboardMarkup(rows)


def public_post_keyboard(r: dict, colored: bool = True, prefer_id: bool = False) -> InlineKeyboardMarkup | None:
    """Scam post buttons: View Profile (blue) / View Proofs (red), then the
    middleman button (green) underneath."""
    row = []

    p_url = profile_url(r.get("target_username"), r.get("target_id"), prefer_id)
    if p_url:
        row.append(_styled_button("View Profile", p_url, "primary", colored))

    if r["report_type"] == "scam" and r.get("proof_link"):
        row.append(_styled_button("View Proofs", r["proof_link"], "danger", colored))

    rows = [row] if row else []
    if MIDDLEMAN_URL:
        rows.append([_styled_button(MIDDLEMAN_TEXT, MIDDLEMAN_URL, "success", colored)])
    return InlineKeyboardMarkup(rows) if rows else None


def impersonation_keyboard(r: dict, original_id: str | None, colored: bool = True,
                           prefer_id: bool = False, prefer_original_id: bool | None = None) -> InlineKeyboardMarkup | None:
    """Real Profile (green) / Fake Profile (red) on one row, then the
    middleman button underneath. Button colours use Telegram's `style`
    field; if the server rejects it we retry with colored=False."""

    def btn(text: str, url: str, style: str | None = None) -> InlineKeyboardButton:
        return _styled_button(text, url, style, colored)

    row = []
    real_url = profile_url(r.get("original_username"), original_id,
                           prefer_id if prefer_original_id is None else prefer_original_id)
    fake_url = profile_url(r.get("target_username"), r.get("target_id"), prefer_id)
    if real_url:
        row.append(btn("Real Profile", real_url, "success"))
    if fake_url:
        row.append(btn("Fake Profile", fake_url, "danger"))

    rows = [row] if row else []
    if MIDDLEMAN_URL:
        rows.append([btn(MIDDLEMAN_TEXT, MIDDLEMAN_URL, "success")])
    return InlineKeyboardMarkup(rows) if rows else None


def get_admin_recipients() -> set[int]:
    return set(db_list_admins()) | set(PRIME_ADMIN_IDS)


async def broadcast_to_admins(context: ContextTypes.DEFAULT_TYPE, report_id: int):
    r = db_get_report(report_id)
    text = format_report_card(r)
    keyboard = decision_keyboard(report_id)

    sent = []
    for chat_id in get_admin_recipients():
        try:
            msg = await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=keyboard,
            )
            sent.append([chat_id, msg.message_id])
        except TelegramError as e:
            log.warning("Could not notify admin %s: %s", chat_id, e)

    db_set_admin_message_ids(report_id, sent)


def format_appeal_card(a: dict, r: dict) -> str:
    reporter = f"@{a['reporter_username']}" if a["reporter_username"] else f"id {a['reporter_id']}"
    created = a["created_at"].split(".")[0].replace("T", " ") + " UTC"
    return (
        f"<b>APPEAL - #{a['id']}</b> (for report #{r['id']})\n{DIVIDER}\n"
        f"<b>Flagged user</b>\n{r['target_username'] or 'N/A'} (<code>{r['target_id'] or 'N/A'}</code>)\n\n"
        f"<b>Explanation</b>\n{a['explanation']}\n"
        f"{DIVIDER}\n"
        f"<b>Submitted by</b>  {reporter}  (<code>{a['reporter_id']}</code>)\n"
        f"<b>Submitted</b>  {created}"
    )


async def broadcast_appeal_to_admins(context: ContextTypes.DEFAULT_TYPE, appeal_id: int):
    a = db_get_appeal(appeal_id)
    r = db_get_report(a["report_id"])
    text = format_appeal_card(a, r)
    keyboard = appeal_decision_keyboard(appeal_id)

    sent = []
    for chat_id in get_admin_recipients():
        try:
            msg = await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=keyboard,
            )
            sent.append([chat_id, msg.message_id])
        except TelegramError as e:
            log.warning("Could not notify admin %s of appeal: %s", chat_id, e)

    db_set_appeal_admin_message_ids(appeal_id, sent)


async def refresh_appeal_admin_copies(context: ContextTypes.DEFAULT_TYPE, appeal_id: int, footer: str):
    a = db_get_appeal(appeal_id)
    r = db_get_report(a["report_id"])
    if not a["admin_message_ids"]:
        return
    pairs = json.loads(a["admin_message_ids"])
    new_text = format_appeal_card(a, r) + footer
    for chat_id, message_id in pairs:
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=new_text,
                parse_mode=ParseMode.HTML,
                reply_markup=None,
            )
        except TelegramError as e:
            log.warning("Could not refresh appeal admin copy %s/%s: %s", chat_id, message_id, e)


async def refresh_admin_copies(context: ContextTypes.DEFAULT_TYPE, report_id: int, footer: str):
    r = db_get_report(report_id)
    if not r["admin_message_ids"]:
        return
    pairs = json.loads(r["admin_message_ids"])
    new_text = format_report_card(r) + footer
    for chat_id, message_id in pairs:
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=new_text,
                parse_mode=ParseMode.HTML,
                reply_markup=None,
            )
        except TelegramError as e:
            log.warning("Could not refresh admin copy %s/%s: %s", chat_id, message_id, e)


async def _bot_knows(bot, user_id) -> bool:
    """Can the bot address this account by ID? Telegram only builds ID-based links
    and buttons for accounts the bot has already seen."""
    if not (user_id and str(user_id).lstrip("-").isdigit()):
        return False
    try:
        await bot.get_chat(int(user_id))
        return True
    except TelegramError:
        return False


async def post_to_channel(context: ContextTypes.DEFAULT_TYPE, report_id: int):
    r = db_get_report(report_id)
    default_photo = db_get_config("default_scammer_photo")
    impersonation = r["report_type"] == "impersonation"

    original_id = None
    if impersonation:
        # Look up the real user's ID if Telegram lets us (works only for
        # accounts the bot has already seen); otherwise show the handle only.
        original_id = r["original_id"] or await auto_user_id(context.bot, r["original_username"])

    known_target = await _bot_knows(context.bot, r["target_id"])
    known_original = await _bot_knows(context.bot, original_id) if impersonation else False

    def who(username, uid, links: bool, use_id: bool) -> str:
        """@name (ID). With links=True the ID is tappable: it opens the profile by ID when
        Telegram can resolve the account (use_id), otherwise through the @username."""
        name = html.escape(username) if username else None
        if uid and links:
            href = (f"tg://user?id={uid}" if (use_id or not username)
                    else f"https://t.me/{username.lstrip('@')}")
            idtxt = f'<a href="{href}">{html.escape(str(uid))}</a>'
        else:
            idtxt = html.escape(str(uid)) if uid else None
        return f"{name} ({idtxt})" if (name and idtxt) else (name or idtxt or "N/A")

    def make_text(links: bool, id_mode: bool) -> str:
        t_ok, o_ok = id_mode and known_target, id_mode and known_original
        if impersonation:
            return (f"❌ <b>Impersonator:</b> {who(r['target_username'], r['target_id'], links, t_ok)}\n"
                    f"✅ <b>Real User:</b> {who(r['original_username'], original_id, links, o_ok)}")
        return f"❌ User {who(r['target_username'], r['target_id'], links, t_ok)} Has Been Marked As A Scammer ❌"

    photo = (db_get_config("impersonator_photo") or default_photo) if impersonation else default_photo

    def make_keyboard(colored: bool, id_mode: bool):
        if impersonation:
            return impersonation_keyboard(r, original_id, colored=colored, prefer_id=id_mode and known_target,
                                          prefer_original_id=id_mode and known_original)
        return public_post_keyboard(r, colored=colored, prefer_id=id_mode and known_target)

    # Best first: tappable IDs + ID-based profile buttons (survive a username change) for accounts
    # Telegram can resolve, @username links for the rest. If Telegram refuses, step down:
    # username buttons, then plain IDs; each tried coloured first, then plain.
    ladder, seen_cfg = [], set()
    for links, id_mode, colored in [(True, True, True), (True, True, False), (True, False, True),
                                    (True, False, False), (False, False, True), (False, False, False)]:
        cfg = (links, id_mode and known_target, id_mode and known_original, colored)
        if cfg not in seen_cfg:
            seen_cfg.add(cfg)
            ladder.append((links, id_mode, colored))

    for links, id_mode, colored in ladder:
        try:
            kwargs = dict(chat_id=f"@{CHANNEL_USERNAME}", parse_mode=ParseMode.HTML,
                          reply_markup=make_keyboard(colored, id_mode))
            if photo:
                msg = await context.bot.send_photo(photo=photo, caption=make_text(links, id_mode), **kwargs)
            else:
                msg = await context.bot.send_message(text=make_text(links, id_mode), **kwargs)
        except TelegramError as e:
            log.warning("Post for report %s failed (links=%s, id-mode=%s, colored=%s): %s",
                        report_id, links, id_mode, colored, e)
            continue
        db_set_channel_message_id(report_id, msg.message_id)

        # Telegram sometimes accepts the post but silently drops an ID link it can't resolve;
        # then re-edit the text so the IDs open the profile through the @username instead.
        entities = getattr(msg, "caption_entities", None) or getattr(msg, "entities", None) or []
        has_link = any(getattr(e, "type", "") in ("text_mention", "text_link") for e in entities)
        if links and id_mode and (known_target or known_original) and not has_link:
            try:
                fixed = make_text(True, False)
                if photo:
                    await context.bot.edit_message_caption(chat_id=f"@{CHANNEL_USERNAME}", message_id=msg.message_id,
                                                           caption=fixed, parse_mode=ParseMode.HTML,
                                                           reply_markup=make_keyboard(colored, id_mode))
                else:
                    await context.bot.edit_message_text(chat_id=f"@{CHANNEL_USERNAME}", message_id=msg.message_id,
                                                        text=fixed, parse_mode=ParseMode.HTML,
                                                        reply_markup=make_keyboard(colored, id_mode))
            except TelegramError as e:
                log.info("Could not re-edit post %s: %s", report_id, e)
        return
    log.error("Could not post report %s to the channel", report_id)


# ==============================================================================
# /start and menu navigation
# ==============================================================================

async def is_channel_member(bot, user_id: int) -> bool | None:
    """True if joined, False if not, None if we couldn't determine (API
    error - e.g. bot isn't actually an admin in the channel yet)."""
    try:
        member = await bot.get_chat_member(chat_id=f"@{CHANNEL_USERNAME}", user_id=user_id)
    except TelegramError as e:
        log.warning("Could not check channel membership for %s: %s", user_id, e)
        return None
    return member.status not in ("left", "kicked")


async def send_join_gate(chat_id: int, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(
        chat_id=chat_id,
        text=f"JOIN OUR REPORT CHANNEL FIRST FOR PROCEEDING @{CHANNEL_USERNAME}",
        reply_markup=join_gate_keyboard(),
    )


_old_keyboard_cleared: set[int] = set()


async def send_welcome(chat_id: int, context: ContextTypes.DEFAULT_TYPE):
    text = build_welcome_text(context.bot.username)
    welcome_photo = db_get_config("welcome_photo")

    # People who used the old bottom-keyboard menu still have it on their phone:
    # remove it once (send an invisible-ish message with ReplyKeyboardRemove, then delete it).
    if chat_id not in _old_keyboard_cleared:
        _old_keyboard_cleared.add(chat_id)
        try:
            tmp = await context.bot.send_message(chat_id=chat_id, text="⏳", reply_markup=ReplyKeyboardRemove())
            await tmp.delete()
        except TelegramError:
            pass

    for colored in (True, False):      # coloured buttons first, plain ones if Telegram refuses
        keyboard = welcome_keyboard(context.bot.username, colored)
        try:
            if welcome_photo:
                await context.bot.send_photo(chat_id=chat_id, photo=welcome_photo, caption=text, reply_markup=keyboard)
            else:
                await context.bot.send_message(chat_id=chat_id, text=text, reply_markup=keyboard)
            return
        except TelegramError as e:
            log.warning("Could not send welcome banner (colored=%s): %s", colored, e)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.effective_chat.id
    joined = await is_channel_member(context.bot, update.effective_user.id)

    if joined is False:
        await send_join_gate(chat_id, context)
        return ConversationHandler.END

    # joined is True, or None (couldn't verify - fail open rather than
    # permanently locking everyone out over an API hiccup)
    await send_welcome(chat_id, context)
    return ConversationHandler.END


async def on_check_membership(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    joined = await is_channel_member(context.bot, user_id)

    if joined is False:
        await query.answer("You still haven't joined the channel.", show_alert=True)
        return

    await query.answer("Joined - let's go!")
    await send_welcome(query.message.chat_id, context)


async def show_report_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "<b>What would you like to report?</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=REPORT_MENU,
    )
    return ConversationHandler.END


async def back_to_main(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "<b>Main menu</b>", parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )
    return ConversationHandler.END


# ==============================================================================
# Lookup flow
# ==============================================================================

async def lookup_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "<b>Provide the chat ID or @username of the user to look up.</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=CANCEL_MENU,
    )
    return LOOKUP_INPUT


async def cmd_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if context.args:
        await do_lookup(update, context, " ".join(context.args))
        return ConversationHandler.END
    await update.message.reply_text(
        "<b>Usage:</b> <code>/lookup @username</code> or <code>/lookup user_id</code>",
        parse_mode=ParseMode.HTML,
    )
    return ConversationHandler.END


async def do_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE, query: str):
    results = db_find_reports_for_target(query)
    label = query if query.startswith("@") else f"@{query}"
    if not results:
        await update.message.reply_text(
            f"<b>No reports found</b> for {label}.",
            parse_mode=ParseMode.HTML,
            reply_markup=MAIN_MENU,
        )
        return
    lines = [f"<b>Report history for {label}</b>", DIVIDER]
    for r in results:
        target = r["target_username"] or label
        tid = r["target_id"] or "N/A"
        lines.append(
            f"{target} | <code>{tid}</code> | {r['status'].capitalize()}"
        )
    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )


async def lookup_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await do_lookup(update, context, update.message.text)
    return ConversationHandler.END


# ==============================================================================
# Impersonation report flow
# ==============================================================================

async def imp_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if db_has_pending_report(update.effective_user.id):
        await update.message.reply_text(
            ALREADY_PENDING_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
        )
        return ConversationHandler.END
    await update.message.reply_text(
        "<b>Send the username of the original handle</b> (e.g. @username1)." + NO_USERNAME_HINT,
        parse_mode=ParseMode.HTML,
        reply_markup=CANCEL_MENU,
    )
    return IMP_ORIGINAL


async def imp_original(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uname, uid, error = read_target(update.message)
    if error:
        await update.message.reply_text(error)
        return IMP_ORIGINAL
    context.user_data["imp_original"] = uname
    context.user_data["imp_original_id"] = uid
    await update.message.reply_text(
        "<b>Send the impersonator's username</b> (e.g. @username2)." + NO_USERNAME_HINT,
        parse_mode=ParseMode.HTML,
        reply_markup=CANCEL_MENU,
    )
    return IMP_IMPERSONATOR


async def _imp_finish(update: Update, context: ContextTypes.DEFAULT_TYPE, impersonator, impersonator_id) -> int:
    original = context.user_data.pop("imp_original")
    original_id = context.user_data.pop("imp_original_id", None)
    user = update.effective_user

    report_id = db_create_report(
        reporter_id=user.id,
        reporter_username=user.username,
        report_type="impersonation",
        target_username=impersonator,
        target_id=impersonator_id,
        original_username=original,
        original_id=original_id,
    )

    await update.message.reply_text(
        REPORT_SUBMITTED_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )
    await autofill_report_ids(context, report_id)
    await broadcast_to_admins(context, report_id)
    return ConversationHandler.END


async def imp_impersonator(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uname, uid, error = read_target(update.message)
    if error:
        await update.message.reply_text(error)
        return IMP_IMPERSONATOR
    return await _imp_finish(update, context, uname, uid)


# ==============================================================================
# Scam report flow
# ==============================================================================

async def scam_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if db_has_pending_report(update.effective_user.id):
        await update.message.reply_text(
            ALREADY_PENDING_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
        )
        return ConversationHandler.END
    await update.message.reply_text(
        "<b>Provide the username of the scammer</b> (e.g. @xyzabc)." + NO_USERNAME_HINT,
        parse_mode=ParseMode.HTML,
        reply_markup=CANCEL_MENU,
    )
    return SCAM_USERNAME


# Deep link from the /check card's "Create Report" button:
#   https://t.me/<bot>?start=report_u_<username>   or   ...report_i_<numeric id>
START_REPORT_RE = r"^/start(?:@\w+)?\s+report_([ui])_(\w{1,64})$"


async def scam_start_prefilled(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    m = re.match(START_REPORT_RE, (update.message.text or "").strip())
    if not m:
        return ConversationHandler.END
    kind, value = m.group(1), m.group(2)
    user = update.effective_user

    # same rules as a normal report: must be in the channel, one pending report at a time
    if await is_channel_member(context.bot, user.id) is False:
        await send_join_gate(update.effective_chat.id, context)
        return ConversationHandler.END
    if db_has_pending_report(user.id):
        await update.message.reply_text(
            ALREADY_PENDING_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
        )
        return ConversationHandler.END

    if kind == "u":
        is_self = bool(user.username) and user.username.lower() == value.lower()
        context.user_data["scam_username"] = f"@{value}"
        context.user_data["scam_target_id"] = None
        label = f"@{value}"
    else:
        is_self = str(user.id) == value
        context.user_data["scam_username"] = None
        context.user_data["scam_target_id"] = value
        label = f"ID {value}"

    if is_self:
        context.user_data.pop("scam_username", None)
        context.user_data.pop("scam_target_id", None)
        await update.message.reply_text(
            "You can't report yourself.", reply_markup=MAIN_MENU
        )
        return ConversationHandler.END

    await update.message.reply_text(
        f"<b>Reporting {html.escape(label)} as a scammer.</b>\n\n"
        "<b>What amount of money was scammed?</b>",
        parse_mode=ParseMode.HTML,
        reply_markup=CANCEL_MENU,
    )
    return SCAM_AMOUNT


async def scam_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    uname, uid, error = read_target(update.message)
    me = update.effective_user
    if not error and ((uid and uid == str(me.id)) or (uname and me.username and uname.lstrip("@").lower() == me.username.lower())):
        error = "You can't report yourself."
    if error:
        await update.message.reply_text(error)
        return SCAM_USERNAME
    context.user_data["scam_username"] = uname
    context.user_data["scam_target_id"] = uid
    await update.message.reply_text(
        "<b>What amount of money was scammed?</b>", parse_mode=ParseMode.HTML
    )
    return SCAM_AMOUNT


async def scam_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.strip()
    if not CURRENCY_RE.match(text):
        await update.message.reply_text(
            "<b>Please give a valid amount</b>, including a currency symbol "
            "(e.g. ₹500, $100, €50):",
            parse_mode=ParseMode.HTML,
        )
        return SCAM_AMOUNT
    context.user_data["scam_amount"] = text
    await update.message.reply_text(
        "<b>Describe the scam in detail.</b>", parse_mode=ParseMode.HTML
    )
    return SCAM_DESC


async def scam_desc(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["scam_desc"] = update.message.text.strip()
    await update.message.reply_text(
        "<b>Create a private Telegram channel</b> with all proof uploaded, "
        "and send the invite link here (starts with <code>https://t.me/+</code>).",
        parse_mode=ParseMode.HTML,
    )
    return SCAM_PROOF


async def scam_proof(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    link = update.message.text.strip()
    if not INVITE_LINK_RE.match(link):
        await update.message.reply_text(
            "<b>That does not look like a valid private invite link.</b>\n"
            "It must start with <code>https://t.me/+</code>. Please try again.",
            parse_mode=ParseMode.HTML,
        )
        return SCAM_PROOF

    user = update.effective_user
    report_id = db_create_report(
        reporter_id=user.id,
        reporter_username=user.username,
        report_type="scam",
        target_username=context.user_data.pop("scam_username"),
        target_id=context.user_data.pop("scam_target_id", None),
        amount=context.user_data.pop("scam_amount"),
        description=context.user_data.pop("scam_desc"),
        proof_link=link,
    )

    await update.message.reply_text(
        REPORT_SUBMITTED_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )
    await autofill_report_ids(context, report_id)
    await broadcast_to_admins(context, report_id)
    return ConversationHandler.END


async def cancel_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the report in progress, then restart the bot (welcome + menu)."""
    context.user_data.clear()
    await update.message.reply_text(
        "❌ <b>Report cancelled.</b>", parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )
    await cmd_start(update, context)          # same as the user sending /start
    return ConversationHandler.END


# ==============================================================================
# Appeal flow
# ==============================================================================

def extract_forwarded_channel_post(message) -> tuple[str | None, int | None]:
    """Returns (channel_username, message_id) if this message is a forward
    of a channel post, else (None, None)."""
    origin = getattr(message, "forward_origin", None)
    if origin is not None:
        chat = getattr(origin, "chat", None)
        msg_id = getattr(origin, "message_id", None)
        if chat is not None and msg_id is not None:
            return chat.username, msg_id
        return None, None

    # Fallback for older API versions without forward_origin
    fwd_chat = getattr(message, "forward_from_chat", None)
    fwd_msg_id = getattr(message, "forward_from_message_id", None)
    if fwd_chat is not None and fwd_msg_id is not None:
        return fwd_chat.username, fwd_msg_id

    return None, None


async def appeal_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        APPEAL_INTRO_TEXT, parse_mode=ParseMode.HTML, reply_markup=CANCEL_MENU
    )
    return APPEAL_FORWARD


async def appeal_forward_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    channel_username, message_id = extract_forwarded_channel_post(update.message)

    if not channel_username or channel_username.lower() != CHANNEL_USERNAME.lower():
        await update.message.reply_text(APPEAL_NOT_A_MATCH_TEXT, parse_mode=ParseMode.HTML)
        return APPEAL_FORWARD

    r = db_get_report_by_channel_message(message_id)
    if not r:
        await update.message.reply_text(APPEAL_NOT_A_MATCH_TEXT, parse_mode=ParseMode.HTML)
        return APPEAL_FORWARD

    context.user_data["appeal_report_id"] = r["id"]
    await update.message.reply_text(
        APPEAL_ASK_EXPLANATION_TEXT, parse_mode=ParseMode.HTML
    )
    return APPEAL_EXPLAIN


async def appeal_explain_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    report_id = context.user_data.pop("appeal_report_id", None)
    if report_id is None:
        await update.message.reply_text(
            "Something went wrong - please start the appeal again.",
            reply_markup=MAIN_MENU,
        )
        return ConversationHandler.END

    user = update.effective_user
    appeal_id = db_create_appeal(
        report_id=report_id,
        reporter_id=user.id,
        reporter_username=user.username,
        explanation=update.message.text.strip(),
    )

    await update.message.reply_text(
        APPEAL_SUBMITTED_TEXT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU
    )
    await broadcast_appeal_to_admins(context, appeal_id)
    return ConversationHandler.END


# ==============================================================================
# Admin decision handling (Accept / Reject buttons)
# ==============================================================================

async def on_decision_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    admin = query.from_user

    if not is_privileged(admin.id):
        await query.answer("You are not authorized to do this.", show_alert=True)
        return

    _, action, report_id_str = query.data.split(":")
    report_id = int(report_id_str)
    r = db_get_report(report_id)

    if not r:
        await query.answer("Report not found.", show_alert=True)
        return
    if r["status"] != "pending":
        await query.answer("This report has already been decided.", show_alert=True)
        return

    if action == "accept":
        await query.answer("Looking up the ID...")
        why = ""
        if (r["target_id"] or "").isdigit():
            target_id = r["target_id"]
        else:
            target_id, why = await auto_user_id_why(context.bot, r["target_username"])
        if target_id:
            await finalize_accept(context, admin, report_id, target_id)
            await context.bot.send_message(
                chat_id=admin.id,
                text=f"✅ Report #{report_id} approved and published. ID found automatically: {target_id}",
            )
        else:
            awaiting_accept_id[admin.id] = report_id
            await context.bot.send_message(
                chat_id=admin.id,
                text=(
                    f"<b>Couldn't find the numeric ID automatically for report #{report_id}.</b>\n"
                    f"Reason: {html.escape(why, quote=False)}.\n\n"
                    + ("" if (TG_API_ID and TG_API_HASH and TG_SESSION) else
                       "To make this automatic for every report, run once on the server:\n"
                       "<code>python scem_bot.py --make-session</code>\n\n")
                    + f"Send it manually (digits only), or /cancel. It will be shown on the published post."
                ),
                parse_mode=ParseMode.HTML,
            )

    elif action == "reject":
        awaiting_reject_reason[admin.id] = report_id
        await query.answer()
        await context.bot.send_message(
            chat_id=admin.id,
            text=f"<b>Send the rejection reason for report #{report_id}.</b>",
            parse_mode=ParseMode.HTML,
        )


async def handle_accept_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    report_id = awaiting_accept_id.get(admin.id)
    if report_id is None:
        return  # not currently awaiting an ID from this admin

    text = (update.message.text or "").strip()
    if not text.isdigit():
        await update.message.reply_text(
            "That doesn't look like a numeric Telegram ID. Send digits only "
            "(e.g. 7223878638), or send /cancel to abort this accept."
        )
        raise ApplicationHandlerStop

    awaiting_accept_id.pop(admin.id, None)
    await finalize_accept(context, admin, report_id, text)
    await update.message.reply_text(f"Report #{report_id} approved and published.")

    raise ApplicationHandlerStop


async def cmd_cancel_accept(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    report_id = awaiting_accept_id.pop(admin.id, None)
    if report_id is not None:
        await update.message.reply_text(f"Cancelled accepting report #{report_id}.")


async def handle_reject_reason(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    report_id = awaiting_reject_reason.pop(admin.id, None)
    if report_id is None:
        return  # not currently awaiting a reason from this admin

    reason = update.message.text.strip()
    db_decide_report(report_id, "rejected", admin.id, admin.username, reject_reason=reason)

    footer = (
        f"\n\n{DIVIDER}\nDecision: REJECTED by @{admin.username or admin.id}\nReason: {reason}"
    )
    await refresh_admin_copies(context, report_id, footer)

    r = db_get_report(report_id)
    await update.message.reply_text(f"Report #{report_id} rejected.")
    try:
        await context.bot.send_message(
            chat_id=r["reporter_id"],
            text=(
                f"<b>Your report has been rejected.</b>\n"
                f"Reason: {reason}"
            ),
            parse_mode=ParseMode.HTML,
        )
    except TelegramError:
        pass

    raise ApplicationHandlerStop


async def on_appeal_decision(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    admin = query.from_user

    if not is_privileged(admin.id):
        await query.answer("You are not authorized to do this.", show_alert=True)
        return

    _, action, appeal_id_str = query.data.split(":")
    appeal_id = int(appeal_id_str)
    a = db_get_appeal(appeal_id)

    if not a:
        await query.answer("Appeal not found.", show_alert=True)
        return
    if a["status"] != "pending":
        await query.answer("This appeal has already been decided.", show_alert=True)
        return

    r = db_get_report(a["report_id"])

    if action == "accept":
        db_decide_appeal(appeal_id, "approved", admin.id, admin.username)
        db_decide_report(
            r["id"], "rejected", admin.id, admin.username,
            reject_reason="Appeal upheld - report was found to be a mistake.",
        )
        await query.answer("Appeal accepted - report removed.")

        if r.get("channel_message_id"):
            try:
                await context.bot.delete_message(
                    chat_id=f"@{CHANNEL_USERNAME}", message_id=r["channel_message_id"]
                )
            except TelegramError as e:
                log.warning("Could not delete channel post for report %s: %s", r["id"], e)

        footer = f"\n\n{DIVIDER}\nAppeal decision: ACCEPTED by @{admin.username or admin.id}"
        await refresh_appeal_admin_copies(context, appeal_id, footer)

        try:
            await context.bot.send_message(
                chat_id=a["reporter_id"],
                text=(
                    "<b>Your appeal was reviewed and accepted.</b>\n"
                    "The report was found to be a mistake and has been removed."
                ),
                parse_mode=ParseMode.HTML,
            )
        except TelegramError:
            pass

    elif action == "reject":
        db_decide_appeal(appeal_id, "rejected", admin.id, admin.username)
        await query.answer("Appeal rejected.")

        footer = f"\n\n{DIVIDER}\nAppeal decision: REJECTED by @{admin.username or admin.id}"
        await refresh_appeal_admin_copies(context, appeal_id, footer)

        try:
            await context.bot.send_message(
                chat_id=a["reporter_id"],
                text=(
                    "<b>Your appeal was reviewed and denied.</b>\n"
                    "The report stands."
                ),
                parse_mode=ParseMode.HTML,
            )
        except TelegramError:
            pass


async def cmd_pfp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if not is_privileged(admin.id):
        await update.message.reply_text("You are not authorized to do this.")
        return

    awaiting_pfp.add(admin.id)
    await update.message.reply_text(
        "Send the photo to use as the flagged-user photo for every future report."
    )


async def handle_pfp_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if admin.id not in awaiting_pfp:
        return  # this admin isn't currently in a /pfp flow, ignore
    awaiting_pfp.discard(admin.id)

    if not update.message.photo:
        await update.message.reply_text("That wasn't a photo. Run /pfp again.")
        raise ApplicationHandlerStop

    file_id = update.message.photo[-1].file_id  # largest resolution
    db_set_config("default_scammer_photo", file_id)

    await update.message.reply_text("✅ Flagged-user photo updated.")
    raise ApplicationHandlerStop


async def cmd_pfp2(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if admin.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return

    awaiting_pfp2.add(admin.id)
    await update.message.reply_text(
        "Send the photo to use as the welcome banner shown on /start."
    )


async def handle_pfp2_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if admin.id not in awaiting_pfp2:
        return  # this admin isn't currently in a /pfp2 flow, ignore
    awaiting_pfp2.discard(admin.id)

    if not update.message.photo:
        await update.message.reply_text("That wasn't a photo. Run /pfp2 again.")
        raise ApplicationHandlerStop

    file_id = update.message.photo[-1].file_id  # largest resolution
    db_set_config("welcome_photo", file_id)

    await update.message.reply_text("✅ Welcome banner updated.")
    raise ApplicationHandlerStop


async def cmd_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/txt <text>  - set the custom welcome text shown on /start.
    /txt reset      - go back to the default welcome text.
    /txt            - show usage and the current text."""
    admin = update.effective_user
    if admin.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return

    # Take everything after the command so line breaks are preserved.
    parts = (update.message.text or "").split(None, 1)
    new_text = parts[1].strip() if len(parts) > 1 else ""

    if not new_text:
        current = db_get_config("welcome_text")
        await update.message.reply_text(
            "Usage:\n"
            "/txt <your welcome text>  - set custom welcome text\n"
            "/txt reset  - restore the default text\n\n"
            + ("Current custom text:\n\n" + current if current else "Currently using the default text.")
        )
        return

    if new_text.lower() == "reset":
        db_set_config("welcome_text", "")
        await update.message.reply_text("✅ Welcome text reset to default.")
        return

    # Telegram caps photo captions at 1024 chars, and the welcome banner
    # is sent as a caption when a /pfp2 photo is set.
    if len(new_text) > 1024:
        await update.message.reply_text(
            f"Text is too long ({len(new_text)}/1024 characters). Please shorten it."
        )
        return

    db_set_config("welcome_text", new_text)
    await update.message.reply_text("✅ Welcome text updated. Send /start to preview it.")


async def cmd_pfp3(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if not is_privileged(admin.id):
        await update.message.reply_text("You are not authorized to do this.")
        return

    awaiting_pfp3.add(admin.id)
    await update.message.reply_text(
        "Send the photo to use as the banner on impersonator alert posts."
    )


async def handle_pfp3_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if admin.id not in awaiting_pfp3:
        return  # this admin isn't currently in a /pfp3 flow, ignore
    awaiting_pfp3.discard(admin.id)

    if not update.message.photo:
        await update.message.reply_text("That wasn't a photo. Run /pfp3 again.")
        raise ApplicationHandlerStop

    file_id = update.message.photo[-1].file_id  # largest resolution
    db_set_config("impersonator_photo", file_id)

    await update.message.reply_text("✅ Impersonator banner updated.")
    raise ApplicationHandlerStop


# ==============================================================================
# /check - image card (needs Pillow: pip install pillow). Without Pillow the
# command still works and replies with text only.
# ==============================================================================
try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageChops, ImageOps
    PIL_OK = True
except ImportError:  # pragma: no cover
    PIL_OK = False

CARD_W, CARD_H = 1280, 720
_WHITE = (245, 245, 245)
_GREY = (150, 150, 158)

# note = two lines; (text, True) segments are drawn in the accent colour.
CARD_THEMES = {
    "scammer": dict(
        accent=(255, 56, 56), bg=(12, 2, 4), bg2=(48, 6, 12), icon="warn", hazard=True,
        fill=((255, 78, 78), (170, 10, 24)), badge_text=(255, 255, 255), badge=["SCAMMER"],
        note=[[("This account has been ", 0), ("FLAGGED", 1)], [("as a ", 0), ("SCAMMER", 1), (" - stay away!", 0)]],
    ),
    "clean": dict(
        accent=(232, 232, 238), bg=(8, 8, 10), bg2=(34, 34, 40), icon="check", hazard=False,
        fill=((248, 248, 250), (178, 178, 190)), badge_text=(16, 16, 20), badge=["NON", "SCAMMER"],
        note=[[("This account is ", 0), ("not flagged", 1)], [("No reports found - ", 0), ("non-scammer", 1)]],
    ),
    "trusted": dict(
        accent=(46, 232, 100), bg=(2, 12, 6), bg2=(6, 48, 20), icon="check", hazard=False,
        fill=((76, 244, 118), (14, 140, 52)), badge_text=(3, 28, 10), badge=["TRUSTED"],
        note=[[("This account is ", 0), ("TRUSTED", 1), (" and ", 0), ("verified", 1)],
              [("Middleman", 1), (" for ", 0), ("secure", 1), (" transactions", 0)]],
    ),
    "pending": dict(
        accent=(255, 198, 40), bg=(14, 10, 2), bg2=(52, 36, 4), icon="info", hazard=True,
        fill=((255, 210, 76), (214, 140, 8)), badge_text=(40, 28, 0), badge=["UNDER", "REVIEW"],
        note=[[("Reports are ", 0), ("UNDER REVIEW", 1)], [("by ", 0), ("moderators", 1), (" - be careful", 0)]],
    ),
}

# Poppins Bold (SIL Open Font License 1.1), cut down to basic Latin: ~9 KB, so the
# card looks the same on every machine. Text with other scripts uses a system font.
_POPPINS_CHARS = set(chr(c) for c in range(0x20, 0x7F)) | set("•·–—‘’“”…×₹€£¥°")
_font_cache: dict = {}
_poppins_data: bytes | None = None

_FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
    "/system/fonts/Roboto-Bold.ttf",
    "/system/fonts/DroidSans-Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "DejaVuSans-Bold.ttf",
    "arialbd.ttf",
]


def _font(size: int, text: str | None = None):
    """Poppins Bold when it can draw `text`, otherwise the best system font."""
    global _poppins_data
    import io
    use_poppins = text is None or all(ch in _POPPINS_CHARS for ch in text)
    key = (size, use_poppins)
    if key in _font_cache:
        return _font_cache[key]
    font = None
    if use_poppins:
        try:
            if _poppins_data is None:
                _poppins_data = zlib.decompress(base64.b64decode(_POPPINS_B64))
            font = ImageFont.truetype(io.BytesIO(_poppins_data), size)
        except Exception:
            font = None
    if font is None:
        for path in _FONT_PATHS:
            try:
                font = ImageFont.truetype(path, size)
                break
            except OSError:
                continue
    if font is None:
        try:
            font = ImageFont.load_default(size=size)  # Pillow >= 10.1, scalable
        except TypeError:
            font = ImageFont.load_default()
    _font_cache[key] = font
    return font


def _clean_name(text: str) -> str:
    """Drop emoji / joiners the card font can't draw (they'd show as boxes)."""
    return re.sub(r"[\U0001F000-\U0001FFFF\u2600-\u27BF\u2B00-\u2BFF\u200d\ufe0f]", "", text or "").strip()


def _fmt_stat(n: float) -> str:
    n = int(n)
    if n < 100:
        return f"{n:02d}"
    if n < 1000:
        return str(n)
    return f"{n / 1000:.1f}K".replace(".0K", "K")


def _parse_amount(text) -> float:
    m = re.search(r"\d[\d,]*\.?\d*", str(text or ""))
    if not m:
        return 0.0
    try:
        return float(m.group().replace(",", ""))
    except ValueError:
        return 0.0


def render_check_card(state: str, display: str, username: str | None,
                      stats: dict, avatar_bytes: bytes | None = None) -> bytes | None:
    """Draws the status card and returns PNG bytes (None if Pillow missing)."""
    if not PIL_OK:
        return None
    import io

    th = CARD_THEMES[state]
    acc = th["accent"]
    dim = tuple(int(c * 0.55) for c in acc)
    tint = tuple(int(c * 0.14) + 8 for c in acc)
    dark = th["bg"]
    S = 2                                   # draw at 2x, shrink at the end = smooth edges
    W, H = CARD_W * S, CARD_H * S

    def s(v):
        return int(round(v * S))

    # ---- background: gradient, texture, glows -------------------------------
    grad = Image.linear_gradient("L").resize((W, H))
    img = Image.composite(Image.new("RGB", (W, H), th["bg2"]), Image.new("RGB", (W, H), th["bg"]), grad)

    tex = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    td = ImageDraw.Draw(tex)
    for x in range(-H, W, s(30)):           # fine diagonal lines
        td.line([(x, 0), (x + H, H)], fill=acc + (13,), width=s(2))
    img = Image.alpha_composite(img.convert("RGBA"), tex).convert("RGB")

    def glow(cx, cy, rx, ry, strength):     # soft colour bloom (made small, blown up = fast)
        q = 4
        layer = Image.new("RGB", (W // q, H // q), (0, 0, 0))
        ImageDraw.Draw(layer).ellipse(
            [s(cx - rx) // q, s(cy - ry) // q, s(cx + rx) // q, s(cy + ry) // q],
            fill=tuple(int(c * strength) for c in acc))
        layer = layer.filter(ImageFilter.GaussianBlur(s(60) // q)).resize((W, H), Image.BILINEAR)
        return layer

    img = ImageChops.add(img, glow(230, 300, 230, 230, 0.55))      # behind the avatar
    img = ImageChops.add(img, glow(1095, 315, 190, 210, 0.45))     # behind the badge

    frame_glow = Image.new("RGB", (W, H), (0, 0, 0))
    ImageDraw.Draw(frame_glow).rounded_rectangle(
        [s(12), s(12), W - s(12), H - s(12)], radius=s(30), outline=tuple(int(c * 0.8) for c in acc), width=s(12))
    img = ImageChops.add(img, frame_glow.filter(ImageFilter.GaussianBlur(s(14))))
    d = ImageDraw.Draw(img)

    def rr(box, r, outline=None, fill=None, w=3):
        d.rounded_rectangle([s(v) for v in box], radius=s(r), outline=outline, fill=fill, width=s(w))

    def F(size, t=None):
        return _font(s(size), t)

    def text(xy, t, font, fill, anchor="la"):
        d.text((s(xy[0]), s(xy[1])), t, font=font, fill=fill, anchor=anchor)

    def fitted(t, max_w, size, min_size=20):
        while size > min_size and d.textlength(t, font=F(size, t)) > s(max_w):
            size -= 2
        f = F(size, t)
        while len(t) > 3 and d.textlength(t, font=f) > s(max_w):
            t = t[:-2].rstrip() + "…"
        return t, F(size, t)

    def hazard_bar(y0, y1):
        x0, x1 = 34, CARD_W - 34
        base = Image.new("RGB", (s(x1 - x0), s(y1 - y0)), tuple(int(c * 0.16) for c in acc))
        sd = ImageDraw.Draw(base)
        h = y1 - y0
        for x in range(-h, x1 - x0 + h, 52):
            sd.polygon([(s(x), s(h)), (s(x + 26), s(h)), (s(x + 26 + h), 0), (s(x + h), 0)], fill=acc)
        img.paste(base, (s(x0), s(y0)))

    if th["hazard"]:
        hazard_bar(24, 42)
        hazard_bar(CARD_H - 42, CARD_H - 24)
    else:
        for y0, y1 in ((24, 42), (CARD_H - 42, CARD_H - 24)):
            d.rounded_rectangle([s(34), s(y0 + 5), s(CARD_W - 34), s(y1 - 5)], radius=s(4), fill=acc)
    rr([12, 12, CARD_W - 12, CARD_H - 12], 30, outline=acc, w=4)

    # ---- top bar: tag + powered by ------------------------------------------
    rr([60, 58, 292, 106], 24, fill=acc, outline=None)
    text((176, 82), "USER CHECK", F(24), th["badge_text"], "mm")
    f_pb = F(24)
    a, b = "POWERED BY  ", POWERED_BY
    wb = d.textlength(b, font=f_pb) / S
    text((CARD_W - 60 - wb, 82), b, f_pb, acc, "lm")
    text((CARD_W - 60 - wb - d.textlength(a, font=f_pb) / S, 82), a, f_pb, _GREY, "lm")

    # ---- avatar ---------------------------------------------------------------
    cx, cy, R = 230, 318, 150
    side = s(R * 2)
    face = Image.new("RGB", (side, side), (30, 30, 36))
    got_photo = False
    if avatar_bytes:
        try:
            photo = Image.open(io.BytesIO(avatar_bytes)).convert("RGB")
            face = ImageOps.fit(photo, (side, side), Image.LANCZOS)
            got_photo = True
        except Exception:
            pass
    if not got_photo:
        fd = ImageDraw.Draw(face)
        fd.ellipse([side * 0.34, side * 0.2, side * 0.66, side * 0.52], fill=(118, 118, 130))
        fd.ellipse([side * 0.16, side * 0.56, side * 0.84, side * 1.2], fill=(118, 118, 130))
    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, side - 1, side - 1], fill=255)
    d.ellipse([s(cx - R - 18), s(cy - R - 18), s(cx + R + 18), s(cy + R + 18)], outline=dim, width=s(3))
    d.ellipse([s(cx - R - 11), s(cy - R - 11), s(cx + R + 11), s(cy + R + 11)], outline=acc, width=s(9))
    img.paste(face, (s(cx - R), s(cy - R)), mask)
    # status chip on the avatar
    chx, chy = cx + int(R * 0.74), cy + int(R * 0.74)
    d.ellipse([s(chx - 40), s(chy - 40), s(chx + 40), s(chy + 40)], fill=th["bg"])
    d.ellipse([s(chx - 33), s(chy - 33), s(chx + 33), s(chy + 33)], fill=acc)
    if th["icon"] == "warn":
        text((chx, chy + 2), "!", F(44), dark, "mm")
    elif th["icon"] == "check":
        d.line([(s(chx - 15), s(chy + 1)), (s(chx - 4), s(chy + 13)), (s(chx + 17), s(chy - 12))],
               fill=dark, width=s(8), joint="curve")
    else:
        text((chx, chy + 2), "i", F(44), dark, "mm")

    # ---- name block -------------------------------------------------------------
    name, f_name = fitted(_clean_name(display) or "Unknown", 500, 64, min_size=40)   # long names get "..." instead of tiny text
    text((430, 190), name, f_name, _WHITE, "lm")
    handle, f_handle = fitted(f"@{username}" if username else "No username", 500, 42, min_size=28)
    text((430, 256), handle, f_handle, acc, "lm")
    d.rounded_rectangle([s(430), s(296), s(930), s(300)], radius=s(2), fill=dim)
    d.rounded_rectangle([s(430), s(296), s(560), s(300)], radius=s(2), fill=acc)

    # ---- verdict note ------------------------------------------------------------
    rr([430, 326, 930, 458], 28, outline=dim, fill=tint, w=3)
    d.rounded_rectangle([s(430), s(326), s(446), s(458)], radius=s(8), fill=acc)
    d.ellipse([s(480), s(362), s(552), s(434)], fill=acc)
    d.ellipse([s(504), s(373), s(528), s(397)], fill=dark)                    # head
    d.pieslice([s(493), s(400), s(539), s(446)], 180, 360, fill=dark)         # shoulders
    for i, segs in enumerate(th["note"]):
        size, y = 28, 378 + i * 42
        while size > 15:
            f = F(size)
            if sum(d.textlength(t, font=f) for t, _ in segs) <= s(350):
                break
            size -= 1
        xx = 572.0
        for t, hot in segs:
            text((xx, y), t, f, acc if hot else _WHITE, "lm")
            xx += d.textlength(t, font=f) / S

    # ---- verdict badge (solid, bold) -------------------------------------------------
    bx0, by0, bx1, by1 = 960, 190, 1230, 458
    bw, bh = s(bx1 - bx0), s(by1 - by0)
    g = Image.linear_gradient("L").resize((bw, bh))
    fill_img = Image.composite(Image.new("RGB", (bw, bh), th["fill"][1]), Image.new("RGB", (bw, bh), th["fill"][0]), g)
    bmask = Image.new("L", (bw, bh), 0)
    ImageDraw.Draw(bmask).rounded_rectangle([0, 0, bw - 1, bh - 1], radius=s(34), fill=255)
    img.paste(fill_img, (s(bx0), s(by0)), bmask)
    d.rounded_rectangle([s(bx0), s(by0), s(bx1), s(by1)], radius=s(34), outline=_WHITE if state != "clean" else acc, width=s(3))
    ix, iy = (bx0 + bx1) // 2, 285
    bt, cut = th["badge_text"], th["fill"][0]
    if th["icon"] == "warn":
        pts = [(ix, iy - 52), (ix + 58, iy + 44), (ix - 58, iy + 44)]
        d.polygon([(s(px), s(py)) for px, py in pts], fill=bt)
        d.line([(s(px), s(py)) for px, py in pts + [pts[0]]], fill=bt, width=s(10), joint="curve")
        text((ix, iy + 18), "!", F(58), th["fill"][1], "mm")
    elif th["icon"] == "check":
        d.ellipse([s(ix - 52), s(iy - 52), s(ix + 52), s(iy + 52)], fill=bt)
        d.line([(s(ix - 26), s(iy + 2)), (s(ix - 7), s(iy + 22)), (s(ix + 28), s(iy - 20))],
               fill=cut, width=s(13), joint="curve")
    else:
        d.ellipse([s(ix - 52), s(iy - 52), s(ix + 52), s(iy + 52)], fill=bt)
        text((ix, iy + 3), "i", F(70), cut, "mm")
    lines = th["badge"]
    for i, line in enumerate(lines):
        t, f = fitted(line, 240, 52 if len(lines) == 1 else 44)
        y = 404 if len(lines) == 1 else 386 + i * 46
        text((ix, y), t, f, bt, "mm")

    # ---- stats row ----------------------------------------------------------------------
    cells = [("REPORTS", _fmt_stat(stats["reports"])), ("VICTIMS", _fmt_stat(stats["victims"])),
             ("SCAMMED", _fmt_stat(stats["scammed"])), ("LAST REPORT", stats["last"])]
    tw, gap = 280, 20
    x0 = (CARD_W - (4 * tw + 3 * gap)) / 2
    for i, (label, value) in enumerate(cells):
        tx = x0 + i * (tw + gap)
        rr([tx, 494, tx + tw, 650], 26, outline=dim, fill=tint, w=2)
        d.rounded_rectangle([s(tx + 26), s(494), s(tx + tw - 26), s(502)], radius=s(4), fill=acc)
        t, f = fitted(value, tw - 36, 66)
        text((tx + tw / 2, 562), t, f, _WHITE, "mm")
        text((tx + tw / 2, 622), label, F(22), acc, "mm")

    out = io.BytesIO()
    img.resize((CARD_W, CARD_H), Image.LANCZOS).save(out, format="PNG", optimize=True)
    return out.getvalue()


_tele_client = None
_tele_disabled = False


async def _get_tele_client():
    """Lazily connect the optional user-account client (Telethon)."""
    global _tele_client, _tele_disabled
    if _tele_disabled or not (TG_API_ID and TG_API_HASH and TG_SESSION):
        return None
    if _tele_client is not None:
        return _tele_client
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        log.warning("TG_SESSION is set but telethon isn't installed (pip install telethon)")
        _tele_disabled = True
        return None
    try:
        client = TelegramClient(StringSession(TG_SESSION), TG_API_ID, TG_API_HASH)
        await client.connect()
        if not await client.is_user_authorized():
            log.warning("TG_SESSION is not logged in - run: python scem_bot.py --make-session")
            await client.disconnect()
            _tele_disabled = True
            return None
        _tele_client = client
        return client
    except Exception as e:  # network hiccup: try again on the next /check
        log.warning("Could not start user-account client: %s", e)
        return None


async def _tele_lookup(username: str | None, user_id: str | None):
    client = await _get_tele_client()
    if client is None:
        return None
    from telethon import utils

    async def go():
        candidates = []
        if username:
            candidates.append(username)
        if user_id and str(user_id).lstrip("-").isdigit():
            candidates.append(int(user_id))
            try:  # last resort for an ID this account has never met
                from telethon.tl.types import InputPeerUser
                candidates.append(InputPeerUser(int(user_id), 0))
            except Exception:
                pass
        for cand in candidates:
            try:
                ent = await client.get_entity(cand)
            except Exception:
                continue
            photo = None
            try:
                photo = await client.download_profile_photo(ent, file=bytes)
            except Exception as e:
                log.info("Could not download profile photo: %s", e)
            return dict(
                display=utils.get_display_name(ent) or None,
                username=getattr(ent, "username", None),
                user_id=str(ent.id),
                photo=bytes(photo) if photo else None,
                is_user=type(ent).__name__ == "User",
            )
        return None

    try:
        return await asyncio.wait_for(go(), 20)
    except Exception as e:
        log.info("User-account lookup failed: %s", e)
        return None


# ---- public profile page (https://t.me/<username>): name + photo, no login ----
_TG_IMAGE_HOSTS = (".cdn-telegram.org", ".telesco.pe", ".telegram.org", "t.me")
_web_cache: dict[str, tuple[float, dict]] = {}


def _http_get(url: str, timeout: int = 8) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; WorkSaferBot/1.0)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(6_000_000)


def _trusted_image_url(url: str) -> bool:
    from urllib.parse import urlparse
    u = urlparse(url)
    host = (u.hostname or "").lower()
    return u.scheme == "https" and any(host == h.lstrip(".") or host.endswith(h) for h in _TG_IMAGE_HOSTS)


async def web_profile(username: str | None, debug: list | None = None, use_cache: bool = True) -> dict:
    """Display name + profile photo from Telegram's public page for @username.
    Works for any public account whose photo isn't hidden. Gives no numeric ID.
    `debug` (a list) receives the reasons when nothing is found."""
    import time
    name = (username or "").lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_]{4,32}", name):
        if debug is not None:
            debug.append("not a valid @username")
        return {}
    key = name.lower()
    cached = _web_cache.get(key) if use_cache else None
    if cached and time.time() - cached[0] < 600:
        return cached[1]

    page, errors = None, []
    for host in ("t.me", "telegram.me"):          # second host in case the first is blocked
        try:
            raw = await asyncio.wait_for(asyncio.to_thread(_http_get, f"https://{host}/{name}"), 12)
            page = raw.decode("utf-8", "replace")
            break
        except Exception as e:
            errors.append(f"{host}: {type(e).__name__} {e}")
    if page is None:
        log.info("Public profile lookup failed for @%s: %s", name, "; ".join(errors))
        if debug is not None:
            debug.extend(errors)
        return {}

    result: dict = {}
    m = re.search(r'<div class="tgme_page_title"[^>]*>(.*?)</div>', page, re.S)
    title = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else None
    if not title:  # fall back to the page's meta tags
        og = re.search(r'<meta property="og:title" content="([^"]*)"', page)
        title = html.unescape(og.group(1)).strip() if og else None
        if title and title.lower().startswith("telegram: contact"):
            title = None
    if title and title.lower() != f"@{key}":   # a bare @handle means "no real name"
        result["display"] = title

    photo_url = None
    for tag in re.findall(r"<img[^>]+>", page):
        if "tgme_page_photo_image" in tag:
            src = re.search(r'src="([^"]+)"', tag)
            photo_url = html.unescape(src.group(1)) if src else None
            break
    if not photo_url:
        og = re.search(r'<meta property="og:image" content="([^"]*)"', page)
        cand = html.unescape(og.group(1)) if og else ""
        if cand and "t_logo" not in cand and "/img/" not in cand:
            photo_url = cand
    if photo_url and _trusted_image_url(photo_url):
        try:
            result["photo"] = await asyncio.wait_for(asyncio.to_thread(_http_get, photo_url), 12)
        except Exception as e:
            if debug is not None:
                debug.append(f"photo download: {type(e).__name__} {e}")

    if not result and debug is not None:
        debug.append("page loaded but shows no name or photo (account missing, private, or photo hidden)")
    _web_cache[key] = (time.time(), result)
    return result


async def fetch_profile_info(bot, username: str | None, user_id: str | None) -> dict:
    """Name, @username, numeric ID and photo - from every source we have:
    user-account login -> bot memory / Bot API -> Telegram's public page."""
    info = await _fetch_profile_core(bot, username, user_id)
    handle = info.get("username") or username
    if handle and not (info["photo"] and info["display"]):
        web = await web_profile(handle)
        if web.get("display") and not info["display"]:
            info["display"] = web["display"]
        if web.get("photo") and not info["photo"]:
            info["photo"] = web["photo"]
    return info


async def _fetch_profile_core(bot, username: str | None, user_id: str | None) -> dict:
    """Display name, username, numeric ID and profile photo - whatever we can
    find. Order: user-account client (sees everyone) -> Bot API (only accounts
    that already talked to this bot). Missing pieces come back as None."""
    info = dict(display=None, username=None, user_id=None, photo=None, is_user=True)

    # People who talked to this bot (or were reported) are remembered, so an
    # ID can be turned into a @username and the other way round.
    seen = db_find_seen(user_id or username)
    if seen:
        user_id = user_id or seen["user_id"]
        username = username or seen["username"]
        info["display"], info["username"], info["user_id"] = seen["display_name"], seen["username"], seen["user_id"]

    tele = await _tele_lookup(username, user_id)
    if tele:
        info["is_user"] = tele.pop("is_user", True)
        info.update({k: v for k, v in tele.items() if v})
        if info["photo"]:
            return info

    # Bot API only sees accounts that have talked to this bot.
    targets = []
    if user_id and str(user_id).lstrip("-").isdigit():
        targets.append(int(user_id))
    if username:
        targets.append(f"@{username}")
    chat = None
    for target in targets:
        try:
            chat = await bot.get_chat(target)
            break
        except TelegramError:
            continue
    if chat is None:
        return info

    info["display"] = getattr(chat, "full_name", None) or getattr(chat, "title", None) or chat.first_name or info["display"]
    info["username"] = chat.username or info["username"]
    info["user_id"] = str(chat.id)
    info["is_user"] = getattr(chat, "type", "private") == "private"
    try:
        file_id = chat.photo.big_file_id if chat.photo else None
        if not file_id and chat.type == "private":
            pics = await bot.get_user_profile_photos(chat.id, limit=1)
            if pics.total_count:
                file_id = pics.photos[0][-1].file_id
        if file_id:
            f = await bot.get_file(file_id)
            info["photo"] = bytes(await f.download_as_bytearray())
    except Exception as e:  # photo hidden / network - card just gets a placeholder
        log.info("Could not download profile photo: %s", e)
    return info


async def remember_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Runs on every update, never blocks other handlers. Keeps a @username -> ID
    list of everyone the bot sees (senders, people replied to, joiners, forwards,
    mentions), which is what lets /id @username work in groups."""
    try:
        people = []
        if update.effective_user:
            people.append(update.effective_user)
        msg = update.effective_message
        if msg:
            if msg.reply_to_message and msg.reply_to_message.from_user:
                people.append(msg.reply_to_message.from_user)
            people += list(getattr(msg, "new_chat_members", None) or [])
            if getattr(msg, "left_chat_member", None):
                people.append(msg.left_chat_member)
            origin = getattr(msg, "forward_origin", None)
            fwd = getattr(origin, "sender_user", None) or getattr(msg, "forward_from", None)
            if fwd:
                people.append(fwd)
            for ent in (getattr(msg, "entities", None) or []):
                if ent.type == "text_mention" and ent.user:
                    people.append(ent.user)
        cm = getattr(update, "chat_member", None)
        if cm and getattr(cm, "new_chat_member", None):
            people.append(cm.new_chat_member.user)
        for person in people:
            if person and not person.is_bot:
                db_remember_user(person.id, person.username, person.full_name)
    except Exception as e:
        log.debug("remember_user failed: %s", e)


async def quick_resolve(bot, raw: str) -> dict | None:
    """@username or ID -> {id, name, username}. Fast sources only (no web pages):
    people the bot has seen -> earlier reports -> verified list -> user-account
    login -> Bot API."""
    raw = (raw or "").strip()
    is_id = raw.lstrip("-").isdigit()
    username = None if is_id else raw.lstrip("@")

    seen = db_find_seen(raw)
    if seen:
        return dict(id=seen["user_id"], name=seen["display_name"], username=seen["username"])
    known = db_known_id_for_username(username) if username else None
    if known:
        return dict(id=known, name=None, username=username)
    verified = db_find_verified(raw)
    if verified and verified.get("user_id"):
        return dict(id=verified["user_id"], name=verified.get("display_name"), username=verified.get("username"))

    tele = await _tele_lookup(username, raw if is_id else None)
    if tele and tele.get("user_id"):
        return dict(id=tele["user_id"], name=tele.get("display"), username=tele.get("username") or username)
    try:
        chat = await bot.get_chat(int(raw) if is_id else f"@{username}")
        return dict(id=str(chat.id), name=getattr(chat, "full_name", None) or getattr(chat, "title", None),
                    username=chat.username or username)
    except TelegramError:
        return None


def _who(name, username, uid) -> str:
    label = name or (f"@{username}" if username else str(uid))
    return html.escape(label)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Like Rose: /id @username | /id ID | reply with /id | /id alone."""
    msg = update.message
    chat = update.effective_chat

    if context.args:
        raw = context.args[0].strip()
        found = await quick_resolve(context.bot, raw)
        if not found:
            await msg.reply_text(
                f"❌ I couldn't find {html.escape(raw)}.\n"
                "I only know people who have sent a message where I can see it, or who have talked to me. "
                "Reply to one of their messages with /id, or forward one to me in private.",
                parse_mode=ParseMode.HTML,
            )
            return
        await msg.reply_text(
            f"User {_who(found['name'], found['username'], found['id'])}'s ID is <code>{found['id']}</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    lines = []
    target = msg.reply_to_message
    if target and target.from_user:
        u = target.from_user
        db_remember_user(u.id, u.username, u.full_name)
        lines.append(f"User {_who(u.full_name, u.username, u.id)}'s ID is <code>{u.id}</code>.")
        origin = getattr(target, "forward_origin", None)
        fwd = getattr(origin, "sender_user", None) or getattr(target, "forward_from", None)
        if fwd:
            lines.append(f"The original sender, {_who(fwd.full_name, fwd.username, fwd.id)}, has an ID of <code>{fwd.id}</code>.")
        fchat = getattr(origin, "chat", None) or getattr(target, "forward_from_chat", None)
        if fchat:
            lines.append(f"The forwarded channel, {html.escape(fchat.title or '')}, has an ID of <code>{fchat.id}</code>.")
    else:
        me = update.effective_user
        lines.append(f"Your ID is <code>{me.id}</code>.")
        if chat.type != "private":
            lines.append(f"This chat's ID is <code>{chat.id}</code>.")
    await msg.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_pfpcheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/pfpcheck @username - admin diagnostic: why is (or isn't) a photo found?"""
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /pfpcheck @username")
        return
    q = context.args[0].lstrip("@")
    is_id = q.lstrip("-").isdigit()
    out = [f"Photo lookup for {q}:"]

    if not (TG_API_ID and TG_API_HASH and TG_SESSION):
        out.append("• User-account login: NOT set up (TG_API_ID / TG_API_HASH / TG_SESSION are empty)."
                   " Without it only people who have messaged this bot can show a photo.")
    else:
        try:
            import telethon  # noqa: F401
        except ImportError:
            out.append("• telethon is not installed (pip install telethon)")
        else:
            client = await _get_tele_client()
            if client is None:
                out.append("• User-account login: FAILED - check the bot log, re-run --make-session")
            else:
                out.append("• User-account login: OK")
                try:
                    ent = await client.get_entity(int(q) if is_id else q)
                    out.append(f"• Found account: {getattr(ent, 'first_name', None) or getattr(ent, 'title', '?')}, id {ent.id}")
                    photo = await client.download_profile_photo(ent, file=bytes)
                    out.append(f"• Profile photo: {'downloaded (%d KB)' % (len(photo) // 1024) if photo else 'none (no photo, or hidden by privacy settings)'}")
                except Exception as e:
                    out.append(f"• Lookup failed: {type(e).__name__} - {e}")

    seen = db_find_seen(q)
    if not is_id:
        why = []
        web = await web_profile(q, debug=why, use_cache=False)
        out.append("• Public t.me page: " + (
            f"name {web.get('display') or '(none)'}, photo {'yes' if web.get('photo') else 'no (hidden, or none)'}"
            if web else "nothing found - " + ("; ".join(why) or "no details")))
    out.append("• Has messaged this bot: " + (f"yes (id {seen['user_id']})" if seen else "no"))
    try:
        await context.bot.get_chat(int(seen["user_id"]) if seen else (int(q) if is_id else f"@{q}"))
        out.append("• Bot API can see this account: yes")
    except TelegramError as e:
        out.append(f"• Bot API can see this account: no ({e})")
    await update.message.reply_text("\n".join(out))


async def auto_user_id_why(bot, username: str | None) -> tuple[str | None, str]:
    """(numeric ID of a PERSON by @username, reason if not found).
    Order: earlier reports -> remembered bot users -> user-account lookup -> Bot API."""
    username = (username or "").lstrip("@")
    if not username:
        return None, "the report has no @username"
    known = db_known_id_for_username(username)
    if known:
        return known, ""
    info = await fetch_profile_info(bot, username, None)
    uid = info.get("user_id")
    if uid and str(uid).isdigit() and info.get("is_user", True):
        return str(uid), ""
    if uid and not info.get("is_user", True):
        return None, f"@{username} is a channel or group, not a person"
    if not (TG_API_ID and TG_API_HASH and TG_SESSION):
        return None, ("the user-account login isn't set up (TG_API_ID / TG_API_HASH / TG_SESSION), "
                      "so the bot can only find people who already used it")
    if _tele_disabled:
        return None, "the user-account login isn't working (telethon missing or TG_SESSION expired)"
    return None, f"Telegram couldn't find @{username} (typo, deleted account, or the username changed)"


async def auto_user_id(bot, username: str | None) -> str | None:
    return (await auto_user_id_why(bot, username))[0]


async def autofill_report_ids(context: ContextTypes.DEFAULT_TYPE, report_id: int):
    """Right after a report is submitted: grab the numeric IDs while the
    username still points at the right account (people change usernames)."""
    try:
        r = db_get_report(report_id)
        if not r["target_id"] and r["target_username"]:
            tid = await auto_user_id(context.bot, r["target_username"])
            if tid:
                db_set_target_id(report_id, tid)
        if r["target_id"] and not r["target_username"]:       # reported by ID: find the @username if we know it
            found = await quick_resolve(context.bot, r["target_id"])
            if found and found.get("username"):
                db_set_target_username(report_id, "@" + found["username"])
        if r["report_type"] == "impersonation" and not r["original_id"] and r["original_username"]:
            oid = await auto_user_id(context.bot, r["original_username"])
            if oid:
                db_set_original_id(report_id, oid)
    except Exception as e:  # never block a report because a lookup failed
        log.warning("Could not auto-fill IDs for report %s: %s", report_id, e)


async def finalize_accept(context: ContextTypes.DEFAULT_TYPE, admin, report_id: int, target_id: str):
    """Approve + publish a report once the reported account's numeric ID is known."""
    db_set_target_id(report_id, target_id)

    # Impersonation: also fill in the real user's ID if we can find it.
    r = db_get_report(report_id)
    if r["report_type"] == "impersonation" and not r["original_id"]:
        original_id = await auto_user_id(context.bot, r["original_username"])
        if original_id:
            db_set_original_id(report_id, original_id)

    db_decide_report(report_id, "approved", admin.id, admin.username)
    footer = f"\n\n{DIVIDER}\nDecision: APPROVED by @{admin.username or admin.id}"
    await refresh_admin_copies(context, report_id, footer)
    await post_to_channel(context, report_id)

    r = db_get_report(report_id)
    try:
        await context.bot.send_message(
            chat_id=r["reporter_id"],
            text="<b>Your report has been approved</b> and published to the scam exposure channel.",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError:
        pass


def _button_row(items, colored: bool):
    return [_styled_button(t, u, st, colored) for t, u, st in items if u]


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/check @username | /check ID | reply to someone's message with /check."""
    msg = update.message
    reply_user = msg.reply_to_message.from_user if (not context.args and msg.reply_to_message) else None

    if not context.args and not reply_user:
        await msg.reply_text(
            "❌ Usage: <code>/check @username</code>, <code>/check ID</code>, "
            "or reply to someone's message with <code>/check</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    if reply_user and reply_user.id in (1087968824, 136817688):   # anonymous-admin / channel pseudo-users
        await msg.reply_text("I can't check an anonymous admin or a channel post. Reply to a person's message.")
        return

    if reply_user:
        # the person's real ID, @username and name come straight from Telegram
        db_remember_user(reply_user.id, reply_user.username, reply_user.full_name)
        raw = str(reply_user.id)
    else:
        raw = context.args[0].strip()
    is_id = raw.lstrip("-").isdigit()

    rows = db_check_target(raw)
    verified = db_find_verified(raw)
    if reply_user and reply_user.username:      # reports/verified entries may only know the @username
        seen_ids = {r["id"] for r in rows}
        rows += [r for r in db_check_target(reply_user.username) if r["id"] not in seen_ids]
        verified = verified or db_find_verified(reply_user.username)
    if not reply_user and not is_id:       # a NEW @username the bot has seen -> same person's old reports
        seen_row = db_find_seen(raw)
        if seen_row and seen_row.get("user_id"):
            have = {r["id"] for r in rows}
            rows += [r for r in db_check_target(seen_row["user_id"]) if r["id"] not in have]
            verified = verified or db_find_verified(seen_row["user_id"])
    approved = [r for r in rows if r["status"] == "approved"]
    pending = [r for r in rows if r["status"] == "pending"]

    if approved:
        state = "scammer"
    elif verified:
        state = "trusted"
    elif pending:
        state = "pending"
    else:
        state = "clean"

    # who is this? (reports and the verified list may know more than the query)
    known_user = (verified or {}).get("username") or next(
        (r["target_username"] for r in rows if r["target_username"]), None
    )
    known_user = known_user.lstrip("@") if known_user else (None if is_id else raw.lstrip("@"))
    known_id = (verified or {}).get("user_id") or next((r["target_id"] for r in rows if r["target_id"]), None)
    known_id = known_id or (raw if is_id else None)

    if reply_user:
        known_user = known_user or reply_user.username
        known_id = known_id or str(reply_user.id)
    info = await fetch_profile_info(context.bot, known_user, known_id)
    known_user = known_user or info["username"]
    known_id = known_id or info["user_id"]
    avatar = info["photo"]
    if reply_user and not avatar:
        try:
            pics = await context.bot.get_user_profile_photos(reply_user.id, limit=1)
            if pics.total_count:
                f = await context.bot.get_file(pics.photos[0][-1].file_id)
                avatar = bytes(await f.download_as_bytearray())
        except Exception as e:
            log.info("Could not get the replied user's photo: %s", e)
    display = (
        (reply_user.full_name if reply_user else None) or info["display"]
        or (verified or {}).get("display_name") or (f"@{known_user}" if known_user else f"ID {known_id}")
    )

    last = max((r["created_at"] for r in rows if r["created_at"]), default=None)
    try:
        last_txt = datetime.datetime.fromisoformat(last).strftime("%d %b") if last else "-"
    except ValueError:
        last_txt = "-"
    stats = dict(
        reports=len(rows),
        victims=len({r["reporter_id"] for r in approved}),
        scammed=sum(_parse_amount(r.get("amount")) for r in approved if r["report_type"] == "scam"),
        last=last_txt,
    )

    who = f"@{html.escape(known_user)}" if known_user else f"<code>{known_id}</code>"
    id_part = f" (<code>{known_id}</code>)" if known_id and known_user else ""
    status_line = {
        "scammer": "🚫 Status: <b>BANNED SCAMMER</b>",
        "trusted": "🤝 Status: <b>TRUSTED MIDDLEMAN</b>",
        "pending": "⏳ Status: <b>UNDER REVIEW</b>",
        "clean": "📌 Status: <b>CLEAN</b>",
    }[state]
    caption = f"Report History for {who}{id_part}:\n{status_line}"

    profile = profile_url(known_user, known_id)
    report_url = None
    for r in approved:
        if r.get("channel_message_id"):
            report_url = f"https://t.me/{CHANNEL_USERNAME}/{r['channel_message_id']}"
            break
    if state == "scammer":
        layout = [[("🔗 View Report", report_url, "danger")], [("👤 Profile", profile, "primary")]]
    elif state == "trusted":
        layout = [[("👤 Profile", profile, "primary"), ("🔗 View Vouch", (verified or {}).get("vouch_link"), "primary")]]
    elif state == "clean":
        bot_url = None
        if context.bot.username:
            bot_url = f"https://t.me/{context.bot.username}"
            if known_user and re.fullmatch(r"\w{1,64}", known_user):
                bot_url += f"?start=report_u_{known_user}"   # opens a report already aimed at them
            elif known_id and known_id.isdigit():
                bot_url += f"?start=report_i_{known_id}"
        layout = [[("📨 Create Report", bot_url, "danger"), ("👤 Profile", profile, "primary")]]
    else:
        layout = [[("👤 Profile", profile, "primary")]]

    def keyboard(colored: bool):
        rows_ = [r_ for r_ in (_button_row(row, colored) for row in layout) if r_]
        return InlineKeyboardMarkup(rows_) if rows_ else None

    png = None
    try:
        png = render_check_card(state, display, known_user, stats, avatar)
    except Exception as e:
        log.warning("Could not render check card: %s", e)

    import io
    for colored in (True, False):
        try:
            if png:
                await update.message.reply_photo(
                    photo=io.BytesIO(png), caption=caption,
                    parse_mode=ParseMode.HTML, reply_markup=keyboard(colored),
                )
            else:
                await update.message.reply_text(
                    caption, parse_mode=ParseMode.HTML,
                    reply_markup=keyboard(colored), disable_web_page_preview=True,
                )
            return
        except TelegramError as e:
            log.warning("/check reply failed (colored=%s): %s", colored, e)


async def cmd_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/verify @username [ID] [vouch_link] - add a trusted / verified user."""
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return

    username = uid = link = None
    for a in context.args:
        low = a.lower()
        if low.startswith(("http://", "https://", "t.me/")):
            link = a if low.startswith("http") else "https://" + a
        elif a.lstrip("-").isdigit() and len(a.lstrip("-")) >= 5:
            uid = a
        else:
            username = a.lstrip("@")
    if not (username or uid):
        await update.message.reply_text(
            "Usage: /verify @username [ID] [vouch link]\n"
            "Example: /verify @dinku https://t.me/yourvouches/12"
        )
        return

    display = None
    try:
        chat = await context.bot.get_chat(f"@{username}" if username else int(uid))
        uid = uid or str(chat.id)
        username = username or chat.username
        display = getattr(chat, "full_name", None) or getattr(chat, "title", None)
    except TelegramError:
        pass

    db_add_verified(username, uid, display, link, update.effective_user.id)
    who = f"@{username}" if username else uid
    msg = f"✅ {who} added to the verified users list."
    if not uid:
        msg += (
            "\n⚠️ Couldn't look up their numeric ID, so /check will match by @username only. "
            "Add it with /verify @username <ID>."
        )
    if not link:
        msg += "\nTip: add a vouch link so the card shows a \"View Vouch\" button."
    await update.message.reply_text(msg)


async def cmd_unverify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /unverify @username or /unverify ID")
        return
    n = db_remove_verified(context.args[0])
    await update.message.reply_text(
        "✅ Removed from the verified list." if n else "That user isn't on the verified list."
    )


async def cmd_verified(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    items = db_list_verified()
    if not items:
        await update.message.reply_text("No verified users yet. Add one with /verify @username")
        return
    lines = [
        f"{i}. {('@' + v['username']) if v['username'] else v['user_id']}"
        + (f" ({v['user_id']})" if v["username"] and v["user_id"] else "")
        for i, v in enumerate(items, 1)
    ]
    await update.message.reply_text("✅ Verified users:\n\n" + "\n".join(lines))


# ---- /purge: wipe everything the bot stores about one user ----
def _norm_name(v) -> str | None:
    return v.strip().lstrip("@").lower() if v and v.strip() else None


def purge_collect(query: str) -> dict:
    """Find everything stored about this @username / ID (and the ID/username
    that goes with it, when the bot knows both)."""
    q = _norm_name(query) or ""
    names = set() if q.isdigit() else {q}
    ids = {q} if q.isdigit() else set()

    with _conn() as c:
        for _ in range(2):  # name -> id -> name, so both identities are covered
            for n in list(names):
                for tbl in ("seen_users", "verified_users"):
                    ids |= {r[0] for r in c.execute(f"SELECT user_id FROM {tbl} WHERE username = ?", (n,)) if r[0]}
                ids |= {r[0] for r in c.execute(
                    "SELECT target_id FROM reports WHERE LOWER(LTRIM(target_username,'@')) = ? AND target_id IS NOT NULL", (n,))}
            for i in list(ids):
                for tbl in ("seen_users", "verified_users"):
                    names |= {r[0] for r in c.execute(f"SELECT username FROM {tbl} WHERE user_id = ?", (i,)) if r[0]}
                names |= {_norm_name(r[0]) for r in c.execute(
                    "SELECT target_username FROM reports WHERE target_id = ? AND target_username IS NOT NULL", (i,))}
        names.discard(None)

        def cond(col, as_name):
            vals = list(names if as_name else ids)
            if not vals:
                return "0", []
            expr = f"LOWER(LTRIM({col},'@'))" if as_name else col
            return f"{expr} IN ({','.join('?' * len(vals))})", vals

        t_n, t_nv = cond("target_username", True)
        t_i, t_iv = cond("target_id", False)
        reports = [dict(r) for r in c.execute(
            f"SELECT * FROM reports WHERE {t_n} OR {t_i}", t_nv + t_iv).fetchall()]
        o_n, o_nv = cond("original_username", True)
        o_i, o_iv = cond("original_id", False)
        as_original = c.execute(
            f"SELECT COUNT(*) FROM reports WHERE (({o_n}) OR ({o_i})) AND id NOT IN ({','.join('?' * len(reports)) or 'NULL'})",
            o_nv + o_iv + [r["id"] for r in reports]).fetchone()[0] if reports else c.execute(
            f"SELECT COUNT(*) FROM reports WHERE ({o_n}) OR ({o_i})", o_nv + o_iv).fetchone()[0]
        filed_by = c.execute(
            f"SELECT COUNT(*) FROM reports WHERE reporter_id IN ({','.join('?' * len(ids)) or 'NULL'})", list(ids)).fetchone()[0] if ids else 0

        rep_ids = [r["id"] for r in reports]
        a_sql, a_args = [], []
        if rep_ids:
            a_sql.append(f"report_id IN ({','.join('?' * len(rep_ids))})"); a_args += rep_ids
        if ids:
            a_sql.append(f"reporter_id IN ({','.join('?' * len(ids))})"); a_args += [int(i) for i in ids if i.lstrip('-').isdigit()]
        appeals = [r[0] for r in c.execute(f"SELECT id FROM appeals WHERE {' OR '.join(a_sql)}", a_args)] if a_sql else []

        u_n = ("username IN (%s)" % ",".join("?" * len(names))) if names else "0"
        u_i = ("user_id IN (%s)" % ",".join("?" * len(ids))) if ids else "0"
        u_args = list(names) + list(ids)
        verified = c.execute(f"SELECT COUNT(*) FROM verified_users WHERE {u_n} OR {u_i}", u_args).fetchone()[0]
        seen = c.execute(f"SELECT COUNT(*) FROM seen_users WHERE {u_n} OR {u_i}", u_args).fetchone()[0]

    return dict(names=sorted(names), ids=sorted(ids), reports=reports, appeals=appeals,
                verified=verified, seen=seen, as_original=as_original, filed_by=filed_by,
                _u=(u_n, u_i, u_args))


def purge_delete(found: dict):
    rep_ids = [r["id"] for r in found["reports"]]
    u_n, u_i, u_args = found["_u"]
    with _conn() as c:
        if found["appeals"]:
            c.execute(f"DELETE FROM appeals WHERE id IN ({','.join('?' * len(found['appeals']))})", found["appeals"])
        if rep_ids:
            c.execute(f"DELETE FROM reports WHERE id IN ({','.join('?' * len(rep_ids))})", rep_ids)
        c.execute(f"DELETE FROM verified_users WHERE {u_n} OR {u_i}", u_args)
        c.execute(f"DELETE FROM seen_users WHERE {u_n} OR {u_i}", u_args)


async def cmd_purge(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/purge @username  -> shows what would be deleted
       /purge @username confirm  -> deletes it"""
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    if not context.args:
        await update.message.reply_text(
            "Usage: /purge @username  (preview)\n/purge @username confirm  (delete)"
        )
        return

    who = context.args[0]
    confirm = len(context.args) > 1 and context.args[1].lower() == "confirm"
    found = purge_collect(who)
    n_rep = len(found["reports"])

    if not (n_rep or found["verified"] or found["seen"] or found["appeals"]):
        await update.message.reply_text(f"Nothing stored about {who}.")
        return

    summary = (
        f"Data stored about {who}"
        + (f" ({', '.join('@' + n for n in found['names'])}" if found["names"] else " (")
        + (f"{' / ' if found['names'] and found['ids'] else ''}{', '.join(found['ids'])})" if found["ids"] else ")")
        + f":\n• Reports against them: {n_rep}\n• Appeals: {len(found['appeals'])}"
        f"\n• Verified-list entry: {'yes' if found['verified'] else 'no'}"
        f"\n• Remembered as a bot user: {'yes' if found['seen'] else 'no'}"
    )
    left = []
    if found["as_original"]:
        left.append(f"{found['as_original']} impersonation report(s) name them as the real user (about someone else)")
    if found["filed_by"]:
        left.append(f"{found['filed_by']} report(s) they filed against others")
    if left:
        summary += "\n\nNot touched: " + "; ".join(left) + "."
    summary += "\nAdmin status is never changed."

    if not confirm:
        await update.message.reply_text(
            summary + f"\n\n⚠️ To delete all of this (and their channel posts), send:\n/purge {who} confirm"
        )
        return

    # remove the channel posts and admin copies first (best effort), then the rows
    removed_posts = 0
    for r in found["reports"]:
        if r.get("channel_message_id"):
            try:
                await context.bot.delete_message(chat_id=f"@{CHANNEL_USERNAME}", message_id=r["channel_message_id"])
                removed_posts += 1
            except TelegramError as e:
                log.info("Could not delete channel post %s: %s", r["channel_message_id"], e)
        try:
            for chat_id, message_id in json.loads(r.get("admin_message_ids") or "[]"):
                try:
                    await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
                except TelegramError:
                    pass
        except (ValueError, TypeError):
            pass
    purge_delete(found)
    await update.message.reply_text(
        f"✅ Done. Deleted {n_rep} report(s), {len(found['appeals'])} appeal(s)"
        f"{', ' + str(removed_posts) + ' channel post(s)' if removed_posts else ''} and the saved profile entries for {who}."
    )


# ==============================================================================
# User info (like @userinfobot): /info @username | /info ID | forward a message
# | tap "Pick an account" | reply to someone with /info
# ==============================================================================
INFO_PICK_ID = 10


def info_menu():
    """Private-chat keyboard with Telegram's account picker (returns the ID)."""
    if KeyboardButtonRequestUsers is None:
        return MAIN_MENU
    try:
        button = KeyboardButton(
            "👤 Pick an account",
            request_users=KeyboardButtonRequestUsers(
                request_id=INFO_PICK_ID, max_quantity=1, request_name=True, request_username=True,
            ),
        )
    except TypeError:
        return MAIN_MENU
    return ReplyKeyboardMarkup([[button], ["Back"]], resize_keyboard=True)


def quick_status(query: str) -> str:
    rows = db_check_target(query)
    if any(r["status"] == "approved" for r in rows):
        return "🚫 Reported scammer"
    if db_find_verified(query):
        return "🤝 Verified trusted user"
    if any(r["status"] == "pending" for r in rows):
        return "⏳ Reports under review"
    return "✅ No reports"


def format_info(uid, name, username, lang=None, premium=None, is_bot=None) -> str:
    lines = [f"🆔 <b>ID:</b> <code>{uid}</code>"]
    if name:
        lines.append(f"👤 <b>Name:</b> {html.escape(name)}")
    lines.append("🔗 <b>Username:</b> " + (f"@{html.escape(username)}" if username else "none"))
    if lang:
        lines.append(f"🌐 <b>Language:</b> {html.escape(lang)}")
    if premium:
        lines.append("⭐ <b>Premium:</b> yes")
    if is_bot:
        lines.append("🤖 <b>Bot:</b> yes")
    lines.append(f"🛡 <b>Report status:</b> {quick_status(username or str(uid))}")
    return "\n".join(lines)


async def send_info(update: Update, context: ContextTypes.DEFAULT_TYPE, uid, name, username,
                    lang=None, premium=None, is_bot=None, photo=None, footer: str = "",
                    skip_fetch: bool = False):
    """Reply with the info card text (and the profile photo when we have one)."""
    import io
    text = format_info(uid, name, username, lang, premium, is_bot) + footer
    menu = info_menu() if update.effective_chat.type == "private" else None
    if photo is None and not skip_fetch:
        got = await fetch_profile_info(context.bot, username, str(uid))
        photo = got["photo"]
    if photo:
        try:
            await update.message.reply_photo(photo=io.BytesIO(photo), caption=text,
                                             parse_mode=ParseMode.HTML, reply_markup=menu)
            return
        except TelegramError as e:
            log.info("Could not send info photo: %s", e)
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=menu)


INFO_HELP = (
    "\n\n<i>Look up anyone: <code>/info @username</code> or <code>/info ID</code>, "
    "forward me one of their messages, or tap <b>👤 Pick an account</b>.</i>"
)


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message

    if context.args:
        raw = context.args[0].strip()
        is_id = raw.lstrip("-").isdigit()
        username = None if is_id else raw.lstrip("@")
        info = await fetch_profile_info(context.bot, username, raw if is_id else None)
        uid = info["user_id"] or (raw if is_id else None)
        if not uid and (info["display"] or info["photo"]):
            # public page knows the person, but Telegram won't give a bot their numeric ID
            await send_info(update, context, "hidden from bots", info["display"], username,
                            photo=info["photo"], skip_fetch=True,
                            footer="\n\n<i>Telegram only gives a bot the ID of accounts it has met. "
                                   "Forward me one of their messages or tap 👤 Pick an account for the ID.</i>")
            return
        if not uid:
            await msg.reply_text(
                f"❌ Couldn't find the ID of {html.escape(raw)}.\n"
                "Telegram only shows a bot the ID of accounts it has met. Forward me one of their "
                "messages or tap <b>👤 Pick an account</b> and I'll read it directly.",
                parse_mode=ParseMode.HTML,
                reply_markup=info_menu() if update.effective_chat.type == "private" else None,
            )
            return
        if info["user_id"] and info["username"] is None and not is_id:
            info["username"] = username
        await send_info(update, context, uid, info["display"], info["username"] or username,
                        photo=info["photo"], skip_fetch=True)
        return

    target = msg.reply_to_message.from_user if msg.reply_to_message and msg.reply_to_message.from_user else None
    who = target or update.effective_user
    footer = INFO_HELP if target is None else ""
    await send_info(update, context, who.id, who.full_name, who.username,
                    lang=who.language_code, premium=getattr(who, "is_premium", None),
                    is_bot=who.is_bot, footer=footer)


async def on_forwarded_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """A message forwarded to the bot in private -> tell who sent it."""
    msg = update.message
    origin = getattr(msg, "forward_origin", None)
    user = getattr(origin, "sender_user", None) or getattr(msg, "forward_from", None)
    if user:
        db_remember_user(user.id, user.username, user.full_name)
        await send_info(update, context, user.id, user.full_name, user.username,
                        lang=getattr(user, "language_code", None),
                        premium=getattr(user, "is_premium", None), is_bot=user.is_bot)
        return

    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None) or getattr(msg, "forward_from_chat", None)
    if chat:
        kind = {"channel": "📣 Channel", "supergroup": "👥 Group", "group": "👥 Group"}.get(chat.type, "💬 Chat")
        lines = [f"{kind}: {html.escape(chat.title or '')}", f"🆔 <b>ID:</b> <code>{chat.id}</code>"]
        lines.append("🔗 <b>Username:</b> " + (f"@{html.escape(chat.username)}" if chat.username else "none"))
        await msg.reply_text("\n".join(lines), parse_mode=ParseMode.HTML,
                             reply_markup=info_menu())
        return

    hidden = getattr(origin, "sender_user_name", None) or getattr(msg, "forward_sender_name", None)
    await msg.reply_text(
        f"🔒 {html.escape(hidden or 'This user')} hides their account when messages are forwarded, "
        "so Telegram doesn't tell me their ID.\nTap <b>👤 Pick an account</b> below and choose them instead.",
        parse_mode=ParseMode.HTML, reply_markup=info_menu(),
    )


async def on_shared_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reply to the 'Pick an account' button."""
    picked = shared_user(update.message)
    if not picked:
        return
    uid, uname, name = picked
    db_remember_user(uid, uname, name)
    await send_info(update, context, uid, name, uname)


# ==============================================================================
# Group moderation: /ban and /unban - group admins only
#   /ban            (reply to the person's message)
#   /ban @username  or  /ban 123456789   [reason]
#   /unban @username | ID  (or reply)
# The person using it must be an admin with the "Ban users" right; the bot must
# be an admin with that right too. Admins can't be banned.
# ==============================================================================
async def _can_restrict(bot, chat_id: int, user_id: int) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except TelegramError:
        return False
    if member.status == "creator":
        return True
    return member.status == "administrator" and bool(getattr(member, "can_restrict_members", False))


async def _moderation_target(update: Update, context: ContextTypes.DEFAULT_TYPE,
                             right: str = "can_restrict_members", what: str = "Ban users"):
    """Shared checks for /ban, /warn, /promote ... The sender must be an admin with
    `right`, and so must the bot. Returns (user_id, name, rest_of_text) or None
    (after replying with what went wrong)."""
    msg, chat = update.message, update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await msg.reply_text("This command only works in groups.")
        return None

    # who is asking? (an anonymous admin posts as the group itself)
    anonymous = bool(msg.sender_chat and msg.sender_chat.id == chat.id)
    if not anonymous and not await _admin_right(context.bot, chat.id, update.effective_user.id, right):
        await msg.reply_text(f"🚫 Only group admins with the “{what}” permission can use this.")
        return None
    if not await _admin_right(context.bot, chat.id, context.bot.id, right):
        await msg.reply_text(f"I need to be an admin with the “{what}” permission to do that.")
        return None

    reply = msg.reply_to_message
    args = list(context.args)
    if reply and reply.from_user:
        # replying to someone: everything typed after the command is the reason
        target = reply.from_user
        user_id, name = target.id, target.full_name
        reason = " ".join(args)
    elif args:
        found = await quick_resolve(context.bot, args[0])
        if not found and args[0].isdigit():
            found = dict(id=args[0], name=None, username=None)   # a numeric ID needs no lookup
        if not found:
            await msg.reply_text(
                f"❌ I couldn't find {html.escape(args[0])}. Reply to one of their messages with the "
                "command, or use their numeric ID."
            )
            return None
        user_id = int(found["id"])
        name = found["name"] or (f"@{found['username']}" if found["username"] else str(user_id))
        reason = " ".join(args[1:])
    else:
        await msg.reply_text("Reply to a user's message, or use: /" + (msg.text or "/ban").lstrip("/").split()[0].split("@")[0]
                             + " @username [reason]")
        return None

    if user_id in (context.bot.id, 1087968824, 136817688):   # me / anonymous-admin bot / channel bot
        await msg.reply_text("I can't do that to this account.")
        return None
    return user_id, name, reason


def _mention(user_id: int, name: str) -> str:
    return f'<a href="tg://user?id={user_id}">{html.escape(name)}</a>'


async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context)
    if not picked:
        return
    user_id, name, reason = picked
    msg, chat = update.message, update.effective_chat
    admin = update.effective_user

    if user_id == (admin.id if admin else None):
        await msg.reply_text("You can't ban yourself.")
        return
    try:
        member = await context.bot.get_chat_member(chat.id, user_id)
        if member.status in ("creator", "administrator"):
            await msg.reply_text("I can't ban an admin.")
            return
    except TelegramError:
        pass   # not in the group any more - banning still blocks them from rejoining
    try:
        await context.bot.ban_chat_member(chat.id, user_id)
    except TelegramError as e:
        await msg.reply_text(f"❌ Couldn't ban them: {html.escape(str(e))}", parse_mode=ParseMode.HTML)
        return

    by = _mention(admin.id, admin.full_name) if admin and not (msg.sender_chat) else "an admin"
    text = f"🚫 {_mention(user_id, name)} was banned by {by}."
    if reason:
        text += f"\n<b>Reason:</b> {html.escape(reason)}"
    await msg.reply_text(text, parse_mode=ParseMode.HTML)
    log.info("Banned %s in chat %s", user_id, chat.id)


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context)
    if not picked:
        return
    user_id, name, _ = picked
    msg, chat = update.message, update.effective_chat
    try:
        await context.bot.unban_chat_member(chat.id, user_id, only_if_banned=True)
    except TelegramError as e:
        await msg.reply_text(f"❌ Couldn't unban them: {html.escape(str(e))}", parse_mode=ParseMode.HTML)
        return
    await msg.reply_text(f"✅ {_mention(user_id, name)} was unbanned.", parse_mode=ParseMode.HTML)


# ==============================================================================
# Group moderation: warnings + word blacklist (group admins only)
#   /warn [reason]  (reply)  |  /warn @username|ID [reason]
#   /warns [@user]   /unwarn [@user]   /resetwarns [@user]   /setwarnlimit 3
#   /addblacklist word   /unblacklist word   /blacklist
# At the warn limit the person is banned. Blacklisted words are deleted
# automatically (admins are exempt). Settings are kept per group.
# ==============================================================================
async def _admin_right(bot, chat_id: int, user_id: int, right: str) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except TelegramError:
        return False
    if member.status == "creator":
        return True
    return member.status == "administrator" and bool(getattr(member, right, False))


async def _is_admin(bot, chat_id: int, user_id: int) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except TelegramError:
        return False
    return member.status in ("creator", "administrator")


async def _group_admin_gate(update: Update, context: ContextTypes.DEFAULT_TYPE, right: str, what: str) -> bool:
    """Group-only + the sender must be an admin with `right`. Replies if not."""
    msg, chat = update.message, update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await msg.reply_text("This command only works in groups.")
        return False
    anonymous = bool(msg.sender_chat and msg.sender_chat.id == chat.id)
    if not anonymous and not await _admin_right(context.bot, chat.id, update.effective_user.id, right):
        await msg.reply_text(f"🚫 Only group admins with the “{what}” permission can use this.")
        return False
    return True


# ---- database helpers --------------------------------------------------------
def db_add_warn(chat_id, user_id, admin_id, reason):
    with _conn() as c:
        c.execute("INSERT INTO warns (chat_id, user_id, admin_id, reason, created_at) VALUES (?,?,?,?,?)",
                  (chat_id, user_id, admin_id, reason or None, datetime.datetime.utcnow().isoformat()))


def db_get_warns(chat_id, user_id) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM warns WHERE chat_id=? AND user_id=? ORDER BY id", (chat_id, user_id))]


def db_remove_last_warn(chat_id, user_id) -> bool:
    with _conn() as c:
        row = c.execute("SELECT id FROM warns WHERE chat_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
                        (chat_id, user_id)).fetchone()
        if row:
            c.execute("DELETE FROM warns WHERE id=?", (row[0],))
        return bool(row)


def db_reset_warns(chat_id, user_id) -> int:
    with _conn() as c:
        return c.execute("DELETE FROM warns WHERE chat_id=? AND user_id=?", (chat_id, user_id)).rowcount


def db_warn_limit(chat_id) -> int:
    with _conn() as c:
        row = c.execute("SELECT warn_limit FROM chat_settings WHERE chat_id=?", (chat_id,)).fetchone()
        return row[0] if row else 3


def db_set_warn_limit(chat_id, limit: int):
    with _conn() as c:
        c.execute("INSERT INTO chat_settings (chat_id, warn_limit) VALUES (?, ?) "
                  "ON CONFLICT(chat_id) DO UPDATE SET warn_limit=excluded.warn_limit", (chat_id, limit))


def db_bl_list(chat_id) -> list[str]:
    with _conn() as c:
        return [r[0] for r in c.execute("SELECT word FROM blacklist WHERE chat_id=? ORDER BY word", (chat_id,))]


def db_bl_add(chat_id, word, admin_id) -> bool:
    with _conn() as c:
        return c.execute("INSERT OR IGNORE INTO blacklist (chat_id, word, added_by) VALUES (?,?,?)",
                         (chat_id, word, admin_id)).rowcount > 0


def db_bl_remove(chat_id, word) -> bool:
    with _conn() as c:
        return c.execute("DELETE FROM blacklist WHERE chat_id=? AND word=?", (chat_id, word)).rowcount > 0


# ---- warnings ------------------------------------------------------------------
async def cmd_warn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context)   # checks admin rights + finds the person
    if not picked:
        return
    user_id, name, reason = picked
    msg, chat, admin = update.message, update.effective_chat, update.effective_user

    if admin and user_id == admin.id:
        await msg.reply_text("You can't warn yourself.")
        return
    if await _is_admin(context.bot, chat.id, user_id):
        await msg.reply_text("I can't warn an admin.")
        return

    db_add_warn(chat.id, user_id, admin.id if admin else 0, reason)
    count, limit = len(db_get_warns(chat.id, user_id)), db_warn_limit(chat.id)
    by = _mention(admin.id, admin.full_name) if admin and not msg.sender_chat else "an admin"

    if count >= limit:
        try:
            await context.bot.ban_chat_member(chat.id, user_id)
        except TelegramError as e:
            await msg.reply_text(f"⚠️ {_mention(user_id, name)} reached {count}/{limit} warns, "
                                 f"but I couldn't ban them: {html.escape(str(e))}", parse_mode=ParseMode.HTML)
            return
        db_reset_warns(chat.id, user_id)
        text = f"🚫 {_mention(user_id, name)} reached {limit}/{limit} warns and was banned."
        if reason:
            text += f"\n<b>Last reason:</b> {html.escape(reason)}"
        await msg.reply_text(text, parse_mode=ParseMode.HTML)
        return

    text = f"⚠️ {_mention(user_id, name)} has been warned by {by} (<b>{count}/{limit}</b>)."
    if reason:
        text += f"\n<b>Reason:</b> {html.escape(reason)}"
    await msg.reply_text(
        text, parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🗑 Remove warn", callback_data=f"uw:{chat.id}:{user_id}")]]),
    )


async def on_unwarn_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    try:
        _, chat_id, user_id = query.data.split(":")
        chat_id, user_id = int(chat_id), int(user_id)
    except ValueError:
        await query.answer()
        return
    if not await _admin_right(context.bot, chat_id, query.from_user.id, "can_restrict_members"):
        await query.answer("Only group admins can remove warns.", show_alert=True)
        return
    removed = db_remove_last_warn(chat_id, user_id)
    await query.answer("Warn removed." if removed else "No warns left.")
    count, limit = len(db_get_warns(chat_id, user_id)), db_warn_limit(chat_id)
    try:
        await query.edit_message_text(
            f"✅ Warn removed by {_mention(query.from_user.id, query.from_user.full_name)} "
            f"({_mention(user_id, 'user')} now has {count}/{limit}).", parse_mode=ParseMode.HTML)
    except TelegramError:
        pass


async def cmd_unwarn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context)
    if not picked:
        return
    user_id, name, _ = picked
    chat = update.effective_chat
    if not db_remove_last_warn(chat.id, user_id):
        await update.message.reply_text(f"{_mention(user_id, name)} has no warns.", parse_mode=ParseMode.HTML)
        return
    count, limit = len(db_get_warns(chat.id, user_id)), db_warn_limit(chat.id)
    await update.message.reply_text(
        f"✅ Removed one warn from {_mention(user_id, name)} (now {count}/{limit}).", parse_mode=ParseMode.HTML)


async def cmd_resetwarns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context)
    if not picked:
        return
    user_id, name, _ = picked
    n = db_reset_warns(update.effective_chat.id, user_id)
    await update.message.reply_text(
        f"✅ Cleared {n} warn(s) for {_mention(user_id, name)}.", parse_mode=ParseMode.HTML)


async def cmd_warns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admins can look up anyone; everyone else sees their own warns."""
    msg, chat = update.message, update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await msg.reply_text("This command only works in groups.")
        return
    me = update.effective_user
    user_id, name = me.id, me.full_name
    reply = msg.reply_to_message
    if (reply and reply.from_user) or context.args:
        if not await _admin_right(context.bot, chat.id, me.id, "can_restrict_members"):
            await msg.reply_text("🚫 Only admins can check other people's warns. Send /warns to see your own.")
            return
        if reply and reply.from_user:
            user_id, name = reply.from_user.id, reply.from_user.full_name
        else:
            found = await quick_resolve(context.bot, context.args[0])
            if not found and context.args[0].isdigit():
                found = dict(id=context.args[0], name=None, username=None)
            if not found:
                await msg.reply_text(f"❌ I couldn't find {html.escape(context.args[0])}.")
                return
            user_id = int(found["id"])
            name = found["name"] or (f"@{found['username']}" if found["username"] else str(user_id))

    warns, limit = db_get_warns(chat.id, user_id), db_warn_limit(chat.id)
    if not warns:
        await msg.reply_text(f"{_mention(user_id, name)} has no warns.", parse_mode=ParseMode.HTML)
        return
    lines = [f"⚠️ {_mention(user_id, name)} has <b>{len(warns)}/{limit}</b> warns:"]
    for i, w in enumerate(warns, 1):
        lines.append(f"{i}. {html.escape(w['reason'] or 'no reason')} <i>({(w['created_at'] or '')[:10]})</i>")
    await msg.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_setwarnlimit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_admin_gate(update, context, "can_restrict_members", "Ban users"):
        return
    chat = update.effective_chat
    if not context.args or not context.args[0].isdigit() or not 1 <= int(context.args[0]) <= 20:
        await update.message.reply_text(
            f"Usage: /setwarnlimit 3   (1-20). Currently {db_warn_limit(chat.id)}: reaching it bans the person.")
        return
    db_set_warn_limit(chat.id, int(context.args[0]))
    await update.message.reply_text(f"✅ Warn limit set to {int(context.args[0])}. Reaching it bans the person.")


# ---- word blacklist --------------------------------------------------------------
_bl_cache: dict[int, list] = {}


def _bl_norm(text: str) -> str:
    """lowercase + fold look-alike/full-width letters + drop zero-width characters"""
    text = unicodedata.normalize("NFKC", text or "")
    return re.sub("[\u200b-\u200f\u2060\ufeff]", "", text).lower().strip()


def bl_patterns(chat_id: int) -> list:
    if chat_id not in _bl_cache:
        _bl_cache[chat_id] = [
            (w, re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)")) for w in db_bl_list(chat_id)
        ]
    return _bl_cache[chat_id]


def _bl_words_from(msg_text: str) -> list[str]:
    body = (msg_text or "").split(None, 1)
    body = body[1] if len(body) > 1 else ""
    words = [_bl_norm(w) for w in re.split(r"[\n,]+", body)]
    return [w for w in dict.fromkeys(words) if w and len(w) <= 100]


async def cmd_addblacklist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_admin_gate(update, context, "can_delete_messages", "Delete messages"):
        return
    chat = update.effective_chat
    words = _bl_words_from(update.message.text)
    if not words:
        await update.message.reply_text(
            "Usage: /addblacklist word\nOne word or phrase per line, or separated by commas.\n"
            "Messages containing it are deleted automatically (admins are exempt).")
        return
    added = [w for w in words if db_bl_add(chat.id, w, update.effective_user.id)]
    _bl_cache.pop(chat.id, None)
    text = (f"✅ Blacklisted: {', '.join(html.escape(w) for w in added)}" if added
            else "Those are already blacklisted.")
    if not await _admin_right(context.bot, chat.id, context.bot.id, "can_delete_messages"):
        text += "\n⚠️ I need the “Delete messages” admin permission to remove them."
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_unblacklist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_admin_gate(update, context, "can_delete_messages", "Delete messages"):
        return
    chat = update.effective_chat
    words = _bl_words_from(update.message.text)
    if not words:
        await update.message.reply_text("Usage: /unblacklist word")
        return
    removed = [w for w in words if db_bl_remove(chat.id, w)]
    _bl_cache.pop(chat.id, None)
    await update.message.reply_text(
        f"✅ Removed: {', '.join(html.escape(w) for w in removed)}" if removed else "None of those were blacklisted.",
        parse_mode=ParseMode.HTML)


async def cmd_blacklist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_admin_gate(update, context, "can_delete_messages", "Delete messages"):
        return
    words = db_bl_list(update.effective_chat.id)
    await update.message.reply_text(
        "🚫 Blacklisted words:\n" + "\n".join(f"• {html.escape(w)}" for w in words) if words
        else "No blacklisted words. Add one with /addblacklist word",
        parse_mode=ParseMode.HTML)


async def blacklist_filter(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deletes group messages that contain a blacklisted word. Admins are exempt."""
    msg, chat = update.effective_message, update.effective_chat
    if not msg or not chat or chat.type not in ("group", "supergroup"):
        return
    text = msg.text or msg.caption
    if not text or text.startswith("/"):
        return
    patterns = bl_patterns(chat.id)
    if not patterns:
        return
    norm = _bl_norm(text)
    if not any(rx.search(norm) for _, rx in patterns):
        return
    user = update.effective_user
    if msg.sender_chat and msg.sender_chat.id == chat.id:      # anonymous admin
        return
    if user and await _is_admin(context.bot, chat.id, user.id):
        return
    try:
        await msg.delete()
    except TelegramError as e:
        log.info("Could not delete blacklisted message in %s (give the bot 'Delete messages'): %s", chat.id, e)
        return
    raise ApplicationHandlerStop


# ==============================================================================
# Group admins: /promote and /demote (needs the "Add new admins" right)
#   /promote (reply) | /promote @username|ID [custom title]
#   /demote  (reply) | /demote  @username|ID
# Safety: you can only hand out rights that YOU have, and the bot can only hand
# out rights it has. Telegram only lets a bot demote admins that it promoted.
# ==============================================================================
PROMOTE_RIGHTS = [
    ("can_manage_chat", "manage chat"),
    ("can_delete_messages", "delete messages"),
    ("can_restrict_members", "ban users"),
    ("can_invite_users", "invite users"),
    ("can_pin_messages", "pin messages"),
    ("can_manage_video_chats", "manage voice chats"),
]
DEMOTE_RIGHTS = [r for r, _ in PROMOTE_RIGHTS] + ["can_change_info", "can_promote_members"]


async def _member_or_none(bot, chat_id: int, user_id: int):
    try:
        return await bot.get_chat_member(chat_id, user_id)
    except TelegramError:
        return None


def _has_right(member, right: str) -> bool:
    if member is None:
        return False
    return member.status == "creator" or (member.status == "administrator" and bool(getattr(member, right, False)))


async def cmd_promote(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context, "can_promote_members", "Add new admins")
    if not picked:
        return
    user_id, name, title = picked
    msg, chat, admin = update.message, update.effective_chat, update.effective_user

    target = await _member_or_none(context.bot, chat.id, user_id)
    if target is None or target.status in ("left", "kicked"):
        await msg.reply_text("They need to be a member of this group first.")
        return
    if target.status == "creator":
        await msg.reply_text("That's the group owner.")
        return
    if target.status == "administrator":
        await msg.reply_text("They're already an admin. Use /demote first if you want to change their rights.")
        return

    # only give rights that both the asker and the bot actually have
    me = await _member_or_none(context.bot, chat.id, context.bot.id)
    asker = None if (msg.sender_chat and msg.sender_chat.id == chat.id) else await _member_or_none(
        context.bot, chat.id, admin.id)
    rights = {r: (_has_right(me, r) and (asker is None or _has_right(asker, r))) for r, _ in PROMOTE_RIGHTS}
    given = [label for r, label in PROMOTE_RIGHTS if rights[r]]
    if not any(rights.values()):
        await msg.reply_text("I can't promote them: there is no admin right that both you and I have to give.")
        return

    try:
        await context.bot.promote_chat_member(chat.id, user_id, **rights)
    except TelegramError as e:
        await msg.reply_text(f"❌ Couldn't promote them: {html.escape(str(e))}", parse_mode=ParseMode.HTML)
        return

    text = f"⭐ {_mention(user_id, name)} was promoted to admin by " + (
        _mention(admin.id, admin.full_name) if not msg.sender_chat else "an admin") + "."
    text += "\n<b>Rights:</b> " + ", ".join(given)
    title = re.sub(r"\s+", " ", title or "").strip()[:16]
    if title and chat.type == "supergroup":
        try:
            await context.bot.set_chat_administrator_custom_title(chat.id, user_id, title)
            text += f"\n<b>Title:</b> {html.escape(title)}"
        except TelegramError as e:
            text += f"\n(Couldn't set the title: {html.escape(str(e))})"
    await msg.reply_text(text, parse_mode=ParseMode.HTML)
    log.info("Promoted %s in chat %s", user_id, chat.id)


async def cmd_demote(update: Update, context: ContextTypes.DEFAULT_TYPE):
    picked = await _moderation_target(update, context, "can_promote_members", "Add new admins")
    if not picked:
        return
    user_id, name, _ = picked
    msg, chat, admin = update.message, update.effective_chat, update.effective_user

    target = await _member_or_none(context.bot, chat.id, user_id)
    if target is None or target.status != "administrator":
        await msg.reply_text(
            "That's the group owner and can't be demoted." if target and target.status == "creator"
            else "They're not an admin.")
        return
    asker = None if (msg.sender_chat and msg.sender_chat.id == chat.id) else await _member_or_none(
        context.bot, chat.id, admin.id)
    if asker is not None and asker.status != "creator" and bool(getattr(target, "can_promote_members", False)):
        await msg.reply_text("Only the group owner can demote an admin who can add other admins.")
        return

    try:
        await context.bot.promote_chat_member(chat.id, user_id, **{r: False for r in DEMOTE_RIGHTS})
    except TelegramError as e:
        await msg.reply_text(
            "❌ Couldn't demote them. Telegram only lets me demote admins that I promoted myself - "
            f"for others, remove them in the group's admin settings.\n<i>{html.escape(str(e))}</i>",
            parse_mode=ParseMode.HTML)
        return
    after = await _member_or_none(context.bot, chat.id, user_id)
    if after is not None and after.status == "administrator":
        await msg.reply_text("⚠️ I removed the rights I can, but they still have some admin rights. "
                             "Remove the rest in the group's admin settings.")
        return
    await msg.reply_text(
        f"⬇️ {_mention(user_id, name)} was demoted by " + (
            _mention(admin.id, admin.full_name) if not msg.sender_chat else "an admin") + ".",
        parse_mode=ParseMode.HTML)
    log.info("Demoted %s in chat %s", user_id, chat.id)


async def cmd_getid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if not is_privileged(admin.id):
        await update.message.reply_text("You are not authorized to do this.")
        return

    if context.args:
        # Inline usage: /getid @username
        await resolve_and_reply_id(update, context, normalize_username(context.args[0]))
        return

    awaiting_getid.add(admin.id)
    await update.message.reply_text(
        "Send the @username to look up, or forward a message from that account "
        "for a more reliable match."
    )


async def resolve_and_reply_id(update: Update, context: ContextTypes.DEFAULT_TYPE, username: str):
    msg = await update.message.reply_text(f"Looking up {username}...")
    numeric_id = await resolve_target_id(context.bot, username)
    if numeric_id:
        await msg.edit_text(f"{username} -> <code>{numeric_id}</code>", parse_mode=ParseMode.HTML)
    else:
        await msg.edit_text(
            f"Could not resolve an ID for {username}.\n"
            f"Try forwarding a message from that account instead - Telegram only "
            f"exposes an account's ID that way unless the bot has already seen them."
        )


async def handle_getid_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user
    if admin.id not in awaiting_getid:
        return  # not currently in a /getid flow, ignore
    awaiting_getid.discard(admin.id)

    fwd_username, fwd_id = extract_forward_identity(update.message)
    if fwd_id:
        label = fwd_username or "that account"
        await update.message.reply_text(
            f"{label} -> <code>{fwd_id}</code>", parse_mode=ParseMode.HTML
        )
        raise ApplicationHandlerStop

    if not update.message.text:
        await update.message.reply_text("Send an @username or forward a message. Run /getid again.")
        raise ApplicationHandlerStop

    username = normalize_username(update.message.text)
    await resolve_and_reply_id(update, context, username)
    raise ApplicationHandlerStop


# ==============================================================================
# Admin management commands
# ==============================================================================

async def cmd_addadmin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    if not context.args:
        await update.message.reply_text(
            "Usage: /admin <id>\n"
            "The chosen admin will start receiving new reports to accept or reject."
        )
        return
    try:
        new_admin_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("id must be numeric.")
        return
    db_add_admin(new_admin_id, added_by=update.effective_user.id)
    await update.message.reply_text(
        f"Added admin: {new_admin_id}\n"
        f"They will now receive every new report and appeal for review.\n\n"
        f"Note: if they haven't sent /start to this bot before, Telegram will "
        f"block the DM until they do - ask them to open a chat with the bot first."
    )


async def cmd_rmadmin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in PRIME_ADMIN_IDS:
        await update.message.reply_text("Only a prime admin can do this.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /rmadmin <chat_id>")
        return
    try:
        rm_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text( "chat_id must be numeric." )
        return
    db_remove_admin(rm_id)
    await update.message.reply_text(f"Removed admin: {rm_id}")


async def cmd_listadmins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_privileged(update.effective_user.id):
        return
    admins = db_list_admins()
    lines = [f"Prime admin: {p}" for p in PRIME_ADMIN_IDS] + [f"Admin: {a}" for a in admins]
    await update.message.reply_text("\n".join(lines))


# ==============================================================================
# Conversation handlers assembly
# ==============================================================================

class _ButtonMessage:
    """Stands in for `update.message` when a flow is started from an inline button,
    so the same functions work for typed text and for button taps."""

    def __init__(self, query, bot):
        self._q, self._bot = query, bot
        self.chat_id = query.message.chat.id
        self.text = ""
        self.entities = []
        self.reply_to_message = None
        self.users_shared = None

    async def reply_text(self, text, **kwargs):
        return await self._bot.send_message(chat_id=self.chat_id, text=text, **kwargs)

    async def reply_photo(self, photo, caption=None, **kwargs):
        return await self._bot.send_photo(chat_id=self.chat_id, photo=photo, caption=caption, **kwargs)

    def __getattr__(self, name):
        return getattr(self._q.message, name)


def via_button(fn):
    """Wrap a message-style handler so an inline button can trigger it."""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        message = _ButtonMessage(query, context.bot)
        shim = SimpleNamespace(
            message=message, effective_message=message, callback_query=query,
            effective_user=query.from_user, effective_chat=query.message.chat,
        )
        return await fn(shim, context)
    wrapper.__name__ = getattr(fn, "__name__", "button")
    return wrapper


# --- navigation that must ALWAYS work, in every step of every flow ----------
# A conversation checks its step handlers BEFORE its fallbacks, so these are
# put first in every step (and excluded from the answer filters) - otherwise
# "Cancel Report" got swallowed as the user's answer (e.g. "invalid amount").
NAV_RE = r"^(Cancel Report|Back|Submit a Report)$"
NOT_NAV = ~filters.Regex(NAV_RE)

_cancel = MessageHandler(filters.Regex("^Cancel Report$"), cancel_report)
_back = MessageHandler(filters.Regex("^Back$"), back_to_main)
_report_menu = MessageHandler(filters.Regex("^Submit a Report$"), show_report_menu)
_start_again = CommandHandler(
    "start", cmd_start, filters=filters.ChatType.PRIVATE & ~filters.Regex(START_REPORT_RE)
)
_cancel_btn = CallbackQueryHandler(via_button(cancel_report), pattern=r"^cancel_report$")
_back_btn = CallbackQueryHandler(via_button(back_to_main), pattern=r"^menu:back$")
_report_menu_btn = CallbackQueryHandler(via_button(show_report_menu), pattern=r"^menu:report$")
NAV = [_cancel, _back, _report_menu, _cancel_btn, _back_btn, _report_menu_btn]      # first in every step
FALLBACKS = [_cancel, _start_again, _back, _report_menu, _cancel_btn, _back_btn, _report_menu_btn]


def _step(callback, any_message: bool = False):
    base = filters.ALL if any_message else filters.TEXT
    return NAV + [MessageHandler(base & ~filters.COMMAND & NOT_NAV, callback)]


lookup_conv = ConversationHandler(
    entry_points=[
        MessageHandler(filters.Regex("^Users Lookup$"), lookup_start),
        CallbackQueryHandler(via_button(lookup_start), pattern=r"^menu:lookup$"),
    ],
    states={
        LOOKUP_INPUT: _step(lookup_input),
    },
    fallbacks=list(FALLBACKS),
)

impersonation_conv = ConversationHandler(
    entry_points=[
        MessageHandler(filters.Regex("^Impersonation Report$"), imp_start),
        CallbackQueryHandler(via_button(imp_start), pattern=r"^menu:imp$"),
    ],
    states={
        IMP_ORIGINAL: _step(imp_original, any_message=True),
        IMP_IMPERSONATOR: _step(imp_impersonator, any_message=True),
    },
    fallbacks=list(FALLBACKS),
)

_prefilled_report = MessageHandler(
    filters.ChatType.PRIVATE & filters.Regex(START_REPORT_RE), scam_start_prefilled
)

scam_conv = ConversationHandler(
    entry_points=[
        MessageHandler(filters.Regex("^Scam Report$"), scam_start),
        CallbackQueryHandler(via_button(scam_start), pattern=r"^menu:scam$"),
        _prefilled_report,
    ],
    states={
        SCAM_USERNAME: _step(scam_username, any_message=True),
        SCAM_AMOUNT: _step(scam_amount),
        SCAM_DESC: _step(scam_desc),
        SCAM_PROOF: _step(scam_proof),
    },
    fallbacks=FALLBACKS + [_prefilled_report],
)

appeal_conv = ConversationHandler(
    entry_points=[
        MessageHandler(filters.Regex("^Submit Appeal$"), appeal_start),
        CallbackQueryHandler(via_button(appeal_start), pattern=r"^menu:appeal$"),
    ],
    states={
        APPEAL_FORWARD: _step(appeal_forward_input, any_message=True),
        APPEAL_EXPLAIN: _step(appeal_explain_input),
    },
    fallbacks=list(FALLBACKS),
)


# ==============================================================================
# Main
# ==============================================================================

def main():
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    install_premium_emoji()
    log.info(
        "Profile photo lookup via user account: %s",
        "ON" if (TG_API_ID and TG_API_HASH and TG_SESSION) else "OFF (set TG_API_ID/TG_API_HASH/TG_SESSION to enable)",
    )
    app.add_handler(TypeHandler(Update, remember_user), group=-10)
    app.add_handler(MessageHandler(
        filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND, blacklist_filter), group=-9)

    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("lookup", cmd_lookup))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("ban", cmd_ban))
    app.add_handler(CommandHandler("unban", cmd_unban))
    app.add_handler(CommandHandler("promote", cmd_promote))
    app.add_handler(CommandHandler("demote", cmd_demote))
    app.add_handler(CommandHandler("warn", cmd_warn))
    app.add_handler(CommandHandler("warns", cmd_warns))
    app.add_handler(CommandHandler("unwarn", cmd_unwarn))
    app.add_handler(CommandHandler("resetwarns", cmd_resetwarns))
    app.add_handler(CommandHandler("setwarnlimit", cmd_setwarnlimit))
    app.add_handler(CommandHandler("addblacklist", cmd_addblacklist))
    app.add_handler(CommandHandler(["unblacklist", "rmblacklist"], cmd_unblacklist))
    app.add_handler(CommandHandler("blacklist", cmd_blacklist))
    app.add_handler(CallbackQueryHandler(on_unwarn_button, pattern=r"^uw:-?\d+:\d+$"))
    app.add_handler(CommandHandler("purge", cmd_purge))
    app.add_handler(CommandHandler("pfpcheck", cmd_pfpcheck))
    app.add_handler(CommandHandler("verify", cmd_verify))
    app.add_handler(CommandHandler("unverify", cmd_unverify))
    app.add_handler(CommandHandler("verified", cmd_verified))
    app.add_handler(CommandHandler(["admin", "addadmin"], cmd_addadmin))
    app.add_handler(CommandHandler("rmadmin", cmd_rmadmin))
    app.add_handler(CommandHandler("listadmins", cmd_listadmins))
    app.add_handler(CommandHandler("pfp", cmd_pfp))
    app.add_handler(CommandHandler("pfp2", cmd_pfp2))
    app.add_handler(CommandHandler("pfp3", cmd_pfp3))
    app.add_handler(CommandHandler("txt", cmd_txt))
    app.add_handler(CommandHandler("getid", cmd_getid))
    app.add_handler(CommandHandler("cancel", cmd_cancel_accept))


    app.add_handler(lookup_conv)
    app.add_handler(impersonation_conv)
    app.add_handler(scam_conv)
    app.add_handler(appeal_conv)

    # Registered AFTER the conversations on purpose: while someone is in the
    # middle of a report, the conversation's own fallbacks catch these first
    # and reset it; otherwise these plain handlers run.
    app.add_handler(CommandHandler("start", cmd_start, filters=filters.ChatType.PRIVATE & ~filters.Regex(START_REPORT_RE)))
    app.add_handler(MessageHandler(filters.Regex("^Submit a Report$"), show_report_menu))
    app.add_handler(MessageHandler(filters.Regex("^Back$"), back_to_main))
    app.add_handler(_back_btn)
    app.add_handler(_report_menu_btn)
    app.add_handler(_cancel_btn)
    app.add_handler(CommandHandler("setemoji", cmd_setemoji))
    app.add_handler(CommandHandler("delemoji", cmd_delemoji))
    app.add_handler(CommandHandler("emojis", cmd_emojis))
    app.add_handler(MessageHandler(
        filters.Entity("custom_emoji") & filters.ChatType.PRIVATE & ~filters.COMMAND, on_custom_emoji_ids))
    app.add_handler(CommandHandler(["info", "userinfo", "whois"], cmd_info))
    app.add_handler(MessageHandler(filters.FORWARDED & filters.ChatType.PRIVATE, on_forwarded_info))
    _shared_flt = getattr(filters.StatusUpdate, "USERS_SHARED", None)
    if _shared_flt is not None:
        app.add_handler(MessageHandler(_shared_flt & filters.ChatType.PRIVATE, on_shared_info))

    app.add_handler(CallbackQueryHandler(on_decision_button, pattern=r"^report:(accept|reject):\d+$"))
    app.add_handler(CallbackQueryHandler(on_appeal_decision, pattern=r"^appeal:(accept|reject):\d+$"))
    app.add_handler(CallbackQueryHandler(on_check_membership, pattern=r"^check_membership$"))

    # Each of the "admin is mid-flow, waiting for a specific reply" handlers
    # below gets its OWN group number. python-telegram-bot only runs the
    # FIRST matching handler within a given group, so if these shared the
    # same group, whichever was registered first would eat every message
    # and the others would silently never fire.
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_accept_id), group=-5
    )
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_reject_reason), group=-4
    )
    app.add_handler(
        MessageHandler((filters.TEXT | filters.FORWARDED) & ~filters.COMMAND, handle_getid_input),
        group=-3,
    )
    app.add_handler(MessageHandler(filters.PHOTO, handle_pfp_photo), group=-2)
    app.add_handler(MessageHandler(filters.PHOTO, handle_pfp2_photo), group=-1)
    app.add_handler(MessageHandler(filters.PHOTO, handle_pfp3_photo), group=-6)

    log.info("Bot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


def _save_tg_settings(api_id, api_hash: str, session: str) -> bool:
    """Write TG_API_ID / TG_API_HASH / TG_SESSION into this file."""
    path = os.path.abspath(__file__)
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        for name, value in (("TG_API_ID", str(api_id)), ("TG_API_HASH", json.dumps(api_hash)),
                            ("TG_SESSION", json.dumps(session))):
            src, n = re.subn(rf"^{name}\s*=.*$", lambda m, nm=name, v=value: f"{nm} = {v}", src, count=1, flags=re.M)
            if n == 0:
                return False
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        return True
    except OSError:
        return False


def make_session():
    """python scem_bot.py --make-session
    One-time login so the bot can look up numeric IDs, names and photos of ANY
    @username (Telegram bots can't do that on their own). Asks for the API ID /
    API hash, your phone number and the login code, then saves it all in this file."""
    try:
        from telethon.sync import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        print("Install telethon first:  pip install telethon")
        return

    api_id, api_hash = TG_API_ID, TG_API_HASH
    if not (api_id and api_hash):
        print("Get your API ID and API hash at https://my.telegram.org -> 'API development tools'.\n")
        try:
            api_id = int(input("API ID: ").strip())
        except ValueError:
            print("The API ID must be a number.")
            return
        api_hash = input("API hash: ").strip()

    print("\nNow log in with the Telegram account the bot should use for lookups (a spare account is best).")
    with TelegramClient(StringSession(), api_id, api_hash) as client:   # asks for phone, code, 2FA password
        session = client.session.save()

    if _save_tg_settings(api_id, api_hash, session):
        print("\n✅ Saved into scem_bot.py. Restart the bot - ID lookups are now automatic.")
        print("Keep scem_bot.py private: it now contains a login for that account.")
    else:
        print("\nCouldn't write to scem_bot.py. Paste these near the top of the file yourself:\n")
        print(f"TG_API_ID = {api_id}\nTG_API_HASH = {json.dumps(api_hash)}\nTG_SESSION = {json.dumps(session)}")


# ==============================================================================
# Embedded font for the /check card: Poppins Bold, cut down to basic Latin.
# Copyright 2020 The Poppins Project Authors - SIL Open Font License 1.1
# (https://openfontlicense.org). Safe to leave as is.
# ==============================================================================
_POPPINS_B64 = """
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
"""


if __name__ == "__main__":
    if "--make-session" in sys.argv:
        make_session()
        sys.exit(0)
    main()
