"""Terminal colour. Off when the target stream is not a terminal or NO_COLOR is set."""
import os
import re
import sys

_CODES = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "dim": "2", "bold": "1",
          "bred": "1;31", "bgreen": "1;32", "bcyan": "1;36"}
_TAG = {"[+]": "green", "[!]": "yellow", "[-]": "red", "[*]": "cyan", "[i]": "dim"}
_BAD_WORDS = re.compile(r"(?i)\b(warning|not fully|failed|refusing|could not|still encrypted|insecure|NOT )")
_LEAD = re.compile(r"^(\s*)(\[[+!\-*i]\])( .*)?$", re.S)


def enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    try:
        return stream.isatty() and not os.environ.get("NO_COLOR")
    except Exception:
        return False


def paint(text, kind, stream=None) -> str:
    return f"\033[{_CODES[kind]}m{text}\033[0m" if enabled(stream) else str(text)


def colorize(msg: str, stream=None) -> str:
    """Colour a status line by its [+] [!] [-] [*] [i] prefix, `error:` and indented continuation lines."""
    if not enabled(stream):
        return msg
    m = _LEAD.match(msg)
    if m:
        lead, tag, rest = m.group(1), m.group(2), m.group(3) or ""
        kind = _TAG[tag]
        if tag == "[!]" and _BAD_WORDS.search(rest):
            kind = "bred"
        body = paint(rest, "bold" if kind == "bred" else ("dim" if tag == "[i]" else "bold" if tag == "[+]" else "bold")) if False else rest
        return lead + paint(tag, kind) + (paint(rest, "bred") if kind == "bred" else rest)
    if msg.startswith("error:"):
        return paint("error:", "bred") + msg[6:]
    if msg.startswith("    ") and msg.strip():
        return paint(msg, "dim")
    return msg
