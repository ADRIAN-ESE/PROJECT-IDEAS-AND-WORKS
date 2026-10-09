"""Upload validation: filename sanitization, type allow-list, content sniffing, malware scan."""
import io
import re
import socket
import struct
import unicodedata
import zipfile

ALLOWED = {  # extension -> (mime, kind)
    "pdf": ("application/pdf", "pdf"), "png": ("image/png", "png"), "jpg": ("image/jpeg", "jpg"),
    "jpeg": ("image/jpeg", "jpg"), "gif": ("image/gif", "gif"), "webp": ("image/webp", "webp"),
    "txt": ("text/plain", "text"), "csv": ("text/csv", "text"), "md": ("text/markdown", "text"),
    "json": ("application/json", "text"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ooxml"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "ooxml"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "ooxml"),
    "zip": ("application/zip", "zip"),
}
_EXEC_EXT = {"exe", "dll", "bat", "cmd", "com", "scr", "msi", "js", "vbs", "ps1", "sh", "jar", "apk", "app", "lnk"}
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
               b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"#!")
# Split so this source file itself doesn't trip antivirus products.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def sanitize_filename(name: str):
    """Return (safe_name, ext). Strips paths, control chars, odd Unicode, double-extension tricks."""
    name = unicodedata.normalize("NFKD", name or "")
    name = re.split(r"[\\/]", name)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] not in "CM")
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    stem = re.sub(r"\.+", "_", stem).strip(" _-") or "file"
    if stem.lower() in _RESERVED:
        stem = "_" + stem
    ext = ext.lower()[:10]
    stem = stem[:100]
    return (f"{stem}.{ext}" if ext else stem), ext


def _check_zip(data: bytes, ext: str, kind: str):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return "File is not a valid ZIP/Office container."
    infos = zf.infolist()
    if len(infos) > 2000:
        return "Archive contains too many entries."
    total = sum(i.file_size for i in infos)
    if total > 100 * 1024 * 1024 or (len(data) and total / len(data) > 200):
        return "Archive expands suspiciously large (possible zip bomb)."
    names = [i.filename for i in infos]
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        return "Archive contains unsafe paths."
    if any(i.flag_bits & 0x1 for i in infos):
        return "Encrypted archives can't be scanned and are not accepted."
    if kind == "ooxml":
        if "[Content_Types].xml" not in names:
            return "File doesn't look like a real Office document."
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            return "Documents with macros are not accepted."
    else:
        bad = [n for n in names if n.rsplit(".", 1)[-1].lower() in _EXEC_EXT]
        if bad:
            return "Archive contains executable or script files."
    return None


def validate_content(safe_name: str, ext: str, data: bytes):
    """Return (error_or_None, mime)."""
    if ext not in ALLOWED:
        return f"'.{ext or '?'}' files are not allowed. Allowed: {', '.join(sorted(ALLOWED))}.", None
    mime, kind = ALLOWED[ext]
    head = data[:16]
    if head.startswith(_EXEC_MAGIC):
        return "Executable content is not allowed, whatever the file extension.", None
    ok = {
        "pdf": head.startswith(b"%PDF-"), "png": head.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": head.startswith(b"\xff\xd8\xff"), "gif": head[:6] in (b"GIF87a", b"GIF89a"),
        "webp": head[:4] == b"RIFF" and data[8:12] == b"WEBP",
        "ooxml": head.startswith(b"PK"), "zip": head.startswith(b"PK"), "text": True,
    }[kind]
    if not ok:
        return f"File contents don't match a .{ext} file.", None
    if kind == "text":
        if b"\x00" in data:
            return "Text files must not contain binary data.", None
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return "Text files must be UTF-8 encoded.", None
    elif kind == "pdf":
        if re.search(rb"/(Launch|JavaScript|JS)\b", data):
            return "PDFs with embedded scripts or launch actions are not accepted.", None
    elif kind in ("ooxml", "zip"):
        err = _check_zip(data, ext, kind)
        if err:
            return err, None
    return None, mime


# ---------------------------------------------------------------- malware scanning
def _clamd_scan(data: bytes, cfg):
    sock = None
    try:
        if cfg.get("CLAMD_SOCKET"):
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(30)
            sock.connect(cfg["CLAMD_SOCKET"])
        elif cfg.get("CLAMD_HOST"):
            sock = socket.create_connection((cfg["CLAMD_HOST"], int(cfg.get("CLAMD_PORT", 3310))), timeout=30)
        else:
            return None
        sock.sendall(b"zINSTREAM\0")
        for i in range(0, len(data), 65536):
            chunk = data[i:i + 65536]
            sock.sendall(struct.pack("!I", len(chunk)) + chunk)
        sock.sendall(struct.pack("!I", 0))
        reply = b""
        while not reply.endswith(b"\0") and len(reply) < 4096:
            part = sock.recv(1024)
            if not part:
                break
            reply += part
        text = reply.strip(b"\0").decode(errors="replace")
        if text.endswith("OK"):
            return {"status": "clean", "engine": "clamav", "signature": None}
        if text.endswith("FOUND"):
            return {"status": "infected", "engine": "clamav", "signature": text.split(":", 1)[-1].replace("FOUND", "").strip()}
        return {"status": "error", "engine": "clamav", "signature": text[:100]}
    except OSError:
        return None
    finally:
        if sock:
            sock.close()


def scan_bytes(data: bytes, cfg) -> dict:
    """ClamAV (clamd INSTREAM) when configured/reachable, else built-in signature heuristics."""
    result = _clamd_scan(data, cfg)
    if result is not None:
        return result
    if cfg.get("REQUIRE_AV"):
        return {"status": "error", "engine": "none", "signature": "antivirus engine unavailable"}
    if EICAR in data:
        return {"status": "infected", "engine": "builtin", "signature": "EICAR-Test-File"}
    return {"status": "clean", "engine": "builtin-heuristics", "signature": None}
