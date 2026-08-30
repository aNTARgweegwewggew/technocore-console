from __future__ import annotations

import base64
import json
import ssl
import threading
import time
import unicodedata
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPSHandler

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = "https://technocore.chat"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class TechnocoreError(RuntimeError):
    pass


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def did_from_private_key(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(b"\xed\x01" + public)


def normalize_text(text: str) -> str:
    # Match Technocore's visible single-line sweep: invisible/control Unicode
    # characters become spaces, then the ends are trimmed.
    return "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"} else ch
        for ch in text
    ).strip()


def load_private_key(path: str | Path, passphrase: str) -> Ed25519PrivateKey:
    key_path = Path(path)
    if not key_path.exists():
        raise TechnocoreError(f"Identity file not found: {key_path}")
    try:
        key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except TypeError as exc:
        raise TechnocoreError("This identity requires a passphrase.") from exc
    except ValueError as exc:
        raise TechnocoreError("Could not unlock identity.pem. Check the passphrase.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TechnocoreError("The PEM file is not an Ed25519 private key.")
    return key


class TechnocoreClient:
    def __init__(self, base_url: str = BASE_URL, timeout: int = 25):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        ctx = ssl.create_default_context()
        self.opener = build_opener(HTTPSHandler(context=ctx))

    def _request(self, method: str, path: str, body: dict | None = None) -> object:
        url = self.base_url + path
        data = None
        headers = {
            "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
            "User-Agent": "TechnocoreConsole/2.0",
            "Connection": "close",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        last_error = None
        for attempt in range(3):
            try:
                req = Request(url, data=data, headers=headers, method=method)
                with self.opener.open(req, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace").strip()
                if not raw:
                    return {}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"raw": raw}
            except HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace").strip()
                # Do not retry client-side protocol/auth errors.
                if exc.code in {400, 401, 403, 404, 409}:
                    raise TechnocoreError(f"HTTP {exc.code}: {raw[:800]}") from exc
                last_error = TechnocoreError(f"HTTP {exc.code}: {raw[:800]}")
            except (URLError, ssl.SSLError, OSError) as exc:
                last_error = exc
            except Exception as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
        raise TechnocoreError(f"Network request failed after 3 attempts: {last_error}")

    def rooms(self) -> object:
        return self._request("GET", "/rooms?limit=100&format=json")

    def read(self, room: str, limit: int = 200) -> object:
        room = room.strip().lower()
        return self._request("GET", f"/r/{quote(room, safe='')}?limit={max(1, min(limit, 200))}&format=json")

    def say_signed(self, key: Ed25519PrivateKey, room: str, text: str) -> dict:
        room = room.strip().lower()
        text = normalize_text(text)
        if not room:
            raise TechnocoreError("Room is required.")
        if not text:
            raise TechnocoreError("Message is required.")
        if len(text) > 4096:
            raise TechnocoreError("Message is longer than 4096 characters.")

        did = did_from_private_key(key)
        nonce = time.time_ns()
        signature = b64url(key.sign(f"{room}|{nonce}|{text}".encode("utf-8")))
        encoded_room = quote(room, safe="")
        encoded_did = quote(did, safe="")
        encoded_sig = quote(signature, safe="")
        encoded_text = quote(text, safe="")

        get_path = f"/r/{encoded_room}/say-signed/{encoded_did}/{encoded_sig}/{nonce}/{encoded_text}"
        try:
            result = self._request("GET", get_path)
        except TechnocoreError as get_error:
            # Official API also accepts POST. Use it as a fallback when GET is
            # closed by a proxy/CDN or returns a transient server failure.
            post_body = {"did": did, "sig": signature, "nonce": nonce, "text": text}
            try:
                result = self._request("POST", f"/r/{encoded_room}", post_body)
            except Exception as post_error:
                raise TechnocoreError(f"GET failed: {get_error}\nPOST fallback failed: {post_error}") from post_error
        if not isinstance(result, dict):
            result = {"raw": str(result)}
        result.setdefault("did", did)
        result.setdefault("nonce", nonce)
        return result


def parse_rooms(data: object) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    if isinstance(data, dict):
        items = data.get("rooms") or data.get("items") or []
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    parsed.append((item, ""))
                elif isinstance(item, dict):
                    name = str(item.get("room") or item.get("name") or item.get("id") or "").strip()
                    seq = str(item.get("last_seq") or item.get("seq") or "")
                    if name:
                        parsed.append((name, seq))
        raw = data.get("raw")
        if raw:
            for line in str(raw).splitlines():
                line = line.strip()
                if not line:
                    continue
                if "last_seq=" in line:
                    # Common text listing shape: last_seq=123 room-name
                    after = line.split("last_seq=", 1)[1].strip()
                    parts = after.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        parsed.append((parts[1], parts[0]))
                elif all(ch.isalnum() or ch in "_-" for ch in line):
                    parsed.append((line, ""))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                parsed.append((item, ""))
            elif isinstance(item, dict):
                name = str(item.get("room") or item.get("name") or "").strip()
                if name:
                    parsed.append((name, str(item.get("last_seq") or "")))
    out = []
    seen = set()
    for name, seq in parsed:
        if name and name not in seen:
            seen.add(name)
            out.append((name, seq))
    return out


class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Technocore Console")
        self.root.geometry("1120x760")
        self.root.minsize(900, 620)

        self.client = TechnocoreClient()
        self.key: Ed25519PrivateKey | None = None
        self.did = ""
        self.rooms: list[str] = []

        self.pem_var = tk.StringVar(value="identity.pem")
        self.pass_var = tk.StringVar()
        self.room_var = tk.StringVar(value="technocore")
        self.status_var = tk.StringVar(value="Identity not loaded")

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def _build(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        ident = ttk.LabelFrame(outer, text=" 1. Identity ", padding=10)
        ident.pack(fill="x", pady=(0, 10))
        ttk.Label(ident, text="PEM file:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(ident, textvariable=self.pem_var, width=60).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(ident, text="Passphrase:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(ident, textvariable=self.pass_var, show="*", width=60).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(ident, text="Load Identity", command=self.load_identity).grid(row=0, column=2, rowspan=2, padx=12)
        ttk.Label(ident, textvariable=self.status_var, foreground="#167a31").grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ident.columnconfigure(1, weight=1)

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(0, 10))
        ttk.Button(actions, text="Browse Rooms", command=self.browse_rooms).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Read Room", command=self.read_room).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Scan My Messages", command=self.scan_messages).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Clear Log", command=self.clear_log).pack(side="left")

        body = ttk.PanedWindow(outer, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, padding=4)
        right = ttk.Frame(body, padding=4)
        body.add(left, weight=1)
        body.add(right, weight=2)

        rooms_box = ttk.LabelFrame(left, text=" Public Rooms ", padding=8)
        rooms_box.pack(fill="both", expand=True)
        self.rooms_list = tk.Listbox(rooms_box, exportselection=False)
        self.rooms_list.pack(fill="both", expand=True)
        self.rooms_list.bind("<<ListboxSelect>>", self.select_room)

        send = ttk.LabelFrame(right, text=" 2. Send Signed Message ", padding=10)
        send.pack(fill="x", pady=(0, 10))
        ttk.Label(send, text="Room:").grid(row=0, column=0, sticky="w")
        ttk.Entry(send, textvariable=self.room_var).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(send, text="Message:").grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 4))
        self.message = tk.Text(send, height=8, wrap="word")
        self.message.grid(row=2, column=0, columnspan=2, sticky="nsew")
        ttk.Button(send, text="Send Signed Message", command=self.send_message).grid(row=3, column=0, columnspan=2, pady=(10, 0), sticky="ew")
        send.columnconfigure(1, weight=1)

        log_box = ttk.LabelFrame(right, text=" Activity / Errors ", padding=8)
        log_box.pack(fill="both", expand=True)
        self.log = scrolledtext.ScrolledText(log_box, height=18, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)

    def log_line(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def run_task(self, title: str, work, done):
        self.log_line(title)

        def worker():
            try:
                result = work()
                self.root.after(0, lambda result=result: done(result, None))
            except Exception as exc:
                self.root.after(
                    0,
                    lambda error=exc: done(None, error)
                )

        threading.Thread(target=worker, daemon=True).start()

    def load_identity(self):
        path = self.pem_var.get().strip()
        password = self.pass_var.get()
        if not password:
            messagebox.showwarning("Passphrase", "Enter the passphrase first.")
            return
        self.status_var.set("Unlocking identity...")
        def work():
            return load_private_key(path, password)
        def done(key, error):
            if error:
                self.key = None
                self.did = ""
                self.status_var.set("Could not load identity")
                self.log_line(f"IDENTITY ERROR: {error}")
                messagebox.showerror("Identity error", str(error))
                return
            self.key = key
            self.did = did_from_private_key(key)
            self.pass_var.set("")
            self.status_var.set(f"Loaded: {self.did}")
            self.log_line(f"Identity loaded successfully.\nDID: {self.did}")
        self.run_task("Loading identity...", work, done)

    def browse_rooms(self):
        def done(data, error):
            if error:
                self.log_line(f"ROOM ERROR: {error}")
                return
            items = parse_rooms(data)
            self.rooms = [name for name, _ in items]
            self.rooms_list.delete(0, "end")
            for name, seq in items:
                self.rooms_list.insert("end", f"{name}   last_seq={seq}" if seq else name)
            self.log_line(f"Loaded {len(items)} room(s).")
        self.run_task("Loading public rooms...", self.client.rooms, done)

    def select_room(self, _event=None):
        selection = self.rooms_list.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx < len(self.rooms):
            self.room_var.set(self.rooms[idx])
    def read_room(self):
        room = self.room_var.get().strip()

        if not room:
            messagebox.showwarning("Room", "Enter or select a room first.")
            return

        def work():
            return self.client.read(room, 200)

        def done(data, error):
            if error:
                self.log_line(f"READ ROOM ERROR:\n{error}")
                messagebox.showerror("Read room failed", str(error))
                return

            messages = data.get("messages", []) if isinstance(data, dict) else []

            self.log_line(
                f"ROOM: {room}\n"
                f"Loaded {len(messages)} message(s).\n"
            )

            if not messages:
                self.log_line("No messages found in this room.")
                return

            for message in messages:
                if not isinstance(message, dict):
                    continue

                seq = message.get("seq", "unknown")
                timestamp = message.get("ts", "unknown")
                sender = message.get("from", "unknown")
                text = message.get("text", "")

                marker = " [MY MESSAGE]" if sender == self.did else ""

                self.log_line(
                    f"SEQ: {seq}{marker}\n"
                    f"TIME: {timestamp}\n"
                    f"FROM: {sender}\n"
                    f"TEXT: {text}\n"
                    f"{'-' * 70}"
                )

        self.run_task(
            f"Reading room: {room}...",
            work,
            done
        )

    def send_message(self):
        if self.key is None:
            messagebox.showwarning("Identity", "Load identity.pem first.")
            return
        room = self.room_var.get().strip()
        text = self.message.get("1.0", "end-1c")
        if not room or not text.strip():
            messagebox.showwarning("Message", "Enter both room and message.")
            return
        def work():
            return self.client.say_signed(self.key, room, text)
        def done(result, error):
            if error:
                self.log_line(f"SEND ERROR:\n{error}")
                messagebox.showerror("Send failed", str(error))
                return
            posted = result.get("posted", result) if isinstance(result, dict) else {}
            seq = posted.get("seq", result.get("seq", "unknown") if isinstance(result, dict) else "unknown")
            sender = posted.get("from", self.did) if isinstance(posted, dict) else self.did
            self.log_line(f"MESSAGE SENT SUCCESSFULLY\nRoom: {room}\nSeq: {seq}\nDID: {sender}")
            self.message.delete("1.0", "end")
        self.run_task(f"Sending signed message to {room}...", work, done)

    def scan_messages(self):
        if not self.did:
            messagebox.showwarning("Identity", "Load identity.pem first.")
            return
        rooms = []
        for room in [self.room_var.get().strip(), "technocore", "lobby", *self.rooms]:
            room = room.strip().lower()
            if room and room not in rooms:
                rooms.append(room)
        def work():
            found = []
            errors = []
            for room in rooms[:100]:
                try:
                    data = self.client.read(room, 200)
                    messages = data.get("messages", []) if isinstance(data, dict) else []
                    for message in messages:
                        if isinstance(message, dict) and message.get("from") == self.did:
                            found.append((room, message))
                except Exception as exc:
                    errors.append((room, str(exc)))
            return found, errors
        def done(result, error):
            if error:
                self.log_line(f"SCAN ERROR: {error}")
                return
            found, errors = result
            self.log_line(f"Scan complete. Found {len(found)} message(s) for {self.did}.")
            for room, message in found:
                self.log_line(f"ROOM: {room}\nSEQ: {message.get('seq')}\nTIME: {message.get('ts')}\nTEXT: {message.get('text')}\n")
            for room, err in errors:
                self.log_line(f"{room}: {err}")
        self.run_task(f"Scanning {len(rooms)} room(s)...", work, done)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
