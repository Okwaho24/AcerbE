#!/usr/bin/env python3
"""
AcerbE™ v3.1.0 — Desktop GUI
Archer Chain Analytics™ | Mahihkan.com
Black / Gold / White — Institutional Grade
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import requests
import subprocess
import sys
import os
import json
import time
from pathlib import Path

# ─── BRAND ────────────────────────────────────────────────────────────────────
BLACK   = "#0A0A0A"
GOLD    = "#C9A84C"
WHITE   = "#F0F0F0"
DGOLD   = "#8A6A1C"
PANEL   = "#111111"
BORDER  = "#222222"
SUCCESS = "#2ECC71"
ERROR   = "#E74C3C"
WARN    = "#E67E22"

F_TITLE = ("Courier New", 22, "bold")
F_HEAD  = ("Courier New", 11, "bold")
F_BODY  = ("Courier New", 10)
F_SMALL = ("Courier New", 9)

SERVER_URL = "http://127.0.0.1:8001"
MAX_MB     = 500


class AcerbEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AcerbE™  |  Archer Chain Analytics™")
        self.configure(bg=BLACK)
        self.geometry("820x720")
        self.resizable(False, False)
        self._server_proc = None
        self._embed_file  = ""
        self._verify_file = ""
        self._build_ui()
        self._start_server()

    # ─── SERVER ───────────────────────────────────────────────────────────────

    def _start_server(self):
        def _launch():
            try:
                env = os.environ.copy()
                server_path = Path(__file__).resolve().parent.parent / "acerbe" / "server.py"
                self._server_proc = subprocess.Popen(
                    [sys.executable, str(server_path)],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                # Poll until responsive
                for _ in range(15):
                    time.sleep(0.5)
                    try:
                        r = requests.get(f"{SERVER_URL}/health", timeout=1)
                        if r.status_code == 200:
                            d = r.json()
                            if d.get("key_configured"):
                                self.after(0, lambda: self._set_status("ENGINE ONLINE — KEY CONFIGURED", SUCCESS))
                            else:
                                self.after(0, lambda: self._set_status("ENGINE ONLINE — KEY NOT SET", WARN))
                            return
                    except Exception:
                        pass
                self.after(0, lambda: self._set_status("ENGINE TIMEOUT — CHECK ACERBE_SECRET_KEY", ERROR))
            except Exception as e:
                self.after(0, lambda: self._set_status(f"LAUNCH ERROR: {e}", ERROR))

        threading.Thread(target=_launch, daemon=True).start()

    def _set_status(self, msg, color=GOLD):
        self._status.config(text=msg, fg=color)

    # ─── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=BLACK)
        hdr.pack(fill="x", pady=(16, 4))
        tk.Label(hdr, text="ACERBE™", font=F_TITLE, bg=BLACK, fg=GOLD).pack()
        tk.Label(hdr, text="DIGITAL FINGERPRINT EMBEDDING DEVICE  |  v3.1.0",
                 font=F_SMALL, bg=BLACK, fg=WHITE).pack()
        tk.Label(hdr, text="ARCHER CHAIN ANALYTICS™  ·  MAHIHKAN.COM",
                 font=F_SMALL, bg=BLACK, fg=DGOLD).pack(pady=(0, 6))
        tk.Frame(self, bg=GOLD, height=1).pack(fill="x", padx=20)

        self._status = tk.Label(self, text="INITIALIZING...", font=F_SMALL,
                                bg=BLACK, fg=GOLD)
        self._status.pack(pady=5)

        # Tabs
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BLACK, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=WHITE,
                        font=F_SMALL, padding=[14, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", GOLD)],
                  foreground=[("selected", BLACK)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=8)

        for attr, label in [
            ("_tab_embed",  "  EMBED  "),
            ("_tab_verify", "  VERIFY  "),
            ("_tab_log",    "  AUDIT LOG  "),
        ]:
            frame = tk.Frame(nb, bg=BLACK)
            setattr(self, attr, frame)
            nb.add(frame, text=label)

        self._build_embed_tab()
        self._build_verify_tab()
        self._build_log_tab()

    # ─── EMBED TAB ────────────────────────────────────────────────────────────

    def _build_embed_tab(self):
        f = self._tab_embed

        self._lbl(f, "OWNER ID").pack(anchor="w", padx=20, pady=(14, 2))
        self._owner = tk.StringVar(value="Mahihkan")
        self._entry(f, self._owner).pack(fill="x", padx=20)

        self._lbl(f, "NOTES  (optional — appended to manifest)").pack(
            anchor="w", padx=20, pady=(10, 2))
        self._notes = tk.StringVar()
        self._entry(f, self._notes).pack(fill="x", padx=20)

        self._lbl(f, "TARGET FILE").pack(anchor="w", padx=20, pady=(10, 2))
        row = tk.Frame(f, bg=BLACK)
        row.pack(fill="x", padx=20)
        self._file_lbl = tk.Label(row, text="No file selected", font=F_SMALL,
                                  bg=PANEL, fg=WHITE, anchor="w", padx=8,
                                  width=54, relief="flat")
        self._file_lbl.pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(row, text="BROWSE", font=F_SMALL, bg=GOLD, fg=BLACK,
                  relief="flat", padx=10,
                  command=self._browse_embed).pack(side="left", padx=(6, 0))

        tk.Label(f, text=f"Max {MAX_MB} MB — PDF, DOCX, TXT, PY, PNG, ZIP, and all types",
                 font=F_SMALL, bg=BLACK, fg=DGOLD).pack(anchor="w", padx=20, pady=(3, 0))

        tk.Frame(f, bg=BORDER, height=1).pack(fill="x", padx=20, pady=10)

        self._embed_btn = tk.Button(
            f, text="▶  EMBED FINGERPRINT",
            font=F_HEAD, bg=GOLD, fg=BLACK, relief="flat",
            padx=20, pady=10, cursor="hand2",
            command=self._run_embed,
        )
        self._embed_btn.pack(padx=20, fill="x")

        style = ttk.Style()
        style.configure("G.Horizontal.TProgressbar",
                        troughcolor=PANEL, background=GOLD, thickness=5)
        self._progress = ttk.Progressbar(f, mode="indeterminate",
                                         style="G.Horizontal.TProgressbar")
        self._progress.pack(fill="x", padx=20, pady=6)

        self._lbl(f, "FINGERPRINT CERTIFICATE").pack(anchor="w", padx=20, pady=(6, 2))
        self._result = self._textbox(f, height=11)
        self._result.pack(fill="both", padx=20, pady=(0, 14))

    # ─── VERIFY TAB ───────────────────────────────────────────────────────────

    def _build_verify_tab(self):
        f = self._tab_verify

        self._lbl(f, "FILE TO VERIFY").pack(anchor="w", padx=20, pady=(14, 2))
        row = tk.Frame(f, bg=BLACK)
        row.pack(fill="x", padx=20)
        self._verify_lbl = tk.Label(row, text="No file selected", font=F_SMALL,
                                    bg=PANEL, fg=WHITE, anchor="w", padx=8,
                                    width=54, relief="flat")
        self._verify_lbl.pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(row, text="BROWSE", font=F_SMALL, bg=GOLD, fg=BLACK,
                  relief="flat", padx=10,
                  command=self._browse_verify).pack(side="left", padx=(6, 0))

        tk.Frame(f, bg=BORDER, height=1).pack(fill="x", padx=20, pady=10)
        tk.Button(
            f, text="▶  VERIFY FINGERPRINT",
            font=F_HEAD, bg=GOLD, fg=BLACK, relief="flat",
            padx=20, pady=10, cursor="hand2",
            command=self._run_verify,
        ).pack(padx=20, fill="x")

        self._lbl(f, "VERIFICATION REPORT").pack(anchor="w", padx=20, pady=(14, 2))
        self._verify_out = self._textbox(f, height=18)
        self._verify_out.pack(fill="both", padx=20, pady=(0, 14))

    # ─── LOG TAB ──────────────────────────────────────────────────────────────

    def _build_log_tab(self):
        f = self._tab_log
        self._lbl(f, "OPERATION LOG — THIS SESSION").pack(
            anchor="w", padx=20, pady=(14, 2))
        self._log_box = self._textbox(f, fg=WHITE)
        self._log_box.pack(fill="both", expand=True, padx=20, pady=(0, 14))

    # ─── HELPERS ──────────────────────────────────────────────────────────────

    def _lbl(self, p, text):
        return tk.Label(p, text=text, font=F_SMALL, bg=BLACK, fg=GOLD)

    def _entry(self, p, var):
        return tk.Entry(p, textvariable=var, font=F_BODY,
                        bg=PANEL, fg=WHITE, insertbackground=WHITE,
                        relief="flat")

    def _textbox(self, p, height=8, fg=GOLD):
        t = tk.Text(p, height=height, font=F_SMALL, bg=PANEL, fg=fg,
                    relief="flat", padx=10, pady=8,
                    insertbackground=GOLD, state="disabled")
        return t

    def _write(self, box, text, color=None):
        box.config(state="normal")
        box.delete("1.0", "end")
        box.insert("end", text)
        if color:
            box.config(fg=color)
        box.config(state="disabled")

    def _log(self, msg):
        self._log_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self._log_box.insert("end", f"[{ts}] {msg}\n")
        self._log_box.see("end")
        self._log_box.config(state="disabled")

    def _browse_embed(self):
        p = filedialog.askopenfilename(title="Select File to Fingerprint")
        if p:
            self._embed_file = p
            self._file_lbl.config(text=Path(p).name)

    def _browse_verify(self):
        p = filedialog.askopenfilename(title="Select Fingerprinted File")
        if p:
            self._verify_file = p
            self._verify_lbl.config(text=Path(p).name)

    # ─── EMBED ────────────────────────────────────────────────────────────────

    def _run_embed(self):
        if not self._embed_file:
            messagebox.showwarning("AcerbE™", "No file selected.")
            return
        owner = self._owner.get().strip() or "Mahihkan"
        notes = self._notes.get().strip()

        self._embed_btn.config(state="disabled")
        self._progress.start(10)
        self._log(f"EMBED — {Path(self._embed_file).name}  |  owner: {owner}")

        def _run():
            try:
                with open(self._embed_file, "rb") as fh:
                    resp = requests.post(
                        f"{SERVER_URL}/embed",
                        files={"file": (Path(self._embed_file).name, fh)},
                        data={"owner_id": owner, "notes": notes},
                        timeout=60,
                    )
                d = resp.json()
                if resp.status_code == 200:
                    ls = d["layer_detail"]
                    cert = (
                        f"AcerbE™ Fingerprint Certificate  [v3.1.0]\n"
                        f"{'─' * 48}\n"
                        f"Status          : FINGERPRINTED\n"
                        f"Fingerprint     : {d['short_fingerprint']}\n"
                        f"Manifest ID     : {d['manifest_id']}\n"
                        f"Timestamp       : {d['timestamp']}\n"
                        f"Layers Active   : {d['layers_active']}/4\n"
                        f"  [1] HMAC-SHA256 Signing  : {'✓' if ls['hmac_sha256_signing'] else '✗'}\n"
                        f"  [2] SHA256 Asset Hash    : {'✓' if ls['sha256_asset_hash'] else '✗'}\n"
                        f"  [3] Steganographic LSB   : {'✓' if ls['steganographic_lsb'] else '✗'}\n"
                        f"  [4] Pydantic Manifest    : {'✓' if ls['pydantic_manifest'] else '✗'}\n"
                        f"File Type       : {d['file_type'].upper()}\n"
                        f"Output File     : {d['output_file']}\n"
                        f"Manifest File   : {d['manifest_file']}\n"
                        f"Issuer          : Archer Chain Analytics™\n"
                        f"Jurisdiction    : Saskatchewan, Canada\n"
                    )
                    self.after(0, lambda: self._write(self._result, cert, GOLD))
                    self._log(f"SUCCESS — {d['short_fingerprint']}  layers:{d['layers_active']}/4")
                else:
                    err = d.get("detail", "Unknown error")
                    self.after(0, lambda: self._write(self._result, f"ERROR: {err}", ERROR))
                    self._log(f"FAILED — {err}")
            except requests.ConnectionError:
                msg = "Engine not reachable. Ensure ACERBE_SECRET_KEY is set."
                self.after(0, lambda: self._write(self._result, msg, ERROR))
                self._log("CONNECTION ERROR")
            except Exception as e:
                self.after(0, lambda: self._write(self._result, f"ERROR: {e}", ERROR))
                self._log(f"ERROR — {e}")
            finally:
                self.after(0, lambda: (
                    self._progress.stop(),
                    self._embed_btn.config(state="normal"),
                ))

        threading.Thread(target=_run, daemon=True).start()

    # ─── VERIFY ───────────────────────────────────────────────────────────────

    def _run_verify(self):
        if not self._verify_file:
            messagebox.showwarning("AcerbE™", "No file selected.")
            return
        self._log(f"VERIFY — {Path(self._verify_file).name}")

        def _run():
            try:
                with open(self._verify_file, "rb") as fh:
                    resp = requests.post(
                        f"{SERVER_URL}/verify",
                        files={"file": (Path(self._verify_file).name, fh)},
                        timeout=60,
                    )
                d    = resp.json()
                text = json.dumps(d, indent=2)
                col  = SUCCESS if d.get("verified") else ERROR
                self.after(0, lambda: self._write(self._verify_out, text, col))
                self._log(f"{'VERIFIED ✓' if d.get('verified') else 'NOT VERIFIED ✗'}")
            except Exception as e:
                self.after(0, lambda: self._write(self._verify_out, f"ERROR: {e}", ERROR))
                self._log(f"VERIFY ERROR — {e}")

        threading.Thread(target=_run, daemon=True).start()

    def on_close(self):
        if self._server_proc:
            self._server_proc.terminate()
        self.destroy()


def main():
    app = AcerbEApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
