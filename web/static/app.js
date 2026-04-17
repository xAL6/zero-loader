/* zero-loader console — client logic
 *
 * Talks to the local Flask backend (same origin, 127.0.0.1). No build step,
 * no framework — fetch + DOM.
 */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ---------- tab switching ----------
$$(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach(t => t.classList.toggle("active", t === btn));
    const target = btn.dataset.tab;
    $$(".panel").forEach(p => p.classList.toggle("active", p.id === `panel-${target}`));
  });
});

// ---------- console writer ----------
function writeConsole(el, line, { ok = null, reset = false } = {}) {
  if (reset) el.textContent = "";
  el.textContent += line;
  el.scrollTop = el.scrollHeight;
  el.classList.remove("ok", "bad");
  if (ok === true)  el.classList.add("ok");
  if (ok === false) el.classList.add("bad");
}

// ---------- status pills ----------
async function refreshStatus() {
  try {
    const r = await fetch("/api/status");
    const j = await r.json();
    const pp = $("#pill-payload");
    pp.textContent = j.payload_h ? "Payload.h ✓" : "Payload.h —";
    pp.classList.toggle("ok",  j.payload_h);
    pp.classList.toggle("bad", !j.payload_h);

    const ps = $("#pill-sideload");
    ps.textContent = j.sideload_h ? "Sideload.h ✓" : "Sideload.h —";
    ps.classList.toggle("ok",  j.sideload_h);
    ps.classList.toggle("bad", !j.sideload_h);
  } catch (e) {
    // backend down — leave placeholders
  }
}

// ---------- artifacts ----------
function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function fmtTime(sec) {
  const d = new Date(sec * 1000);
  return d.toLocaleString();
}

async function refreshArtifacts() {
  try {
    const r = await fetch("/api/artifacts");
    const arts = await r.json();
    const list = $("#artifact-list");
    list.innerHTML = "";
    if (!arts.length) {
      const empty = document.createElement("p");
      empty.className = "empty-note";
      empty.textContent = "No build artifacts yet.";
      list.appendChild(empty);
      return;
    }
    for (const a of arts) {
      const li = document.createElement("li");
      li.className = "artifact";
      li.innerHTML = `
        <div class="name">
          <span>${a.name}</span>
          <a class="dl" href="/api/download/${encodeURIComponent(a.name)}">download</a>
        </div>
        <div class="meta">${fmtSize(a.size)} · ${fmtTime(a.mtime)}</div>
      `;
      list.appendChild(li);
    }
  } catch (e) {
    // ignore
  }
}

$("#btn-refresh-arts").addEventListener("click", refreshArtifacts);

// ---------- encrypt ----------
$("#form-encrypt").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-encrypt");
  writeConsole(out, "> running Encrypt.py ...\n", { reset: true });

  const form = new FormData(e.target);
  try {
    const r = await fetch("/api/encrypt", { method: "POST", body: form });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    writeConsole(out, `\n[exit ${j.code ?? (j.ok ? 0 : -1)}]\n`, { ok: j.ok });

    if (j.payload_preview) {
      $("#preview-payload").textContent = j.payload_preview;
    }
  } catch (err) {
    writeConsole(out, `[network error] ${err}\n`, { ok: false });
  }
  refreshStatus();
});

// ---------- sideload ----------
$("#form-sideload").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-sideload");
  writeConsole(out, "> running SideloadGen.py ...\n", { reset: true });

  const form = new FormData(e.target);
  try {
    const r = await fetch("/api/sideload", { method: "POST", body: form });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    writeConsole(out, `\n[exit ${j.code ?? (j.ok ? 0 : -1)}]\n`, { ok: j.ok });
  } catch (err) {
    writeConsole(out, `[network error] ${err}\n`, { ok: false });
  }
  refreshStatus();
});

// ---------- build (streaming) ----------
const fieldOutput = $("#field-output");

function syncBuildMode() {
  const mode = $("input[name=mode]:checked", $("#form-build")).value;
  fieldOutput.style.display = mode === "sideload" ? "" : "none";
}
$$("input[name=mode]").forEach(r => r.addEventListener("change", syncBuildMode));
syncBuildMode();

$("#form-build").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-build");
  out.textContent = "";
  out.classList.remove("ok", "bad");

  const form = e.target;
  const body = {
    mode:       $("input[name=mode]:checked", form).value,
    output:     form.output?.value || "",
    uac:        form.uac.checked,
    rwx:        form.rwx.checked,
    debug:      form.debug.checked,
    synthetic:  form.synthetic.checked,
  };

  const btn = $("button.primary", form);
  btn.disabled = true;
  btn.textContent = "Building...";

  try {
    const r = await fetch("/api/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer = decoder.decode(value, { stream: true });
      writeConsole(out, buffer);
    }

    // Infer status from the last line "[exit N]"
    const lines = out.textContent.trim().split("\n");
    const exitLine = lines[lines.length - 1];
    const m = exitLine.match(/\[exit (-?\d+)\]/);
    if (m) {
      out.classList.toggle("ok",  m[1] === "0");
      out.classList.toggle("bad", m[1] !== "0");
    }
  } catch (err) {
    writeConsole(out, `[network error] ${err}\n`, { ok: false });
  } finally {
    btn.disabled = false;
    btn.textContent = "Build";
    refreshArtifacts();
    refreshStatus();
  }
});

// ---------- boot ----------
refreshStatus();
refreshArtifacts();
setInterval(refreshArtifacts, 5000);
