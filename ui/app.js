const $ = (id) => document.getElementById(id);
const ENT = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ENT[c]);
const DASH = "—";

const PAGE_SIZE = 100;

const state = {
  rows: [],
  byNum: new Map(),
  cap: 500,
  selected: null,
  paused: false,
  pending: [],
  failOnly: false,
  query: "",
  page: 0,
  cfg: {},
  failures: 0,

  firstSeen: new Map(),
  expanded: new Set(),
  collapsed: new Set(),
  shown: new Map(),
};

let renderQueued = false;
function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => { renderQueued = false; renderList(); });
}

function statusCell(r) {
  if (r.outcome === "ok") return '<span class="s' + Math.floor(r.status / 100) + 'xx">' + r.status + "</span>";
  if (r.outcome === "client-gone") return '<span class="gone">gave up</span>';
  if (r.outcome === "proxy-failed") return '<span class="err">proxy</span>';
  return '<span class="err">failed</span>';
}

function matches(r) {
  if (state.failOnly && (r.outcome === "ok" || r.outcome === "client-gone")) return false;
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [r.host, r.path, r.session, r.conn, r.error]
    .some((v) => (v || "").toLowerCase().includes(q));
}

const ICON_PAUSE = '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">' +
  '<rect x="2.4" y="1.8" width="2.7" height="8.4" rx=".8" fill="currentColor"/>' +
  '<rect x="6.9" y="1.8" width="2.7" height="8.4" rx=".8" fill="currentColor"/></svg>';
const ICON_PLAY = '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">' +
  '<path d="M3.3 1.9 L10 6 L3.3 10.1 Z" fill="currentColor" stroke="currentColor" ' +
  'stroke-width=".9" stroke-linejoin="round"/></svg>';
function paintPause() {
  const b = $("pause");
  const held = state.pending.length;
  b.setAttribute("aria-pressed", String(state.paused));
  b.innerHTML = state.paused
    ? ICON_PLAY + "<span>Resume" + (held ? " · " + held : "") + "</span>"
    : ICON_PAUSE + "<span>Pause</span>";
  b.title = state.paused
    ? "Show the requests that arrived while paused"
    : "Hold new requests so the list stops moving";
}

const narrow = window.matchMedia("(max-width: 1280px)");
const columns = () => (narrow.matches ? 6 : 8);
const GROUP_ROWS = 50;

const pad2 = (n) => String(n).padStart(2, "0");
function stamp(at) {
  const d = new Date(at);
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " +
    pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
}
const timeOf = (r) => stamp(r.at);
const hostOf = (r) => r.host || "(no host)";
const failed = (r) => r.outcome === "proxy-failed" || r.outcome === "failed";

function rowHTML(r) {
  return '<tr class="req-row" data-num="' + r.num + '" aria-selected="' + (state.selected === r.num) + '">' +
    '<td class="gone">' + r.num + "</td>" +
    '<td class="gone">' + timeOf(r) + "</td>" +
    "<td>" + esc(r.method) + "</td>" +
    '<td class="path" title="' + esc(r.path) + '">' + esc(r.path) + "</td>" +
    "<td>" + statusCell(r) + "</td>" +
    '<td class="gone">' + r.millis + "</td>" +
    (narrow.matches ? "" :
      "<td>" + esc(r.session || DASH) + "</td>" +
      '<td class="gone">' + esc(r.conn || DASH) + "</td>") +
    "</tr>";
}

const CHEVRON = '<svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">' +
  '<path d="M3.5 1.8 L6.7 5 L3.5 8.2" fill="none" stroke="currentColor" stroke-width="1.7" ' +
  'stroke-linecap="round" stroke-linejoin="round"/></svg>';

function groupHTML(g, open) {
  const n = g.rows.length;
  return '<tr class="host-row" data-host="' + esc(g.host) + '" aria-expanded="' + open + '"' +
      ' title="' + (open ? "Click to collapse" : "Click to expand") + '">' +
    '<td colspan="' + columns() + '"><div class="host-head">' +
      '<span class="host-toggle">' + CHEVRON + "</span>" +
      '<span class="host-name">' + esc(g.host) + "</span>" +
      '<span class="host-meta">' +
        "<span>" + n + (n === 1 ? " request" : " requests") + "</span>" +
        (g.failed ? '<span class="err">' + g.failed + " failed</span>" : "") +
        "<span>" + timeOf(g.rows[0]) + "</span>" +
      "</span>" +
    "</div></td></tr>";
}

function groupRows() {
  const byHost = new Map();
  for (const r of state.rows) {
    if (!matches(r)) continue;
    const host = hostOf(r);
    let g = byHost.get(host);
    if (!g) byHost.set(host, (g = { host, rows: [], failed: 0 }));
    g.rows.push(r);
    if (failed(r)) g.failed++;
  }

  const groups = [...byHost.values()];
  for (const g of groups) g.rows.sort((a, b) => b.num - a.num);
  groups.sort((a, b) => (state.firstSeen.get(b.host) ?? 0) - (state.firstSeen.get(a.host) ?? 0));
  return groups;
}

const filtering = () => state.query !== "" || state.failOnly;
const isOpen = (host) => filtering() ? !state.collapsed.has(host) : state.expanded.has(host);

function toggleHost(host) {
  const set = filtering() ? state.collapsed : state.expanded;
  if (set.has(host)) set.delete(host); else set.add(host);
  renderList();
}

function renderList() {
  const groups = groupRows();
  const pages = Math.max(1, Math.ceil(groups.length / PAGE_SIZE));
  if (state.page > pages - 1) state.page = pages - 1;

  const start = state.page * PAGE_SIZE;
  const html = [];
  for (const g of groups.slice(start, start + PAGE_SIZE)) {
    const open = isOpen(g.host);
    html.push(groupHTML(g, open));
    if (!open) continue;

    const limit = state.shown.get(g.host) || GROUP_ROWS;
    for (const r of g.rows.slice(0, limit)) html.push(rowHTML(r));
    const rest = g.rows.length - limit;
    if (rest > 0) {
      html.push('<tr class="host-more" data-more="' + esc(g.host) + '"><td colspan="' + columns() + '">' +
        "Show " + Math.min(rest, 100) + " more · " + rest + " older" + "</td></tr>");
    }
  }

  $("rows").innerHTML = html.join("");
  $("empty").hidden = groups.length > 0;
  $("empty").textContent = state.rows.length
    ? "nothing matches this filter"
    : "waiting for traffic…";

  const total = groups.reduce((n, g) => n + g.rows.length, 0);
  const held = state.pending.length;
  $("pagecount").textContent =
    groups.length + (groups.length === 1 ? " host · " : " hosts · ") +
    total + (total === 1 ? " request" : " requests") +
    (held ? " · " + held + " held" : "");
  $("pagenum").textContent = (state.page + 1) + " / " + pages;
  $("p-prev").disabled = state.page === 0;
  $("p-newest").disabled = state.page === 0;
  $("p-next").disabled = state.page >= pages - 1;
  paintPause();
}

function paintRaw(raw) {
  let inBody = false;
  return String(raw).split("\n").map((line, i) => {
    const text = line.replace(/\r$/, "");
    if (inBody) return esc(text);
    if (text === "") { inBody = true; return ""; }
    const pseudo = text.startsWith(":");
    if (i === 0 && !pseudo) return '<span class="first">' + esc(text) + "</span>";
    const cut = text.indexOf(":", pseudo ? 1 : 0);
    if (cut < 0) return esc(text);
    return '<span class="' + (pseudo ? "pseudo" : "hname") + '">' +
      esc(text.slice(0, cut)) + "</span>" + esc(text.slice(cut));
  }).join("\n");
}

function looksBinary(s) {
  let control = 0;
  const n = Math.min(s.length, 2048);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) return true;
    if (c < 9 || (c > 13 && c < 32)) control++;
  }
  return n > 0 && control / n > 0.08;
}

function bodyHTML(rec) {
  if (!rec.rawBody) {
    if (rec.bodyBytes) {
      return '<p class="note">' + rec.bodyBytes + " bytes, not captured.</p>";
    }
    return '<p class="note">No body.</p>';
  }

  const size = rec.bodyBytes
    ? rec.bodyBytes.toLocaleString() + " bytes"
    : rec.rawBody.length + " bytes";
  const cut = rec.bodyTruncated
    ? ' \u00b7 showing the first ' + rec.rawBody.length.toLocaleString()
    : "";

  if (looksBinary(rec.rawBody)) {
    return "<h3>Body</h3>" +
      '<p class="note">Binary content \u2014 ' + esc(size) + ".</p>";
  }
  return "<h3>Body <span class=\"sz\">" + esc(size + cut) + "</span></h3>" +
    "<pre>" + esc(rec.rawBody) + "</pre>";
}

async function select(num) {
  state.selected = num;
  renderList();

  let full = state.byNum.get(num) || {};
  try {
    const res = await api("/api/requests?num=" + num);
    if (res.ok) full = await res.json();
  } catch (e) {  }

  $("pane-req").innerHTML = full.rawRequest
    ? "<pre>" + paintRaw(full.rawRequest) + "</pre>" +
      (full.truncated ? '<p class="note">Truncated at the recorder’s body limit.</p>' : "")
    : '<p class="note">No raw capture. This request has aged out of the recording window.</p>';

  const parts = [];
  if (full.error) parts.push('<dl><dt>error</dt><dd class="err">' + esc(full.error) + "</dd></dl>");
  parts.push("<dl>" +
    "<dt>time</dt><dd>" + (full.at ? stamp(full.at) : DASH) + "</dd>" +
    "<dt>outcome</dt><dd>" + esc(full.outcome || DASH) + "</dd>" +
    "<dt>status</dt><dd>" + (full.status || DASH) + "</dd>" +
    "<dt>protocol</dt><dd>" + esc(full.proto || DASH) + "</dd>" +
    "<dt>duration</dt><dd>" + (full.millis ?? DASH) + " ms</dd>" +
    "<dt>session</dt><dd>" + esc(full.session || DASH) + "</dd>" +
    "<dt>upstream</dt><dd>" + esc(full.proxy || "direct") + "</dd>" +
    "<dt>connection</dt><dd>" + esc(full.conn || DASH) + "</dd>" +
    "</dl>");
  if (full.rawResponse) {
    parts.push("<h3>Headers</h3><pre>" + paintRaw(full.rawResponse) + "</pre>");
  }
  parts.push(bodyHTML(full));
  $("pane-res").innerHTML = parts.join("");
}

function addRecord(r, atFront) {
  if (state.byNum.has(r.num)) return;
  state.byNum.set(r.num, r);

  const host = hostOf(r);
  const seen = state.firstSeen.get(host);
  if (seen === undefined || r.num < seen) state.firstSeen.set(host, r.num);

  if (atFront) state.rows.unshift(r); else state.rows.push(r);
  while (state.rows.length > state.cap) {
    const dropped = state.rows.pop();
    if (dropped) state.byNum.delete(dropped.num);
  }
}

function openModal(title, html) {
  $("modal-title").textContent = title;
  $("modal-body").innerHTML = html;
  if (!$("modal").open) $("modal").showModal();
}

function snippetBlock(caption, lines) {
  return '<div class="snippet"><div class="snippet-head"><span>' + esc(caption) + "</span>" +
    '<button type="button" data-copy-pre>Copy</button></div>' +
    "<pre>" + esc(lines.join("\n")) + "</pre></div>";
}

function detectOS() {
  const p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  if (/win/i.test(p)) return "windows";
  if (/mac/i.test(p)) return "macos";
  return "linux";
}

const CA_FILE = "tlsmask-ca.crt";
const CA_INSTALL = {
  windows: { label: "Windows", blocks: [
    ["Current user, no administrator needed", ["certutil -addstore -user Root " + CA_FILE]],
    ["Whole machine, from an administrator prompt", ["certutil -addstore Root " + CA_FILE]],
  ] },
  macos: { label: "macOS", blocks: [
    ["System keychain", [
      "sudo security add-trusted-cert -d -r trustRoot \\",
      "  -k /Library/Keychains/System.keychain " + CA_FILE,
    ]],
  ] },
  linux: { label: "Linux", blocks: [
    ["Debian, Ubuntu", [
      "sudo cp " + CA_FILE + " /usr/local/share/ca-certificates/" + CA_FILE,
      "sudo update-ca-certificates",
    ]],
    ["Fedora, RHEL, CentOS", [
      "sudo cp " + CA_FILE + " /etc/pki/ca-trust/source/anchors/",
      "sudo update-ca-trust",
    ]],
    ["Arch", ["sudo trust anchor --store " + CA_FILE]],
  ] },
};

function certHTML() {
  const c = state.cfg;
  const oses = Object.keys(CA_INSTALL).map((id) =>
    '<button type="button" class="chip" data-os="' + id + '" aria-pressed="false">' +
      CA_INSTALL[id].label + "</button>").join("");
  const panes = Object.keys(CA_INSTALL).map((id) =>
    '<div class="os-pane" data-os-pane="' + id + '" hidden>' +
      CA_INSTALL[id].blocks.map((b) => snippetBlock(b[0], b[1])).join("") + "</div>").join("");

  return '<p class="note">One CA signs every host, so it is installed once. Without it, ' +
      "clients have to turn certificate verification off.</p>" +
    '<div class="cert-actions"><a class="primary" href="/ca.crt" download>Download ' + CA_FILE + "</a>" +
      '<button type="button" id="c-regen" class="with-icon">' +
        '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8M3 3v5h5"/></svg>' +
        "<span>Regenerate</span></button>" +
      '<span class="msg" id="c-msg"></span></div>' +
    "<dl>" +
      "<dt>sha-256</dt><dd>" + esc(c.caFingerprint || DASH) + "</dd>" +
      "<dt>expires</dt><dd>" + esc(c.caExpires || DASH) + "</dd>" +
      "<dt>kept at</dt><dd>" + esc(c.caPath || "in memory only; pass --data-dir to persist it") + "</dd>" +
    "</dl>" +

    "<h3>Install It</h3>" +
    '<p class="note">Run these where you saved ' + CA_FILE + ".</p>" +
    '<div class="langs" id="c-oses">' + oses + "</div>" + panes +

    '<details class="fold">' +
      "<summary>" + CHEVRON + "<span>Python, Node.js, Java or Firefox? They keep their own list</span></summary>" +
      '<div class="fold-body">' +
        '<p class="note">Browsers, Go, .NET and curl use the system store, so the step above is ' +
          "all they need. These ignore it and have to be pointed at the file.</p>" +
        snippetBlock("Python: requests and httpx read certifi, not the system store", [
          'requests.get(url, proxies=proxies, verify="' + CA_FILE + '")',
          "# or for the whole process:  SSL_CERT_FILE=" + CA_FILE + "  REQUESTS_CA_BUNDLE=" + CA_FILE,
        ]) +
        snippetBlock("Node.js", ["NODE_EXTRA_CA_CERTS=" + CA_FILE + " node app.js"]) +
        snippetBlock("Java: JDK 9 and later, as administrator", [
          "keytool -importcert -alias tlsmask -file " + CA_FILE + " -cacerts -storepass changeit",
        ]) +
        '<p class="note">Firefox: Settings → Privacy &amp; Security → Certificates → View ' +
          "Certificates → Authorities → Import, unless it is already set to trust the system store.</p>" +
      "</div>" +
    "</details>" +
    '<p class="note">Generated once and kept in the data directory, so a restart reuses it ' +
      "as long as that directory is on a volume. After Regenerate, install the new one " +
      "everywhere the old one was trusted.</p>";
}

function paintOS(id) {
  $("c-oses").querySelectorAll("[data-os]").forEach((c) => {
    c.setAttribute("aria-pressed", String(c.dataset.os === id));
  });
  $("modal-body").querySelectorAll("[data-os-pane]").forEach((p) => {
    p.hidden = p.dataset.osPane !== id;
  });
}

function openCert(notice) {
  openModal("Certificate", certHTML());
  paintOS(detectOS());
  $("c-oses").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-os]");
    if (chip) paintOS(chip.dataset.os);
  });
  if (notice) {
    $("c-msg").className = "msg ok";
    $("c-msg").textContent = notice;
  }

  $("c-regen").addEventListener("click", async () => {
    const sure = await confirmDialog({
      title: "Regenerate the certificate?",
      body: "A new CA replaces the current one. Every client and browser that trusts the " +
        "current certificate rejects the proxy until the new one is installed.",
      confirm: "Regenerate",
    });
    if (!sure) return;
    try {
      const res = await api("/api/ca", { method: "POST" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.statusText);
      await loadConfig();
      openCert("New certificate ready. Download it and install it again.");
    } catch (err) {
      $("c-msg").className = "msg bad";
      $("c-msg").textContent = errText(err);
    }
  });
}

function fingerprintHTML() {
  const c = state.cfg;
  if (!c.activeJA3) {
    return '<p class="note">No fingerprint is configured yet. Set one in Settings.</p>';
  }
  const greased = c.effectiveJA3 && c.effectiveJA3 !== c.activeJA3;
  let html = "<h3>What this proxy impersonates</h3><dl>" +
    "<dt>JA3</dt><dd>" + esc(c.activeJA3) + "</dd>" +
    "<dt>profile</dt><dd>" + esc(c.profile || DASH) + "</dd>" +
    "<dt>randomize</dt><dd>" + esc(c.randomize || DASH) + "</dd></dl>";
  if (greased) {
    html += "<h3>What goes on the wire</h3>" +
      '<p class="note">GREASE is redrawn every handshake. JA3 and JA4 discard it, so ' +
      "the fingerprint a peer computes is the one above.</p>" +
      "<dl><dt>greased JA3</dt><dd>" + esc(c.effectiveJA3) + "</dd></dl>" +
      '<p class="note">Extension order is permuted per connection, so the JA3 hash ' +
      "differs every handshake while the JA4 stays pinned, as Chrome does.</p>";
  }
  return html;
}

function opt(list, selected) {
  return (list || []).map(function (v) {
    return '<option value="' + esc(v) + '"' + (v === selected ? " selected" : "") +
      ">" + esc(v) + "</option>";
  }).join("");
}

const DUR_UNITS = { h: 3600, ms: 0.001, m: 60, s: 1 };

function durationSeconds(value) {
  if (typeof value === "number") return Math.max(0, Math.round(value));
  let total = 0;
  for (const [, n, unit] of String(value || "").matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s)/g)) {
    total += Number(n) * DUR_UNITS[unit];
  }
  return Math.max(0, Math.round(total));
}

function durField(label, id, value, hint) {
  return field(label,
    '<div class="dur"><input type="number" min="0" step="1" id="' + id + '" value="' +
      durationSeconds(value) + '"><span class="unit">sec</span></div>', hint);
}

function field(label, control, hint) {
  return '<div class="field"><label>' + esc(label) + "</label>" + control +
    (hint ? '<span class="hint">' + hint + "</span>" : "") + "</div>";
}

function settingsHTML(s) {
  const c = state.cfg;

  return '<form class="form" id="settings-form">' +

    '<section class="group"><h4>Fingerprint</h4>' +
      field("Preset",
        '<select id="f-preset"><option value="">Custom (use JA3 + JA4)</option>' +
          opt(c.presets, s.ja3 ? "" : s.preset) + "</select>" +
          '<span class="hint" id="f-preset-hint"></span>') +
      field("Hex Dump",
        '<textarea id="f-hex" rows="2" placeholder="Paste a ClientHello hex stream from Wireshark"></textarea>' +
          '<button type="button" id="f-expand" class="inline-btn">Expand into JA3 + JA4</button>') +
      field("JA3", '<textarea id="f-ja3" rows="3">' + esc(s.ja3 || "") + "</textarea>") +
      field("JA4", '<textarea id="f-ja4r" rows="3">' + esc(s.ja4r || "") + "</textarea>",
        "The raw form, JA4_r, not the hash. Required together with JA3.") +
      '<div class="row2">' +
        field("Randomize", '<select id="f-randomize">' + opt(c.modes, s.randomize) + "</select>") +
        '<div class="field"><label>GREASE</label><div class="check">' +
          '<input type="checkbox" id="f-grease"' + (s.grease ? " checked" : "") + ">" +
          '<label for="f-grease">Inject GREASE values</label></div></div>' +
      "</div>" +
    "</section>" +

    '<section class="group"><h4>Upstream Proxies</h4>' +
      field("Proxy List",
        '<textarea id="f-proxies" rows="6" placeholder="host:port&#10;host:port:user:pass">' +
          esc((s.proxies || []).join("\n")) + "</textarea>",
        "One per line, used round-robin. Empty means requests leave from this host.") +
      '<div class="check"><input type="checkbox" id="f-require"' +
        (s.requireProxy ? " checked" : "") + ">" +
        '<label for="f-require">Refuse requests that would leave without a proxy</label></div>' +
      '<div class="check"><input type="checkbox" id="f-verify"' +
        (s.verifyUpstream ? " checked" : "") + ">" +
        '<label for="f-verify">Verify the target’s certificate</label></div>' +
      durField("Cooldown After Repeated Failures", "f-cooldown", s.proxyCooldown,
        "0 never sidelines a failing proxy.") +
    "</section>" +

    '<section class="group"><h4>Timeouts</h4><div class="row2">' +
      durField("Request", "f-timeout", s.timeout, "Keep at or below your client’s timeout.") +
      durField("Dial", "f-dial", s.dialTimeout, "How long one connection attempt may take.") +
    "</div></section>" +

    '<section class="group"><h4>Sessions</h4><div class="row3">' +
      durField("Idle TTL", "f-ttl", s.sessionTTL, "Idle time before a session is dropped.") +
      durField("Release Connections After", "f-idleconns", s.sessionIdleConns,
        "Sockets go, the session keeps its identity.") +
      field("Session Cap",
        '<div class="dur"><input type="number" id="f-maxsess" min="0" step="1" value="' +
          (s.maxSessions || 0) + '"><span class="unit">sessions</span></div>',
        "0 is no cap.") +
    "</div></section>" +

    '<section class="group"><h4>Logging</h4>' +
      '<div class="check"><input type="checkbox" id="f-verbose"' +
        (s.verbose ? " checked" : "") + '><label for="f-verbose">Log requests to the console</label></div>' +
      '<div class="check"><input type="checkbox" id="f-lograw"' +
        (s.logRaw ? " checked" : "") + '><label for="f-lograw">Print raw HTTP to the console</label></div>' +
    "</section>" +

    '<div class="actions"><button type="submit" class="save" id="f-save">Save Changes</button>' +
      '<span class="msg" id="f-msg"></span></div>' +
    "</form>";
}

function readSettingsForm(base) {
  const val = (id) => ($(id).value || "").trim();

  const count = (id, label) => {
    const raw = val(id);
    const n = Number(raw);
    if (raw === "" || !isFinite(n) || n < 0) throw new Error(label + " needs a number, 0 or more");
    return Math.round(n);
  };
  const secs = (id, label) => count(id, label) + "s";
  return Object.assign({}, base, {
    preset: val("f-preset"),
    ja3: val("f-preset") ? "" : val("f-ja3"),
    ja4r: val("f-preset") ? "" : val("f-ja4r"),
    randomize: val("f-randomize"),
    grease: $("f-grease").checked,
    proxies: val("f-proxies").split("\n").map((l) => l.trim()).filter(Boolean),
    requireProxy: $("f-require").checked,
    verifyUpstream: $("f-verify").checked,
    proxyCooldown: secs("f-cooldown", "Cooldown After Repeated Failures"),
    timeout: secs("f-timeout", "Request timeout"),
    dialTimeout: secs("f-dial", "Dial timeout"),
    sessionTTL: secs("f-ttl", "Idle TTL"),
    sessionIdleConns: secs("f-idleconns", "Release Connections After"),
    maxSessions: count("f-maxsess", "Session Cap"),
    verbose: $("f-verbose").checked,
    logRaw: $("f-lograw").checked,
  });
}

function syncPresetFields() {
  const preset = $("f-preset").value;
  for (const id of ["f-hex", "f-expand", "f-ja3", "f-ja4r"]) $(id).disabled = preset !== "";
  $("f-preset-hint").textContent = preset
    ? "Using the " + preset + " fingerprint. Choose Custom to set your own JA3 and JA4."
    : "";
}

async function openSettings() {
  let s = {};
  try {
    s = await (await api("/api/settings")).json();
  } catch (e) {  }

  openModal("Settings", settingsHTML(s));

  syncPresetFields();
  $("f-preset").addEventListener("change", syncPresetFields);

  $("f-expand").addEventListener("click", async () => {
    const msg = $("f-msg");
    try {
      const res = await api("/api/fingerprint/hex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hex: $("f-hex").value.trim() }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.statusText);
      $("f-ja3").value = body.ja3;
      $("f-ja4r").value = body.ja4r;
      $("f-preset").value = "";
      msg.className = "msg ok";
      msg.textContent = "Expanded.";
    } catch (err) {
      msg.className = "msg bad";
      msg.textContent = errText(err);
    }
  });

  $("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("f-msg");
    const save = $("f-save");
    save.disabled = true;
    msg.className = "msg";
    msg.textContent = "Saving…";
    try {
      const res = await api("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(readSettingsForm(s)),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.statusText);
      s = body;
      msg.className = "msg ok";
      msg.textContent = "Saved and applied.";
      loadConfig();
    } catch (err) {
      msg.className = "msg bad";
      msg.textContent = errText(err);
    } finally {
      save.disabled = false;
    }
  });
}

function pick(report) {
  const t = (report && report.tls) || {};
  return {
    "exit ip": (report && report.ip ? String(report.ip).replace(/:\d+$/, "") : null),
    "http version": report && report.http_version,
    ja3: t.ja3_hash,
    ja4: t.ja4,
    "ja4_r": t.ja4_r,
    "user agent": report && report.user_agent,
  };
}

function testResultHTML(res) {
  if (!res.ok && res.error) {
    return '<p class="msg bad">' + esc(res.error) + "</p>" +
      "<dl><dt>through</dt><dd>" + esc(res.through || DASH) + "</dd>" +
      "<dt>target</dt><dd>" + esc(res.target || DASH) + "</dd>" +
      "<dt>took</dt><dd>" + (res.millis ?? DASH) + " ms</dd></dl>";
  }

  const summary = pick(res.report);
  let rows = "";
  for (const key of Object.keys(summary)) {
    if (summary[key]) rows += "<dt>" + esc(key) + "</dt><dd>" + esc(summary[key]) + "</dd>";
  }

  const body = res.report ? JSON.stringify(res.report, null, 2) : (res.raw || "");
  return '<p class="msg ok">HTTP ' + esc(res.status) + " in " + res.millis + " ms via " +
      esc(res.through) + "</p>" +
    (rows ? "<h3>What the target saw</h3><dl>" + rows + "</dl>" : "") +
    "<h3>Full response</h3><pre>" + esc(body) + "</pre>";
}

async function runSelfTest() {
  openModal("Test Request", '<p class="note">Sending a request through the proxy…</p>');
  try {
    const res = await api("/api/test", { method: "POST" });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || res.statusText);
    $("modal-body").innerHTML = testResultHTML(body);
  } catch (err) {
    $("modal-body").innerHTML = '<p class="msg bad">' + esc(errText(err)) + "</p>";
  }
}

async function api(path, opts) {
  const o = Object.assign({ headers: {} }, opts || {});
  if (o.method && o.method !== "GET" && !o.headers["Content-Type"]) {
    o.headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, o);
  if (res.status === 401) {
    showGate(await authState());
    throw new Error("signed out");
  }
  return res;
}

async function authState() {
  try {
    return await (await fetch("/api/auth")).json();
  } catch (e) {
    return { configured: true, authenticated: false };
  }
}

function gateHTML(a) {
  if (!a.configured) {
    const token = a.needsToken
      ? '<label for="g-token">Setup Token</label>' +
        '<input type="text" id="g-token" autocomplete="off" spellcheck="false">' +
        '<p class="hint">Printed in the console' +
          (a.tokenPath ? ", and kept in " + esc(a.tokenPath) : "") +
          ". It is asked for because this page was not opened on the machine running tlsmask.</p>"
      : "";
    const warn = a.memoryOnly
      ? '<p class="hint">No data directory is set, so this password is forgotten on restart.</p>'
      : "";
    const intro = a.hasProxyCredentials
      ? "<h1>Set a New Password</h1>" +
        "<p>The password was reset. The proxy username and password are unchanged, so clients keep working.</p>"
      : "<h1>Set a Password</h1>" +
        "<p>The proxy refuses every request until one is set. Saving it also generates the proxy username and password clients use.</p>";
    return intro +
      '<form id="gate-form">' + token +
        '<label for="g-pass">Password</label>' +
        '<input type="password" id="g-pass" autocomplete="new-password">' +
        '<p class="hint">At least ' + (a.minPassword || 8) + " characters.</p>" +
        '<label for="g-pass2">Re-Password</label>' +
        '<input type="password" id="g-pass2" autocomplete="new-password">' + warn +
        '<button type="submit" class="save">Set Password</button>' +
        '<span class="msg bad" id="g-msg"></span>' +
      "</form>";
  }
  return "<h1>Sign In</h1><p>Enter the web UI password to see traffic and change settings.</p>" +
    '<form id="gate-form">' +
      '<div class="gate-row"><label for="g-pass">Password</label>' +
        '<button type="button" class="linkish" id="g-forgot">Forgot password?</button></div>' +
      '<input type="password" id="g-pass" autocomplete="current-password">' +
      '<button type="submit" class="save">Sign In</button>' +
      '<span class="msg bad" id="g-msg"></span>' +
    "</form>";
}

function forgotHTML() {
  return "<h1>Reset the Password</h1>" +
    "<p>It can only be reset from the machine running tlsmask. Run this there:</p>" +
    snippetBlock("Docker", ["docker exec tlsmask tlsmask reset-password"]) +
    snippetBlock("Without Docker, same --data-dir", ["tlsmask reset-password"]) +
    '<p class="note">It prints a setup token. Come back to this page and it will ask for the ' +
      "token and a new password. The proxy username and password stay as they are, so clients " +
      "keep working in the meantime.</p>" +
    '<button type="button" class="save" id="g-back">Back to Sign In</button>';
}

function showGate(a) {
  $("gate-card").innerHTML = gateHTML(a);
  $("gate").hidden = false;
  $("gate-form").addEventListener("submit", (e) => submitGate(e, a));
  const first = $("gate-form").querySelector("input");
  if (first) first.focus();

  const forgot = $("g-forgot");
  if (forgot) {
    forgot.addEventListener("click", () => {
      $("gate-card").innerHTML = forgotHTML();
      $("g-back").addEventListener("click", async () => showGate(await authState()));
    });
  }
}

async function submitGate(e, a) {
  e.preventDefault();
  const msg = $("g-msg");
  const btn = e.target.querySelector("button");
  msg.textContent = "";
  btn.disabled = true;

  const post = (path, payload) => fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  try {
    let res;
    if (!a.configured) {
      if ($("g-pass").value !== $("g-pass2").value) throw new Error("the two passwords do not match");
      res = await post("/api/setup", { password: $("g-pass").value, token: $("g-token") ? $("g-token").value : "" });
    } else {
      res = await post("/api/login", { password: $("g-pass").value });
    }
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || res.statusText);

    $("gate").hidden = true;
    start(!a.configured);
  } catch (err) {
    msg.textContent = errText(err);
    $("g-pass").value = "";
    if ($("g-pass2")) $("g-pass2").value = "";
    $("g-pass").focus();
  } finally {
    btn.disabled = false;
  }
}

function errText(err) {
  const s = String((err && err.message) || err || "");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function proxyURL(a, user) {
  return "http://" + (user || a.username) + ":" + a.password + "@" + a.host + ":" + a.port;
}

function credRow(label, id, value) {
  return '<div class="field"><label>' + label + "</label>" +
    '<div class="secret"><code id="' + id + '">' + esc(value) + "</code>" +
    '<button type="button" data-copy="' + id + '">Copy</button></div></div>';
}

function clientSnippets(a) {
  const url = proxyURL(a);
  const host = a.host, port = a.port, user = a.username, pass = a.password;
  return [
    { id: "python", chip: "Python", lib: "requests", code: [
      "import requests",
      "",
      'proxy = "' + url + '"',
      'r = requests.get("https://example.com", proxies={"http": proxy, "https": proxy})',
      "print(r.status_code)",
    ] },
    { id: "httpx", chip: "Python httpx", lib: "httpx", code: [
      "import httpx",
      "",
      'with httpx.Client(proxy="' + url + '") as client:',
      '    r = client.get("https://example.com")',
      "    print(r.status_code)",
    ] },
    { id: "curl", chip: "curl", lib: "curl", code: [
      "curl -x " + url + " https://example.com",
    ] },
    { id: "node", chip: "Node.js", lib: "undici", code: [
      'import { fetch, ProxyAgent } from "undici";',
      "",
      'const dispatcher = new ProxyAgent("' + url + '");',
      'const res = await fetch("https://example.com", { dispatcher });',
      "console.log(res.status);",
    ] },
    { id: "go", chip: "Go", lib: "net/http", code: [
      'proxy, _ := url.Parse("' + url + '")',
      "client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}",
      "",
      'res, err := client.Get("https://example.com")',
    ] },
    { id: "java", chip: "Java", lib: "java.net.http.HttpClient", code: [
      "// Java refuses Basic on HTTPS tunnels by default; start the JVM with",
      "//   -Djdk.http.auth.tunneling.disabledSchemes=",
      "HttpClient client = HttpClient.newBuilder()",
      '    .proxy(ProxySelector.of(new InetSocketAddress("' + host + '", ' + port + ")))",
      "    .authenticator(new Authenticator() {",
      "        @Override protected PasswordAuthentication getPasswordAuthentication() {",
      '            return new PasswordAuthentication("' + user + '", "' + pass + '".toCharArray());',
      "        }",
      "    })",
      "    .build();",
      "",
      "HttpResponse<String> res = client.send(",
      '    HttpRequest.newBuilder(URI.create("https://example.com")).build(),',
      "    HttpResponse.BodyHandlers.ofString());",
    ] },
    { id: "csharp", chip: "C#", lib: "System.Net.Http.HttpClient", code: [
      "var handler = new HttpClientHandler",
      "{",
      '    Proxy = new WebProxy("http://' + host + ":" + port + '")',
      "    {",
      '        Credentials = new NetworkCredential("' + user + '", "' + pass + '"),',
      "    },",
      "};",
      "using var client = new HttpClient(handler);",
      "",
      'var res = await client.GetAsync("https://example.com");',
    ] },
    { id: "php", chip: "PHP", lib: "ext-curl", code: [
      '$ch = curl_init("https://example.com");',
      'curl_setopt($ch, CURLOPT_PROXY, "http://' + host + ":" + port + '");',
      'curl_setopt($ch, CURLOPT_PROXYUSERPWD, "' + user + ":" + pass + '");',
      "curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);",
      "",
      "$body = curl_exec($ch);",
    ] },
    { id: "ruby", chip: "Ruby", lib: "Net::HTTP", code: [
      'require "net/http"',
      "",
      'uri = URI("https://example.com")',
      'Net::HTTP.start(uri.host, uri.port, "' + host + '", ' + port + ', "' + user + '", "' + pass + '",',
      "                use_ssl: true) do |http|",
      "  puts http.get(uri.request_uri).code",
      "end",
    ] },
    { id: "rust", chip: "Rust", lib: "reqwest", code: [
      'let proxy = reqwest::Proxy::all("' + url + '")?;',
      "let client = reqwest::Client::builder().proxy(proxy).build()?;",
      "",
      'let res = client.get("https://example.com").send().await?;',
    ] },
  ];
}

function savedLang() {
  try { return localStorage.getItem("tlsmask-lang") || "python"; } catch (e) { return "python"; }
}

function paintSnippet(a, id) {
  const all = clientSnippets(a);
  const pick = all.find((s) => s.id === id) || all[0];
  $("a-langs").querySelectorAll("[data-lang]").forEach((c) => {
    c.setAttribute("aria-pressed", String(c.dataset.lang === pick.id));
  });
  $("a-lib").textContent = pick.lib;
  $("a-code").textContent = pick.code.join("\n");
  try { localStorage.setItem("tlsmask-lang", pick.id); } catch (e) {  }
}

function accessHTML(a) {
  const langs = clientSnippets(a).map((s) =>
    '<button type="button" class="chip" data-lang="' + s.id + '" aria-pressed="false">' + esc(s.chip) + "</button>"
  ).join("");

  return "<h3>Proxy Credentials</h3>" +
    '<p class="note">Ordinary proxy authentication: any client or intercepting proxy that ' +
      "takes a username and password works. Without them the proxy answers 407.</p>" +
    '<div class="row2">' +
      credRow("Proxy Host", "a-host", a.host) + credRow("Proxy Port", "a-port", a.port) +
    "</div>" +
    '<div class="row2">' +
      credRow("Proxy Username", "a-user", a.username) + credRow("Proxy Password", "a-pass", a.password) +
    "</div>" +
    credRow("Proxy URL", "a-url", proxyURL(a)) +

    '<div class="field"><label>Use It From</label>' +
      '<div class="langs" id="a-langs">' + langs + "</div>" +
      '<div class="snippet">' +
        '<div class="snippet-head"><span id="a-lib"></span>' +
          '<button type="button" id="a-copy-code">Copy</button></div>' +
        '<pre id="a-code"></pre>' +
      "</div>" +
    "</div>" +
    '<p class="note">HTTPS through the proxy needs its CA trusted; see Certificate. To keep one ' +
      "upstream proxy and one cookie jar for a whole run, add a session to the username: <code>" +
      esc(a.username) + "-session-&lt;id&gt;</code>. Where requests leave from is the proxy list " +
      "in Settings; the client does not choose.</p>" +
    '<div class="btnrow"><button id="a-rotate">Generate a New Proxy Password</button>' +
      '<span class="msg" id="a-msg"></span></div>' +

    "<h3>Web UI Login</h3>" +
    '<p class="note">The password you sign in to this page with. It is separate from the proxy ' +
      "password above. Changing it signs out every browser, including this one.</p>" +
    '<form class="form" id="a-pwform">' +
      '<div class="row3">' +
        '<div class="field"><label>Current Password</label><input type="password" id="a-cur" autocomplete="current-password"></div>' +
        '<div class="field"><label>New Password</label><input type="password" id="a-new" autocomplete="new-password"></div>' +
        '<div class="field"><label>Re-Password</label><input type="password" id="a-new2" autocomplete="new-password"></div>' +
      "</div>" +
      '<div class="actions"><button type="submit" class="save">Change Login Password</button>' +
        '<span class="msg" id="a-pwmsg"></span></div>' +
    "</form>";
}

function confirmDialog({ title, body, confirm }) {
  const d = $("confirm");
  $("confirm-title").textContent = title;
  $("confirm-body").textContent = body;
  $("confirm-ok").textContent = confirm || "Confirm";
  d.showModal();
  d.querySelector('button[value="cancel"]').focus();

  return new Promise((resolve) => {
    const finish = (ok) => {
      d.removeEventListener("click", onClick);
      d.removeEventListener("cancel", onEscape);
      if (d.open) d.close();
      resolve(ok);
    };
    const onClick = (e) => {
      const button = e.target.closest("button[value]");
      if (button) {
        e.preventDefault();
        finish(button.value === "confirm");
      } else if (e.target === d) {
        finish(false);
      }
    };
    const onEscape = (e) => { e.preventDefault(); finish(false); };
    d.addEventListener("click", onClick);
    d.addEventListener("cancel", onEscape);
  });
}

async function copyText(text, btn) {
  const was = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied";
  } catch (e) {
    btn.textContent = "Select it instead";
  }
  setTimeout(() => { btn.textContent = was; }, 1600);
}

async function openAccess() {
  openModal("Access", '<p class="note">Loading…</p>');
  let a;
  try {
    a = await (await api("/api/access")).json();
  } catch (err) {
    $("modal-body").innerHTML = '<p class="msg bad">' + esc(errText(err)) + "</p>";
    return;
  }
  $("modal-body").innerHTML = accessHTML(a);

  $("modal-body").querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => copyText($(btn.dataset.copy).textContent, btn));
  });

  paintSnippet(a, savedLang());
  $("a-langs").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-lang]");
    if (chip) paintSnippet(a, chip.dataset.lang);
  });
  $("a-copy-code").addEventListener("click", (e) => copyText($("a-code").textContent, e.target));

  $("a-rotate").addEventListener("click", async () => {
    const msg = $("a-msg");
    const sure = await confirmDialog({
      title: "Generate a new proxy password?",
      body: "Every client still using the current password gets 407 until it is updated. " +
        "The proxy username stays the same.",
      confirm: "Generate New Password",
    });
    if (!sure) return;
    try {
      const res = await api("/api/access", { method: "POST" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.statusText);
      loadConfig();
      openAccess();
    } catch (err) {
      msg.className = "msg bad";
      msg.textContent = errText(err);
    }
  });

  $("a-pwform").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = $("a-pwmsg");
    msg.className = "msg";
    msg.textContent = "";
    try {
      if ($("a-new").value !== $("a-new2").value) throw new Error("the two passwords do not match");
      const res = await api("/api/password", {
        method: "POST",
        body: JSON.stringify({ current: $("a-cur").value, next: $("a-new").value }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || res.statusText);
      location.reload();
    } catch (err) {
      msg.className = "msg bad";
      msg.textContent = errText(err);
    }
  });

}

async function signOut() {
  try { await fetch("/api/logout", { method: "POST", headers: { "Content-Type": "application/json" } }); } catch (e) {}
  location.reload();
}

async function loadConfig() {
  try {
    state.cfg = await (await api("/api/config")).json();
    $("listen").textContent = state.cfg.listen || "";
    $("m-version").textContent = state.cfg.version ? "tlsmask " + state.cfg.version : "";
    if (state.cfg.capacity > 0) state.cap = state.cfg.capacity;
  } catch (e) {  }
}

async function loadBacklog() {
  try {
    const recs = await (await api("/api/requests?limit=" + state.cap)).json();
    for (const r of recs) {
      addRecord(r, false);
      if (r.outcome === "proxy-failed" || r.outcome === "failed") state.failures++;
    }
  } catch (e) {  }
  renderList();
}

function pollStats() {
  api("/api/stats").then((r) => r.json()).then((s) => {
    $("m-req").textContent = s.requestsTotal ?? 0;
    $("m-tun").textContent = (s.tunnelsOpen ?? 0) + (s.tunnelsDialing ? "+" + s.tunnelsDialing : "");
    $("m-sess").textContent = s.sessions ?? 0;
    $("m-fail").textContent = state.failures;
    $("m-fail").classList.toggle("err", state.failures > 0);
    $("m-drop").textContent = s.recordsDropped ?? 0;
    $("m-drop").classList.toggle("warn-text", (s.recordsDropped ?? 0) > 0);
    $("m-drop").title = s.recordsDropped
      ? "records the browser could not keep up with; the proxy never waits for it"
      : "";
  }).catch(() => {});
}

function connect() {
  const es = new EventSource("/api/stream");
  es.onopen = () => { $("m-state").textContent = "live"; $("m-dot").className = "dot live"; };
  es.onerror = () => {
    $("m-dot").className = "dot lost";
    $("m-state").textContent = "lost";
    authState().then((a) => {
      if (!a.authenticated) { es.close(); showGate(a); }
    });
  };
  es.addEventListener("request", (ev) => {
    const r = JSON.parse(ev.data);
    if (r.outcome === "proxy-failed" || r.outcome === "failed") state.failures++;

    if (state.paused || state.page > 0) {
      state.pending.push(r);
      scheduleRender();
      return;
    }
    addRecord(r, true);
    scheduleRender();
  });
}

function drainPending() {
  for (const r of state.pending.reverse()) addRecord(r, true);
  state.pending = [];
}

$("rows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  if (tr.dataset.host !== undefined) {
    toggleHost(tr.dataset.host);
  } else if (tr.dataset.more !== undefined) {
    const host = tr.dataset.more;
    state.shown.set(host, (state.shown.get(host) || GROUP_ROWS) + 100);
    renderList();
  } else if (tr.dataset.num !== undefined) {
    select(Number(tr.dataset.num));
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      $("pane-" + t.dataset.pane).hidden = !on;
    });
  });
});

$("run-test").addEventListener("click", runSelfTest);
function markNav(id) {
  document.querySelectorAll(".nav-item").forEach((b) => {
    if (b.id === id) b.setAttribute("aria-current", "true");
    else b.removeAttribute("aria-current");
  });
}
$("modal").addEventListener("close", () => markNav(null));

$("open-settings").addEventListener("click", () => { markNav("open-settings"); openSettings(); });
$("open-cert").addEventListener("click", () => { markNav("open-cert"); openCert(); });

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy-pre]");
  if (btn) copyText(btn.closest(".snippet").querySelector("pre").textContent, btn);
});
$("open-fp").addEventListener("click", () => {
  markNav("open-fp");
  openModal("Fingerprint", fingerprintHTML());
});
$("open-access").addEventListener("click", () => { markNav("open-access"); openAccess(); });
$("modal-close").addEventListener("click", () => $("modal").close());
$("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").close(); });
$("q").addEventListener("input", (e) => {
  state.query = e.target.value.trim();
  state.page = 0;
  state.collapsed.clear();
  renderList();
});

function setFailOnly(on) {
  state.failOnly = on;
  state.page = 0;
  state.collapsed.clear();
  $("f-bad").setAttribute("aria-pressed", String(on));
  $("f-all").setAttribute("aria-pressed", String(!on));
  renderList();
}
$("f-bad").addEventListener("click", () => setFailOnly(!state.failOnly));
$("f-all").addEventListener("click", () => setFailOnly(false));

narrow.addEventListener("change", () => renderList());

$("pause").addEventListener("click", () => {
  state.paused = !state.paused;
  if (!state.paused) { drainPending(); state.page = 0; }
  renderList();
});

paintPause();

function setMenu(open) {
  $("account-menu").hidden = !open;
  $("account").setAttribute("aria-expanded", String(open));
}
$("account").addEventListener("click", (e) => {
  e.stopPropagation();
  setMenu($("account-menu").hidden);
});
document.addEventListener("click", (e) => {
  if (!$("account-menu").hidden && !e.target.closest(".account")) setMenu(false);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("account-menu").hidden) setMenu(false);
});
$("menu-access").addEventListener("click", () => { setMenu(false); openAccess(); });
$("sign-out").addEventListener("click", () => { setMenu(false); signOut(); });

$("f-clear").addEventListener("click", () => {
  state.rows = [];
  state.byNum.clear();
  state.pending = [];
  state.selected = null;
  state.failures = 0;
  state.page = 0;
  state.firstSeen.clear();
  state.shown.clear();
  renderList();
});

$("p-newest").addEventListener("click", () => { state.page = 0; drainPending(); renderList(); });
$("p-prev").addEventListener("click", () => {
  state.page = Math.max(0, state.page - 1);
  if (state.page === 0) drainPending();
  renderList();
});
$("p-next").addEventListener("click", () => { state.page += 1; renderList(); });

let started = false;

async function start(showAccess) {
  if (started) return;
  started = true;

  await loadConfig();
  await loadBacklog();
  connect();
  pollStats();
  setInterval(pollStats, 2000);

  if (showAccess) openAccess();
}

authState().then((a) => {
  if (a.configured && a.authenticated) start(false);
  else showGate(a);
});
