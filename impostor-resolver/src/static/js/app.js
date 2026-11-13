(() => {
  "use strict";

  const body = document.body;
  const TARGET = body.dataset.target;
  const LEGIT_IP = body.dataset.legit;
  const IMPOSTOR_NS = "ns.evil.ctf";
  const IMPOSTOR_IP = "6.6.6.6";

  const el = (id) => document.getElementById(id);

  const subInput = el("subInput");
  const btnRound = el("btnRound");
  const btnRand = el("btnRand");
  const roundNote = el("roundNote");
  const adminBody = el("adminBody");

  const fTxid = el("fTxid");
  const fSport = el("fSport");
  const fQname = el("fQname");
  const fQr = el("fQr");
  const fAa = el("fAa");
  const fRecords = el("fRecords");
  const btnVent = el("btnVent");
  const btnTpl = el("btnTpl");
  const btnReset = el("btnReset");
  const ventNote = el("ventNote");

  const cNs = el("cNs");
  const cGlue = el("cGlue");
  const cIp = el("cIp");
  const cacheBox = el("cacheBox");
  const btnResolve = el("btnResolve");
  const resolveNote = el("resolveNote");

  const logBox = el("log");
  const clock = el("clock");
  const shipStatusText = el("shipStatusText");
  const shipDot = document.querySelector("#shipStatus .dot");

  const victory = el("victory");
  const vTarget = el("vTarget");
  const vIp = el("vIp");
  const vFlag = el("vFlag");
  const vClose = el("vClose");

  const startTime = Date.now();

  const tabs = document.querySelectorAll(".tab");
  const views = document.querySelectorAll(".view");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      views.forEach((v) => (v.hidden = true));
      tab.classList.add("active");
      const target = document.querySelector('.view[data-view="' + tab.dataset.tab + '"]');
      if (target) target.hidden = false;
    });
  });

  function log(msg, cls) {
    const t = new Date().toLocaleTimeString();
    const line = document.createElement("p");
    line.className = "ln " + (cls || "info");
    line.innerHTML = '<span class="t">' + t + "</span>" + escapeHtml(msg);
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  }

  function note(elm, msg, cls) {
    elm.textContent = msg || "";
    elm.className = "note" + (cls ? " " + cls : "");
  }

  function randLabel(n) {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let s = "";
    for (let i = 0; i < (n || 8); i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
  }

  function defaultRecords() {
    const leaf = fQname.value || ("example." + TARGET);
    return JSON.stringify(
      {
        answer: [{ name: leaf, type: "A", data: IMPOSTOR_IP }],
        authority: [{ name: TARGET, type: "NS", data: IMPOSTOR_NS }],
        additional: [{ name: IMPOSTOR_NS, type: "A", data: IMPOSTOR_IP }],
      },
      null,
      2
    );
  }

  fRecords.value = defaultRecords();

  btnTpl.addEventListener("click", () => {
    fRecords.value = defaultRecords();
    note(ventNote, "Template reset.");
  });

  btnRand.addEventListener("click", () => {
    subInput.value = randLabel();
  });

  async function callRound() {
    const sub = (subInput.value || randLabel()).trim().toLowerCase();
    subInput.value = sub;
    const qname = sub + "." + TARGET;
    try {
      const res = await fetch("/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: qname }),
      });
      const data = await res.json();
      const ok = data.status === "querying";
      note(roundNote, data.message, ok ? "" : "warn");
      log(data.message, ok ? "info" : "warn");
      if (ok) fQname.value = qname;
      refreshEgress();
    } catch (e) {
      note(roundNote, "Request failed: " + e, "bad");
    }
  }
  btnRound.addEventListener("click", callRound);
  subInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") callRound();
  });

  async function refreshEgress() {
    try {
      const res = await fetch("/egress");
      const data = await res.json();
      renderAdmin(data.pending || []);
    } catch (e) {
      /* transient network hiccup, ignore */
    }
  }

  function renderAdmin(rows) {
    if (!rows.length) {
      adminBody.innerHTML = '<tr class="empty"><td colspan="5">Nobody in Admin. Call a round.</td></tr>';
      return;
    }
    adminBody.innerHTML = rows
      .map((r) => {
        const eta = r.remaining_ms;
        const etaCls = eta < 100 ? "hot" : eta < 300 ? "warm" : "";
        return (
          '<tr data-txid="' + r.txid + '" data-sport="' + r.sport + '" data-qname="' + r.qname + '">' +
          "<td>" + r.qid + "</td>" +
          '<td class="mono">' + r.qname + "</td>" +
          '<td class="mono">' + r.txid_hex + "</td>" +
          '<td class="mono">' + r.sport + "</td>" +
          '<td class="eta ' + etaCls + '">' + eta + " ms</td>" +
          "</tr>"
        );
      })
      .join("");
    adminBody.querySelectorAll("tr[data-txid]").forEach((tr) => {
      tr.addEventListener("click", () => {
        fTxid.value = tr.dataset.txid;
        fSport.value = tr.dataset.sport;
        fQname.value = tr.dataset.qname;
        note(ventNote, "Loaded colours from round #" + tr.children[0].textContent + ".");
      });
    });
  }

  function parseRecordsField() {
    try {
      const v = JSON.parse(fRecords.value || "{}");
      return {
        answer: Array.isArray(v.answer) ? v.answer : [],
        authority: Array.isArray(v.authority) ? v.authority : [],
        additional: Array.isArray(v.additional) ? v.additional : [],
      };
    } catch (e) {
      return null;
    }
  }

  async function ventIn() {
    const recs = parseRecordsField();
    if (!recs) {
      note(ventNote, "Records field is not valid JSON.", "bad");
      return;
    }
    const payload = {
      txid: fTxid.value.trim(),
      sport: fSport.value.trim(),
      qname: fQname.value.trim().toLowerCase(),
      flags: { qr: fQr.checked, aa: fAa.checked },
      answer: recs.answer,
      authority: recs.authority,
      additional: recs.additional,
    };
    try {
      const res = await fetch("/inject", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      const cls = data.success ? (data.poisoned ? "good" : "warn") : "bad";
      note(ventNote, data.message, cls);
      log(data.message, cls);
      refreshEgress();
      refreshCache();
    } catch (e) {
      note(ventNote, "Request failed: " + e, "bad");
    }
  }
  btnVent.addEventListener("click", ventIn);

  async function doResolveTarget() {
    try {
      const res = await fetch("/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: TARGET }),
      });
      const data = await res.json();
      note(resolveNote, data.message, data.poisoned ? "good" : "");
      log(data.message, data.poisoned ? "good" : "info");
      if (data.poisoned) showVictory(data);
      refreshCache();
    } catch (e) {
      note(resolveNote, "Request failed: " + e, "bad");
    }
  }
  btnResolve.addEventListener("click", doResolveTarget);

  function showVictory(data) {
    vTarget.textContent = TARGET;
    vIp.textContent = data.ip;
    vFlag.textContent = data.flag;
    victory.classList.remove("hidden");
    body.classList.add("poisoned");
  }
  vClose.addEventListener("click", () => victory.classList.add("hidden"));

  async function refreshCache() {
    try {
      const res = await fetch("/cache");
      const data = await res.json();
      cNs.textContent = data.delegation ? data.delegation.ns : "none";
      cGlue.textContent = data.delegation ? data.delegation.glue_ip : "none";
      cIp.textContent = data.resolves_to;
      cacheBox.classList.toggle("poisoned", !!data.poisoned);
      shipStatusText.textContent = data.poisoned ? "SUS" : "NOT SUS";
      shipDot.className = "dot " + (data.poisoned ? "bad" : "ok");
      body.classList.toggle("poisoned", !!data.poisoned);
    } catch (e) {
      /* transient network hiccup, ignore */
    }
  }

  btnReset.addEventListener("click", async () => {
    try {
      await fetch("/reset", { method: "POST" });
    } catch (e) {
      /* ignore */
    }
    logBox.innerHTML = "";
    body.classList.remove("poisoned");
    victory.classList.add("hidden");
    note(roundNote, "");
    note(ventNote, "");
    note(resolveNote, "");
    refreshCache();
    refreshEgress();
    log("Ship reset. Cache cleared.", "warn");
  });

  setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const mm = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const ss = String(elapsed % 60).padStart(2, "0");
    clock.textContent = mm + ":" + ss;
  }, 1000);

  setInterval(refreshEgress, 150);
  setInterval(refreshCache, 1000);
  refreshEgress();
  refreshCache();
  log("Welcome aboard. The crew trusts whoever answers first — call a round to begin.", "info");
})();
