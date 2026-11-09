(function () {
  "use strict";

  // ---------------------------------------------------------- intro sequence

  const INTRO_LINES = [
    ["booting infiltration kit...", ""],
    ["spoofing uplink address...", "dim"],
    ["locating Stark Industries perimeter relay...", ""],
    ["testing outer firewall...  [bypassed]", "accent"],
    ["tunneling into the internal monitoring segment...", ""],
    ["you're in. this is R&D's internal network -- not the vault itself.", "accent"],
    ["target: Mk-series plasma cannon schematics. R&D vault, sub-level 3.", ""],
    ["the vault door still answers to badges. one of them shouldn't.", "accent"],
  ];

  function playIntro(onDone) {
    const container = document.getElementById("introLines");
    const btn = document.getElementById("beginBtn");
    const CHAR_MS = 10;
    const LINE_PAUSE_MS = 220;

    function typeLine(index) {
      if (index >= INTRO_LINES.length) {
        btn.style.display = "inline-block";
        btn.addEventListener("click", onDone, { once: true });
        return;
      }
      const [text, cls] = INTRO_LINES[index];
      const lineEl = document.createElement("div");
      lineEl.className = "line" + (cls ? " " + cls : "");
      const prompt = document.createElement("span");
      prompt.className = "prompt";
      prompt.textContent = ">";
      const typed = document.createElement("span");
      typed.className = "typed";
      lineEl.appendChild(prompt);
      lineEl.appendChild(typed);
      container.appendChild(lineEl);

      let i = 0;
      (function typeChar() {
        if (i < text.length) {
          typed.textContent += text[i];
          i += 1;
          setTimeout(typeChar, CHAR_MS);
        } else {
          typed.classList.remove("typed");
          setTimeout(() => typeLine(index + 1), LINE_PAUSE_MS);
        }
      })();
    }

    typeLine(0);
  }

  // -------------------------------------------------------------- console

  const DEFAULT_CODE = `function planStrike(pulses) {
  // pulses: [{kind: "OPENS" | "SEALS", vaultMs, yourMs}, ...]
  // yourMs is your own clock -- return a yourMs value too.
  // vaultMs is the vault door's own clock (same clock stamps both
  // ends of one cycle, so a difference between them isn't affected
  // by anything on your end).
  // nowOnYourClock() gives you "now" in the yourMs domain.
  //
  // Return when you think the door opens next, or null if it's too
  // early to say.

  return null;
}
`;

  const el = (id) => document.getElementById(id);
  const statusEl = el("connStatus");
  const logEl = el("log");
  const tableBody = document.querySelector("#pulseTable tbody");
  const chart = el("chart");
  const ctx = chart.getContext("2d");
  const codeEl = el("code");
  const predictOutEl = el("predictOut");
  const vaultRing = document.querySelector("#vaultCore .vaultRing");
  const vaultStateEl = el("vaultState");

  codeEl.value = DEFAULT_CODE;

  const pulses = [];
  let clockAnchor = null; // {yourMs, perfNow}
  let rowCount = 0;

  function nowOnYourClock() {
    if (!clockAnchor) return null;
    return clockAnchor.yourMs + (performance.now() - clockAnchor.perfNow);
  }
  window.nowOnYourClock = nowOnYourClock;
  window.pulses = pulses;

  function log(msg, cls) {
    const line = document.createElement("div");
    if (cls) line.className = cls;
    const t = new Date().toLocaleTimeString();
    line.textContent = `[${t}] ${msg}`;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function addPulseRow(p) {
    rowCount += 1;
    const tr = document.createElement("tr");
    const label = p.kind === "OPENS" ? "door opens" : "door seals";
    const vault = p.vaultMs === null || p.vaultMs === undefined ? "-" : p.vaultMs.toFixed(1);
    tr.innerHTML = `<td>${rowCount}</td><td>${label}</td><td>${vault}</td><td>${p.yourMs.toFixed(1)}</td>`;
    tableBody.appendChild(tr);
    while (tableBody.children.length > 200) tableBody.removeChild(tableBody.firstChild);
    tableBody.parentElement.scrollTop = tableBody.parentElement.scrollHeight;
  }

  function pulseVaultCore(kind) {
    vaultRing.classList.remove("pulseOpen", "pulseSeal");
    // force reflow so the animation restarts even on back-to-back pulses
    void vaultRing.offsetWidth;
    vaultRing.classList.add(kind === "OPENS" ? "pulseOpen" : "pulseSeal");
    vaultStateEl.textContent = kind === "OPENS" ? "door open" : "door sealed";
    if (kind === "OPENS") {
      setTimeout(() => {
        if (vaultStateEl.textContent === "door open") vaultStateEl.textContent = "listening...";
      }, 1400);
    }
  }

  // --- simplified heartbeat strip ---
  const WINDOW_MS = 15000;
  function drawChart() {
    const w = chart.width, h = chart.height;
    ctx.clearRect(0, 0, w, h);
    const now = nowOnYourClock();
    const mid = h / 2;
    ctx.strokeStyle = "#15232f";
    ctx.beginPath();
    ctx.moveTo(0, mid);
    ctx.lineTo(w, mid);
    ctx.stroke();
    if (now === null) return;
    const t0 = now - WINDOW_MS;
    for (const p of pulses) {
      if (p.yourMs < t0) continue;
      const x = ((p.yourMs - t0) / WINDOW_MS) * w;
      const isOpen = p.kind === "OPENS";
      const age = (now - p.yourMs) / WINDOW_MS;
      const alpha = Math.max(0.15, 1 - age);
      ctx.strokeStyle = isOpen ? `rgba(79,210,255,${alpha})` : `rgba(138,92,255,${alpha * 0.8})`;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(x, mid);
      ctx.lineTo(x, isOpen ? mid - 22 : mid + 16);
      ctx.stroke();
    }
  }
  setInterval(drawChart, 100);

  // --- toggles ---
  const feedWrap = el("feedWrap");
  const toggleFeedBtn = el("toggleFeed");
  toggleFeedBtn.addEventListener("click", () => {
    const hidden = feedWrap.hasAttribute("hidden");
    if (hidden) {
      feedWrap.removeAttribute("hidden");
      toggleFeedBtn.textContent = "hide raw feed";
    } else {
      feedWrap.setAttribute("hidden", "");
      toggleFeedBtn.textContent = "show raw feed";
    }
  });

  const advancedRow = el("advancedRow");
  const toggleAdvancedBtn = el("toggleAdvanced");
  toggleAdvancedBtn.addEventListener("click", () => {
    const hidden = advancedRow.hasAttribute("hidden");
    if (hidden) {
      advancedRow.removeAttribute("hidden");
      toggleAdvancedBtn.textContent = "hide custom time";
    } else {
      advancedRow.setAttribute("hidden", "");
      toggleAdvancedBtn.textContent = "use a custom time instead";
    }
  });

  function runPlan(showResult) {
    let fn;
    try {
      // eslint-disable-next-line no-new-func
      fn = new Function(codeEl.value + "\nreturn planStrike;")();
    } catch (e) {
      log("that plan doesn't parse: " + e.message, "bad");
      return null;
    }
    if (typeof fn !== "function") {
      log("planStrike() is not defined", "bad");
      return null;
    }
    try {
      const result = fn(pulses.slice());
      if (showResult) {
        predictOutEl.textContent = result === null || result === undefined
          ? "no plan yet"
          : `planned for ${Number(result).toFixed(1)}`;
      }
      return result;
    } catch (e) {
      log("your plan threw: " + e.message, "bad");
      return null;
    }
  }

  el("runBtn").addEventListener("click", () => runPlan(true));

  function goAt(ms) {
    if (ms === null || ms === undefined || Number.isNaN(Number(ms))) {
      log("nothing to go on -- your plan returned no value", "bad");
      return;
    }
    if (!window.ws || window.ws.readyState !== WebSocket.OPEN) {
      log("uplink not open", "bad");
      return;
    }
    window.ws.send(JSON.stringify({ type: "strike", atMs: Number(ms) }));
    log(`committed to ${Number(ms).toFixed(1)}`, "info");
  }
  window.goAt = goAt;

  el("armPredictedBtn").addEventListener("click", () => {
    const result = runPlan(true);
    goAt(result);
  });
  el("armManualBtn").addEventListener("click", () => {
    goAt(el("manualMs").value);
  });

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    window.ws = ws;

    ws.onopen = () => {
      statusEl.textContent = "live";
      statusEl.className = "status live";
      log("connected");
    };
    ws.onclose = () => {
      statusEl.textContent = "disconnected";
      statusEl.className = "status down";
      log("uplink dropped -- reload to retry", "bad");
    };
    ws.onerror = () => {
      statusEl.textContent = "error";
      statusEl.className = "status down";
    };
    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch (e) {
        return;
      }
      if (msg.type === "pulse") {
        if (!clockAnchor) clockAnchor = { yourMs: msg.yourMs, perfNow: performance.now() };
        pulses.push(msg);
        if (pulses.length > 500) pulses.shift();
        addPulseRow(msg);
        pulseVaultCore(msg.kind);
      } else if (msg.type === "log") {
        log(msg.msg, "info");
      } else if (msg.type === "outcome") {
        if (msg.ok) {
          log(`ACCESS GRANTED -- schematics in hand: ${msg.flag}`, "ok");
        } else {
          log(`access denied (${msg.attempts} attempts sent) -- the door didn't blink`, "bad");
        }
      }
    };
  }

  connect();

  playIntro(() => {
    document.getElementById("intro").remove();
    document.getElementById("app").hidden = false;
  });
})();
