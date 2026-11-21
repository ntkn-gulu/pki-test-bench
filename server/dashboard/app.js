/* ==========================================================================
   G16 PKI dashboard · v4
   All data comes from /api/info (real certificates + real TLS connection).
   The Test Bench verdicts come from THIS browser: the page tries to connect
   to every port (/api/ping) and records which certificates the browser accepts.
   Motion uses anime.js v4 (vendor/anime.umd.min.js). Without it, or with
   "reduced motion", the page simply renders without animation.
   ========================================================================== */
(() => {
  "use strict";

  const A = window.anime;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ANIM = !!A && !reduceMotion;
  if (ANIM) document.documentElement.classList.add("anim");

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  /* ---------- tiny DOM helper ------------------------------------------- */
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "html") el.innerHTML = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const tag = (text, kind = "") => h("span", { class: `tag ${kind ? "tag--" + kind : ""}` }, text);

  /* ---------- theme: light by default, dark only when chosen ------------- */
  const THEME_KEY = "g16-theme";
  const root = document.documentElement;
  // ?theme=dark / ?theme=light forces a theme for this visit (handy for screenshots)
  const forced = new URLSearchParams(location.search).get("theme");
  try { root.dataset.theme = ["dark", "light"].includes(forced) ? forced : localStorage.getItem(THEME_KEY) || "light"; }
  catch { root.dataset.theme = "light"; }
  $("#theme-toggle").addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch { /* ignore */ }
  });

  /* ---------- toast ------------------------------------------------------ */
  let toastTimer;
  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
  }

  /* ---------- formatting -------------------------------------------------- */
  const fmtDate = (iso) => new Date(iso).toISOString().slice(0, 10);
  const shortFp = (fp) => fp.split(":").slice(0, 6).join(":") + " …";
  // allow line breaks after "::" and "_" only (never in the middle of a word)
  const softWrap = (s) => String(s).replace(/(::|_)/g, "$1​");
  // never break a date such as 2025-04-01 at its hyphens
  const DATE = /(\d{4}-\d{2}-\d{2})/;
  const keepDates = (t) => String(t).split(DATE).map((x, i) => (i % 2 ? h("span", { class: "nowrap" }, x) : x));
  const keepDatesHtml = (html) => html.replace(new RegExp(DATE.source, "g"), '<span class="nowrap">$1</span>');
  const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  const icons = {
    pass: '<svg viewBox="0 0 16 16"><path class="ic" d="M3.5 8.5 6.5 11.5 12.5 4.5"/></svg>',
    fail: '<svg viewBox="0 0 16 16"><path class="ic" d="M4.5 4.5l7 7M11.5 4.5l-7 7"/></svg>',
    skip: '<svg viewBox="0 0 16 16"><path class="ic" d="M4 8h8"/></svg>',
    arrow: '<svg viewBox="0 0 16 16"><path d="M5 11 11 5M6 5h5v5"/></svg>',
    chevron: '<svg viewBox="0 0 16 16"><path d="M4 6l4 4 4-4"/></svg>',
  };

  /* wrap every word of a heading in <span class="w"> so it can animate */
  function splitWords(el) {
    const out = [];
    [...el.childNodes].forEach((node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        node.textContent.split(/(\s+)/).forEach((part) => {
          if (!part) return;
          out.push(/^\s+$/.test(part) ? document.createTextNode(part) : h("span", { class: "w" }, part));
        });
      } else {
        node.classList.add("w");
        out.push(node);
      }
    });
    el.replaceChildren(...out);
  }

  /* ======================================================================
     RENDER
     ====================================================================== */
  function render(info) {
    const { connection: c, validation: v, scenario: s } = info;
    const ok = v.ok;
    const failed = v.steps.find((x) => x.status === "fail");
    const leaf = info.chain[info.chain.length - 1];

    /* -- top bar status cell -- */
    const pill = $("#conn-pill");
    pill.innerHTML = "";
    pill.append(h("i", { class: `dot ${ok ? "ok" : "bad"}` }), h("span", {}, `${c.host}:${c.port} · ${c.protocol}`));

    /* -- hero -- */
    $("#hero-cap").textContent = `Port ${c.port} · ${s.title}`;
    $("#hero-chips").replaceChildren(tag(ok ? "● chain valid" : "● chain broken", ok ? "ok" : "bad"));
    const title = $("#hero-title");
    const lede = $("#hero-lede");
    const hint = $("#hero-hint");
    hint.classList.toggle("bad", !ok);

    if (ok) {
      title.innerHTML = 'Every link in the chain <span class="hl ok">holds</span>.';
      const issuer = info.chain.length > 1 ? info.chain[info.chain.length - 2].subject : leaf.issuer;
      lede.innerHTML = `Served over <b>${esc(c.protocol)}</b> with a certificate for <b>${esc(c.host)}</b>,
        signed by <b>${esc(issuer)}</b>.`;
      hint.innerHTML = `<span>↖</span><span>Look at the address bar. A lock means your browser found
        <span class="mono">${esc(info.chain[0].subject)}</span> in its own trust store. "Not secure" means the root is not installed yet.</span>`;
    } else {
      title.innerHTML = 'One link in the chain is <span class="hl bad">broken</span>.';
      lede.innerHTML = `Validation stops at <b>step ${failed.n} · ${esc(failed.title)}</b>: ${keepDatesHtml(esc(failed.detail))}.`;
      hint.innerHTML = `<span>!</span><span>You only see this page because the browser warning was bypassed.
        A browser should stop here with <span class="mono">${esc(softWrap(v.error))}</span>.</span>`;
    }
    splitWords(title);

    renderStack(info, failed);

    /* -- readout -- */
    const passed = v.steps.filter((x) => x.status === "pass").length;
    const items = [
      ["Protocol", c.protocol, "TLS ≥ 1.2 enforced"],
      ["Cipher", c.cipher, `${c.bits}-bit`],
      ["Leaf key", leaf.key, `signed with ${leaf.signature}`],
      ["Issued by", leaf.issuer, `${info.chain.length} certificates`],
      ["Checks", ok ? `${passed} / 6 passed` : `failed at step ${failed.n}`, ok ? "1 skipped (private CA)" : failed.title],
    ];
    const ro = $("#readout");
    ro.innerHTML = "";
    for (const [k, val, sub] of items) {
      ro.append(h("div", {}, h("dt", {}, k),
        h("dd", { class: String(val).length > 16 ? "long" : null }, val, h("small", {}, sub))));
    }

    renderChain(info);
    renderSteps(v);
    renderBench(info);
  }

  /* ---------- hero illustration: isometric certificate stack -------------
     Root is the foundation (bottom), the leaf sits on top and carries the
     lock. Each layer gets a seal: ✓ verified, ✕ where validation fails,
     nothing above the break, dashed outline when the certificate is absent. */
  const ISO = { W: 160, D: 110, TX: 128, T: 6, TY: { root: 182, inter: 118, leaf: 54 } };
  const ORDER = ["root", "inter", "leaf"];
  const ip = (x, y, ty, dy = 0) => `${(ISO.TX + 0.866 * (x - y)).toFixed(1)} ${(ty + 0.5 * (x + y) + dy).toFixed(1)}`;
  const ipath = (pts, ty, close = false) => pts.map(([x, y], i) => (i ? "L" : "M") + ip(x, y, ty)).join("") + (close ? "Z" : "");
  const icircle = (cx, cy, r, ty) =>
    ipath(Array.from({ length: 40 }, (_, i) => {
      const a = (i / 40) * Math.PI * 2;
      return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
    }), ty, true);

  function stackStates(info, failed) {
    const chain = info.chain;
    const hasRoot = chain.some((x) => !x.sent);
    const leaf = chain[chain.length - 1];
    const inter = chain.length > 1 && chain[chain.length - 2].sent ? chain[chain.length - 2] : null;
    const L = {
      root: { role: "Root CA", sub: hasRoot ? chain[0].subject : "not in trust store", state: hasRoot ? "ok" : "ghost" },
      inter: { role: "Intermediate", sub: inter ? inter.subject : "none sent", state: inter ? "ok" : "ghost" },
      leaf: { role: "Leaf", sub: leaf.subject, state: "ok" },
    };
    if (failed) {
      let at = "leaf";
      if (failed.n === 2 || failed.n === 4) at = inter ? "inter" : "leaf";
      if (failed.n === 3) at = leaf.days_left < 0 ? "leaf" : inter && inter.days_left < 0 ? "inter" : "root";
      if (failed.n === 1) at = hasRoot ? "root" : "leaf";
      const cut = ORDER.indexOf(at);
      ORDER.forEach((k, i) => {
        if (L[k].state === "ghost") return;
        if (i === cut) { L[k].state = "bad"; L[k].sub = `✕ step ${failed.n} · ${failed.title}`; }
        if (i > cut) L[k].state = "idle";
      });
    }
    return L;
  }

  function renderStack(info, failed) {
    const { W, D, T, TY } = ISO;
    const L = stackStates(info, failed);
    const c = info.connection;
    let out = "";

    // dashed guides through the corners, behind the plates
    const gx = (x, y) => (ISO.TX + 0.866 * (x - y)).toFixed(1);
    const gy = (x, y, ty) => (ty + 0.5 * (x + y)).toFixed(1);
    for (const [x, y] of [[0, D], [W, D], [W, 0]]) {
      out += `<path class="guide" d="M${gx(x, y)} ${gy(x, y, TY.leaf)}V${(Number(gy(x, y, TY.root)) + T).toFixed(1)}"/>`;
    }

    for (const k of ORDER) {
      const ty = TY[k];
      const st = L[k].state;
      out += `<g class="layer is-${st}" data-layer="${k}">`;
      if (st === "ghost") {
        out += `<path class="plate" d="${ipath([[0, 0], [W, 0], [W, D], [0, D]], ty, true)}"/>`;
      } else {
        out += `<path class="side side--a" d="M${ip(0, D, ty)}L${ip(W, D, ty)}L${ip(W, D, ty, T)}L${ip(0, D, ty, T)}Z"/>`;
        out += `<path class="side side--b" d="M${ip(W, D, ty)}L${ip(W, 0, ty)}L${ip(W, 0, ty, T)}L${ip(W, D, ty, T)}Z"/>`;
        out += `<path class="plate draw" d="${ipath([[0, 0], [W, 0], [W, D], [0, D]], ty, true)}"/>`;
        out += `<path class="ln draw" d="${ipath([[0, 26], [W, 26]], ty)}"/>`;
        if (k !== "leaf") out += `<path class="ln ln--hi draw" d="${ipath([[14, 13], [88, 13]], ty)}"/>`;
        for (const [y, x2] of [[44, 96], [58, 74], [72, 104], [86, 52]]) {
          out += `<path class="ln draw" d="${ipath([[14, y], [x2, y]], ty)}"/>`;
        }
        if (k === "leaf") out += `<path class="shadow" d="${icircle(80, 55, 27, ty)}"/>`;
        out += `<path class="seal-fill" d="${icircle(128, 76, 15, ty)}"/>`;
        out += `<path class="seal draw" d="${icircle(128, 76, 15, ty)}"/>`;
        const [sx, sy] = ip(128, 76, ty).split(" ").map(Number);
        if (st === "ok") out += `<path class="mark" d="M${sx - 6} ${sy}l4 4 8-8"/>`;
        if (st === "bad") out += `<path class="mark" d="M${sx - 5} ${sy - 5}l10 10m0-10-10 10"/>`;
      }
      out += "</g>";
    }

    // the lock stands on the leaf
    out += `<circle class="pulse" id="stack-pulse" cx="150" cy="98" r="30"/>
      <g class="lock ${failed ? "is-bad" : "is-ok"}">
        <g id="shackle"><path class="lock__shackle" d="M135 76V62a15 15 0 0 1 30 0v14"/></g>
        <rect class="lock__body" x="123" y="76" width="54" height="44" rx="6"/>
        <circle class="lock__key" cx="150" cy="94" r="5"/><path class="lock__key" d="M150 99v9"/>
      </g>`;

    // callouts on the right corner of each plate
    for (const k of ORDER) {
      const x = ISO.TX + 0.866 * W;
      const y = TY[k] + 80;
      out += `<g class="callout is-${L[k].state}" data-callout="${k}">
        <circle class="knob" cx="${x.toFixed(1)}" cy="${y}" r="2.6"/>
        <path class="leader" d="M${(x + 8).toFixed(1)} ${y}H${(x + 38).toFixed(1)}"/>
        <text class="role" x="${(x + 44).toFixed(1)}" y="${y - 4}">${esc(L[k].role)}</text>
        <text class="sub" x="${(x + 44).toFixed(1)}" y="${y + 12}">${esc(clip(L[k].sub, 21))}</text>
      </g>`;
    }

    out += `<text class="svg-label" x="33" y="340">FIG. 01 — CHAIN OF TRUST</text>
      <text class="svg-label svg-label--end" x="436" y="340">${esc(c.protocol.toUpperCase())} · ${c.port}</text>`;

    $("#stack-svg").innerHTML = out;
    $("#stack").classList.toggle("is-bad", !!failed);
  }

  /* ---------- chain cards: essentials first, details on demand ---------- */
  function roleOf(card, i, list) {
    if (!card.sent) return "Root CA";
    if (card.self_signed) return "Self-signed";
    if (card.is_ca) return "Intermediate";
    if (i === list.length - 1) return "Leaf";
    return "Leaf as CA";
  }

  function renderChain(info) {
    const wrap = $("#chain-list");
    wrap.innerHTML = "";
    wrap.classList.remove("is-open");
    const list = info.chain;
    const n = list.length;
    const step4Failed = info.validation.steps.some((s) => s.n === 4 && s.status === "fail");
    wrap.style.setProperty("--chain-cols", list.map(() => "minmax(0, 1fr)").join(n > 3 ? " 56px " : " 64px "));
    wrap.classList.toggle("chain--dense", n > 3);

    const words = ["", "One", "Two", "Three", "Four", "Five"];
    const sent = list.filter((c) => c.sent).length;
    const chainOk = info.validation.ok;
    $("#chain h2").innerHTML = n === 1
      ? 'One certificate, <span class="hl bad">no</span> path to trust.'
      : chainOk
        ? `${words[n] || n} certificates, <span class="hl">one</span> path to trust.`
        : `${words[n] || n} certificates, one <span class="hl bad">broken</span> path.`;
    $("#chain .lede").textContent = sent === n
      ? `The server sends ${sent === 1 ? "one certificate" : sent + " certificates"}, and none of them leads to a root in the trust store.`
      : `The server sends ${sent === 1 ? "the leaf" : sent + " certificates"}. The root is never sent: the browser already has it in its trust store.`;
    $("#chain-cap").textContent = "";

    const toggles = [];
    function setOpen(open) {
      wrap.classList.toggle("is-open", open);
      toggles.forEach((b) => {
        b.setAttribute("aria-expanded", String(open));
        b.firstChild.textContent = open ? "Hide details" : "Details";
      });
      if (open) $$(".fp", wrap).forEach(scramble);
    }

    list.forEach((cert, i) => {
      const role = roleOf(cert, i, list);
      const expired = cert.days_left < 0;
      const life = expired
        ? `expired ${-cert.days_left} d ago`
        : `day ${Math.max(1, cert.lifetime_days - cert.days_left)} of ${cert.lifetime_days}`;

      // SAN entries outside the issuer's Name Constraints are marked red
      const issuer = i > 0 ? list[i - 1] : null;
      const outside = (entry) => step4Failed && issuer && issuer.name_constraints.length
        && !issuer.name_constraints.some((nc) => nc.includes(entry));

      // essentials: what the certificate IS and what it is FOR
      const chips = [
        tag(cert.is_ca ? "CA:TRUE" : "CA:FALSE", role === "Leaf as CA" ? "bad" : cert.is_ca ? "ink" : ""),
        cert.is_ca && cert.path_len !== null && cert.path_len !== undefined ? tag(`pathlen:${cert.path_len}`) : null,
        !cert.is_ca ? (cert.san.length ? cert.san.map((x) => tag(x, outside(x) ? "bad" : "")) : tag("no SAN", "bad")) : null,
        expired ? tag("expired", "bad") : null,
      ].flat();

      // details: shown when "Details" is open
      const lines = (arr) => arr.map((x) => h("span", {}, x));
      const rows = [
        ["Key", cert.key],
        ["Signature", cert.signature],
        ["Serial", cert.serial.length > 16 ? cert.serial.slice(0, 16) + "…" : cert.serial],
        ["Valid", lines([`from ${fmtDate(cert.not_before)}`, `to   ${fmtDate(cert.not_after)}`])],
      ];
      if (cert.name_constraints.length) rows.push(["Permits", lines(cert.name_constraints)]);
      if (cert.key_usage && cert.key_usage.length) rows.push(["Usage", lines(cert.key_usage)]);

      const fp = h("dd", { class: "fp", title: "Click to copy the full SHA-256 fingerprint" }, shortFp(cert.fingerprint));
      fp.addEventListener("click", () => {
        navigator.clipboard?.writeText(cert.fingerprint).then(() => toast("SHA-256 fingerprint copied"), () => toast(cert.fingerprint));
      });

      const toggle = h("button", { class: "cert__toggle", type: "button", "aria-expanded": "false" },
        "Details", h("i", { html: icons.chevron }));
      toggle.addEventListener("click", () => setOpen(!wrap.classList.contains("is-open")));
      toggles.push(toggle);

      wrap.append(h("article", { class: `cert ${cert.sent ? "" : "cert--anchor"}`, "data-chain": "card" },
        h("div", { class: "cert__head" },
          h("span", { class: "cert__level" }, `${String(i + 1).padStart(2, "0")} / ${role}`),
          cert.sent ? tag("sent") : tag("trust store", "ink")),
        h("div", { class: "cert__main" },
          h("h3", { class: "cert__name" }, cert.subject),
          h("p", { class: "cert__issuer" }, cert.self_signed ? "issued by itself (self-signed)" : `issued by ${cert.issuer}`),
          cert.sent ? null : h("p", { class: "cert__note" }, "not sent · already on this device"),
          h("div", { class: "chips" }, chips),
          h("div", { class: "life" },
            h("div", { class: "life__track" },
              h("div", { class: `life__fill ${expired ? "bad" : ""}`, "data-used": expired ? 1 : cert.lifetime_used })),
            h("div", { class: "life__meta" }, h("span", {}, "lifetime"), h("span", {}, life)))),
        h("div", { class: "cert__more" },
          h("div", { class: "cert__more-in" },
            h("dl", { class: "kv" },
              rows.map(([k, val]) => h("div", {}, h("dt", {}, k), h("dd", {}, val))),
              h("div", {}, h("dt", {}, "SHA-256"), fp)))),
        toggle,
      ));

      if (i < n - 1) {
        const child = list[i + 1];
        const bad = !cert.is_ca || (step4Failed && cert.name_constraints.length && !child.is_ca);
        wrap.append(h("div", { class: `link ${bad ? "bad" : ""}`, "data-chain": "link" },
          h("span", { class: "link__line" }),
          h("span", { class: "link__label" }, bad ? "invalid" : "signs")));
      }
    });

    // static state (overwritten by the animation when it runs)
    $$(".life__fill", wrap).forEach((f) => { f.style.transform = `scaleX(${f.dataset.used})`; });
  }

  /* ---------- validation steps ----------------------------------------- */
  function renderSteps(v) {
    const ol = $("#steps");
    ol.innerHTML = "";
    const count = (st) => v.steps.filter((x) => x.status === st).length;
    $("#steps-cap").textContent = `${count("pass")} pass · ${count("fail")} fail · ${count("skip")} skip`;
    for (const s of v.steps) {
      const detail = h("div", { class: "step__detail" }, s.detail);
      if (s.error) detail.append(h("br"), h("span", { class: "err" }, softWrap(s.error)));
      ol.append(h("li", { class: `step ${s.status === "fail" ? "is-fail" : ""}` },
        h("span", { class: "step__n" }, String(s.n).padStart(2, "0")),
        h("span", { class: "step__title" }, s.title),
        detail,
        h("span", { class: "step__status" },
          h("span", { class: `status ${s.status}`, html: `${icons[s.status]}<span>${s.status}</span>` }))));
    }
  }

  /* ---------- test bench ----------------------------------------------- */
  function renderBench(info) {
    const grid = $("#bench-grid");
    grid.innerHTML = "";
    for (const sc of info.bench) {
      const here = sc.port === info.connection.port;
      const valid = sc.id === "valid";
      grid.append(h("a", { class: `case ${here ? "is-here" : ""} ${valid ? "case--featured" : ""}`, href: sc.url, "data-bench": "", "data-port": sc.port },
        h("div", { class: "case__top" },
          h("span", { class: "case__port" }, sc.port),
          here ? tag("you are here", "ink") : (valid ? tag("valid", "ok") : tag("broken", "bad"))),
        h("h3", { class: "case__title" }, sc.title),
        h("p", { class: "case__wrong" }, keepDates(sc.wrong)),
        valid ? h("div", { class: "mini" },
          tag("G16 Root CA", "ink"), h("span", { class: "mini__arrow" }, "→"),
          tag("G16 Intermediate"), h("span", { class: "mini__arrow" }, "→"),
          tag("localhost", "ok")) : null,
        h("div", { class: `case__expect ${valid ? "ok" : "bad"}` }, softWrap(sc.expect)),
        h("div", { class: "case__verdict" },
          h("span", { class: "case__vlabel" }, "This browser"),
          h("span", { class: "case__vres" }, tag("waiting"))),
        h("div", { class: "case__foot" },
          h("span", { class: "case__theory" }, sc.theory),
          h("span", { class: "case__open", html: `${esc(sc.host)}:${sc.port} ${icons.arrow}` }))));
    }
  }

  /* ======================================================================
     LIVE BROWSER VERDICT
     The page fetches https://<host>:<port>/api/ping for every bench port.
     The fetch only succeeds if THIS browser accepted that port's certificate
     during the TLS handshake, so the result is the browser's own decision.
     Caveat: a port where you clicked "Continue" before counts as accepted
     until the browser forgets that exception (restart it to reset).
     ====================================================================== */
  function browserLabel() {
    const ua = navigator.userAgent;
    const known = [[/Edg\/(\d+)/, "Edge"], [/OPR\/(\d+)/, "Opera"], [/Firefox\/(\d+)/, "Firefox"],
      [/Chrome\/(\d+)/, "Chrome"], [/Version\/(\d+).*Safari/, "Safari"]];
    for (const [re, name] of known) {
      const m = ua.match(re);
      if (m) return `${name} ${m[1]}`;
    }
    return "This browser";
  }

  async function ping(sc) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 6000);
    try {
      const r = await fetch(`https://${sc.host}:${sc.port}/api/ping`,
        { cache: "no-store", mode: "cors", credentials: "omit", signal: ctl.signal });
      return r.ok ? "accepted" : "error";
    } catch {
      return ctl.signal.aborted ? "timeout" : "refused";
    } finally {
      clearTimeout(timer);
    }
  }

  function setupVerdict(info) {
    const name = browserLabel();
    const bar = $("#verdict");
    const sum = h("span", { class: "verdict__sum" }, "not tested yet");
    const dot = h("i", { class: "dot" });
    const retest = h("button", { class: "btn", type: "button" }, "Re-test");
    const copy = h("button", { class: "btn", type: "button", disabled: true }, "Copy as table");
    bar.replaceChildren(
      h("div", { class: "verdict__who" }, dot, h("b", {}, name), h("span", {}, "live verdict")),
      sum,
      h("div", { class: "verdict__actions" }, retest, copy));

    let last = [];
    const expectOf = (sc) => (sc.id === "valid" ? "accepted" : "refused");

    function show(sc, res) {
      const box = $(`[data-port="${sc.port}"] .case__vres`);
      if (!box) return;
      const good = res === expectOf(sc);
      let el;
      if (res === "testing") el = tag("testing…", "wait");
      else if (res === "accepted") el = tag(good ? "✓ connects" : "! connects", good ? "ok" : "bad");
      else if (res === "refused") el = tag(good ? "✓ refused" : "! refused", good ? "ok" : "bad");
      else el = tag(res === "timeout" ? "no answer" : "server error", "bad");
      if (res === "accepted" && !good) {
        el.title = "Did you click \"Continue\" on this port before? The browser keeps that exception until it restarts.";
      }
      box.replaceChildren(el);
      if (ANIM && res !== "testing") A.animate(el, { opacity: [0, 1], scale: [0.85, 1], duration: 450, ease: "outBack(2)" });
    }

    async function test() {
      retest.disabled = true;
      copy.disabled = true;
      dot.className = "dot";
      sum.textContent = "connecting to every port…";
      info.bench.forEach((sc) => show(sc, "testing"));
      last = await Promise.all(info.bench.map(async (sc) => {
        const res = await ping(sc);
        show(sc, res);
        return [sc, res];
      }));
      const good = last.filter(([sc, res]) => res === expectOf(sc)).length;
      const all = good === last.length;
      dot.className = `dot ${all ? "ok" : "bad"}`;
      sum.textContent = `${good} / ${last.length} as expected`;
      $("#bench-cap").textContent = `${name} · ${good} / ${last.length} as expected`;
      retest.disabled = false;
      copy.disabled = false;
    }

    retest.addEventListener("click", test);
    copy.addEventListener("click", () => {
      const word = { accepted: "✅ connects", refused: "❌ refused", timeout: "? no answer", error: "? server error" };
      const md = [`| Port | Scenario | ${name} |`, "|---|---|---|",
        ...last.map(([sc, res]) => `| ${sc.port} | ${sc.title} | ${word[res]} |`)].join("\n");
      navigator.clipboard?.writeText(md).then(() => toast("Copied as a Markdown table"), () => toast("Clipboard blocked"));
    });

    onVisible($("#bench"), test);
  }

  /* ======================================================================
     SCROLL: active nav item + right rail (section index, ruler, slider)
     ====================================================================== */
  function setupScroll() {
    const sections = $$("[data-section]");
    const navLinks = $$(".nav a");
    const ticks = $("#rail-ticks");
    const slider = $("#rail-slider");
    const pct = $("#rail-pct");
    const past = $("#rail-past");
    const next = $("#rail-next");
    let current = -1;
    let docH = 0;

    // ruler as long as the page: one tick per 1 %, a labelled major tick every 5 %
    function buildTicks() {
      const hNow = document.documentElement.scrollHeight;
      if (hNow === docH) return;
      docH = hNow;
      ticks.style.height = `${docH}px`;
      ticks.innerHTML = "";
      for (let i = 0; i <= 100; i++) {
        const y = `${(i / 100) * docH}px`;
        const t = h("i", { class: i % 5 === 0 ? "major" : "" });
        t.style.top = y;
        ticks.append(t);
        if (i % 5 === 0) {
          const b = h("b", {}, String(i));
          b.style.top = y;
          ticks.append(b);
        }
      }
    }

    // section index: past + current at the top, upcoming at the bottom
    function renderIndex(idx) {
      past.innerHTML = "";
      next.innerHTML = "";
      sections.forEach((sec, i) => {
        const li = h("li", { class: i === idx ? "is-current" : "" });
        if (i === idx) {
          [...sec.dataset.label].forEach((ch) => li.append(h("span", { class: "ch" }, ch)));
        } else {
          li.textContent = sec.dataset.label;
        }
        (i <= idx ? past : next).append(li);
      });
      // shrink the current label until it fits the free space beside the frame
      const cur = $(".is-current", past);
      const room = $("#rail").clientWidth - 76;
      let fs = 26;
      cur.style.fontSize = fs + "px";
      while (cur.scrollWidth > room && fs > 13) { fs -= 1; cur.style.fontSize = fs + "px"; }
      if (ANIM) {
        // letters fly in from random angles, like a mechanical counter
        A.animate($$(".is-current .ch", past), {
          opacity: [0, 1],
          translateY: () => [A.utils.random(-46, 46), 0],
          rotate: () => [A.utils.random(-90, 90), 0],
          duration: 650, ease: "outExpo", delay: A.stagger(28),
        });
      }
    }

    let ticking = false;
    function update() {
      ticking = false;
      const vh = window.innerHeight;
      const railH = vh - 52;
      const max = docH - vh;
      const p = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
      ticks.style.transform = `translateY(${-window.scrollY}px)`;
      const y = 10 + p * (railH - 40);
      slider.style.transform = `translateY(${y}px)`;
      const under = docH > 0 ? ((window.scrollY + y) / docH) * 100 : 0;
      pct.textContent = `${String(Math.round(under)).padStart(3, "0")}%`;

      let idx = 0;
      sections.forEach((sec, i) => { if (sec.getBoundingClientRect().top < vh * 0.4) idx = i; });
      if (idx !== current) {
        current = idx;
        navLinks.forEach((a) => a.classList.toggle("is-active", a.dataset.nav === sections[idx].dataset.section));
        sections.forEach((sec, i) => sec.classList.toggle("is-current", i === idx));
        renderIndex(idx);
      }
    }
    const request = () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } };
    window.addEventListener("scroll", request, { passive: true });
    window.addEventListener("resize", () => { buildTicks(); request(); });
    // the page grows after /api/info renders: rebuild the ruler when it does
    if ("ResizeObserver" in window) new ResizeObserver(() => { buildTicks(); request(); }).observe(document.body);
    buildTicks();
    update();
  }

  /* ======================================================================
     MOTION (anime.js)
     ====================================================================== */
  const rise = { opacity: [0, 1], translateY: [14, 0], filter: ["blur(6px)", "blur(0px)"] };

  function buildDots() {
    const box = $("#dots");
    const cols = Math.max(12, Math.round(box.clientWidth / 30));
    const rows = Math.max(6, Math.round(box.clientHeight / 30));
    box.style.setProperty("--cols", cols);
    box.innerHTML = "";
    for (let i = 0; i < cols * rows; i++) box.append(document.createElement("span"));
    return { cols, rows, dots: $$("span", box) };
  }

  function animateHero(ok) {
    const { animate, stagger } = A;
    const grid = buildDots();

    animate(grid.dots, {
      scale: [0, 1], opacity: [0, 1],
      duration: 700, ease: "outQuad",
      delay: stagger(20, { grid: [grid.cols, grid.rows], from: "center" }),
    });

    animate("[data-reveal]", { ...rise, duration: 800, ease: "outExpo", delay: stagger(80, { start: 80 }) });

    // headline: word by word
    animate(".hero__title .w", {
      opacity: [0, 1], translateY: ["0.45em", "0em"], rotate: [4, 0], filter: ["blur(8px)", "blur(0px)"],
      duration: 900, ease: "outExpo", delay: stagger(70, { start: 160 }),
    });

    animateStack(ok);

    // pointer: dots ripple from where you click
    $("#hero").addEventListener("pointerdown", (e) => {
      const r = $("#dots").getBoundingClientRect();
      const col = Math.floor(((e.clientX - r.left) / r.width) * grid.cols);
      const row = Math.floor(((e.clientY - r.top) / r.height) * grid.rows);
      if (col < 0 || row < 0 || col >= grid.cols || row >= grid.rows) return;
      animate(grid.dots, {
        scale: [{ to: 2.4, duration: 180 }, { to: 1, duration: 650 }],
        delay: stagger(28, { grid: [grid.cols, grid.rows], from: row * grid.cols + col }),
        ease: "outQuad",
      });
    });
  }

  /* the stack builds itself bottom-up, then each layer is "verified" in turn */
  function animateStack(ok) {
    const { animate, stagger, svg, utils } = A;
    const layers = ORDER.map((k) => $(`.layer[data-layer="${k}"]`));
    const lines = svg.createDrawable(".stack__svg .draw");

    utils.set(layers, { opacity: 0, translateY: 34 });
    utils.set(".stack__svg .guide, [data-callout], .lock, .seal-fill, .mark", { opacity: 0 });
    utils.set(lines, { draw: "0 0" });
    utils.set("#shackle", { translateY: -12 });

    animate(layers, { opacity: 1, translateY: 0, duration: 900, ease: "outExpo", delay: stagger(160, { start: 200 }) });
    animate(lines, { draw: ["0 0", "0 1"], duration: 800, ease: "inOut(3)", delay: stagger(12, { start: 260 }) });
    animate(".stack__svg .guide", { opacity: 1, duration: 600, delay: 800 });
    animate("[data-callout]", { opacity: [0, 1], translateX: [-8, 0], duration: 600, ease: "outExpo", delay: stagger(130, { start: 750 }) });
    animate(".lock", { opacity: [0, 1], translateY: [-18, 0], duration: 700, ease: "outExpo", delay: 900 });

    // verification sweep: root → intermediate → leaf
    const T0 = 1350;
    const STEP = 300;
    const marked = layers.filter((el) => $(".mark", el));
    marked.forEach((el, i) => {
      const at = T0 + i * STEP;
      animate($(".seal-fill", el), { opacity: [0, 1], duration: 350, delay: at });
      const mark = svg.createDrawable($(".mark", el));
      utils.set($(".mark", el), { opacity: 1 });
      utils.set(mark, { draw: "0 0" });
      animate(mark, { draw: ["0 0", "0 1"], duration: 420, ease: "outQuad", delay: at + 80 });
      if (el.classList.contains("is-bad")) {
        animate(el, { translateX: [0, -7, 6, -3, 0], duration: 520, ease: "inOutQuad", delay: at + 200 });
      }
    });

    const tEnd = T0 + marked.length * STEP + 80;
    if (ok) {
      animate("#shackle", { translateY: 0, duration: 900, delay: tEnd, ease: "outElastic(1, .55)" });
      animate("#stack-pulse", { r: [30, 200], opacity: [0.5, 0], duration: 1400, ease: "outQuad", delay: tEnd + 120, loop: 1 });
    } else {
      animate("#shackle", { rotate: [0, -10, 6, 0], duration: 700, delay: tEnd, ease: "inOutQuad" });
    }
  }

  function animateChain() {
    const { createTimeline } = A;
    const parts = $$("[data-chain]");
    const vertical = window.matchMedia("(max-width: 980px)").matches;
    A.utils.set(parts.filter((p) => p.dataset.chain === "card"), { opacity: 0, translateY: 16 });
    A.utils.set($$(".link__line"), vertical ? { scaleY: 0 } : { scaleX: 0 });
    A.utils.set($$(".link__label"), { opacity: 0 });
    A.utils.set($$(".life__fill"), { scaleX: 0 });

    const tl = createTimeline({ defaults: { duration: 650, ease: "outExpo" } });
    parts.forEach((p, i) => {
      if (p.dataset.chain === "card") {
        tl.add(p, { opacity: 1, translateY: 0 }, i === 0 ? 0 : "-=350");
        tl.add($(".life__fill", p), { scaleX: Number($(".life__fill", p).dataset.used), duration: 900 }, "<<+=150");
      } else {
        tl.add($(".link__line", p), vertical ? { scaleY: 1, duration: 450 } : { scaleX: 1, duration: 450 }, "-=250");
        tl.add($(".link__label", p), { opacity: 1, duration: 300 }, "-=200");
      }
    });
  }

  function animateSteps() {
    const { animate, stagger, svg } = A;
    animate($$(".step"), { opacity: [0, 1], translateX: [-12, 0], duration: 600, ease: "outExpo", delay: stagger(90) });
    const marks = svg.createDrawable(".status .ic");
    animate(marks, { draw: ["0 0", "0 1"], duration: 500, ease: "outQuad", delay: stagger(90, { start: 250 }) });
  }

  function animateBench() {
    const { animate, stagger } = A;
    animate("[data-bench]", { opacity: [0, 1], translateY: [10, 0], duration: 600, ease: "outExpo",
      delay: stagger(55, { grid: [4, 2], from: "first" }) });
  }

  /* fingerprint "decodes" itself, like a terminal readout */
  function scramble(el) {
    if (!el || reduceMotion) return;
    const target = el.dataset.fp || el.textContent;
    el.dataset.fp = target;
    const hex = "0123456789ABCDEF";
    const total = 26;
    let frame = 0;
    const tick = () => {
      frame++;
      const done = Math.floor((frame / total) * target.length);
      el.textContent = [...target].map((ch, i) =>
        i < done || ch === ":" || ch === " " || ch === "…" ? ch : hex[(Math.random() * 16) | 0]).join("");
      if (frame < total) requestAnimationFrame(tick);
      else el.textContent = target;
    };
    requestAnimationFrame(tick);
  }

  /* run something once, when an element scrolls into view */
  function onVisible(el, fn) {
    if (!("IntersectionObserver" in window)) return fn();
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) { io.disconnect(); fn(); }
    }, { threshold: 0.18 });
    io.observe(el);
  }

  /* the stack follows the pointer a little */
  function tiltStack() {
    const fig = $("#stack");
    $("#hero").addEventListener("pointermove", (e) => {
      const r = fig.getBoundingClientRect();
      const dx = (e.clientX - (r.left + r.width / 2)) / window.innerWidth;
      const dy = (e.clientY - (r.top + r.height / 2)) / window.innerHeight;
      A.animate(".stack__svg", { rotateY: dx * 16, rotateX: -dy * 12, duration: 600, ease: "outQuad" });
    });
    $("#hero").addEventListener("pointerleave", () => {
      A.animate(".stack__svg", { rotateY: 0, rotateX: 0, duration: 900, ease: "outElastic(1, .6)" });
    });
  }

  /* ======================================================================
     BOOT
     ====================================================================== */
  async function boot() {
    setupScroll();
    let info;
    try {
      const res = await fetch("/api/info", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      info = await res.json();
    } catch (err) {
      $("#hero-title").textContent = "Could not load /api/info.";
      $("#hero-lede").textContent = String(err);
      root.classList.remove("anim");
      return;
    }

    render(info);
    setupVerdict(info);

    if (!ANIM) {
      root.classList.remove("anim");
      return;
    }
    animateHero(info.validation.ok);
    tiltStack();
    A.utils.set([...$$(".step"), ...$$("[data-bench]")], { opacity: 0 });
    onVisible($("#chain"), animateChain);
    onVisible($("#validation"), animateSteps);
    onVisible($("#bench"), animateBench);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
