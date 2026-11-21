// Dev helper (NOT part of the demo): drive headless Edge over the DevTools
// protocol to take dashboard screenshots after scrolling / clicking.
//   node tools/dev/cdp_shot.mjs <spec.json>
//   spec = [{ "url"?: "https://localhost:8443/?theme=dark", "w": 1536, "h": 864,
//             "js"?: "scrollTo({top: document.querySelector('#chain').offsetTop - 52, behavior: 'instant'}); 1",
//             "wait"?: 1200, "load"?: 4200, "out"?: "shot.png" }]
// PNGs are written next to spec.json. Uses --ignore-certificate-errors, so the
// "live browser verdict" shows every port as "connects" in these screenshots.
// Drive headless Edge over the DevTools protocol: navigate, run JS, screenshot.
// usage: node cdp_shot.mjs spec.json   (spec = [{url, w, h, js?, wait?, out}])
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const spec = JSON.parse(readFileSync(process.argv[2], "utf8"));
const dir = path.resolve(path.dirname(process.argv[2])).replaceAll("\\", "/");
const EDGE = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const PORT = 9300 + Math.floor(Math.random() * 400);
const edge = spawn(EDGE, ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}/edge-cdp-${Date.now()}`,
  "--ignore-certificate-errors", "--hide-scrollbars", "--no-first-run", "about:blank"]);
edge.stderr.on("data", () => {}); edge.stdout.on("data", () => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let tab;
for (let i = 0; i < 150 && !tab; i++) {
  try { tab = await (await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: "PUT" })).json(); } catch { await sleep(200); }
}
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pending = new Map();
ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
const send = (method, params = {}) => new Promise((r) => { const n = ++id; pending.set(n, r); ws.send(JSON.stringify({ id: n, method, params }));
  setTimeout(() => { if (pending.has(n)) { pending.delete(n); console.log("timeout", method); r({}); } }, 15000); });

await send("Page.enable");
for (const s of spec) {
  await send("Emulation.setDeviceMetricsOverride", { width: s.w, height: s.h, deviceScaleFactor: 1, mobile: false });
  if (s.url) { await send("Page.navigate", { url: s.url }); await sleep(s.load ?? 4200); }
  if (s.js) {
    const r = await send("Runtime.evaluate", { expression: s.js, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) console.log("JS error:", JSON.stringify(r.result.exceptionDetails).slice(0, 300));
    else if (r.result?.result?.value !== undefined) console.log(s.out, "=>", JSON.stringify(r.result.result.value));
    await sleep(s.wait ?? 1200);
  }
  if (s.out) {
    const shot = await send("Page.captureScreenshot", { format: "png", fromSurface: true });
    if (!shot.result) continue;
    writeFileSync(path.join(dir, s.out), Buffer.from(shot.result.data, "base64"));
    console.log("saved", s.out);
  }
}
ws.close();
spawn("taskkill", ["/PID", String(edge.pid), "/T", "/F"], { stdio: "ignore" });
