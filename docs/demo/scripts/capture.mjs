#!/usr/bin/env node
/** Render the unchanged frontend against the strictly local demo API.
 * Run from any directory: node docs/demo/scripts/capture.mjs
 * API fixture values illustrate features; they do not benchmark a live router.
 */
import { createServer } from "node:http";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import puppeteer from "puppeteer";
import { browserPath } from "./browser.mjs";
import * as fixture from "../fixtures/api.mjs";

const demo = fileURLToPath(new URL("..", import.meta.url));
const root = path.resolve(demo, "../..");
const output = path.join(demo, "assets/ui");
await mkdir(output, { recursive: true });
const catalogSource = await readFile(
  path.join(root, "internal/app/engine_catalog.go"),
  "utf8",
);
const modesLiteral = /var allCaptureModes = \[\]string\{([^}]+)\}/.exec(
  catalogSource,
)?.[1];
const advertisedModes = modesLiteral
  ? [...modesLiteral.matchAll(/"([^"]+)"/g)].map((match) => match[1])
  : undefined;
if (
  !advertisedModes ||
  fixture.engines.some(
    (engine) =>
      JSON.stringify(engine.supportedCaptureModes) !==
      JSON.stringify(advertisedModes),
  )
) {
  throw new Error(
    "Demo capture modes differ from internal/app/engine_catalog.go. Refresh fixtures/api.mjs before regenerating.",
  );
}
const unknown = [];
const requests = new Map();
const streams = new Set();
const sockets = new Set();
const screenshots = [];
let browser;
let vite;
const dashboard = structuredClone(fixture.dashboard);
const api = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const endpoint = url.pathname.replace(/^\/api\/v1/, "");
  const method = req.method;
  const key = `${method} ${endpoint}`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
  let body = "";
  for await (const chunk of req) body += chunk;
  const json = (data, status = 200) => {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    res.end(
      JSON.stringify(
        status < 400
          ? { data }
          : { error: { code: "unhandled_demo_request", message: key } },
      ),
    );
  };
  const stream = (event, items) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.flushHeaders();
    for (const item of items)
      res.write(`event: ${event}\ndata: ${JSON.stringify(item)}\n\n`);
    const current = { endpoint, response: res };
    streams.add(current);
    req.on("close", () => streams.delete(current));
  };
  if (method === "GET") {
    if (endpoint === "/auth/session")
      return json({
        authenticated: true,
        user: { id: "demo", displayName: "Demo administrator" },
        csrfToken: "demo-local-token",
        expiresAt: "2027-01-01T00:00:00Z",
      });
    if (endpoint === "/core/capabilities") return json(fixture.capabilities);
    if (endpoint === "/engines") return json(fixture.engines);
    if (endpoint === "/status") return json(fixture.status);
    if (endpoint === "/settings") return json(fixture.settings);
    if (endpoint === "/profiles") return json(fixture.profiles);
    if (endpoint === "/proxy-subscriptions") return json(fixture.subscriptions);
    if (endpoint === "/core/rules") return json(fixture.rules);
    if (endpoint === "/rule-lists") return json(fixture.ruleLists);
    if (endpoint === "/fake-ip-whitelist") return json(fixture.fakeIPWhitelist);
    if (endpoint === "/manager/update") return json(fixture.managerUpdate);
    if (endpoint === "/external-dashboard")
      return json(fixture.externalDashboard);
    const updateEngine = /^\/engines\/([^/]+)\/update$/.exec(endpoint);
    if (updateEngine) {
      const engine = fixture.engines.find((e) => e.id === updateEngine[1]);
      if (engine)
        return json({
          engine: engine.id,
          currentVersion: engine.version,
          latestVersion: engine.version,
          channel: "stable",
          updateAvailable: false,
        });
    }
    const profileConfig = /^\/profiles\/([^/]+)\/config$/.exec(endpoint);
    if (profileConfig) {
      const profile = fixture.profiles.find((p) => p.id === profileConfig[1]);
      if (profile)
        return json({
          profile,
          engine: profile.engine,
          format: profile.engine === "sing-box" ? "json" : "yaml",
          content:
            profile.engine === "sing-box"
              ? fixture.configJson
              : fixture.configYaml,
          revision: "demo-rev-01",
          updatedAt: fixture.capturedAt,
          active: profile.active,
          pending: false,
        });
    }
    const ruleList = /^\/rule-lists\/([^/]+)$/.exec(endpoint);
    if (ruleList) {
      const list = fixture.ruleLists.find((p) => p.id === ruleList[1]);
      if (list) return json(list);
    }
    if (endpoint === "/core/dashboard/stream")
      return stream("dashboard", [dashboard]);
    if (endpoint === "/core/connections/stream")
      return stream("connections", [fixture.connections]);
    if (
      endpoint === "/core/logs/stream" ||
      endpoint === "/logs/system/stream"
    ) {
      const kind = endpoint.startsWith("/core") ? "core" : "system";
      return stream(
        "log",
        fixture.logs[kind].map((message, i) => ({
          time: `2026-09-08T11:59:${String(20 + i).padStart(2, "0")}Z`,
          level: "info",
          component:
            kind === "core"
              ? "mihomo"
              : [
                  "manager",
                  "engine",
                  "profiles",
                  "firewall",
                  "dns",
                  "controller",
                  "maintenance",
                  "subscriptions",
                ][i],
          message,
        })),
      );
    }
  }
  if (
    method === "POST" &&
    /^\/profiles\/[^/]+\/config\/validate$/.test(endpoint)
  )
    return json({ valid: true, diagnostics: [] });
  if (method === "POST" && endpoint === "/core/proxies/delay") {
    const { proxy } = JSON.parse(body);
    const option = dashboard.groups
      .flatMap((g) => g.options)
      .find((p) => p.name === proxy);
    return json({ proxy, delayMs: option?.delayMs ?? 42 });
  }
  if (method === "PUT" && endpoint === "/core/proxies") {
    const { group, proxy } = JSON.parse(body);
    const target = dashboard.groups.find((g) => g.name === group);
    if (!target || !target.options.some((p) => p.name === proxy))
      return json(undefined, 400);
    target.selected = proxy;
    for (const stream of streams)
      if (stream.endpoint === "/core/dashboard/stream")
        stream.response.write(
          `event: dashboard\ndata: ${JSON.stringify(dashboard)}\n\n`,
        );
    return json({ selected: proxy });
  }
  unknown.push(key);
  json(undefined, 501);
});
api.on("connection", (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let page;
const errors = [];
async function assertText(text) {
  await page.waitForFunction(
    (text) => document.body.innerText.includes(text),
    { timeout: 15000 },
    text,
  );
}
async function clickText(selector, text) {
  const match = await page.evaluateHandle(
    (selector, text) =>
      [...document.querySelectorAll(selector)].find(
        (el) => el.textContent.trim() === text && el.getClientRects().length,
      ),
    selector,
    text,
  );
  const element = match.asElement();
  if (!element) throw new Error(`Missing visible ${selector}: ${text}`);
  await element.click();
  await match.dispose();
  await pause(200);
}
async function shot(name, route, expected, action, options = {}) {
  if (route)
    await page.goto(
      `${vite.resolvedUrls.local[0].replace(/\/$/, "")}${route}`,
      { waitUntil: "networkidle2" },
    );
  if (expected) await assertText(expected);
  if (action) await action();
  await page.evaluate(() => document.fonts.ready);
  await pause(300);
  const geometry = await page.evaluate(() => ({
    viewportWidth: innerWidth,
    viewportHeight: innerHeight,
    documentWidth: document.documentElement.scrollWidth,
    scrollY,
    theme: document.documentElement.dataset.theme,
    language: document.documentElement.lang,
    alerts: [...document.querySelectorAll(".du-alert-error, .toast-error")]
      .filter((el) => el.getClientRects().length)
      .map((el) => el.innerText),
  }));
  if (geometry.documentWidth > geometry.viewportWidth + 1)
    throw new Error(
      `Horizontal overflow in ${name}: ${JSON.stringify(geometry)}`,
    );
  if (geometry.alerts.length)
    throw new Error(`Visible error in ${name}: ${geometry.alerts.join("; ")}`);
  if (errors.length || unknown.length)
    throw new Error(`Capture ${name}: ${JSON.stringify({ errors, unknown })}`);
  const filename = `${name}.png`;
  const destination = path.join(output, filename);
  await page.screenshot({ path: destination, fullPage: false, ...options });
  screenshots.push({
    name,
    file: `assets/ui/${filename}`,
    route: new URL(page.url()).pathname + new URL(page.url()).search,
    width: geometry.viewportWidth,
    height: geometry.viewportHeight,
    deviceScaleFactor: 2,
    sha256: createHash("sha256")
      .update(await readFile(destination))
      .digest("hex"),
    ...geometry,
  });
  console.log(`Captured ${filename}`);
}

try {
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  const { createServer: createViteServer } = await import(
    pathToFileURL(
      path.join(root, "frontend/node_modules/vite/dist/node/index.js"),
    ).href
  );
  vite = await createViteServer({
    root: path.join(root, "frontend"),
    configFile: path.join(root, "frontend/vite.config.ts"),
    logLevel: "error",
    server: {
      host: "127.0.0.1",
      port: 0,
      strictPort: false,
      proxy: { "/api": `http://127.0.0.1:${api.address().port}` },
    },
  });
  await vite.listen();
  browser = await puppeteer.launch({
    headless: true,
    executablePath: browserPath(),
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--font-render-hinting=none",
    ],
  });
  page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 960, deviceScaleFactor: 2 });
  await page.emulateTimezone("UTC");
  const themeSetup = await page.evaluateOnNewDocument(() => {
    if (location.protocol !== "http:") return;
    localStorage.setItem("boxctl.theme", "dark");
    localStorage.setItem("boxctl.locale", "en");
  });
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      ["data:", "blob:"].includes(url.protocol) ||
      (["127.0.0.1", "localhost"].includes(url.hostname) &&
        url.port === new URL(vite.resolvedUrls.local[0]).port)
    )
      void request.continue();
    else {
      errors.push(`Blocked non-local request: ${url.origin}${url.pathname}`);
      void request.abort();
    }
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  await page.setViewport({
    width: 430,
    height: 900,
    deviceScaleFactor: 2,
    isMobile: true,
    hasTouch: true,
  });
  await shot("mobile-status", "/", "Everyday network");
  await shot("mobile-proxies", "/proxies", "Auto · fastest route");
  await shot("mobile-config", "/config", "YAML");
  await page.removeScriptToEvaluateOnNewDocument(themeSetup.identifier);
  const lightSetup = await page.evaluateOnNewDocument(() => {
    if (location.protocol !== "http:") return;
    localStorage.setItem("boxctl.theme", "light");
    localStorage.setItem("boxctl.locale", "en");
  });
  await shot("mobile-light", "/", "Everyday network");
  await page.removeScriptToEvaluateOnNewDocument(lightSetup.identifier);
  await page.evaluateOnNewDocument(() => {
    if (location.protocol !== "http:") return;
    localStorage.setItem("boxctl.theme", "dark");
    localStorage.setItem("boxctl.locale", "en");
  });
  await page.setViewport({ width: 1440, height: 960, deviceScaleFactor: 2 });
  await shot("status", "/", "Everyday network");
  await shot("proxies", "/proxies", "Auto · fastest route", async () => {
    const measured = page.waitForResponse(
      (response) =>
        response.url().endsWith("/core/proxies/delay") &&
        response.request().method() === "POST",
    );
    await page.click('button[aria-label="Test latency"]');
    await measured;
    await page.waitForFunction(
      () =>
        !document.querySelector('button[aria-label="Test latency"]').disabled,
    );
  });
  await shot("proxy-selection", null, "Global proxy", async () => {
    await clickText(".proxy-group-title strong", "Global proxy");
    await page.click(
      ".proxy-group-card.expanded .proxy-node:nth-child(2) .proxy-node-select",
    );
    await page.waitForFunction(() =>
      [
        ...document.querySelectorAll(
          '.proxy-group-card.expanded .proxy-node-select[aria-pressed="true"]',
        ),
      ].some((el) => el.textContent.includes("Frankfurt")),
    );
  });
  await shot("proxy-providers", null, "Global proxy", async () =>
    clickText("[role=tab]", "Providers"),
  );
  await shot("profiles-mihomo", "/profiles", "Work & development");
  await shot(
    "profiles-sing-box",
    "/profiles?engine=sing-box",
    "Home · sing-box",
  );
  await shot("config-editor", "/config?engine=mihomo&profile=everyday", "YAML");
  await shot("config-validated", null, "YAML", async () => {
    await clickText("button", "Validate");
    await assertText("Configuration is valid");
  });
  await shot(
    "config-json",
    "/config?engine=sing-box&profile=sing-home",
    "JSON",
  );
  await shot("subscriptions", "/profiles", "Everyday network", async () => {
    await page.click("#configuration-tab-subscriptions");
    await assertText("Global network");
  });
  await shot("rules", "/rules", "private-networks");
  await shot("rule-providers", null, "private-networks", async () => {
    await clickText("[role=tab]", "Providers · 3");
    await assertText("1248");
  });
  await shot("rule-lists", "/rule-lists", "development", async () => {
    await page.click(".rule-list-toggle");
    await page.waitForSelector("#rule-list-content");
  });
  await shot("connections", "/connections", "github.com");
  await shot("connection-detail", null, "github.com", async () => {
    await page.click(".connections-expand button");
    await page.waitForSelector(".connections-details-row");
  });
  await shot("connections-filtered", "/connections", "github.com", async () => {
    await page.type(".proxies-search input", "github");
  });
  await shot("logs", "/logs", "Configuration reloaded successfully");
  await shot("logs-system", "/logs/system", "Capture plan applied");
  await shot("settings", "/settings", "Blackhole during restart");
  await shot("config-capture", "/settings?section=routing", "Capture mode");
  await shot("config-dns", null, "DNS mode", async () => {
    await page.evaluate(() => window.scrollTo(0, 310));
  });
  await shot("recovery", null, "Network recovery", async () => {
    await page.evaluate(() =>
      document
        .querySelector(".settings-recovery")
        .scrollIntoView({ block: "end" }),
    );
  });
  await shot("updates", "/settings?section=updates", "Zashboard");
  await shot("backups", "/settings?section=backups", "Export");
  const gitRevision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  const fixtureSha256 = createHash("sha256")
    .update(await readFile(path.join(demo, "fixtures/api.mjs")))
    .digest("hex");
  const manifest = {
    schemaVersion: 1,
    description:
      "Real unchanged boxctl frontend, deterministic sanitized API fixtures; illustrative values, no live-router measurements. Validation success and latency are simulated API scenarios.",
    sourceRevision: gitRevision,
    fixtureTimestamp: fixture.capturedAt,
    fixtureSha256,
    browserVersion: await browser.version(),
    desktopViewport: { width: 1440, height: 960 },
    mobileViewport: { width: 430, height: 900 },
    screenshots,
    validation: {
      pageErrors: errors,
      unhandledAPIRequests: unknown,
      allScreenshotsWithoutHorizontalOverflow: true,
      engineCaptureModesMatchSource: true,
    },
    apiRequests: Object.fromEntries([...requests.entries()].sort()),
  };
  await writeFile(
    path.join(output, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );
  console.log(
    `Validated ${screenshots.length} captures; no unknown API calls, browser errors or horizontal overflow.`,
  );
} finally {
  if (browser) await browser.close();
  for (const stream of streams) stream.response.end();
  for (const socket of sockets) socket.destroy();
  api.close();
  if (vite) await vite.close();
}
