import assert from "node:assert/strict";

// Exercises the real panel in Chrome with strictly local, synthetic API data.
// Backend persistence and kernel filtering are covered separately by Go/VM tests.
export async function checkPanelFeatures({ page, shot, clickText, assertText, pause, state, emitConnections }) {
  const radio = async (legend, value) => {
    await page.evaluate((legend, value) => {
      const field = [...document.querySelectorAll("fieldset.choice-field")].find((field) => field.querySelector("legend")?.textContent === legend);
      const option = [...(field?.querySelectorAll("[role=radio]") ?? [])].find((option) => option.textContent === value);
      if (!option || option.disabled) throw new Error(`Unavailable choice ${legend}: ${value}`);
      option.click();
    }, legend, value);
  };
  const toggle = async (label) => page.evaluate((label) => {
    const row = [...document.querySelectorAll("label.toggle-row")].find((row) => row.querySelector(".toggle-copy > span")?.textContent === label);
    const input = row?.querySelector("input");
    if (!input || input.disabled) throw new Error(`Unavailable toggle ${label}`);
    input.click();
  }, label);
  await shot("features-routing", "/settings?section=routing", "Block DoT", async () => {
    await radio("TUN stack", "mips");
    await toggle("Block DoT");
    await clickText("button", "Save");
    await page.waitForFunction(() => !document.querySelector(".settings-save-bar.is-dirty"));
  });
  assert.equal(state.saves.at(-1)?.tunStack, "mips");
  assert.equal(state.saves.at(-1)?.blockDoT, true);
  await page.reload({ waitUntil: "networkidle2" });
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('[role=radio]')].find((option) => option.textContent === 'mips')?.getAttribute('aria-checked')), 'true');
  assert.equal(await page.evaluate(() => [...document.querySelectorAll("label.toggle-row")].find((row) => row.textContent.includes("Block DoT"))?.querySelector("input")?.checked), true);
  await radio("DNS mode", "disabled");
  const savesBefore = state.saves.length;
  await clickText("button", "Save");
  await assertText("select gateway mode and DNS upstream/redirect");
  assert.equal(state.saves.length, savesBefore, "Invalid DoT/DNS combination must not save");
  // Saved mips is preserved when another engine becomes active; explicitly
  // choosing a supported stack is required before saving that engine's settings.
  state.engines.forEach((engine) => { engine.selected = engine.id === "sing-box"; engine.running = engine.selected; });
  await page.reload({ waitUntil: "networkidle2" });
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('[role=radio]')].find((option) => option.textContent === "mips (Mihomo)")?.disabled), true);
  await radio("TUN stack", "system");
  await clickText("button", "Save");
  state.engines.forEach((engine) => { engine.selected = engine.id === "mihomo"; engine.running = engine.selected; });
  // Locale is also verified with a fresh app mount, not a source-string check.
  const russianSetup = await page.evaluateOnNewDocument(() => localStorage.setItem("boxctl.locale", "ru"));
  await shot("features-routing-russian", "/settings?section=routing", "Блокировать DoT");
  await page.removeScriptToEvaluateOnNewDocument(russianSetup.identifier);

  const seed = state.connections.active[0];
  state.connections.active = Array.from({ length: 5000 }, (_, index) => ({
    ...seed,
    id: `stress-${String(index).padStart(5, "0")}`,
    host: `host-${String(index).padStart(5, "0")}.example.test`,
    downloadRateBytes: 5000 - index,
    sourceIP: index % 2 ? "192.168.10.20" : "192.168.10.21",
    source: `${index % 2 ? "192.168.10.20" : "192.168.10.21"}:${51000 + index}`,
  }));
  state.connections.closed = Array.from({ length: 20 }, (_, index) => ({ ...seed, id: `closed-stress-${index}`, host: `closed-${index}.example.test`, closedAt: state.connections.capturedAt }));
  const mounted = () => page.$$eval("tbody[data-connection-id]", (rows) => rows.length);
  await shot("features-connections-desktop", "/connections", "5000 of 5000");
  assert.ok(await mounted() < 100, "5000 connections must not mount 5000 DOM rows");
  await page.type(".proxies-search input", "host-04999");
  await assertText("1 of 5000");
  await assertText("host-04999.example.test");
  await page.$eval(".proxies-search input", (element) => { element.select(); });
  await page.keyboard.press("Backspace");
  await assertText("5000 of 5000");
  await page.select('.connections-device-filter', '192.168.10.20');
  await assertText('2500 of 5000');
  await page.select('.connections-device-filter', '');
  await page.type('.proxies-search input', 'host-0499[0-9]');
  await assertText('10 of 5000');
  await page.$eval('.proxies-search input', (element) => element.select());
  await page.keyboard.press('Backspace');
  await page.evaluate(() => [...document.querySelectorAll('[role=tab]')].find((tab) => tab.textContent.startsWith('Closed'))?.click());
  await assertText('20 of 20');
  assert.equal(await page.$('.connections-close-one'), null, 'Closed rows must not offer a close action');
  await page.evaluate(() => [...document.querySelectorAll('[role=tab]')].find((tab) => tab.textContent.startsWith('All'))?.click());
  await assertText('5020 of 5020');
  await page.evaluate(() => [...document.querySelectorAll('[role=tab]')].find((tab) => tab.textContent.startsWith('Active'))?.click());
  await assertText('5000 of 5000');
  await page.focus(".connections-table-wrap");
  await page.keyboard.press("End");
  await page.waitForSelector('tbody[data-connection-id="stress-04999"]');
  await page.click('tbody[data-connection-id="stress-04999"] .connections-expand button');
  await page.waitForSelector('.connections-details-row');
  assert.ok(await mounted() < 100);
  await page.$eval(".connections-table-wrap", (element) => element.focus());
  await page.$eval(".connections-table-wrap", (element) => { element.scrollTop = element.scrollHeight / 2; });
  await pause(500);
  const firstVisible = () => page.evaluate(() => {
    const viewport = document.querySelector(".connections-table-wrap").getBoundingClientRect();
    const row = [...document.querySelectorAll("tbody[data-connection-id]")].find((row) => { const rect = row.getBoundingClientRect(); return rect.bottom > viewport.top + 55 && rect.top < viewport.bottom; });
    return row ? { id: row.dataset.connectionId, top: row.getBoundingClientRect().top } : null;
  });
  const before = await firstVisible();
  assert.ok(before, "A middle viewport row must be visible");
  state.connections.active.unshift({ ...seed, id: "stress-new", host: "new.example.test", downloadRateBytes: 10000 });
  emitConnections();
  await assertText("5001 of 5001");
  await pause(500);
  const after = await firstVisible();
  assert.equal(after?.id, before.id, "Live reorder must preserve the visible row");
  assert.ok(Math.abs(after.top - before.top) < 8, "Live reorder must preserve the scroll offset");
  await page.type(".proxies-search input", "host-02500");
  await assertText("1 of 5001");
  await page.click(".connections-close-one");
  await page.waitForSelector('dialog[open]');
  await page.evaluate(() => [...document.querySelectorAll('dialog[open] button')].find((button) => button.textContent.trim() === "Close")?.click());
  await page.waitForFunction(() => !document.querySelector('.connections-close-one'));
  assert.deepEqual(state.closedIDs, ["stress-02500"]);
  await page.setViewport({ width: 430, height: 900, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  await shot("features-connections-mobile", "/connections", "5000 of 5000", async () => {
    await page.click(".connections-expand button");
    await page.waitForSelector(".connections-details-row");
    await page.$eval('.connections-table-wrap', (element) => element.scrollIntoView({ block: 'start' }));
  });
  assert.ok(await mounted() < 40, "Mobile rows must remain virtualized");
  await page.focus(".connections-table-wrap");
  await page.keyboard.press("End");
  await page.waitForSelector('tbody[data-connection-id="stress-04999"]');
  await shot("features-connections-mobile-end", null, "host-04999.example.test");
  return { settingsSaveAndReload: true, invalidDoTBlocked: true, singBoxMipsDisabled: true, rows: 5000, boundedDOM: true, offscreenSearch: true, regexAndDeviceFilters: true, tabs: true, liveAnchor: true, closeCorrectID: true, mobileExpandedAndEnd: true };
}
