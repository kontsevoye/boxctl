import { install, computeExecutablePath, Browser } from "@puppeteer/browsers";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const buildId = "152.0.7977.30";
export const cacheDir = fileURLToPath(
  new URL("../.cache/browser", import.meta.url),
);
export function browserPath() {
  const path =
    process.env.HYPERFRAMES_BROWSER_PATH ||
    computeExecutablePath({
      browser: Browser.CHROMEHEADLESSSHELL,
      buildId,
      cacheDir,
    });
  if (!existsSync(path))
    throw new Error("Chrome is missing. Run npm run setup:browser first.");
  return path;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const browser = await install({
    browser: Browser.CHROMEHEADLESSSHELL,
    buildId,
    cacheDir,
  });
  console.log(browser.executablePath);
}
