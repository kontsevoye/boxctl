import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { browserPath } from "./browser.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const result = spawnSync(
  `${root}/node_modules/.bin/hyperframes`,
  process.argv.slice(2),
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      HYPERFRAMES_NO_TELEMETRY: "1",
      HYPERFRAMES_BROWSER_PATH: browserPath(),
    },
  },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
