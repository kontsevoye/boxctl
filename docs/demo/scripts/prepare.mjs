import { copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(`${root}/assets/vendor`, { recursive: true });
await mkdir(`${root}/output`, { recursive: true });
await copyFile(
  `${root}/node_modules/gsap/dist/gsap.min.js`,
  `${root}/assets/vendor/gsap.min.js`,
);
// The npm distribution states its license in README/package metadata, not a LICENSE file.
await copyFile(
  `${root}/node_modules/gsap/README.md`,
  `${root}/assets/vendor/GSAP-README.md`,
);
for (const weight of [400, 500, 600, 700]) {
  await copyFile(
    `${root}/node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-${weight}-normal.woff2`,
    `${root}/assets/vendor/space-grotesk-${weight}.woff2`,
  );
}
await copyFile(
  `${root}/node_modules/@fontsource/space-grotesk/LICENSE`,
  `${root}/assets/vendor/SPACE-GROTESK-LICENSE.txt`,
);
console.log("Prepared local GSAP and Space Grotesk assets.");
