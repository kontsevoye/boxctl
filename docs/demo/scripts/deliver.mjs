import { execFileSync } from "node:child_process";
import { readFile, writeFile, stat, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { browserPath, buildId } from "./browser.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const run = (binary, args) =>
  execFileSync(binary, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
const ffmpeg = (...args) =>
  run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", ...args]);
const hash = async (path) =>
  createHash("sha256")
    .update(await readFile(`${root}/${path}`))
    .digest("hex");
const probe = (path) =>
  JSON.parse(
    run("ffprobe", [
      "-v",
      "error",
      "-show_format",
      "-show_streams",
      "-of",
      "json",
      path,
    ]),
  );
const rendered = probe("output/boxctl-demo.mp4");
const video = rendered.streams.find((s) => s.codec_type === "video");
const audio = rendered.streams.find((s) => s.codec_type === "audio");
if (
  !video ||
  video.width !== 1920 ||
  video.height !== 1080 ||
  video.codec_name !== "h264" ||
  video.pix_fmt !== "yuv420p" ||
  video.r_frame_rate !== "60/1"
) {
  throw new Error("Expected a 1920×1080 / 60 fps / H.264 / yuv420p render.");
}
if (
  Math.abs(Number(rendered.format.duration) - 30) > 0.05 ||
  Number(video.nb_frames) !== 1800
) {
  throw new Error(
    `Expected exactly 30 seconds and 1800 video frames: ${rendered.format.duration}, ${video.nb_frames}`,
  );
}
if (!audio || audio.codec_name !== "aac" || audio.channels !== 2)
  throw new Error("Expected stereo AAC soundtrack.");
ffmpeg(
  "-i",
  "output/boxctl-demo.mp4",
  "-map",
  "0:v:0",
  "-map",
  "0:a:0",
  "-c",
  "copy",
  "-movflags",
  "+faststart",
  "boxctl-demo.mp4",
);
ffmpeg(
  "-ss",
  "1.8",
  "-i",
  "boxctl-demo.mp4",
  "-frames:v",
  "1",
  "-update",
  "1",
  "poster.jpg",
);
// A contact sheet made from the encoded deliverable, not only from HTML snapshots.
ffmpeg(
  "-i",
  "boxctl-demo.mp4",
  "-vf",
  "select='eq(n,108)+eq(n,297)+eq(n,405)+eq(n,585)+eq(n,675)+eq(n,801)+eq(n,945)+eq(n,1125)+eq(n,1269)+eq(n,1485)+eq(n,1683)+eq(n,1782)',scale=480:270,tile=3x4:padding=12:margin=12:color=0x111820",
  "-frames:v",
  "1",
  "-update",
  "1",
  "output/contact-sheet.jpg",
);
const captures = JSON.parse(
  await readFile(`${root}/assets/ui/manifest.json`, "utf8"),
);
const frontendFiles = run("git", ["ls-files", "-z", "--", "../../frontend"])
  .split("\0")
  .filter(Boolean)
  .sort();
const sourceHash = createHash("sha256");
for (const file of frontendFiles) {
  sourceHash
    .update(file.replace("../../", ""))
    .update("\0")
    .update(await readFile(`${root}/${file}`))
    .update("\0");
}
const filmInputs = {};
for (const file of [
  "index.html",
  "film.css",
  "film.js",
  "package-lock.json",
  "scripts/audio.py",
])
  filmInputs[file] = await hash(file);
const artifacts = {};
await copyFile(`${root}/output/contact-sheet.jpg`, `${root}/contact-sheet.jpg`);
for (const file of ["boxctl-demo.mp4", "poster.jpg", "contact-sheet.jpg"]) {
  const size = (await stat(`${root}/${file}`)).size;
  if (size > 10_000_000)
    throw new Error(`${file} exceeds the 10 MB GitHub attachment budget (${size}).`);
  artifacts[file] = { bytes: size, sha256: await hash(file) };
}
const manifest = {
  description:
    "Actual boxctl frontend with local synthetic demo API fixtures; not live router measurements.",
  source: {
    ...captures,
    frontendSourceSha256: sourceHash.digest("hex"),
    filmInputs,
  },
  toolchain: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    hyperframes: "0.8.31",
    chrome: run(browserPath(), ["--version"]).trim(),
    expectedChromeBuild: buildId,
    ffmpeg: run("ffmpeg", ["-version"]).split("\n")[0],
  },
  video: {
    durationSeconds: Number(rendered.format.duration),
    width: video.width,
    height: video.height,
    frames: Number(video.nb_frames),
    fps: 60,
    codec: video.codec_name,
    pixelFormat: video.pix_fmt,
  },
  audio: {
    codec: audio.codec_name,
    channels: audio.channels,
    sampleRate: Number(audio.sample_rate),
    sourceSha256: await hash("assets/audio/boxctl-promo.wav"),
  },
  artifacts,
};
await writeFile(
  `${root}/render-manifest.json`,
  `${JSON.stringify(manifest, null, 2)}\n`,
);
console.log(JSON.stringify({ video: manifest.video, artifacts }, null, 2));
