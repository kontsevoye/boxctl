# boxctl product film

A 30-second English product tour rendered with [Hyperframes](https://github.com/heygen-com/hyperframes):
1920 × 1080, 60 fps, H.264/AAC, with an original stereo soundtrack.

[Watch the film](boxctl-demo.mp4)

## Regenerate

Requirements: Node.js 22+, npm, Python 3, and FFmpeg/FFprobe on `PATH`.
The repository's Nix development shell provides Node and Python; install FFmpeg
separately if needed. The pinned Chrome build is downloaded into ignored `.cache/`.

From the repository root:

```sh
npm --prefix frontend ci
PUPPETEER_SKIP_DOWNLOAD=1 npm --prefix docs/demo ci
npm --prefix docs/demo run setup:browser
npm --prefix docs/demo run build
```

The first setup needs internet for packages and Chrome. No router, account,
API key, hosted renderer, or music service is needed to build the film.
The capture process starts its own loopback Vite frontend and fixture API,
exercises the actual React pages, captures them at 2× resolution, and shuts down.
It rejects browser errors, missing expected UI, horizontal overflow, external
requests, and API calls without explicit fixtures. It does not edit the app.

`build` regenerates screenshots, local fonts/GSAP, original music, the MP4,
poster, contact sheet and provenance manifest. The MP4 stays below 10 MB for
GitHub attachment compatibility. The poster and contact sheet are local review
artifacts, ignored alongside intermediate screenshots, WAV, browser files,
and npm dependencies. There is one composition and one delivered
video; no GIF is generated.

## Preview and iterate

```sh
npm --prefix docs/demo run capture
npm --prefix docs/demo run prepare:assets
npm --prefix docs/demo run preview

cd docs/demo
node scripts/hyperframes.mjs snapshot --describe false \
  --at 1.8,4.95,6.75,9.75,11.25,13.35,15.75,18.75,21.15,24.75,28.05,29.7 \
  --output output/snapshots
npm run lint
npm run check -- --samples 30
npm run render
npm run deliver
```

The wrapper opts out of Hyperframes telemetry and selects the pinned local
browser. `HYPERFRAMES_BROWSER_PATH=/absolute/path/to/chrome` overrides it for
troubleshooting; use the pinned build for consistent rendering.

## Source files

| File | Purpose |
| --- | --- |
| `index.html` | English copy, screenshots, 30-second composition/audio contract |
| `film.css` | Brand palette, typography, layouts and close-up crops |
| `film.js` | Native 30-second paused GSAP timeline, with seekable animation |
| `fixtures/api.mjs` | Synthetic profiles, hosts, resources, traffic and API responses |
| `scripts/capture.mjs` | Real frontend navigation, interactions and assertions |
| `scripts/audio.py` | Original, seeded 80 BPM soundtrack |
| `scripts/browser.mjs` | Chrome pin and local installation |
| `scripts/deliver.mjs` | Encoding checks, delivery assets and source hashes |
| `scripts/upload.mjs` | Upload-only GitHub attachment and local README player update |
| `package-lock.json` | Exact JavaScript dependency graph |

When pages or APIs change, update fixtures and capture assertions first. Inspect
new screenshots and adjust CSS crops. Keep claims consistent with actual
engine capabilities. Root duration, timeline and audio all span 30 seconds;
the delivered video has 1800 frames.

## Storyboard

| Time | Message | Real interface / capabilities |
| --- | --- | --- |
| 0–3 s | Your network. Your rules. | Animated cube, transparent-routing positioning |
| 3–7.5 s | Two cores. One panel. | Mihomo / sing-box profiles, YAML / JSON editors, lifecycle controls |
| 7.5–12 s | Route it. Your way. | Proxies / latency, rules, capture, DNS, remote profiles, Mihomo subscriptions / providers and local lists |
| 12–16.5 s | See every connection. | Status, per-process CPU / memory, LAN hosts, connections and logs |
| 16.5–22.5 s | Update. Protect. Recover. | Core / manager updates, backups, optional restart guard and recovery |
| 22.5–27 s | Full control. Any screen. | Desktop dark and mobile light UI; EN / RU, authentication, optional Zashboard |
| 27–30 s | Own your OpenWrt network. | Project name and GitHub URL |

The capture set also includes subscriptions, proxy/rule providers, local lists,
validation, connection filtering/details, system logs, DNS and recovery. All
chapter backgrounds use the same dark palette. The mobile light-mode screen
is part of the actual theme demonstration.

Numbers, devices, profiles and events are synthetic and labelled as demo data.
They are not benchmarks or evidence that a router update/restart was performed.
Restart protection is optional and off by default; the demo shows it enabled.
Provider/subscription management and local rule-list editing are Mihomo features.
Zashboard is optional external software. Managed routing capture is IPv4-only.

## GitHub README player

GitHub supports MP4 playback inside README Markdown, including `<details>`.
The player needs a real GitHub attachment URL on its own line. A repository-relative
MP4 link or manually authored `<video>` is not an equivalent attachment embed.
No GIF is needed. See [GitHub's video announcement](https://github.blog/changelog/2021-05-13-video-uploads-now-generally-available/)
and [attachment documentation](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/attaching-files).

After reviewing the freshly built video, publish its attachment and update the
local README with an authenticated GitHub CLI that has push access:

```sh
npm --prefix docs/demo run upload
```

This explicit step uploads only the MP4. It creates no issue, PR, comment, or
commit. It verifies the README through GitHub's Markdown renderer without signing
in, checks anonymous video playback, and saves the
attachment URL and video hash in `github-upload.json`. Running it again with the
same video reuses that URL. The endpoint follows the [official GitHub CLI uploader](https://github.com/cli/cli/blob/v2.99.0/internal/attachments/client.go).

Attachment URLs are immutable, so rerun `upload` after regenerating changed
content. The script deliberately does not automatically retry a failed upload.
To attach manually, drag the MP4 into GitHub's Markdown editor and paste the
resulting URL on its own line between the root README's `boxctl-demo:player`
markers. The local MP4 and poster remain available for downloads/offline viewing.
The verification uses the public repository's Markdown context; opening the
attachment URL outside that context may return 404 even when the README player works.
The build itself does not publish anything or commit repository changes.

## Verify

Inspect the encoded `contact-sheet.jpg` and play `boxctl-demo.mp4`. Delivery
checks exactly 30 seconds / 1800 frames, 1080p, 60 fps, H.264 yuv420p, stereo AAC
and size. `render-manifest.json` records source hashes, capture evidence and
actual tool versions. Review editor, capture-mode, guard and log crops after
frontend changes; automated checks supplement visual review.

## Assets and licenses

The music and motion artwork are original contributions under the repository's
MIT license; see [audio notes](assets/audio/README.md). The cube adapts the existing
boxctl/Lucide mark. Space Grotesk uses the SIL Open Font License, copied into
generated `assets/vendor`; GSAP retains its npm distribution license, and
Hyperframes is Apache-2.0. Fonts and scripts come from locked npm packages instead
of a CDN. No stock footage or licensed recording is required.
