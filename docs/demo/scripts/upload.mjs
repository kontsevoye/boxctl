import { execFileSync } from 'node:child_process';
import { readFile, writeFile, stat, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Explicit publication step: upload the reviewed MP4, then update the local README.
// GitHub CLI supplies authentication; credentials never enter script output.
const root = fileURLToPath(new URL('..', import.meta.url));
const gh = (args, input) => execFileSync('gh', args, {
  cwd: root, input, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024,
  stdio: ['pipe', 'pipe', 'pipe'],
}).trim();
const file = 'boxctl-demo.mp4';
const bytes = (await stat(`${root}/${file}`)).size;
const sha256 = createHash('sha256').update(await readFile(`${root}/${file}`)).digest('hex');
const manifest = JSON.parse(await readFile(`${root}/render-manifest.json`, 'utf8'));
if (manifest.artifacts[file]?.sha256 !== sha256 || manifest.video.durationSeconds !== 30 || manifest.video.frames !== 1800)
  throw new Error('Run npm run build and review the resulting video before uploading.');
if (bytes > 10_000_000) throw new Error('The MP4 exceeds the 10 MB attachment budget.');
const readmePath = `${root}/../../README.md`;
const readme = await readFile(readmePath, 'utf8');
const marker = /<!-- boxctl-demo:player:start -->[\s\S]*?<!-- boxctl-demo:player:end -->/;
if (!marker.test(readme)) throw new Error('README video markers are missing.');
const repository = gh(['repo', 'view', '--json', 'nameWithOwner', '--jq', '.nameWithOwner']);
if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw new Error('Unexpected GitHub repository name.');
let previous;
try { previous = JSON.parse(await readFile(`${root}/github-upload.json`, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
let url;
if (previous?.sha256 === sha256 && previous?.repository === repository) {
  url = previous.url;
} else {
  const repo = JSON.parse(gh(['api', `repos/${repository}`]));
  if (!repo.permissions?.push || !Number.isSafeInteger(repo.id)) throw new Error('Push access to the repository is required for attachments.');
  const params = new URLSearchParams({ name: file, content_type: 'video/mp4', repository_id: String(repo.id) });
  // Same upload-only endpoint as github.com/cli/cli internal/attachments/client.go.
  // No issue, PR, comment or commit is created. Do not automatically retry uploads.
  url = gh(['api', `https://uploads.github.com/user-attachments/assets?${params}`,
    '--method', 'POST', '--input', `${root}/${file}`,
    '-H', 'Content-Type: application/octet-stream', '-H', 'Accept: application/vnd.github+json',
    '-H', `Content-Length: ${bytes}`, '--jq', '.url']);
}
if (!/^https:\/\/github\.com\/user-attachments\/assets\/[0-9a-f-]+$/i.test(url))
  throw new Error(`GitHub returned an unexpected attachment URL: ${url}`);
// Save the URL before editing Markdown, so reruns can reuse an already uploaded asset.
await writeFile(`${root}/github-upload.json`, `${JSON.stringify({ repository, url, file, bytes, sha256 }, null, 2)}\n`);
const player = `<!-- boxctl-demo:player:start -->\n\n${url}\n\n<!-- boxctl-demo:player:end -->`;
const updated = readme.replace(marker, player);
// Verify as a signed-out reader. Repository context is required: a standalone
// attachment URL may return 404 while the public README player works normally.
const rendered = await fetch('https://api.github.com/markdown', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Accept: 'application/vnd.github+json', 'User-Agent': 'boxctl-demo' },
  body: JSON.stringify({ text: updated, mode: 'gfm', context: repository }),
  signal: AbortSignal.timeout(30_000),
});
if (!rendered.ok) throw new Error(`Anonymous README rendering failed (${rendered.status}). The attachment URL is saved.`);
const html = await rendered.text();
await mkdir(`${root}/output`, { recursive: true });
await writeFile(`${root}/output/github-readme.html`, html);
const playerSource = html.match(/<video\b[^>]*\bsrc="([^"]+)"/)?.[1]?.replaceAll('&amp;', '&');
if (!playerSource) throw new Error('GitHub did not render a public inline video player. The uploaded URL is saved in github-upload.json.');
const playback = await fetch(playerSource, {
  headers: { Range: 'bytes=0-4095' }, signal: AbortSignal.timeout(30_000),
});
if (!playback.ok || !playback.headers.get('content-type')?.startsWith('video/mp4'))
  throw new Error(`Anonymous video playback failed (${playback.status}). The attachment URL is saved.`);
const downloaded = Buffer.from(await playback.arrayBuffer());
const original = await readFile(`${root}/${file}`);
if (downloaded.length < 4096 || !downloaded.subarray(0, 4096).equals(original.subarray(0, 4096)))
  throw new Error('Anonymous video playback returned unexpected content.');
await writeFile(readmePath, updated);
console.log(`GitHub video player verified without sign-in; local README updated: ${url}`);
