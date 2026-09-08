/* One paused, seekable timeline. Hyperframes owns the clock, including audio. */
const tl = gsap.timeline({ paused: true });
const sceneTimes = [
  ["intro", 0, 3],
  ["engines", 3, 7.5],
  ["routing", 7.5, 12],
  ["visibility", 12, 16.5],
  ["confidence", 16.5, 22.5],
  ["anywhere", 22.5, 27],
  ["outro", 27, 30],
];

for (const [id, start, end] of sceneTimes) {
  const selector = `#${id}`;
  tl.set(selector, { autoAlpha: 1 }, start);
  const reveals = document.querySelectorAll(`${selector} .reveal`);
  if (reveals.length)
    tl.fromTo(
      reveals,
      { opacity: 0, y: 26 },
      {
        opacity: 1,
        y: 0,
        duration: 0.66,
        stagger: 0.0825,
        ease: "power3.out",
        immediateRender: false,
      },
      start + 0.12,
    );
  if (id !== "outro")
    tl.to(
      selector,
      { autoAlpha: 0, duration: 0.255, ease: "power1.in" },
      end - 0.195,
    );
}
tl.fromTo(
  ".line",
  { y: 90, opacity: 0 },
  { y: 0, opacity: 1, stagger: 0.195, duration: 0.975, ease: "power4.out" },
  0.09,
);
tl.fromTo(
  ".network-art",
  { scale: 0.65, rotation: -12, opacity: 0 },
  { scale: 1, rotation: 0, opacity: 1, duration: 1.575, ease: "power3.out" },
  0,
);
tl.fromTo(
  ".cube-lines",
  { strokeDasharray: 2200, strokeDashoffset: 2200 },
  { strokeDashoffset: 0, duration: 1.95, ease: "power2.out" },
  0,
);
tl.fromTo(
  ".nodes circle",
  { opacity: 0.2, scale: 0.2, transformOrigin: "center" },
  { opacity: 1, scale: 1, duration: 0.75, stagger: 0.135, ease: "back.out(2)" },
  0.525,
);
tl.fromTo(
  ".network-tag",
  { opacity: 0, y: 16 },
  { opacity: 1, y: 0, duration: 0.525, stagger: 0.135 },
  0.9,
);
tl.to(
  ".orbit-lines",
  { rotation: 10, svgOrigin: "450 450", duration: 3.15, ease: "none" },
  0,
);

function screenEnter(selector, start, end, tilt = -1.5, dx = 90) {
  tl.fromTo(
    selector,
    { x: dx, y: 58, rotation: tilt - 2, scale: 0.94, opacity: 0 },
    {
      x: 0,
      y: 0,
      rotation: tilt,
      scale: 1,
      opacity: 1,
      duration: 1.02,
      ease: "power3.out",
      immediateRender: false,
    },
    start,
  );
  tl.to(
    selector,
    {
      y: -20,
      rotation: tilt + 0.7,
      scale: 1.024,
      duration: end - start - 0.975,
      ease: "none",
    },
    start + 0.975,
  );
}
function insetEnter(selector, start, end) {
  tl.fromTo(
    selector,
    { y: 65, x: 25, opacity: 0, scale: 0.92 },
    {
      y: 0,
      x: 0,
      opacity: 1,
      scale: 1,
      duration: 0.825,
      ease: "power3.out",
      immediateRender: false,
    },
    start,
  );
  tl.to(
    selector,
    { y: -12, duration: Math.max(0.15, end - start - 0.825), ease: "none" },
    start + 0.825,
  );
}
screenEnter("#engine-screen", 3.045, 7.5, -1.5);
insetEnter("#editor-inset", 4.05, 7.5);
tl.to("#singbox-shot", { opacity: 1, duration: 0.36 }, 5.4);
tl.to("#json-editor-shot", { opacity: 1, duration: 0.36 }, 5.4);
screenEnter("#proxy-screen", 7.53, 12, 1.2);
insetEnter("#routing-inset", 8.625, 12);
tl.to("#rules-shot", { opacity: 1, duration: 0.33 }, 10.05);
screenEnter("#monitor-screen", 12.06, 16.5, -0.8, 140);
tl.to("#connections-shot", { opacity: 1, duration: 0.345 }, 13.875);
insetEnter("#logs-inset", 14.625, 16.5);
screenEnter("#update-screen", 16.56, 22.5, -1.5);
insetEnter("#protection-inset", 17.625, 22.5);
tl.to("#backups-shot", { opacity: 1, duration: 0.36 }, 19.8);
screenEnter("#desktop-screen", 22.53, 27, -2);
screenEnter("#phone", 22.83, 27, 3, 160);
tl.fromTo(
  ".outro-lockup",
  { scale: 0.83, y: 35, opacity: 0 },
  { scale: 1, y: 0, opacity: 1, duration: 0.9, ease: "power3.out" },
  27,
);
tl.fromTo(
  ".outro-title",
  { y: 30, opacity: 0 },
  { y: 0, opacity: 1, duration: 0.675, ease: "power3.out" },
  27.225,
);
tl.fromTo(
  ".outro-link",
  { y: 25, opacity: 0, scale: 0.97 },
  { y: 0, opacity: 1, scale: 1, duration: 0.675, ease: "power3.out" },
  27.45,
);
tl.fromTo(
  ".outro-footer",
  { opacity: 0 },
  { opacity: 1, duration: 0.525 },
  27.825,
);
tl.fromTo(
  ".outro-orbit",
  { scale: 0.8, opacity: 0 },
  { scale: 1.06, opacity: 1, stagger: 0.225, duration: 2.25, ease: "power1.out" },
  27,
);
tl.to(".identity", { opacity: 0, duration: 0.3 }, 27);
for (const t of [3, 7.5, 12, 16.5, 22.5, 27]) {
  tl.fromTo(
    ".transition-slice",
    { x: 0, skewX: -18, opacity: 0.75 },
    {
      x: 2300,
      opacity: 0,
      duration: 0.45,
      ease: "power2.inOut",
      immediateRender: false,
    },
    t - 0.18,
  );
}
tl.fromTo(
  "#progress-fill",
  { scaleX: 0 },
  { scaleX: 1, duration: 30, ease: "none" },
  0,
);
window.__timelines = { boxctl: tl };
window.BOXCTL_SCENES = sceneTimes.map(([id, start, end]) => ({
  id,
  start,
  end,
}));
