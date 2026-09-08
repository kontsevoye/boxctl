# Original demo soundtrack

`boxctl-promo.wav` is an original instrumental score generated for this repository
by [`../../scripts/audio.py`](../../scripts/audio.py). Every oscillator,
percussion hit, noise swell, and room reflection is synthesized procedurally.
It contains no downloaded samples, recordings, or third-party music. The source
and resulting audio are provided under the repository's license.

The score lasts exactly 30 seconds: 10 bars at 80 BPM, in D minor. Its five
six-second musical phrases support the continuous montage. The final phrase resolves
and fades, and brief air swells accent transitions at 6, 12, 18, and 24 seconds.

Regenerate from the repository root with Python 3 and FFmpeg installed:

```sh
python3 docs/demo/scripts/audio.py
```

The script writes stereo 48 kHz, 16-bit PCM WAV and a JSON measurement report.
It uses a fixed seed and measured two-pass FFmpeg loudness normalization, targeting
−16 LUFS integrated and at most −1.5 dBTP, then sets the final tempo with
pitch-preserving time stretching. The synthesis runs at its fixed internal tempo
to retain the approved sound's pitch and transients. With the same Python and
FFmpeg versions, repeated runs produce identical bytes. Different FFmpeg builds
may vary slightly in their normalization and time stretching; the musical events
and seeded synthesis remain fixed.

For reference, use the rendered JSON report for exact loudness and SHA-256.
Audio is optional when watching the demo; all feature explanations are visual.
