#!/usr/bin/env python3
"""Render the original, deterministic thirty-second boxctl promo score.

Python's standard library synthesizes every note and effect. FFmpeg then applies
measured, two-pass loudness normalization and sets the final tempo without changing
pitch; no samples or licensed music are used.
"""

from __future__ import annotations

import argparse
from array import array
import hashlib
import json
import math
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import wave


RATE = 48_000
SCORE_BARS = 10
BEATS_PER_BAR = 4
SCORE_BPM = 120
OUTPUT_BPM = 80
SCORE_SECONDS = SCORE_BARS * BEATS_PER_BAR * 60 / SCORE_BPM
OUTPUT_SECONDS = SCORE_BARS * BEATS_PER_BAR * 60 / OUTPUT_BPM
SAMPLES = round(RATE * SCORE_SECONDS)
TAU = math.tau
SEED = 20260908
ASSETS = Path(__file__).resolve().parents[1] / "assets" / "audio"


def frequency(midi: float) -> float:
    return 440 * 2 ** ((midi - 69) / 12)


def envelope(t: float, duration: float, attack: float, release: float) -> float:
    return min(1.0, t / attack) * min(1.0, max(0.0, duration - t) / release)


def synthesize(path: Path) -> None:
    """Render float accumulators to 24-bit PCM with a fixed random seed."""
    rng = random.Random(SEED)
    left, right = array("f", [0]) * SAMPLES, array("f", [0]) * SAMPLES

    def mix(start: float, duration: float, voice, gain: float, pan: float = 0) -> None:
        first = round(start * RATE)
        length = min(round(duration * RATE), SAMPLES - first)
        l_gain = gain * math.sqrt((1 - pan) / 2)
        r_gain = gain * math.sqrt((1 + pan) / 2)
        for i in range(max(0, length)):
            sample = voice(i / RATE)
            left[first + i] += sample * l_gain
            right[first + i] += sample * r_gain

    # Dm9 -> Bbmaj9 -> Fmaj9/C -> Csus2(add6) -> Dm(add9).
    # Close, warm upper voices and stereo micro-detuning create a quiet halo.
    chords = [
        (0, [50, 57, 60, 64, 65]),
        (4, [46, 53, 57, 60, 65]),
        (8, [48, 53, 57, 64, 67]),
        (12, [48, 55, 57, 62, 64]),
        (16, [50, 57, 62, 64, 65]),
    ]
    for chord_start, notes in chords:
        duration = min(5.0, SCORE_SECONDS - chord_start)
        for index, note in enumerate(notes):
            hz = frequency(note)
            pan = (index - 2) * 0.32

            def pad(t, hz=hz, duration=duration, phase=index * 0.71):
                cycle = TAU * hz * t
                body = (math.sin(cycle + phase)
                        + 0.27 * math.sin(cycle * 2.002 + phase)
                        + 0.15 * math.sin(cycle * 0.998 - phase))
                slow = 0.91 + 0.09 * math.sin(TAU * 0.32 * t + phase)
                return body * envelope(t, duration, 0.32, 1.1) * slow

            mix(chord_start, duration, pad, 0.018, pan)

    # A rounded, understated synth bass: eight bars of movement, a held ending.
    roots = [38, 34, 36, 36, 38]
    for bar in range(SCORE_BARS):
        start = bar * 2.0
        root = roots[bar // 2]
        for offset, note, length, level in [
            (0, root, 0.42, 1.0), (0.75, root, 0.20, 0.71),
            (1.0, root + 12, 0.28, 0.61), (1.5, root + 7, 0.30, 0.72),
        ]:
            if bar == 9 and offset > 0:
                continue
            if bar == 9:
                length = 1.75
            hz = frequency(note)

            def bass(t, hz=hz, length=length):
                phase = TAU * hz * t
                return (math.sin(phase) + 0.2 * math.sin(phase * 2)
                        + 0.07 * math.sin(phase * 3)) * envelope(t, length, 0.008, 0.12)

            mix(start + offset, length, bass, 0.106 * level)

    # Tight kick, soft rim/clap, and alternating closed hats leave room for UI.
    for beat in range(38):
        at = beat * 0.5
        if beat in (15, 31):
            continue

        def kick(t):
            # Integral of an exponential pitch drop: clean transient, no click.
            phase = TAU * (47 * t + 75 * 0.022 * (1 - math.exp(-t / 0.022)))
            return math.sin(phase) * math.exp(-t * 20) * min(1, t / 0.001)

        mix(at, 0.28, kick, 0.142 if beat % 4 == 0 else 0.115)
        if beat % 2:
            noise = [rng.uniform(-1, 1) for _ in range(round(0.14 * RATE) + 1)]

            def rim(t, noise=noise):
                i = min(len(noise) - 1, int(t * RATE))
                highpass = noise[i] - (noise[i - 1] if i else 0)
                snap = math.exp(-t * 57)
                tone = math.sin(TAU * 860 * t) * math.exp(-t * 130)
                return (highpass * 0.38 + tone * 0.4) * snap * min(1, t / 0.0005)

            mix(at, 0.14, rim, 0.056, 0.07)
    for step in range(75):
        at = step * 0.25
        if step % 16 in (14, 15):
            continue
        noise = [rng.uniform(-1, 1) for _ in range(3361)]

        def hat(t, noise=noise):
            i = min(len(noise) - 1, int(t * RATE))
            highpass = noise[i] - (noise[i - 1] if i else 0)
            return highpass * math.exp(-t * 93) * min(1, t / 0.0007)

        mix(at, 0.07, hat, 0.013 if step % 2 else 0.021, -0.3 if step % 2 else 0.25)

    # Sparse glassy notes with two dark, wide echoes. The phrase opens in bar five.
    phrases = [
        [(0.25, 74), (1.00, 76), (1.75, 69), (2.5, 72), (3.25, 76)],
        [(0.25, 77), (1.00, 76), (1.75, 72), (2.75, 69), (3.25, 72)],
        [(0.25, 76), (0.75, 79), (1.5, 77), (2.25, 76), (3.0, 72)],
        [(0.25, 74), (1.00, 76), (1.75, 79), (2.5, 76), (3.25, 74)],
        [(0.0, 74), (0.75, 76), (1.5, 77), (2.0, 74)],
    ]
    for section, phrase in enumerate(phrases):
        for index, (offset, note) in enumerate(phrase):
            hz = frequency(note)
            duration = 1.65

            def pluck(t, hz=hz):
                return (math.sin(TAU * hz * t) * math.exp(-t * 4.7)
                        + 0.35 * math.sin(TAU * hz * 2 * t) * math.exp(-t * 11)
                        + 0.08 * math.sin(TAU * hz * 3 * t) * math.exp(-t * 19)
                        ) * envelope(t, duration, 0.003, 0.3)

            pan = -0.25 if index % 2 else 0.25
            at = section * 4 + offset
            mix(at, duration, pluck, 0.043, pan)
            mix(at + 0.375, duration, pluck, 0.010, -pan * 2.5)
            mix(at + 0.750, duration, pluck, 0.0045, pan * 2.5)

    # Small filtered air swells draw attention to chapter changes, not the sound.
    for transition in (4, 8, 12, 16):
        duration = 0.6
        noise = [rng.uniform(-1, 1) for _ in range(round(duration * RATE) + 1)]
        filtered = []
        previous = 0.0
        for i, sample in enumerate(noise):
            progress = i / len(noise)
            previous += (0.04 + 0.3 * progress) * (sample - previous)
            filtered.append(previous)

        def air(t, filtered=filtered):
            progress = t / duration
            i = min(len(filtered) - 1, int(t * RATE))
            return filtered[i] * progress ** 1.8 * min(1, (duration - t) / 0.035)

        mix(transition - duration, duration, air, 0.065, -0.18)

        def shimmer(t):
            return (math.sin(TAU * frequency(86) * t)
                    + 0.35 * math.sin(TAU * frequency(93) * t)) * math.exp(-t * 8) * min(1, t / 0.003)

        mix(transition, 0.7, shimmer, 0.014, 0.35)

    # Short stereo room, without external effects, preserves transients.
    for delay, feedback in ((0.047, 0.055), (0.083, 0.035)):
        offset = round(delay * RATE)
        for i in range(SAMPLES - 1, offset - 1, -1):
            left[i] += right[i - offset] * feedback
            right[i] += left[i - offset] * feedback

    maximum = max(max(map(abs, left)), max(map(abs, right)))
    scale = 0.8 / max(maximum, 0.00001)
    pcm = bytearray(SAMPLES * 6)
    for i in range(SAMPLES):
        t = i / RATE
        master = min(1.0, t / 0.018) * min(1.0, max(0, (SCORE_SECONDS - t) / 1.15))
        for channel, samples in enumerate((left, right)):
            value = max(-8_388_608, min(8_388_607, round(samples[i] * scale * master * 8_388_607)))
            position = i * 6 + channel * 3
            pcm[position:position + 3] = value.to_bytes(3, "little", signed=True)
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(2)
        wav.setsampwidth(3)
        wav.setframerate(RATE)
        wav.writeframes(pcm)


def loudness(ffmpeg: str, path: Path) -> dict:
    command = [ffmpeg, "-hide_banner", "-nostdin", "-i", str(path), "-af",
               "loudnorm=I=-16:TP=-1.5:LRA=9:print_format=json", "-f", "null", "-"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    # Some FFmpeg builds print the final progress line after the JSON block.
    return json.JSONDecoder().raw_decode(result.stderr[result.stderr.rfind("{"):])[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ASSETS / "boxctl-promo.wav")
    args = parser.parse_args()
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        parser.error("ffmpeg is required for two-pass loudness normalization")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="boxctl-score-") as temp:
        raw = Path(temp) / "mix.wav"
        normalized = Path(temp) / "normalized.wav"
        synthesize(raw)
        measurement = loudness(ffmpeg, raw)
        settings = (
            "loudnorm=I=-16:TP=-1.5:LRA=9:linear=true:"
            f"measured_I={measurement['input_i']}:"
            f"measured_TP={measurement['input_tp']}:"
            f"measured_LRA={measurement['input_lra']}:"
            f"measured_thresh={measurement['input_thresh']}:"
            f"offset={measurement['target_offset']}"
        )
        subprocess.run([
            ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
            "-i", str(raw), "-af", settings, "-ar", str(RATE), "-ac", "2",
            "-c:a", "pcm_s24le", "-fflags", "+bitexact", "-flags:a", "+bitexact",
            "-map_metadata", "-1", str(normalized),
        ], check=True)
        # Set the delivery tempo after normalization to preserve the approved
        # score's pitch, transients, and ending. Padding fixes sample-exact length.
        tempo_filter = (
            f"atempo={OUTPUT_BPM / SCORE_BPM},apad,"
            f"atrim=duration={OUTPUT_SECONDS:g},asetpts=PTS-STARTPTS"
        )
        subprocess.run([
            ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
            "-i", str(normalized), "-af", tempo_filter,
            "-ac", "2", "-ar", str(RATE), "-c:a", "pcm_s16le", str(args.output),
        ], check=True)
    with wave.open(str(args.output), "rb") as wav:
        if (wav.getnframes(), wav.getframerate(), wav.getnchannels(), wav.getsampwidth()) != (
            round(OUTPUT_SECONDS * RATE), RATE, 2, 2
        ):
            raise SystemExit("Rendered soundtrack has an unexpected duration or PCM format")
    final = loudness(ffmpeg, args.output)
    report = {
        "duration_seconds": OUTPUT_SECONDS,
        "sample_rate": RATE,
        "channels": 2,
        "bit_depth": 16,
        "bpm": OUTPUT_BPM,
        "seed": SEED,
        "integrated_lufs": float(final["input_i"]),
        "true_peak_dbtp": float(final["input_tp"]),
        "loudness_range_lu": float(final["input_lra"]),
        "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
    }
    args.output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if abs(report["integrated_lufs"] + 16) > 0.5 or report["true_peak_dbtp"] > -1.45:
        raise SystemExit("Rendered loudness is outside the expected range")


if __name__ == "__main__":
    main()
