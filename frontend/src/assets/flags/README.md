# Language flag images

`apple-ru.png` and `apple-gb.png` reproduce the Russian and United Kingdom flag glyphs from **Apple Color Emoji**, rendered locally on 2026-09-08 for the requested UI review.

- Source: `/System/Library/Fonts/Apple Color Emoji.ttc`, font version `21.4d3e1`, supplied with macOS.
- Rendering: AppKit `NSAttributedString` at 48 pt, centered on a transparent 60 × 60 px bitmap; PNG output.
- Files: Russian flag 2,715 bytes; United Kingdom flag 4,275 bytes; total 6,990 bytes.
- Delivery: CSS image URLs with Vite `?no-inline` produce separate hashed PNG files. No emoji library, emoji font, image URL, or embedded image payload is added to JavaScript.

The artwork belongs to Apple and is **not covered by this repository's MIT license**. No independent license to redistribute Apple's artwork is asserted here. Unicode code points and artwork rights are separate: see [Unicode's emoji image ownership notice](https://unicode.org/emoji/images.html) and [Apple's intellectual property guidance](https://www.apple.com/legal/intellectual-property/). Apple lists the supplied font in its [system font catalog](https://developer.apple.com/fonts/system-fonts/).
