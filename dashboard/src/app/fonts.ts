/*! Hanken Grotesk, copyright The Hanken Grotesk Project Authors; Geist Mono, copyright 2024 The Geist Project Authors. SIL Open Font License 1.1, notices in src/fonts/. */
import hanken from '@fontsource-variable/hanken-grotesk/files/hanken-grotesk-latin-wght-normal.woff2?url'
import mono from '@fontsource-variable/geist-mono/files/geist-mono-latin-wght-normal.woff2?url'

// The gateway serves the dashboard under a content policy whose font-src is
// the dashboard's own origin, so the faces are two files of the build, kept
// by the browser like its other assets. They are registered with the CSS Font
// Loading API rather than @font-face rules, because the page renders only
// after they have loaded: text never changes face, and layout never shifts,
// once it has appeared.

export async function loadFonts(): Promise<void> {
  const faces = [
    new FontFace('Hanken Grotesk', `url("${hanken}") format("woff2")`, { weight: '100 900' }),
    new FontFace('Geist Mono', `url("${mono}") format("woff2")`, { weight: '100 900' }),
  ]
  await Promise.all(faces.map((face) => face.load()))
  for (const face of faces) document.fonts.add(face)
}
