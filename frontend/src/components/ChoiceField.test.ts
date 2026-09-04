import { describe, expect, it } from 'vitest'
import { fuzzyMatch } from './ChoiceField'

describe('fuzzyMatch', () => {
  it('matches substrings and ordered fuzzy characters without requiring a regex', () => {
    expect(fuzzyMatch('mixed capture', 'mix')).toBe(true)
    expect(fuzzyMatch('TProxy', 'tpy')).toBe(true)
    expect(fuzzyMatch('redirect', 'rdt')).toBe(true)
    expect(fuzzyMatch('redirect', 'tun')).toBe(false)
  })
})
