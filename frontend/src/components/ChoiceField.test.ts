import { describe, expect, it } from 'vitest'
import { choiceIndexForKey, fuzzyMatch } from './ChoiceField'

describe('choiceIndexForKey', () => {
  it('moves in both directions and wraps at either end of a radio group or list', () => {
    expect(choiceIndexForKey('ArrowRight', 1, 4)).toBe(2)
    expect(choiceIndexForKey('ArrowDown', 3, 4)).toBe(0)
    expect(choiceIndexForKey('ArrowLeft', 0, 4)).toBe(3)
    expect(choiceIndexForKey('ArrowUp', 2, 4)).toBe(1)
  })

  it('supports first and last options without consuming text editing keys', () => {
    expect(choiceIndexForKey('Home', 3, 4)).toBe(0)
    expect(choiceIndexForKey('End', 0, 4)).toBe(3)
    expect(choiceIndexForKey('a', 0, 4)).toBeNull()
    expect(choiceIndexForKey('Tab', 0, 4)).toBeNull()
  })

  it('handles empty search results and a single option', () => {
    expect(choiceIndexForKey('End', 0, 0)).toBeNull()
    expect(choiceIndexForKey('ArrowDown', 0, 0)).toBeNull()
    expect(choiceIndexForKey('ArrowUp', 0, 1)).toBe(0)
  })
})

describe('fuzzyMatch', () => {
  it('matches substrings and ordered fuzzy characters without requiring a regex', () => {
    expect(fuzzyMatch('mixed capture', 'mix')).toBe(true)
    expect(fuzzyMatch('TProxy', 'tpy')).toBe(true)
    expect(fuzzyMatch('redirect', 'rdt')).toBe(true)
    expect(fuzzyMatch('redirect', 'tun')).toBe(false)
  })
})
