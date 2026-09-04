import { describe, expect, it, vi } from 'vitest'
import { copyRawConfig, normalizeRawConfigContent, rawConfigDocumentMatchesDraft, rawConfigFormatLabel, reconcileRawConfigAfterSave, shouldApplyRawConfigReload, shouldRecoverRawConfigSave } from './RawConfigPage'

describe('raw configuration editor state', () => {
  it('accepts the initial document and clean background reloads', () => {
    expect(shouldApplyRawConfigReload({ content: '', savedContent: '', revision: '' })).toBe(true)
    expect(shouldApplyRawConfigReload({ content: 'mode: rule\n', savedContent: 'mode: rule\n', revision: 'r1' })).toBe(true)
  })

  it('preserves dirty edits during a background reload', () => {
    expect(shouldApplyRawConfigReload({ content: 'mode: direct\n', savedContent: 'mode: rule\n', revision: 'r1' })).toBe(false)
  })

  it('normalizes the saved editor content exactly once', () => {
    expect(normalizeRawConfigContent('mode: rule')).toBe('mode: rule\n')
    expect(normalizeRawConfigContent('mode: rule\n')).toBe('mode: rule\n')
    expect(normalizeRawConfigContent('mode: rule\r\n')).toBe('mode: rule\n')
    expect(normalizeRawConfigContent('mode: rule\n\n')).toBe('mode: rule\n')
    expect(normalizeRawConfigContent('mode: rule\r')).toBe('mode: rule\n')
  })

  it('recognizes a save that reached disk before apply failed', () => {
    expect(rawConfigDocumentMatchesDraft({ content: 'mode: direct\n', revision: 'r2' }, 'mode: direct\r\n')).toBe(true)
    expect(rawConfigDocumentMatchesDraft({ content: 'mode: rule\n', revision: 'r1' }, 'mode: direct\n')).toBe(false)
  })

  it('preserves edits made while a save request is in flight', () => {
    expect(reconcileRawConfigAfterSave('mode: direct', 'mode: direct', 'mode: direct\n')).toBe('mode: direct\n')
    expect(reconcileRawConfigAfterSave('mode: global\n', 'mode: direct', 'mode: direct\n')).toBe('mode: global\n')
  })

  it('reconciles ambiguous transport failures as well as server apply failures', () => {
    expect(shouldRecoverRawConfigSave(0)).toBe(true)
    expect(shouldRecoverRawConfigSave(500)).toBe(true)
    expect(shouldRecoverRawConfigSave(409)).toBe(false)
  })

  it('falls back to YAML when older responses omit the format', () => {
    expect(rawConfigFormatLabel()).toBe('YAML')
    expect(rawConfigFormatLabel(' yaml ')).toBe('YAML')
  })

  it('surfaces unavailable and rejected clipboard writes', async () => {
    await expect(copyRawConfig('secret')).rejects.toThrow('Clipboard API is unavailable')
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    await expect(copyRawConfig('secret', { writeText })).rejects.toThrow('denied')
    expect(writeText).toHaveBeenCalledWith('secret')
  })
})
