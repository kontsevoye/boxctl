import { describe, expect, it } from 'vitest'
import { appendRulePrefix, fakeIPMutationResultKey } from './RuleListsPage'

describe('fake-IP whitelist mutation status', () => {
  it('reports whether a saved generation is live, pending restart, or only persisted', () => {
    expect(fakeIPMutationResultKey({ applied: true, restartRequired: false })).toBe('fakeIPApplied')
    expect(fakeIPMutationResultKey({ applied: false, restartRequired: true })).toBe('fakeIPRestartRequired')
    expect(fakeIPMutationResultKey({ applied: false, restartRequired: false })).toBe('fakeIPSavedNotApplied')
  })
})

describe('rule list prefix toolbar', () => {
  it('starts a new classical-rule line without corrupting existing content', () => {
    expect(appendRulePrefix('', 'IP-CIDR')).toBe('IP-CIDR,')
    expect(appendRulePrefix('DOMAIN-SUFFIX,example.test', 'GEOIP')).toBe('DOMAIN-SUFFIX,example.test\nGEOIP,')
    expect(appendRulePrefix('one\n', 'GEOSITE')).toBe('one\nGEOSITE,')
  })
})
