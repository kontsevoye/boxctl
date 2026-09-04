import type { Capabilities } from './types'

export const minimalCapabilities: Capabilities = {
  coreName: 'unavailable',
  pages: {},
  actions: {},
  features: {},
}

const alwaysAvailable = new Set(['status', 'profiles', 'settings', 'systemLogs'])

export function canShowPage(capabilities: Capabilities, page: string): boolean {
  if (Object.hasOwn(capabilities.pages, page)) return capabilities.pages[page] === true
  return alwaysAvailable.has(page)
}

export function canPerform(capabilities: Capabilities, action: string): boolean {
  return capabilities.actions[action] === true
}
