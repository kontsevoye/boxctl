import { readSetting, writeSetting } from './storage'

export type Theme = 'system' | 'dark' | 'light'

export function applyTheme(value: string): Theme {
  const theme: Theme = value === 'light' || value === 'dark' ? value : 'system'
  writeSetting('theme', theme)
  const roots = [document.documentElement, document.getElementById('app')].filter((root): root is HTMLElement => root !== null)
  for (const root of roots) {
    if (theme === 'system') delete root.dataset.theme
    else root.dataset.theme = theme
  }
  return theme
}

export function initializeTheme(): Theme {
  return applyTheme(readSetting('theme') ?? 'system')
}
