import { useSyncExternalStore } from 'react'
import { readSetting, writeSetting } from './storage'

export type Theme = 'system' | 'dark' | 'light'
type ColorTheme = Exclude<Theme, 'system'>
const systemThemeQuery = '(prefers-color-scheme: light)'

export function currentTheme(): Theme {
  const stored = readSetting('theme')
  return stored === 'dark' || stored === 'light' ? stored : 'system'
}

export function nextTheme(theme: Theme, systemTheme: ColorTheme): Theme {
  if (theme === 'system') return systemTheme === 'dark' ? 'light' : 'dark'
  return theme === systemTheme ? 'system' : systemTheme
}

function readSystemTheme(): ColorTheme {
  return window.matchMedia(systemThemeQuery).matches ? 'light' : 'dark'
}

function subscribeSystemTheme(onChange: () => void): () => void {
  const query = window.matchMedia(systemThemeQuery)
  query.addEventListener('change', onChange)
  return () => query.removeEventListener('change', onChange)
}

export function useSystemTheme(): ColorTheme {
  return useSyncExternalStore(subscribeSystemTheme, readSystemTheme, () => 'dark')
}

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
  return applyTheme(currentTheme())
}
