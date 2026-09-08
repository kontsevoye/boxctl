import { Moon, Sun, SunMoon } from 'lucide-react'
import { useState } from 'react'
import { useI18n } from '../i18n'
import { applyTheme, currentTheme, nextTheme, useSystemTheme } from '../theme'

const themeNames = { system: 'themeSystem', dark: 'themeDark', light: 'themeLight' }

export function ThemeToggle() {
  const { t } = useI18n()
  const [theme, setTheme] = useState(currentTheme)
  const systemTheme = useSystemTheme()
  const next = nextTheme(theme, systemTheme)
  const Icon = theme === 'system' ? SunMoon : theme === 'dark' ? Moon : Sun
  const label = `${t('theme')}: ${t(themeNames[theme])}. ${t('switchTheme')}: ${t(themeNames[next])}`
  return <button type="button" className="sidebar-theme-toggle" aria-label={label} title={label} onClick={() => setTheme(applyTheme(next))}>
    <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
  </button>
}
