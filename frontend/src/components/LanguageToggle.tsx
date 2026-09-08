import { useI18n } from '../i18n'
import '../styles/language-toggle.css'

const languageNames = { ru: 'russianLanguage', en: 'englishLanguage' }

export function LanguageToggle() {
  const { locale, setLocale, t } = useI18n()
  const next = locale === 'ru' ? 'en' : 'ru'
  const label = `${t('language')}: ${t(languageNames[locale])}. ${t('switchTheme')}: ${t(languageNames[next])}`

  return <button
    type="button"
    className="sidebar-theme-toggle sidebar-language-toggle"
    aria-label={label}
    title={label}
    onClick={() => setLocale(next)}
  ><span className={`language-flag language-flag-${locale}`} aria-hidden="true" /></button>
}
