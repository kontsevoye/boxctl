import { createRoot } from 'react-dom/client'
import { App } from './App'
import { I18nProvider } from './i18n'
import { initializeTheme } from './theme'
import './styles.css'

const target = document.getElementById('app')
if (!target) throw new Error('Application root is missing')

initializeTheme()

createRoot(target).render(<I18nProvider><App /></I18nProvider>)
