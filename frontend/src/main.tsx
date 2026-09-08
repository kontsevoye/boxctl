import { createRoot } from 'react-dom/client'
import { App } from './App'
import { ConfirmProvider } from './components/ConfirmDialog'
import { I18nProvider } from './i18n'
import { initializeTheme } from './theme'
import './styles.css'
import './styles/design-system.css'

const target = document.getElementById('app')
if (!target) throw new Error('Application root is missing')

initializeTheme()

createRoot(target).render(<I18nProvider><ConfirmProvider><App /></ConfirmProvider></I18nProvider>)
