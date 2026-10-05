import { RefreshCw } from 'lucide-react'
import { Empty, ErrorPanel, formatDate, Loading } from './Common'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'

export interface ConvertedRule {
  id: string
  name: string
  target: string
  format: string
  behavior?: string
  count: number
  checkedAt: string
  convertedAt: string
  lastError?: string
}

export function ConvertedRulesPanel() {
  const { t, locale } = useI18n()
  const query = useQuery<ConvertedRule[]>('/converted-rules')
  return <section>
    <p className="muted">{t('convertedRulesHint')}</p>
    <button className="du-btn du-btn-outline du-btn-sm" onClick={query.reload}><RefreshCw size={16} aria-hidden="true" /> {t('convertedRulesInspect')}</button>
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {query.data?.length === 0 && <Empty>{t('convertedRulesEmpty')}</Empty>}
    {!!query.data?.length && <div className="table-wrap"><table className="du-table du-table-sm">
      <thead><tr><th>{t('convertedRulesName')}</th><th>{t('convertedRulesFormat')}</th><th>{t('convertedRulesChecked')}</th><th>{t('convertedRulesBuilt')}</th><th>{t('status')}</th></tr></thead>
      <tbody>{query.data.map((rule) => <tr key={rule.id}>
        <td>{rule.name || rule.id.slice(0, 12)}</td>
        <td>{rule.format === 'binary' ? 'SRS' : rule.format.toUpperCase()}{rule.behavior ? ` · ${rule.behavior}` : ''}</td>
        <td>{formatDate(rule.checkedAt, locale)}</td>
        <td>{formatDate(rule.convertedAt, locale)}</td>
        <td>{rule.lastError ? <><strong>{t('convertedRulesError')}</strong><p>{rule.lastError}</p></> : t('convertedRulesReady')}</td>
      </tr>)}</tbody>
    </table></div>}
  </section>
}
