import { useEffect, useState } from 'react'
import { useApp } from '../app-context'
import { canShowPage } from '../capabilities'
import { PageHeader } from '../components/Common'
import { useI18n } from '../i18n'
import { ProfilesPage } from './ProfilesPage'
import { ProxySubscriptionsPage } from './ProxySubscriptionsPage'
import { RawConfigPage } from './RawConfigPage'
import './ConfigurationPage.css'

export type ConfigurationTab = 'profiles' | 'subscriptions' | 'editor'

export function configurationTabs(rawConfigAvailable: boolean): ConfigurationTab[] {
  return rawConfigAvailable ? ['profiles', 'subscriptions', 'editor'] : ['profiles', 'subscriptions']
}

export function activateConfigurationTab(mounted: ConfigurationTab[], tab: ConfigurationTab): ConfigurationTab[] {
  return mounted.includes(tab) ? mounted : [...mounted, tab]
}

export function ConfigurationPage({ initialTab = 'editor' }: { initialTab?: ConfigurationTab }) {
  const { capabilities } = useApp()
  const { t } = useI18n()
  const rawConfigAvailable = canShowPage(capabilities, 'rawConfig')
  const tabs = configurationTabs(rawConfigAvailable)
  const [tab, setTab] = useState<ConfigurationTab>(() => tabs.includes(initialTab) ? initialTab : 'profiles')
  const [mountedTabs, setMountedTabs] = useState<ConfigurationTab[]>(() => [tabs.includes(initialTab) ? initialTab : 'profiles'])

  const selectTab = (next: ConfigurationTab) => {
    setMountedTabs((current) => activateConfigurationTab(current, next))
    setTab(next)
  }

  useEffect(() => {
    if (tab === 'editor' && !rawConfigAvailable) {
      setMountedTabs((current) => activateConfigurationTab(current, 'profiles'))
      setTab('profiles')
    }
  }, [rawConfigAvailable, tab])

  return <>
    <PageHeader title={t('configuration')} description={t('configurationHint')} />
    <div className="du-tabs du-tabs-box section-tabs configuration-tabs" role="tablist" aria-label={t('configuration')}>
      <button className={`du-tab ${tab === 'profiles' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'profiles'} aria-controls="configuration-profiles" onClick={() => selectTab('profiles')}>{t('profiles')}</button>
      <button className={`du-tab ${tab === 'subscriptions' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'subscriptions'} aria-controls="configuration-subscriptions" onClick={() => selectTab('subscriptions')}>{t('proxySubscriptions')}</button>
      {tabs.includes('editor') && <button className={`du-tab ${tab === 'editor' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'editor'} aria-controls="configuration-editor" onClick={() => selectTab('editor')}>{t('yamlEditor')}</button>}
    </div>
    {mountedTabs.includes('subscriptions') && <div id="configuration-subscriptions" role="tabpanel" hidden={tab !== 'subscriptions'} aria-hidden={tab !== 'subscriptions'}><ProxySubscriptionsPage /></div>}
    {mountedTabs.includes('profiles') && <div id="configuration-profiles" role="tabpanel" hidden={tab !== 'profiles'} aria-hidden={tab !== 'profiles'}>
      <ProfilesPage embedded />
    </div>}
    {tabs.includes('editor') && mountedTabs.includes('editor') && <div id="configuration-editor" role="tabpanel" hidden={tab !== 'editor'} aria-hidden={tab !== 'editor'}>
      <RawConfigPage embedded />
    </div>}
  </>
}
