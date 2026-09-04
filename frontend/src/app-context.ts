import { createContext } from 'react'
import { useContext } from 'react'
import { minimalCapabilities } from './capabilities'
import type { Capabilities, EngineInfo, Session } from './types'

export interface AppState {
  session: Session
  capabilities: Capabilities
  engines?: EngineInfo[]
  refreshCapabilities: () => Promise<void>
}

export const AppContext = createContext<AppState | undefined>(undefined)

export function useApp(): AppState {
  const value = useContext(AppContext)
  if (!value) throw new Error('AppContext is not available')
  return value
}

export { minimalCapabilities }
