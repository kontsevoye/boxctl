import { useCallback, useEffect, useRef, useState } from 'react'
import { APIError, request } from './api'
import { useAppRefreshSignal } from './app-events'

export interface QueryResult<T> {
  data?: T
  loading: boolean
  error?: APIError
  reload: () => void
  cancel: () => void
}

export function useQuery<T>(path: string, enabled = true): QueryResult<T> {
  const [data, setData] = useState<T>()
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState<APIError>()
  const [revision, setRevision] = useState(0)
  const activeRequest = useRef<AbortController | undefined>(undefined)
  const appRevision = useAppRefreshSignal()
  const reload = useCallback(() => setRevision((value) => value + 1), [])
  const cancel = useCallback(() => {
    activeRequest.current?.abort()
    activeRequest.current = undefined
    setLoading(false)
  }, [])

  useEffect(() => {
    if (!enabled) {
      setData(undefined)
      setLoading(false)
      setError(undefined)
      return
    }
    const controller = new AbortController()
    activeRequest.current = controller
    setLoading(true)
    setError(undefined)
    request<T>(path, { signal: controller.signal })
      .then(setData)
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
        if (activeRequest.current === controller) activeRequest.current = undefined
      })
    return () => {
      controller.abort()
      if (activeRequest.current === controller) activeRequest.current = undefined
    }
  }, [appRevision, enabled, path, revision])

  return { data, loading, error, reload, cancel }
}
