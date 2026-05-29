/**
 * useWebSocket — custom hook for WebSocket connection management.
 * Connects to /ws/scan/{scanId}, feeds all events into scanStore.
 * Auto-reconnects up to MAX_RETRIES times with exponential backoff.
 */

import { useEffect, useRef, useCallback } from 'react'
import { useScanStore } from '../store/scanStore'

const MAX_RETRIES = 5
const BASE_DELAY_MS = 1000
const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL

/**
 * Manage a WebSocket connection for live scan events.
 * @param {string} scanId - The scan ID to connect to
 * @returns {{ connect: Function, disconnect: Function }} Connection controls
 */
export function useWebSocket(scanId) {
  const handleEvent = useScanStore((state) => state.handleEvent)
  const setConnected = useScanStore((state) => state.setConnected)
  const setConnectionError = useScanStore((state) => state.setConnectionError)

  const wsRef = useRef(null)
  const retryCount = useRef(0)
  const retryTimeout = useRef(null)

  const disconnect = useCallback(() => {
    if (retryTimeout.current) {
      clearTimeout(retryTimeout.current)
      retryTimeout.current = null
    }
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setConnected(false)
  }, [setConnected])

  const connect = useCallback(() => {
    if (!scanId || !WS_BASE_URL) {
      setConnectionError('WebSocket base URL or scan ID is missing')
      return
    }

    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    const url = `${WS_BASE_URL}/ws/scan/${scanId}`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      setConnectionError(null)
      retryCount.current = 0
    }

    ws.onmessage = (messageEvent) => {
      try {
        const parsed = JSON.parse(messageEvent.data)
        handleEvent(parsed)
      } catch {
        setConnectionError('Failed to parse WebSocket message')
      }
    }

    ws.onerror = () => {
      setConnectionError('WebSocket connection error')
    }

    ws.onclose = () => {
      setConnected(false)
      if (retryCount.current < MAX_RETRIES) {
        const delay = BASE_DELAY_MS * 2 ** retryCount.current
        retryTimeout.current = setTimeout(() => {
          connect()
        }, delay)
        retryCount.current += 1
      } else {
        setConnectionError('Max reconnection attempts reached')
      }
    }
  }, [scanId, handleEvent, setConnected, setConnectionError])

  useEffect(() => {
    if (!scanId) {
      return undefined
    }

    connect()

    return () => {
      disconnect()
    }
  }, [scanId, connect, disconnect])

  return { connect, disconnect }
}
