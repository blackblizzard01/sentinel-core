/**
 * WarRoomPage — page wrapper for the war room dashboard.
 * Initializes the WebSocket connection for a given scanId.
 * Reads scanId from URL query param: /war-room?scanId=xxx
 * Falls back to a hardcoded test scan ID if none provided.
 */

import { useSearchParams } from 'react-router-dom'
import { useEffect } from 'react'
import { useScanStore } from '../store/scanStore'
import { useWebSocket } from '../hooks/useWebSocket'
import WarRoom from '../components/WarRoom'

const DEFAULT_SCAN_ID = 'test-scan-001'

/**
 * War room page that wires scan ID and WebSocket to the dashboard.
 * @returns {import('react').ReactElement} War room page
 */
function WarRoomPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scanId') || DEFAULT_SCAN_ID
  const setScanId = useScanStore((state) => state.setScanId)

  useEffect(() => {
    setScanId(scanId)
  }, [scanId, setScanId])

  useWebSocket(scanId)

  return <WarRoom />
}

export default WarRoomPage
