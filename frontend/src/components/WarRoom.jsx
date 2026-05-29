/**
 * WarRoom — main war room dashboard container.
 * Renders all live scan panels side by side.
 * Reads all state from scanStore — no local state for scan data.
 */

import { useScanStore } from '../store/scanStore'
import AgentStatusBar from './AgentStatusBar'
import AttackFeed from './AttackFeed'
import SeverityHeatmap from './SeverityHeatmap'
import ScoreChart from './ScoreChart'

/**
 * Main war room dashboard layout for live scan visualization.
 * @returns {import('react').ReactElement} War room dashboard UI
 */
function WarRoom() {
  const scanId = useScanStore((state) => state.scanId)
  const isConnected = useScanStore((state) => state.isConnected)
  const phase = useScanStore((state) => state.phase)
  const criticalHalt = useScanStore((state) => state.criticalHalt)
  const scanComplete = useScanStore((state) => state.scanComplete)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {criticalHalt && (
        <div className="bg-red-900 border-b border-red-700 px-4 py-2 text-center text-sm font-medium text-red-100">
          ⚠ CRITICAL HALT — Scan stopped. Check vulnerability report.
        </div>
      )}

      {scanComplete && (
        <div className="bg-green-900 border-b border-green-700 px-4 py-2 text-center text-sm font-medium text-green-100">
          ✓ Scan Complete
        </div>
      )}

      <header className="border-b border-gray-800 px-6 py-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Sentinel War Room</h1>
            <p className="text-sm text-gray-400">Scan ID: {scanId || '—'}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-2 text-sm">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                }`}
              />
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
            {phase && (
              <span className="rounded-full bg-indigo-900 px-3 py-1 text-xs font-medium uppercase tracking-wide text-indigo-200">
                {phase}
              </span>
            )}
          </div>
        </div>
      </header>

      {!isConnected && (
        <div className="flex items-center justify-center gap-3 px-6 py-10 text-gray-400">
          <span className="h-2 w-2 animate-pulse rounded-full bg-indigo-400" />
          <span>Waiting for scan connection...</span>
        </div>
      )}

      <main className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-2">
        <div className="flex flex-col gap-6">
          <AgentStatusBar />
          <AttackFeed />
        </div>
        <div className="flex flex-col gap-6">
          <SeverityHeatmap />
          <ScoreChart />
        </div>
      </main>
    </div>
  )
}

export default WarRoom
