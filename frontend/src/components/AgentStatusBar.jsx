/**
 * AgentStatusBar — displays status of all 5 Sentinel AI agents.
 * Shows agent name, current phase, and active/idle indicator.
 * Updates live as agent_started events arrive via scanStore.
 */

import { useScanStore } from '../store/scanStore'

const AGENT_NAMES = [
  'recon_agent',
  'attack_agent',
  'mutation_agent',
  'report_agent',
  'autopatch_agent',
]

/**
 * Render status cards for all Sentinel AI agents.
 * @returns {import('react').ReactElement} Agent status bar
 */
function AgentStatusBar() {
  const agents = useScanStore((state) => state.agents)

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Agent Status
      </h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
        {AGENT_NAMES.map((agentName) => {
          const agentState = agents.find((agent) => agent.agent_name === agentName)
          const isActive = agentState?.status === 'active'
          const phaseLabel = agentState?.phase || 'idle'

          return (
            <div
              key={agentName}
              className="flex items-center justify-between rounded-md border border-gray-800 bg-gray-950 px-3 py-2"
            >
              <div>
                <p className="font-mono text-sm text-gray-200">{agentName}</p>
                <p className="text-xs text-gray-500">{phaseLabel}</p>
              </div>
              <span className="flex items-center gap-2 text-xs text-gray-400">
                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                    isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-600'
                  }`}
                />
                {isActive ? 'active' : 'idle'}
              </span>
            </div>
          )
        })}
      </div>
    </section>
  )
}

export default AgentStatusBar
