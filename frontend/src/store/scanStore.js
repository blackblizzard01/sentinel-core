/**
 * scanStore — Zustand global state for all live scan events.
 * All WebSocket events are dispatched into this store.
 * Components read from here — never directly from WebSocket.
 */

import { create } from 'zustand'

const MAX_ATTACK_FEED_ITEMS = 100

const initialState = {
  scanId: null,
  isConnected: false,
  phase: null,
  agents: [],
  attackFeed: [],
  vulnerabilities: [],
  components: [],
  scanComplete: false,
  criticalHalt: false,
  connectionError: null,
  lastEventAt: null,
}

/**
 * Zustand store for live scan dashboard state.
 */
export const useScanStore = create((set) => ({
  ...initialState,

  /**
   * Set the active scan identifier.
   * @param {string|null} scanId - Current scan ID
   */
  setScanId: (scanId) => set({ scanId }),

  /**
   * Set WebSocket connection status.
   * @param {boolean} status - Whether the socket is connected
   */
  setConnected: (status) => set({ isConnected: status }),

  /**
   * Set connection error message.
   * @param {string|null} error - Error description or null
   */
  setConnectionError: (error) => set({ connectionError: error }),

  /**
   * Route incoming WebSocket events to the appropriate state updates.
   * @param {object} event - Parsed WebSocket event payload
   */
  handleEvent: (event) => {
    const eventType = event?.event_type
    const timestamp = new Date().toISOString()

    set((state) => {
      const nextState = { ...state, lastEventAt: timestamp }

      switch (eventType) {
        case 'connection_established':
          return { ...nextState, isConnected: true, connectionError: null }

        case 'agent_started': {
          const agentEntry = {
            agent_name: event.agent_name,
            phase: event.phase,
            status: 'active',
            timestamp: event.timestamp || timestamp,
          }
          const existingIndex = nextState.agents.findIndex(
            (agent) => agent.agent_name === event.agent_name,
          )
          const agents =
            existingIndex >= 0
              ? nextState.agents.map((agent, index) =>
                  index === existingIndex ? { ...agent, ...agentEntry } : agent,
                )
              : [...nextState.agents, agentEntry]
          return {
            ...nextState,
            agents,
            phase: event.phase || nextState.phase,
          }
        }

        case 'attack_executed': {
          const attackEntry = {
            component_id: event.component_id,
            domain: event.domain,
            score: event.score ?? 0,
            payload_preview: event.payload_preview || event.payload || '',
            response_preview: event.response_preview || event.response || '',
            iteration: event.iteration ?? 0,
            timestamp: event.timestamp || timestamp,
          }
          const attackFeed = [attackEntry, ...nextState.attackFeed].slice(
            0,
            MAX_ATTACK_FEED_ITEMS,
          )
          return { ...nextState, attackFeed }
        }

        case 'vulnerability_found': {
          const vulnerabilityEntry = {
            component_id: event.component_id,
            domain: event.domain,
            severity: event.severity,
            description: event.description,
            timestamp: event.timestamp || timestamp,
          }
          return {
            ...nextState,
            vulnerabilities: [...nextState.vulnerabilities, vulnerabilityEntry],
          }
        }

        case 'component_complete': {
          const componentEntry = {
            component_id: event.component_id,
            domains_tested: event.domains_tested,
            findings_count: event.findings_count,
            status: 'complete',
          }
          const existingComponentIndex = nextState.components.findIndex(
            (component) => component.component_id === event.component_id,
          )
          const components =
            existingComponentIndex >= 0
              ? nextState.components.map((component, index) =>
                  index === existingComponentIndex
                    ? { ...component, ...componentEntry }
                    : component,
                )
              : [...nextState.components, componentEntry]
          return { ...nextState, components }
        }

        case 'scan_complete':
          return {
            ...nextState,
            scanComplete: true,
            phase: 'done',
          }

        case 'critical_halt':
          return {
            ...nextState,
            criticalHalt: true,
          }

        case 'progress_update':
          return {
            ...nextState,
            phase: event.current_domain || event.phase || nextState.phase,
          }

        default:
          return nextState
      }
    })
  },

  /**
   * Reset all scan state to initial values before a new scan.
   */
  resetScan: () => set({ ...initialState }),
}))
