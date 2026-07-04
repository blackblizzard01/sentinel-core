import { create } from 'zustand'

export const useScanStore = create((set) => ({
  scanStatus: 'idle',
  components: [],
  events: [],
  vulnerabilities: [],
  agentStatus: {},
  reportPath: null,

  addEvent: (event) => set((state) => ({
    events: [...state.events, event]
  })),

  updateAgentStatus: (agentName, status) => set((state) => ({
    agentStatus: { ...state.agentStatus, [agentName]: status }
  })),

  addVulnerability: (vuln) => set((state) => ({
    vulnerabilities: [...state.vulnerabilities, vuln]
  })),

  setScanComplete: (reportPath) => set({
    scanStatus: 'complete',
    reportPath
  }),
}))
