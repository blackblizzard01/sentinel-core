/**
 * SeverityHeatmap — grid showing vulnerability severity
 * per component. Rows = components, columns = attack domains.
 * Cell color = highest severity found for that combination.
 * Stub with placeholder grid until real data arrives.
 */

import { useScanStore } from '../store/scanStore'

const DOMAINS = [
  'prompt_injection',
  'rag_poisoning',
  'api_attacks',
  'indirect_injection',
  'system_prompt_extraction',
]

/**
 * Map severity string to Tailwind cell background class.
 * @param {string|undefined} severity - Vulnerability severity label
 * @returns {string} Tailwind background class
 */
function getSeverityColor(severity) {
  switch (severity) {
    case 'critical':
      return 'bg-red-600'
    case 'high':
      return 'bg-orange-500'
    case 'medium':
      return 'bg-yellow-500'
    case 'low':
      return 'bg-blue-400'
    default:
      return 'bg-gray-800'
  }
}

/**
 * Render vulnerability severity heatmap grid.
 * @returns {import('react').ReactElement} Severity heatmap panel
 */
function SeverityHeatmap() {
  const vulnerabilities = useScanStore((state) => state.vulnerabilities)
  const components = useScanStore((state) => state.components)

  const rowIds = [
    ...new Set([
      ...components.map((component) => component.component_id),
      ...vulnerabilities.map((vulnerability) => vulnerability.component_id),
    ]),
  ]

  const displayRows = rowIds.length > 0 ? rowIds : ['—']

  const severityMap = vulnerabilities.reduce((accumulator, vulnerability) => {
    const key = `${vulnerability.component_id}::${vulnerability.domain}`
    accumulator[key] = vulnerability.severity
    return accumulator
  }, {})

  return (
    <section className="relative rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Severity Heatmap
      </h2>

      {vulnerabilities.length === 0 && (
        <p className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center text-sm text-gray-600">
          Awaiting scan data...
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-xs">
          <thead>
            <tr>
              <th className="p-2 text-left text-gray-500">Component</th>
              {DOMAINS.map((domain) => (
                <th key={domain} className="p-2 text-center text-gray-500">
                  {domain.replace(/_/g, ' ')}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {displayRows.map((componentId) => (
              <tr key={componentId}>
                <td className="p-2 font-mono text-gray-400">{componentId}</td>
                {DOMAINS.map((domain) => {
                  const severity = severityMap[`${componentId}::${domain}`]
                  return (
                    <td key={`${componentId}-${domain}`} className="p-1">
                      <div
                        className={`h-8 rounded ${getSeverityColor(severity)}`}
                        title={severity || 'none'}
                      />
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default SeverityHeatmap
