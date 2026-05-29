/**
 * AttackFeed — live scrolling feed of attack events.
 * Shows the last 100 attack_executed events in reverse order.
 * Color codes each row by score severity.
 * Auto-scrolls to latest event.
 */

import { useEffect, useRef } from 'react'
import { useScanStore } from '../store/scanStore'

/**
 * Return Tailwind classes for score severity badge coloring.
 * @param {number} score - Attack score between 0 and 1
 * @returns {string} Tailwind class names
 */
function getScoreColorClass(score) {
  if (score >= 0.9) {
    return 'bg-red-600 text-red-100'
  }
  if (score >= 0.7) {
    return 'bg-orange-500 text-orange-950'
  }
  if (score >= 0.4) {
    return 'bg-yellow-500 text-yellow-950'
  }
  return 'bg-gray-600 text-gray-200'
}

/**
 * Render the live attack event feed.
 * @returns {import('react').ReactElement} Attack feed panel
 */
function AttackFeed() {
  const attackFeed = useScanStore((state) => state.attackFeed)
  const feedEndRef = useRef(null)

  useEffect(() => {
    if (feedEndRef.current) {
      feedEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [attackFeed])

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Attack Feed
      </h2>
      <div className="h-96 overflow-y-auto rounded-md border border-gray-800 bg-gray-950">
        {attackFeed.length === 0 ? (
          <p className="p-4 text-center text-sm text-gray-500">No attacks yet...</p>
        ) : (
          <ul className="divide-y divide-gray-800">
            {attackFeed.map((attack, index) => {
              const preview = (attack.payload_preview || '').slice(0, 60)
              return (
                <li key={`${attack.component_id}-${attack.timestamp}-${index}`} className="p-3">
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs text-gray-400">
                      {attack.component_id}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-semibold ${getScoreColorClass(
                        attack.score,
                      )}`}
                    >
                      {(attack.score ?? 0).toFixed(2)}
                    </span>
                  </div>
                  <p className="text-xs text-indigo-300">{attack.domain}</p>
                  <p className="mt-1 truncate text-sm text-gray-300">{preview}</p>
                  <p className="mt-1 text-xs text-gray-600">{attack.timestamp}</p>
                </li>
              )
            })}
          </ul>
        )}
        <div ref={feedEndRef} />
      </div>
    </section>
  )
}

export default AttackFeed
