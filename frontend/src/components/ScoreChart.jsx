/**
 * ScoreChart — Recharts line chart showing attack score
 * progression over iterations for the current scan.
 * X axis = iteration number, Y axis = score (0.0 - 1.0).
 * Updates live as attack_executed events arrive.
 */

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useScanStore } from '../store/scanStore'

/**
 * Render live attack score progression chart.
 * @returns {import('react').ReactElement} Score chart panel
 */
function ScoreChart() {
  const attackFeed = useScanStore((state) => state.attackFeed)

  const chartData = [...attackFeed]
    .reverse()
    .map((event) => ({
      iteration: event.iteration ?? 0,
      score: event.score ?? 0,
    }))

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Score Progression
      </h2>
      <div className="h-64 rounded-md bg-gray-900">
        {chartData.length === 0 ? (
          <p className="flex h-full items-center justify-center text-sm text-gray-500">
            No score data yet...
          </p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
              <XAxis dataKey="iteration" stroke="#9ca3af" />
              <YAxis domain={[0, 1]} stroke="#9ca3af" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#111827',
                  border: '1px solid #374151',
                  borderRadius: '6px',
                }}
                formatter={(value) => [Number(value).toFixed(2), 'score']}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#6366f1"
                strokeWidth={2}
                dot={{ fill: '#6366f1', r: 3 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  )
}

export default ScoreChart
