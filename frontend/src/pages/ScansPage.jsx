/**
 * ScansPage — stub page for listing past scans.
 * Will be fully implemented in Week 7 (client portal).
 */

import { Link } from 'react-router-dom'

/**
 * Stub scans listing page.
 * @returns {import('react').ReactElement} Scans page placeholder
 */
function ScansPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-950 text-gray-100">
      <h1 className="text-3xl font-semibold">Scans</h1>
      <p className="mt-2 text-gray-400">Past scan history coming in Week 7</p>
      <Link
        to="/war-room"
        className="mt-6 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
      >
        Go to War Room
      </Link>
    </div>
  )
}

export default ScansPage
