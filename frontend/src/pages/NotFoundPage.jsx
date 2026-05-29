/**
 * NotFoundPage — 404 page for unknown routes.
 */

import { Link } from 'react-router-dom'

/**
 * 404 not found page.
 * @returns {import('react').ReactElement} Not found page
 */
function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-950 text-gray-100">
      <p className="text-6xl font-bold text-gray-700">404</p>
      <p className="mt-4 text-lg text-gray-400">Page not found</p>
      <Link
        to="/war-room"
        className="mt-6 text-indigo-400 hover:text-indigo-300 hover:underline"
      >
        Back to War Room
      </Link>
    </div>
  )
}

export default NotFoundPage
