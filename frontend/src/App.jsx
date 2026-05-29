/**
 * App — root component. Defines all client-side routes.
 * Routes:
 *   /          → DashboardPage (redirect to /war-room)
 *   /war-room  → WarRoomPage
 *   /scans     → ScansPage (stub)
 *   *          → NotFoundPage (stub)
 */

import { Routes, Route, Navigate } from 'react-router-dom'
import WarRoomPage from './pages/WarRoomPage'
import ScansPage from './pages/ScansPage'
import NotFoundPage from './pages/NotFoundPage'

/**
 * Root application component with client-side routing.
 * @returns {import('react').ReactElement} Routed application tree
 */
function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/war-room" replace />} />
      <Route path="/war-room" element={<WarRoomPage />} />
      <Route path="/scans" element={<ScansPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
