import { createBrowserRouter, Navigate } from "react-router";
import { Layout } from "./components/Layout";
import { AnalystPage } from "./pages/Analyst";
import { ApprovalsPage } from "./pages/Approvals";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { IncidentsPage } from "./pages/Incidents";
import { LiveAttackPage } from "./pages/LiveAttack";
import { LiveFeedPage } from "./pages/LiveFeed";
import { OverviewPage } from "./pages/Overview";
import { ReplayPage } from "./pages/Replay";
import { SettingsPage } from "./pages/Settings";
import { NotFoundPage } from "./pages/NotFound";

export const router = createBrowserRouter(
  [
    {
      path: "/",
      Component: Layout,
      children: [
        { index: true, element: <Navigate to="/overview" replace /> },
        { path: "overview", Component: OverviewPage },
        { path: "incidents", Component: IncidentsPage },
        { path: "incidents/:id", Component: IncidentDetailPage },
        { path: "approvals", Component: ApprovalsPage },
        { path: "live-attack", Component: LiveAttackPage },
        { path: "live", Component: LiveFeedPage },
        { path: "replay", Component: ReplayPage },
        { path: "analyst", Component: AnalystPage },
        { path: "settings", Component: SettingsPage },
        { path: "*", Component: NotFoundPage },
      ],
    },
  ],
  { basename: "/app" },
);
