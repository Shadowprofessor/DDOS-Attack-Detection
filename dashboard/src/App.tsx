import { createBrowserRouter, Navigate } from "react-router";
import { Layout } from "./components/Layout";
import { ApprovalsPage } from "./pages/Approvals";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { IncidentsPage } from "./pages/Incidents";
import { OverviewPage } from "./pages/Overview";
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
        { path: "*", Component: NotFoundPage },
      ],
    },
  ],
  { basename: "/app" },
);
