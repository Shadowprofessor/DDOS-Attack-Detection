import { createBrowserRouter, Navigate } from "react-router";
import { Layout } from "./components/Layout";
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
        { path: "*", Component: NotFoundPage },
      ],
    },
  ],
  { basename: "/app" },
);
