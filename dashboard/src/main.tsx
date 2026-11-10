import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router/dom";
import { router } from "./App";
import { ApiError } from "./api/client";
import { clearAuth, restore } from "./auth/store";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: (count, err) => !(err instanceof ApiError && [401, 403, 404, 422].includes(err.status)) && count < 2,
    },
  },
});

// A 401 anywhere means the session ended: drop to the login screen.
queryClient.getQueryCache().subscribe((e) => {
  const err = e.query.state.error;
  if (err instanceof ApiError && err.status === 401) clearAuth();
});

void restore();

const el = document.getElementById("root");
if (el) {
  createRoot(el).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </StrictMode>,
  );
}
