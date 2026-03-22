import { QueryClient, QueryFunction } from "@tanstack/react-query";

/**
 * Handle 401 globally: clear auth tokens and redirect to login.
 * Debounced so multiple concurrent 401s don't thrash the page.
 */
let redirecting = false;
function handleUnauthorized() {
  if (redirecting) return;
  redirecting = true;
  localStorage.removeItem("odinforge_access_token");
  localStorage.removeItem("odinforge_refresh_token");
  // Allow the current call-stack to finish, then redirect
  setTimeout(() => {
    window.location.href = "/login";
  }, 0);
}

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    if (res.status === 401) {
      handleUnauthorized();
      return; // Don't throw — the redirect will handle it
    }
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

function getAuthHeaders(includeContentType: boolean = false): HeadersInit {
  const headers: Record<string, string> = {};

  const accessToken = localStorage.getItem("odinforge_access_token");
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  if (includeContentType) {
    headers["Content-Type"] = "application/json";
  }

  return headers;
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const res = await fetch(url, {
    method,
    headers: getAuthHeaders(!!data),
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const res = await fetch(queryKey.join("/") as string, {
      headers: getAuthHeaders(),
      credentials: "include",
    });

    if (res.status === 401) {
      if (unauthorizedBehavior === "returnNull") {
        return null;
      }
      // For "throw" behavior, redirect to login instead of crashing
      handleUnauthorized();
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchOnWindowFocus: true,
      staleTime: 5 * 60 * 1000, // 5 minutes — data served from cache until stale
      gcTime: 10 * 60 * 1000, // 10 minutes — keep unused cache entries
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
