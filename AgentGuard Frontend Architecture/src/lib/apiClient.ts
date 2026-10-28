import { toast } from "sonner";
import { secureStorage } from "./secureStorage";
//ok
export class ApiError extends Error {
  statusCode: number;
  detail: string;
  data: any;

  constructor(statusCode: number, detail: string, data?: any) {
    super(detail || `API Request failed with status ${statusCode}`);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.detail = detail;
    this.data = data;
  }
}

export interface RequestOptions extends RequestInit {
  showToastOnError?: boolean;
  errorTitle?: string;
  params?: Record<string, string | number | boolean | undefined | null>;
}

/**
 * Base API URL resolved from environment variable NEXT_PUBLIC_API_URL.
 * Automatically falls back to http://127.0.0.1:8000.
 */
export function getApiBaseUrl(): string {
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  if (envUrl && envUrl.trim().length > 0) {
    return envUrl.trim().replace(/\/$/, "");
  }
  return "http://127.0.0.1:8000";
}

/**
 * Parses and formats error message from backend responses.
 */
function parseErrorMessage(data: any, status: number): string {
  if (!data) {
    return `HTTP error ${status}`;
  }

  // FastAPI standard format: { "detail": "..." } or { "detail": [{ "msg": "..." }] }
  if (typeof data.detail === "string") {
    return data.detail;
  }

  if (Array.isArray(data.detail)) {
    return data.detail
      .map((item: any) => item.msg || item.message || JSON.stringify(item))
      .filter(Boolean)
      .join("; ");
  }

  if (typeof data.message === "string") {
    return data.message;
  }

  if (typeof data.error === "string") {
    return data.error;
  }

  return `Request failed with status ${status}`;
}

/**
 * Centralized API client automatically prepending NEXT_PUBLIC_API_URL,
 * attaching Bearer authorization tokens, and handling errors with frosted glass toasts.
 */
async function request<T>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const {
    showToastOnError = true,
    errorTitle,
    params,
    headers: customHeaders = {},
    ...customConfig
  } = options;

  const baseUrl = getApiBaseUrl();
  let fullUrl = `${baseUrl}${endpoint.startsWith("/") ? "" : "/"}${endpoint}`;

  if (params) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null) {
        query.append(key, String(val));
      }
    });
    const queryString = query.toString();
    if (queryString) {
      fullUrl += `${fullUrl.includes("?") ? "&" : "?"}${queryString}`;
    }
  }

  const token = secureStorage.getToken();
  const headers = new Headers(customHeaders);

  // Automatically attach Bearer auth token if user has active session
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  // If body is NOT FormData, set JSON content type if not already set
  const isFormData = customConfig.body instanceof FormData;
  if (!isFormData && !headers.has("Content-Type") && customConfig.body) {
    headers.set("Content-Type", "application/json");
  }

  const config: RequestInit = {
    ...customConfig,
    headers,
  };

  let response: Response;
  try {
    response = await fetch(fullUrl, config);
  } catch (networkError: any) {
    const errorMsg =
      networkError?.message || "Failed to connect to the AgentGuard backend.";
    if (showToastOnError) {
      toast.error(errorTitle || "Backend Connection Offline", {
        description: `Unable to reach ${baseUrl}. Please ensure the FastAPI server is running on port 8000.`,
      });
    }
    throw new ApiError(0, errorMsg, networkError);
  }

  // Handle successful 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  let data: any = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    try {
      data = await response.text();
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const errorMessage = parseErrorMessage(data, response.status);

    if (showToastOnError) {
      let title = errorTitle;
      if (!title) {
        if (response.status === 401) {
          title = "401 Unauthorized";
        } else if (response.status === 403) {
          title = "403 Access Forbidden";
        } else if (response.status === 404) {
          title = "404 Not Found";
        } else if (response.status === 413) {
          title = "413 Payload Too Large";
        } else if (response.status === 422) {
          title = "422 Validation Error";
        } else if (response.status === 429) {
          title = "429 Rate Limit Exceeded";
        } else if (response.status >= 500) {
          title = "500 Internal Server Error";
        } else {
          title = `Request Error (${response.status})`;
        }
      }

      toast.error(title, {
        description: errorMessage,
      });
    }

    throw new ApiError(response.status, errorMessage, data);
  }

  return data as T;
}

export const apiClient = {
  get<T = any>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, { ...options, method: "GET" });
  },

  post<T = any>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    const isFormData = body instanceof FormData;
    return request<T>(endpoint, {
      ...options,
      method: "POST",
      body: isFormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    });
  },

  put<T = any>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    const isFormData = body instanceof FormData;
    return request<T>(endpoint, {
      ...options,
      method: "PUT",
      body: isFormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    });
  },

  patch<T = any>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    const isFormData = body instanceof FormData;
    return request<T>(endpoint, {
      ...options,
      method: "PATCH",
      body: isFormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    });
  },

  delete<T = any>(endpoint: string, options?: RequestOptions): Promise<T> {
    return request<T>(endpoint, { ...options, method: "DELETE" });
  },

  /**
   * Dedicated helper for multipart/form-data uploads (PDFs, manifests, etc.)
   */
  upload<T = any>(
    endpoint: string,
    formData: FormData,
    options?: RequestOptions
  ): Promise<T> {
    return request<T>(endpoint, {
      ...options,
      method: "POST",
      body: formData,
    });
  },

  getBaseUrl: getApiBaseUrl,
};
