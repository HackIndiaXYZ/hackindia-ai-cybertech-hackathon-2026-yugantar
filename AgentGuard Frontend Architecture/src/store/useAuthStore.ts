import { create } from "zustand";
import { AuthUser, secureStorage } from "@/lib/secureStorage";
import { useChatStore } from "@/store/useChatStore";
import { apiClient, ApiError } from "@/lib/apiClient";
import { formatProfileName } from "@/lib/utils";
//ok
export interface AuthState {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;

  // Actions
  login: (credentials: { email: string; password: string }) => Promise<boolean>;
  signup: (data: {
    email: string;
    password: string;
    fullName?: string;
    name?: string;
    role?: string;
  }) => Promise<boolean>;
  loginWithOAuth: (provider: "github" | "google") => Promise<boolean>;
  requestPasswordReset: (email: string) => Promise<{ status: string; message: string }>;
  confirmPasswordReset: (data: {
    email: string;
    otp: string;
    newPassword: string;
  }) => Promise<{ status: string; message: string }>;
  logout: () => Promise<void>;
  initializeAuth: () => Promise<void>;
  clearError: () => void;
}

interface BackendAuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  session_id: string;
  user: {
    id: string;
    email: string;
    name: string;
    role?: string;
    authProvider?: string;
    createdAt?: number;
  };
  email_notification?: string;
}

function mapBackendUser(rawUser: BackendAuthResponse["user"]): AuthUser {
  const resolvedName = rawUser.name || formatProfileName(undefined, rawUser.email);
  return {
    id: rawUser.id,
    email: rawUser.email,
    fullName: resolvedName,
    name: resolvedName,
    role: rawUser.role || "Security Analyst",
    authProvider: rawUser.authProvider || "local",
    createdAt: rawUser.createdAt,
  };
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  isInitialized: false,
  error: null,

  clearError: () => set({ error: null }),

  initializeAuth: async () => {
    try {
      const session = secureStorage.getSession();
      if (session && session.token) {
        // Optimistically restore session
        set({
          user: session.user,
          token: session.token,
          isAuthenticated: true,
          isLoading: false,
          isInitialized: true,
          error: null,
        });

        // Revalidate session with backend
        try {
          const meData = await apiClient.get<{ user: BackendAuthResponse["user"]; session_id: string }>(
            "/api/auth/me",
            { showToastOnError: false }
          );
          if (meData && meData.user) {
            const mappedUser = mapBackendUser(meData.user);
            secureStorage.saveSession(session.token, mappedUser);
            set({ user: mappedUser, isAuthenticated: true });
          }
        } catch (err: any) {
          // If token is invalid or expired (401), clean up
          if (err instanceof ApiError && err.statusCode === 401) {
            secureStorage.clearSession();
            set({
              user: null,
              token: null,
              isAuthenticated: false,
              isLoading: false,
            });
          }
        }
        return;
      }
    } catch (e) {
      console.warn("Failed to initialize auth from storage:", e);
    }
    set({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      isInitialized: true,
    });
  },

  login: async ({ email, password }) => {
    set({ isLoading: true, error: null });

    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !password) {
      set({ isLoading: false, error: "Email and password are required." });
      return false;
    }

    try {
      const response = await apiClient.post<BackendAuthResponse>(
        "/api/auth/login",
        {
          email: cleanEmail,
          password,
        },
        {
          showToastOnError: false, // Let caller handle toast or display store error
        }
      );

      const mappedUser = mapBackendUser(response.user);
      secureStorage.saveSession(response.access_token, mappedUser);

      set({
        user: mappedUser,
        token: response.access_token,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      return true;
    } catch (err: any) {
      const errorMsg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Authentication failed. Please verify credentials.";
      set({ isLoading: false, error: errorMsg });
      return false;
    }
  },

  signup: async ({ email, password, fullName, name, role }) => {
    set({ isLoading: true, error: null });

    const cleanEmail = email.trim().toLowerCase();
    const cleanFullName = (fullName || name || "").trim();

    if (!cleanEmail || !cleanFullName) {
      set({ isLoading: false, error: "Full name and email are required." });
      return false;
    }

    if (!password || password.length < 8) {
      set({
        isLoading: false,
        error: "Password must be at least 8 characters for SecOps compliance.",
      });
      return false;
    }

    try {
      const response = await apiClient.post<BackendAuthResponse>(
        "/api/auth/signup",
        {
          email: cleanEmail,
          password,
          name: cleanFullName,
          role: role || "Security Operations Analyst",
        },
        {
          showToastOnError: false,
        }
      );

      const mappedUser = mapBackendUser(response.user);
      secureStorage.saveSession(response.access_token, mappedUser);

      set({
        user: mappedUser,
        token: response.access_token,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      return true;
    } catch (err: any) {
      const errorMsg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Registration failed. Please check your details.";
      set({ isLoading: false, error: errorMsg });
      return false;
    }
  },

  loginWithOAuth: async (provider: "github" | "google") => {
    set({ isLoading: true, error: null });

    try {
      if (typeof window !== "undefined") {
        window.location.href = `${apiClient.getBaseUrl()}/api/auth/oauth/${provider}/start`;
        return true;
      }
      return false;
    } catch (err: any) {
      set({
        isLoading: false,
        error: `${provider.toUpperCase()} authentication unavailable.`,
      });
      return false;
    }
  },

  requestPasswordReset: async (email: string) => {
    set({ isLoading: true, error: null });
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail) {
      set({ isLoading: false, error: "SecOps email address is required." });
      throw new Error("SecOps email address is required.");
    }

    try {
      const response = await apiClient.post<{ status: string; message: string }>(
        "/api/auth/password-reset/request",
        { email: cleanEmail },
        { showToastOnError: false }
      );
      set({ isLoading: false, error: null });
      return response;
    } catch (err: any) {
      const errorMsg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Password reset request failed.";
      set({ isLoading: false, error: errorMsg });
      throw new Error(errorMsg);
    }
  },

  confirmPasswordReset: async ({ email, otp, newPassword }) => {
    set({ isLoading: true, error: null });
    const cleanEmail = email.trim().toLowerCase();
    const cleanOtp = otp.trim();

    if (!cleanEmail) {
      set({ isLoading: false, error: "SecOps email address is required." });
      throw new Error("SecOps email address is required.");
    }
    if (!/^\d{6}$/.test(cleanOtp)) {
      set({ isLoading: false, error: "Verification code must be exactly 6 digits." });
      throw new Error("Verification code must be exactly 6 digits.");
    }
    if (!newPassword || newPassword.length < 8) {
      set({
        isLoading: false,
        error: "New password must be at least 8 characters.",
      });
      throw new Error("New password must be at least 8 characters.");
    }

    try {
      const response = await apiClient.post<{ status: string; message: string }>(
        "/api/auth/password-reset/confirm",
        {
          email: cleanEmail,
          otp: cleanOtp,
          new_password: newPassword,
        },
        { showToastOnError: false }
      );
      set({ isLoading: false, error: null });
      return response;
    } catch (err: any) {
      const errorMsg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Password reset failed. The code may be invalid or expired.";
      set({ isLoading: false, error: errorMsg });
      throw new Error(errorMsg);
    }
  },

  logout: async () => {
    // Attempt backend session revocation
    try {
      await apiClient.post("/api/auth/logout", {}, { showToastOnError: false }).catch(() => {});
    } catch {}

    // Reset chat store to wipe messages, sessions, attachments & PDFs
    try {
      useChatStore.getState().resetAll();
    } catch (e) {
      console.warn("Failed to reset chat store on logout:", e);
    }

    secureStorage.clearSession();
    set({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  },
}));
