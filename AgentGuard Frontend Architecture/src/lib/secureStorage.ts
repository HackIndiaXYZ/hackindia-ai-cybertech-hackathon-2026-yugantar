/**
 * AgentGuard Secure Storage & Session Token Management
 * 
 * Manages JWT tokens and authenticated session state:
 * 1. Stores access token in localStorage and cookies for seamless Next.js Edge Middleware route guarding.
 * 2. Caches authenticated user identity.
 * 3. Safely clears credentials upon logout.
 */

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  name: string;
  role: string;
  avatarUrl?: string;
  authProvider?: "email" | "github" | "google" | "local" | string;
  lastLoginAt?: string;
  createdAt?: number;
}

export interface SessionData {
  token: string;
  user: AuthUser;
  expiresAt: number;
}

const COOKIE_NAME = "agentguard_auth_token";
const TOKEN_LOCAL_STORAGE_KEY = "agentguard_auth_token";
const USER_LOCAL_STORAGE_KEY = "agentguard_auth_user";
const SESSION_STORAGE_KEY = "secops_vault_session";
const TOKEN_EXPIRY_SECONDS = 60 * 60 * 24; // 24 hours

/**
 * Reads cookie by name in browser runtime
 */
function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(^|;\\s*)(" + name + ")=([^;]*)"));
  return match ? decodeURIComponent(match[3]) : null;
}

/**
 * Sets a secure cookie with SameSite=Strict and path=/
 */
function setCookie(name: string, value: string, maxAgeSeconds: number = TOKEN_EXPIRY_SECONDS): void {
  if (typeof document === "undefined") return;
  const isSecure = typeof window !== "undefined" && window.location.protocol === "https:";
  const secureFlag = isSecure ? "; Secure" : "";
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSeconds}; SameSite=Strict${secureFlag}`;
}

/**
 * Deletes a cookie by setting Max-Age=0
 */
function deleteCookie(name: string): void {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Strict`;
}

/**
 * Parses payload from standard JWT
 */
export function parseJwtPayload(token: string): any | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

/**
 * Secure Storage Public Interface:
 * Handles token and user persistence across localStorage, cookies, and sessionStorage.
 */
export const secureStorage = {
  saveSession(token: string, user: AuthUser): void {
    if (typeof window === "undefined") return;

    // 1. Save token and user in localStorage
    try {
      window.localStorage.setItem(TOKEN_LOCAL_STORAGE_KEY, token);
      window.localStorage.setItem(USER_LOCAL_STORAGE_KEY, JSON.stringify(user));
    } catch (e) {
      console.warn("Could not write to localStorage:", e);
    }

    // 2. Set browser cookie for Next.js Middleware route guard
    setCookie(COOKIE_NAME, token, TOKEN_EXPIRY_SECONDS);

    // 3. Keep sessionStorage synced
    try {
      window.sessionStorage.setItem(
        SESSION_STORAGE_KEY,
        JSON.stringify({ token, user, savedAt: Date.now() })
      );
    } catch {}
  },

  getSession(): { token: string; user: AuthUser } | null {
    if (typeof window === "undefined") return null;

    let token = this.getToken();
    if (!token) return null;

    // Check localStorage for cached user
    try {
      const userRaw = window.localStorage.getItem(USER_LOCAL_STORAGE_KEY);
      if (userRaw) {
        const user = JSON.parse(userRaw) as AuthUser;
        return { token, user };
      }
    } catch {}

    // Check sessionStorage
    try {
      const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (raw) {
        const data = JSON.parse(raw);
        if (data && data.user) {
          return { token, user: data.user };
        }
      }
    } catch {}

    // Fallback: parse token payload
    const payload = parseJwtPayload(token);
    if (payload) {
      const resolvedName = payload.name || payload.fullName || "Security Analyst";
      const user: AuthUser = {
        id: payload.sub || "usr_recovered",
        email: payload.email || "user@agentguard.secops",
        fullName: resolvedName,
        name: resolvedName,
        role: payload.role || "Security Analyst",
        authProvider: payload.provider || "local",
      };
      return { token, user };
    }

    return null;
  },

  getToken(): string | null {
    if (typeof window === "undefined") return null;

    // 1. Check localStorage first
    try {
      const localToken = window.localStorage.getItem(TOKEN_LOCAL_STORAGE_KEY);
      if (localToken && localToken.trim().length > 0) {
        return localToken.trim();
      }
    } catch {}

    // 2. Check cookie
    const cookieToken = getCookie(COOKIE_NAME);
    if (cookieToken && cookieToken.trim().length > 0) {
      return cookieToken.trim();
    }

    // 3. Check sessionStorage
    try {
      const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (raw) {
        const data = JSON.parse(raw);
        if (data && data.token) return data.token;
      }
    } catch {}

    return null;
  },

  clearSession(): void {
    if (typeof window === "undefined") return;

    try {
      window.localStorage.removeItem(TOKEN_LOCAL_STORAGE_KEY);
      window.localStorage.removeItem(USER_LOCAL_STORAGE_KEY);
    } catch {}

    try {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {}

    deleteCookie(COOKIE_NAME);
  },

  hasValidSession(): boolean {
    return this.getToken() !== null;
  },
};
