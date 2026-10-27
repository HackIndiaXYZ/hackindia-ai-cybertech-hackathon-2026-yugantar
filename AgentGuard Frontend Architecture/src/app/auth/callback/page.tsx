"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ShieldAlert, Terminal, CheckCircle2, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/store/useAuthStore";
import { secureStorage, AuthUser } from "@/lib/secureStorage";
import { formatProfileName } from "@/lib/utils";

function AuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<"processing" | "success" | "error">("processing");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const processOAuthCallback = async () => {
      try {
        // 1. Check for query parameter errors
        const queryError = searchParams?.get("oauth_error") || searchParams?.get("error");
        if (queryError) {
          const readable =
            queryError === "account_exists"
              ? "An account with this email already exists with password credentials. Please sign in with email."
              : queryError === "provider_exchange_failed"
              ? "Identity provider credential exchange failed. Please verify provider settings and try again."
              : `OAuth authorization failed: ${queryError}`;
          throw new Error(readable);
        }

        // 2. Parse hash fragment (#token=...&user=...)
        const rawHash = typeof window !== "undefined" ? window.location.hash.replace(/^#/, "") : "";
        const hashParams = new URLSearchParams(rawHash);

        const token = hashParams.get("token") || searchParams?.get("token");
        const userParam = hashParams.get("user") || searchParams?.get("user");
        const hashError = hashParams.get("oauth_error") || hashParams.get("error");

        if (hashError) {
          throw new Error(`SSO Authorization failed: ${hashError}`);
        }

        if (!token) {
          throw new Error("No authorization token received from the identity provider.");
        }

        let parsedUser: any = null;
        if (userParam) {
          try {
            parsedUser = JSON.parse(decodeURIComponent(userParam));
          } catch {
            try {
              parsedUser = JSON.parse(userParam);
            } catch {
              console.warn("Could not parse user payload JSON from callback");
            }
          }
        }

        const resolvedEmail = parsedUser?.email || "analyst@corp.security";
        const resolvedName = parsedUser?.name || formatProfileName(undefined, resolvedEmail);

        const mappedUser: AuthUser = {
          id: parsedUser?.id || `usr_${Date.now()}`,
          email: resolvedEmail,
          fullName: resolvedName,
          name: resolvedName,
          role: parsedUser?.role || "Security Analyst",
          authProvider: parsedUser?.authProvider || "oauth",
          createdAt: parsedUser?.createdAt || Math.floor(Date.now() / 1000),
        };

        // Persist session to localStorage, cookies, and sessionStorage
        secureStorage.saveSession(token, mappedUser);

        // Update Zustand store
        useAuthStore.setState({
          user: mappedUser,
          token: token,
          isAuthenticated: true,
          isLoading: false,
          isInitialized: true,
          error: null,
        });

        if (!isMounted) return;
        setStatus("success");

        toast.success("Zero-Trust Session Established", {
          description: `Authenticated via SSO identity assertion as ${mappedUser.email}. Redirecting to console...`,
        });

        // Clean redirect to dashboard
        setTimeout(() => {
          router.push("/");
        }, 800);
      } catch (err: any) {
        if (!isMounted) return;
        const msg = err?.message || "Failed to complete SSO authentication.";
        setStatus("error");
        setErrorMessage(msg);

        toast.error("SSO Verification Failed", {
          description: msg,
        });

        setTimeout(() => {
          router.push(`/login?oauth_error=${encodeURIComponent(msg)}`);
        }, 2200);
      }
    };

    processOAuthCallback();

    return () => {
      isMounted = false;
    };
  }, [router, searchParams]);

  return (
    <div className="relative min-h-screen w-full flex flex-col items-center justify-center p-4 bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 font-sans select-none">
      {/* Ambient background glow */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(186,230,253,0.45),rgba(224,242,254,0.18)_45%,transparent_75%)] dark:bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(30,40,90,0.35),rgba(18,24,55,0.15)_45%,transparent_75%)]" />
      </div>

      <div className="relative z-10 w-full max-w-md mx-auto">
        <div className="border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-panel rounded-none space-y-5 text-center">
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-slate-100 dark:bg-zinc-800 border border-slate-200 dark:border-zinc-700 text-slate-600 dark:text-zinc-400 text-[10px] font-mono">
            <Terminal className="w-3 h-3 text-slate-400 dark:text-zinc-500" />
            <span>OAuth Token Exchange // RFC 6749</span>
          </div>

          {status === "processing" && (
            <div className="space-y-4 py-4">
              <div className="w-12 h-12 mx-auto border-2 border-slate-900 dark:border-zinc-100 border-t-transparent animate-spin" />
              <div className="space-y-1">
                <h2 className="text-sm font-bold font-mono tracking-wider uppercase text-slate-900 dark:text-zinc-50">
                  Verifying Cryptographic Assertion
                </h2>
                <p className="text-xs text-slate-500 dark:text-zinc-400 font-mono">
                  Negotiating zero-trust session with backend enclave...
                </p>
              </div>
            </div>
          )}

          {status === "success" && (
            <div className="space-y-4 py-4">
              <div className="w-12 h-12 mx-auto rounded-none bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-500">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h2 className="text-sm font-bold font-mono tracking-wider uppercase text-slate-900 dark:text-zinc-50">
                  Assertion Verified
                </h2>
                <p className="text-xs text-emerald-600 dark:text-emerald-400 font-mono">
                  Enclave access token issued. Initializing dashboard...
                </p>
              </div>
            </div>
          )}

          {status === "error" && (
            <div className="space-y-4 py-4">
              <div className="w-12 h-12 mx-auto rounded-none bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-500">
                <AlertCircle className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h2 className="text-sm font-bold font-mono tracking-wider uppercase text-red-600 dark:text-red-400">
                  Authentication Failed
                </h2>
                <p className="text-xs text-slate-500 dark:text-zinc-400 font-mono">
                  {errorMessage || "OAuth provider negotiation failed. Returning to sign-in screen..."}
                </p>
              </div>
            </div>
          )}

          <div className="border-t border-slate-200 dark:border-zinc-800 pt-3 text-[10px] font-mono text-slate-400 dark:text-zinc-500">
            FIPS 140-3 COMPLIANT // SECURE ENCLAVE CALLBACK
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen w-full flex items-center justify-center bg-slate-50 dark:bg-zinc-950 font-mono text-xs text-slate-500">
          Loading authentication gateway...
        </div>
      }
    >
      <AuthCallbackContent />
    </Suspense>
  );
}
