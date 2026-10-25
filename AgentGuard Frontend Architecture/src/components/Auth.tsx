"use client";

import React, { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  ShieldAlert,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  Sun,
  Moon,
  AlertCircle,
  Terminal,
  KeyRound,
  UserPlus,
  Briefcase,
  CheckCircle2,
} from "lucide-react";
import { useTheme } from "next-themes";
import { useAuthStore } from "@/store/useAuthStore";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export interface AuthProps {
  initialTab?: "signin" | "register";
  redirectPath?: string;
}

export const Auth: React.FC<AuthProps> = ({
  initialTab = "signin",
  redirectPath: customRedirectPath,
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login, signup, isAuthenticated, clearError, error: storeError } = useAuthStore();
  const { theme, setTheme, resolvedTheme } = useTheme();

  // Tab state: "signin" | "register"
  const tabFromQuery = searchParams?.get("tab");
  const [activeTab, setActiveTab] = useState<"signin" | "register">(
    tabFromQuery === "register" || initialTab === "register" ? "register" : "signin"
  );

  const [mounted, setMounted] = useState(false);
  const redirectPath = customRedirectPath || searchParams?.get("from") || "/";

  // Sign In Form State
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [isLoginSubmitting, setIsLoginSubmitting] = useState(false);
  const [loginErrors, setLoginErrors] = useState<{ email?: string; password?: string }>({});

  // Registration Form State
  const [fullName, setFullName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerRole, setRegisterRole] = useState("Security Architect");
  const [registerPassword, setRegisterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showRegisterPassword, setShowRegisterPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isRegisterSubmitting, setIsRegisterSubmitting] = useState(false);
  const [registerErrors, setRegisterErrors] = useState<{
    fullName?: string;
    email?: string;
    password?: string;
    confirmPassword?: string;
  }>({});

  useEffect(() => {
    setMounted(true);
    if (isAuthenticated) {
      router.push(redirectPath);
    }
  }, [isAuthenticated, redirectPath, router]);

  useEffect(() => {
    if (tabFromQuery === "register") {
      setActiveTab("register");
    } else if (tabFromQuery === "signin") {
      setActiveTab("signin");
    }
  }, [tabFromQuery]);

  const handleTabChange = (tab: "signin" | "register") => {
    clearError();
    setLoginErrors({});
    setRegisterErrors({});
    setActiveTab(tab);
  };

  // Sign In Validation
  const validateLogin = () => {
    const newErrors: { email?: string; password?: string } = {};

    if (!loginEmail.trim()) {
      newErrors.email = "SecOps email address is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(loginEmail.trim())) {
      newErrors.email = "Please enter a valid security email format.";
    }

    if (!loginPassword) {
      newErrors.password = "Master enclave password is required.";
    } else if (loginPassword.length < 6) {
      newErrors.password = "Password must be at least 6 characters.";
    }

    setLoginErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Registration Validation
  const validateRegister = () => {
    const newErrors: {
      fullName?: string;
      email?: string;
      password?: string;
      confirmPassword?: string;
    } = {};

    const cleanFullName = fullName.trim();
    if (!cleanFullName) {
      newErrors.fullName = "Full Name is required (e.g. Aryan Saini).";
    } else if (cleanFullName.length < 2) {
      newErrors.fullName = "Full Name must be at least 2 characters.";
    }

    if (!registerEmail.trim()) {
      newErrors.email = "SecOps email address is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(registerEmail.trim())) {
      newErrors.email = "Please enter a valid security email format.";
    }

    if (!registerPassword) {
      newErrors.password = "Master enclave password is required.";
    } else if (registerPassword.length < 8) {
      newErrors.password = "SecOps compliance requires minimum 8 characters.";
    }

    if (!confirmPassword) {
      newErrors.confirmPassword = "Confirm password is required.";
    } else if (registerPassword !== confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match.";
    }

    setRegisterErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle Sign In Submit
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    if (!validateLogin()) {
      return;
    }

    setIsLoginSubmitting(true);
    try {
      const success = await login({ email: loginEmail, password: loginPassword });
      if (success) {
        toast.success("Zero-Trust Session Established", {
          description: `Authenticated as ${loginEmail}. Redirecting to dashboard...`,
        });
        router.push(redirectPath);
      } else {
        const currentError = useAuthStore.getState().error || storeError;
        toast.error("Authentication Denied", {
          description: currentError || "Invalid credentials or unauthorized security token.",
        });
      }
    } finally {
      setIsLoginSubmitting(false);
    }
  };

  // Handle Registration Submit
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    if (!validateRegister()) {
      return;
    }

    setIsRegisterSubmitting(true);
    try {
      const formattedFullName = fullName.trim();
      const success = await signup({
        fullName: formattedFullName,
        name: formattedFullName,
        email: registerEmail.trim(),
        password: registerPassword,
        role: registerRole,
      });

      if (success) {
        toast.success("Enclave Identity Provisioned", {
          description: `Welcome aboard, ${formattedFullName}. Redirecting to console...`,
        });
        router.push(redirectPath);
      } else {
        const currentError = useAuthStore.getState().error || storeError;
        toast.error("Registration Denied", {
          description: currentError || "Could not register security identity.",
        });
      }
    } finally {
      setIsRegisterSubmitting(false);
    }
  };

  const handleSocialClick = (provider: "github" | "google") => {
    toast.error("Federated login unavailable", {
      description: `${provider.toUpperCase()} SSO identity provider is currently offline. Please use email credentials.`,
    });
  };

  const currentTheme = mounted ? resolvedTheme || theme : "dark";

  return (
    <div className="relative min-h-screen w-full flex flex-col items-center justify-center p-4 sm:p-6 bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 font-sans overflow-hidden select-none transition-colors duration-150">
      {/* Ambient Background Radial Glow (Polar Bear Light & Industrial Zinc Dark) */}
      <div
        className="pointer-events-none absolute inset-0 overflow-hidden select-none"
        aria-hidden="true"
      >
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(186,230,253,0.45),rgba(224,242,254,0.18)_45%,transparent_75%)] dark:bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(30,40,90,0.35),rgba(18,24,55,0.15)_45%,transparent_75%)]" />
        <div className="absolute top-[38%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[450px] sm:w-[850px] sm:h-[600px] rounded-full blur-[120px] pointer-events-none opacity-45 dark:opacity-20 bg-gradient-to-tr from-sky-200 via-blue-100 to-sky-100 dark:from-indigo-950 dark:via-[#1e2247] dark:to-blue-950" />
      </div>

      {/* Top Navbar Bar: Interactive Logo, Security Status & Theme Toggle */}
      <header className="absolute top-0 left-0 right-0 h-14 px-6 flex items-center justify-between border-b border-slate-200 dark:border-zinc-800 bg-white/70 dark:bg-zinc-950/70 backdrop-blur-md z-20">
        <Link
          href="/"
          title="Return to AgentGuard Dashboard"
          className="flex items-center gap-2.5 hover:opacity-85 transition-opacity group cursor-pointer"
        >
          <div className="w-7 h-7 rounded-none bg-slate-100 dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 flex items-center justify-center text-slate-900 dark:text-zinc-50 shadow-sm group-hover:border-slate-400 dark:group-hover:border-zinc-600 transition-colors">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <span className="text-xs font-semibold tracking-wider font-mono text-slate-900 dark:text-zinc-50 uppercase">
            AgentGuard // SecOps Enclave
          </span>
        </Link>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 border border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-900 text-[11px] font-mono text-slate-500 dark:text-zinc-400">
            <span className="w-1.5 h-1.5 rounded-none bg-emerald-500 inline-block" />
            <span>Zero-Trust Gateway:</span>
            <span className="text-slate-900 dark:text-zinc-50">Enforcing</span>
          </div>

          <button
            type="button"
            onClick={() => setTheme(currentTheme === "dark" ? "light" : "dark")}
            title={
              currentTheme === "dark"
                ? "Switch to Polar Bear Light Mode"
                : "Switch to Industrial Zinc Dark Mode"
            }
            aria-label="Toggle light/dark theme"
            className="p-1.5 rounded-none bg-slate-100 hover:bg-slate-200 dark:bg-zinc-900 dark:hover:bg-zinc-800 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 transition-colors cursor-pointer"
          >
            {mounted && currentTheme === "dark" ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-slate-700" />
            )}
          </button>
        </div>
      </header>

      {/* Main Auth Card Container */}
      <div className="relative z-10 w-full max-w-lg mx-auto mt-14 sm:mt-18 mb-8">
        <div className="border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-panel rounded-none space-y-5">
          {/* Header Typography */}
          <div className="space-y-1.5 text-center">
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-slate-100 dark:bg-zinc-800 border border-slate-200 dark:border-zinc-700 text-slate-600 dark:text-zinc-400 text-[10px] font-mono mb-1">
              <Terminal className="w-3 h-3 text-slate-400 dark:text-zinc-500" />
              <span>
                {activeTab === "signin"
                  ? "Identity Assertion Layer // RFC 9449"
                  : "Identity Provisioning Service // Zero-Trust v2"}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-zinc-50 font-mono">
              {activeTab === "signin" ? "Enclave Authentication" : "Register SecOps Enclave"}
            </h1>
            <p className="text-xs text-slate-600 dark:text-zinc-400">
              {activeTab === "signin"
                ? "Sign in with your SecOps credentials or federated enterprise provider"
                : "Provision audited cryptographic credentials with verified analyst identity"}
            </p>
          </div>

          {/* PROMINENT TABS / TOGGLE: "Sign In" vs "Create Enclave Identity" */}
          <div className="grid grid-cols-2 p-1 bg-slate-100 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 rounded-none">
            <button
              type="button"
              id="tab-signin"
              onClick={() => handleTabChange("signin")}
              className={cn(
                "py-2 px-3 text-xs font-mono font-medium transition-all text-center rounded-none cursor-pointer flex items-center justify-center gap-2",
                activeTab === "signin"
                  ? "bg-white dark:bg-zinc-800 text-slate-900 dark:text-zinc-50 shadow-sm border border-slate-300 dark:border-zinc-700 font-semibold"
                  : "text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200"
              )}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>

            <button
              type="button"
              id="tab-register"
              onClick={() => handleTabChange("register")}
              className={cn(
                "py-2 px-3 text-xs font-mono font-medium transition-all text-center rounded-none cursor-pointer flex items-center justify-center gap-2",
                activeTab === "register"
                  ? "bg-white dark:bg-zinc-800 text-slate-900 dark:text-zinc-50 shadow-sm border border-slate-300 dark:border-zinc-700 font-semibold"
                  : "text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200"
              )}
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Create Enclave Identity</span>
            </button>
          </div>

          {/* Social OAuth Providers */}
          <div className="grid grid-cols-2 gap-2.5">
            <button
              type="button"
              onClick={() => handleSocialClick("github")}
              className="flex items-center justify-center gap-2 py-2 px-3 bg-slate-100 hover:bg-slate-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 border border-slate-200 dark:border-zinc-700 text-slate-900 dark:text-zinc-50 text-xs font-mono transition-colors rounded-none cursor-pointer"
            >
              <svg className="w-4 h-4 fill-current shrink-0" viewBox="0 0 24 24">
                <path
                  fillRule="evenodd"
                  clipRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                />
              </svg>
              <span>GitHub</span>
            </button>

            <button
              type="button"
              onClick={() => handleSocialClick("google")}
              className="flex items-center justify-center gap-2 py-2 px-3 bg-slate-100 hover:bg-slate-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 border border-slate-200 dark:border-zinc-700 text-slate-900 dark:text-zinc-50 text-xs font-mono transition-colors rounded-none cursor-pointer"
            >
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>Google</span>
            </button>
          </div>

          {/* Monospace Divider */}
          <div className="relative flex items-center justify-center my-3">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-200 dark:border-zinc-800" />
            </div>
            <span className="relative bg-white dark:bg-zinc-900 px-2 text-[10px] uppercase font-mono tracking-wider text-slate-500 dark:text-zinc-400">
              {activeTab === "signin" ? "OR CONTINUE WITH EMAIL" : "OR REGISTER VIA EMAIL"}
            </span>
          </div>

          {/* Shared Store Error Banner */}
          {storeError && (
            <div className="p-3 border border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400 text-xs font-mono flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{storeError}</span>
            </div>
          )}

          {/* ========================================================= */}
          {/* TAB 1: SIGN IN FORM */}
          {/* ========================================================= */}
          {activeTab === "signin" && (
            <form onSubmit={handleLoginSubmit} noValidate className="space-y-4">
              {/* Login Email Field */}
              <div className="space-y-1.5 text-left">
                <label
                  htmlFor="email"
                  className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                >
                  SecOps Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    value={loginEmail}
                    onChange={(e) => {
                      setLoginEmail(e.target.value);
                      if (loginErrors.email) {
                        setLoginErrors((prev) => ({ ...prev, email: undefined }));
                      }
                    }}
                    placeholder="analyst@corp.security"
                    className={cn(
                      "w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      loginErrors.email
                        ? "border-red-500 focus:border-red-500"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                </div>
                {loginErrors.email && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{loginErrors.email}</span>
                  </p>
                )}
              </div>

              {/* Login Password Field */}
              <div className="space-y-1.5 text-left">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="password"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    Master Enclave Password
                  </label>
                  <span className="text-[10px] font-mono text-slate-400 dark:text-zinc-500">
                    Min. 6 chars
                  </span>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="password"
                    name="password"
                    type={showLoginPassword ? "text" : "password"}
                    autoComplete="current-password"
                    value={loginPassword}
                    onChange={(e) => {
                      setLoginPassword(e.target.value);
                      if (loginErrors.password) {
                        setLoginErrors((prev) => ({ ...prev, password: undefined }));
                      }
                    }}
                    placeholder="••••••••••••"
                    className={cn(
                      "w-full pl-9 pr-10 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      loginErrors.password
                        ? "border-red-500 focus:border-red-500"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                  <button
                    type="button"
                    onClick={(e) => {
                      e.preventDefault();
                      setShowLoginPassword(!showLoginPassword);
                    }}
                    tabIndex={-1}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors p-0.5 cursor-pointer"
                    aria-label={showLoginPassword ? "Hide password" : "Show password"}
                  >
                    {showLoginPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
                {loginErrors.password && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{loginErrors.password}</span>
                  </p>
                )}
              </div>

              {/* Submit Sign In */}
              <button
                type="submit"
                disabled={isLoginSubmitting}
                className="w-full py-2.5 px-4 bg-slate-900 dark:bg-zinc-50 text-white dark:text-zinc-950 font-mono font-semibold text-xs border border-slate-900 dark:border-zinc-50 hover:bg-slate-800 dark:hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 rounded-none cursor-pointer disabled:opacity-50"
              >
                {isLoginSubmitting ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white dark:border-zinc-950 border-t-transparent animate-spin inline-block" />
                    <span>Authenticating Session...</span>
                  </>
                ) : (
                  <>
                    <KeyRound className="w-4 h-4" />
                    <span>Authenticate Session</span>
                  </>
                )}
              </button>

              {/* Bottom Quick Switch */}
              <div className="pt-2 text-center text-xs font-mono text-slate-600 dark:text-zinc-400">
                <span>Need an enclave identity? </span>
                <button
                  type="button"
                  onClick={() => handleTabChange("register")}
                  className="text-slate-900 dark:text-zinc-100 font-semibold hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  Create Enclave Identity &rarr;
                </button>
              </div>
            </form>
          )}

          {/* ========================================================= */}
          {/* TAB 2: CREATE ENCLAVE IDENTITY (REGISTRATION) FORM */}
          {/* ========================================================= */}
          {activeTab === "register" && (
            <form onSubmit={handleRegisterSubmit} noValidate className="space-y-3.5 text-left">
              {/* CRITICAL REQUIREMENT: Dedicated, Required Input Field for Full Name */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="fullName"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-700 dark:text-zinc-300 font-semibold"
                  >
                    Full Name <span className="text-red-500">*</span>
                  </label>
                  <span className="text-[10px] font-mono text-slate-400 dark:text-zinc-500">
                    Real Identity (e.g., Aryan Saini)
                  </span>
                </div>
                <div className="relative">
                  <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="fullName"
                    name="fullName"
                    type="text"
                    required
                    autoComplete="name"
                    value={fullName}
                    onChange={(e) => {
                      setFullName(e.target.value);
                      if (registerErrors.fullName) {
                        setRegisterErrors((prev) => ({ ...prev, fullName: undefined }));
                      }
                    }}
                    placeholder="Aryan Saini"
                    className={cn(
                      "w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      registerErrors.fullName
                        ? "border-red-500 focus:border-red-500 ring-1 ring-red-500/20"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                </div>
                {registerErrors.fullName && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{registerErrors.fullName}</span>
                  </p>
                )}
              </div>

              {/* Registration Email Field */}
              <div className="space-y-1">
                <label
                  htmlFor="registerEmail"
                  className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                >
                  SecOps Email Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="registerEmail"
                    name="email"
                    type="email"
                    autoComplete="email"
                    value={registerEmail}
                    onChange={(e) => {
                      setRegisterEmail(e.target.value);
                      if (registerErrors.email) {
                        setRegisterErrors((prev) => ({ ...prev, email: undefined }));
                      }
                    }}
                    placeholder="analyst@corp.security"
                    className={cn(
                      "w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      registerErrors.email
                        ? "border-red-500 focus:border-red-500"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                </div>
                {registerErrors.email && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{registerErrors.email}</span>
                  </p>
                )}
              </div>

              {/* Auditor Role Selector */}
              <div className="space-y-1">
                <label
                  htmlFor="registerRole"
                  className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                >
                  Auditor Operational Role
                </label>
                <div className="relative">
                  <Briefcase className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <select
                    id="registerRole"
                    name="role"
                    value={registerRole}
                    onChange={(e) => setRegisterRole(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border border-slate-300 dark:border-zinc-700 focus:outline-none focus:border-slate-900 dark:focus:border-zinc-100 transition-colors rounded-none cursor-pointer"
                  >
                    <option value="Security Architect">Security Architect</option>
                    <option value="DevSecOps Lead">DevSecOps Lead</option>
                    <option value="Cloud Security Engineer">Cloud Security Engineer</option>
                    <option value="Penetration Tester / Red Team">
                      Penetration Tester / Red Team
                    </option>
                    <option value="Compliance & Risk Officer">Compliance & Risk Officer</option>
                  </select>
                </div>
              </div>

              {/* Password and Confirm Password Row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* Password Field */}
                <div className="space-y-1">
                  <label
                    htmlFor="registerPassword"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    Password (Min 8) <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                    <input
                      id="registerPassword"
                      name="password"
                      type={showRegisterPassword ? "text" : "password"}
                      value={registerPassword}
                      onChange={(e) => {
                        setRegisterPassword(e.target.value);
                        if (registerErrors.password) {
                          setRegisterErrors((prev) => ({ ...prev, password: undefined }));
                        }
                      }}
                      placeholder="••••••••"
                      className={cn(
                        "w-full pl-9 pr-8 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                        registerErrors.password
                          ? "border-red-500 focus:border-red-500"
                          : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                      )}
                    />
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        setShowRegisterPassword(!showRegisterPassword);
                      }}
                      tabIndex={-1}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors p-0.5 cursor-pointer"
                      aria-label={showRegisterPassword ? "Hide password" : "Show password"}
                    >
                      {showRegisterPassword ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  {registerErrors.password && (
                    <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3 shrink-0" />
                      <span>{registerErrors.password}</span>
                    </p>
                  )}
                </div>

                {/* Confirm Password Field */}
                <div className="space-y-1">
                  <label
                    htmlFor="confirmPassword"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    Confirm <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                    <input
                      id="confirmPassword"
                      name="confirmPassword"
                      type={showConfirmPassword ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(e) => {
                        setConfirmPassword(e.target.value);
                        if (registerErrors.confirmPassword) {
                          setRegisterErrors((prev) => ({
                            ...prev,
                            confirmPassword: undefined,
                          }));
                        }
                      }}
                      placeholder="••••••••"
                      className={cn(
                        "w-full pl-9 pr-8 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                        registerErrors.confirmPassword
                          ? "border-red-500 focus:border-red-500"
                          : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                      )}
                    />
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        setShowConfirmPassword(!showConfirmPassword);
                      }}
                      tabIndex={-1}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors p-0.5 cursor-pointer"
                      aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}
                    >
                      {showConfirmPassword ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  {registerErrors.confirmPassword && (
                    <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3 shrink-0" />
                      <span>{registerErrors.confirmPassword}</span>
                    </p>
                  )}
                </div>
              </div>

              {/* Submit Registration Button */}
              <button
                type="submit"
                disabled={isRegisterSubmitting}
                className="w-full mt-2 py-2.5 px-4 bg-slate-900 dark:bg-zinc-50 text-white dark:text-zinc-950 font-mono font-semibold text-xs border border-slate-900 dark:border-zinc-50 hover:bg-slate-800 dark:hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 rounded-none cursor-pointer disabled:opacity-50"
              >
                {isRegisterSubmitting ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white dark:border-zinc-950 border-t-transparent animate-spin inline-block" />
                    <span>Provisioning Enclave Identity...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Create Enclave Identity</span>
                  </>
                )}
              </button>

              {/* Bottom Quick Switch */}
              <div className="pt-2 text-center text-xs font-mono text-slate-600 dark:text-zinc-400">
                <span>Already provisioned? </span>
                <button
                  type="button"
                  onClick={() => handleTabChange("signin")}
                  className="text-slate-900 dark:text-zinc-100 font-semibold hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  Authenticate Existing Session &rarr;
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Security & Compliance Footer Metadata */}
        <div className="mt-4 text-center text-[10px] font-mono text-slate-500 dark:text-zinc-400 space-y-1">
          <p>FIPS 140-3 COMPLIANT // TLS 1.3 ENFORCED // SAME-SITE STRICT</p>
          <p>AgentGuard Security Operations Console v2.4.0</p>
        </div>
      </div>
    </div>
  );
};

export default Auth;
