"use client";
//system
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
  ArrowLeft,
  RefreshCw,
} from "lucide-react";
import { useTheme } from "next-themes";
import { useAuthStore } from "@/store/useAuthStore";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { apiClient, ApiError } from "@/lib/apiClient";

export type AuthTab = "signin" | "register" | "forgot_password" | "reset_password";

export interface AuthProps {
  initialTab?: AuthTab;
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

  // Determine initial tab from query param or prop
  const tabFromQuery = searchParams?.get("tab") || searchParams?.get("view");
  const resolveInitialTab = (): AuthTab => {
    if (tabFromQuery === "register") return "register";
    if (tabFromQuery === "forgot" || tabFromQuery === "forgot_password" || tabFromQuery === "recovery") {
      return "forgot_password";
    }
    if (tabFromQuery === "reset" || tabFromQuery === "reset_password") {
      return "reset_password";
    }
    return initialTab;
  };

  const [activeTab, setActiveTab] = useState<AuthTab>(resolveInitialTab());
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

  // Password Recovery (Forgot Password) State
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [isRecoverySubmitting, setIsRecoverySubmitting] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);

  // Password Reset (OTP Verification) State
  const [resetEmail, setResetEmail] = useState("");
  const [resetOtp, setResetOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmNewPassword, setShowConfirmNewPassword] = useState(false);
  const [isResetSubmitting, setIsResetSubmitting] = useState(false);
  const [resetErrors, setResetErrors] = useState<{
    email?: string;
    otp?: string;
    newPassword?: string;
    confirmNewPassword?: string;
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
    } else if (tabFromQuery === "forgot" || tabFromQuery === "forgot_password" || tabFromQuery === "recovery") {
      setActiveTab("forgot_password");
    } else if (tabFromQuery === "reset" || tabFromQuery === "reset_password") {
      setActiveTab("reset_password");
    }
  }, [tabFromQuery]);

  // Handle incoming OAuth errors from search parameters
  useEffect(() => {
    const oauthError = searchParams?.get("oauth_error") || searchParams?.get("error");
    if (oauthError) {
      const readable =
        oauthError === "account_exists"
          ? "An account with this email already exists with password credentials. Please sign in with email."
          : oauthError === "provider_exchange_failed"
          ? "Federated identity provider exchange failed. Please verify provider settings or sign in with email."
          : `SSO Error: ${oauthError}`;
      toast.error("Federated Authentication Failed", {
        description: readable,
      });
    }
  }, [searchParams]);

  const handleTabChange = (tab: AuthTab) => {
    clearError();
    setLoginErrors({});
    setRegisterErrors({});
    setRecoveryError(null);
    setResetErrors({});
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

  // Password Recovery Validation
  const validateRecovery = () => {
    const clean = recoveryEmail.trim();
    if (!clean) {
      setRecoveryError("SecOps email address is required.");
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      setRecoveryError("Please enter a valid security email format.");
      return false;
    }
    setRecoveryError(null);
    return true;
  };

  // Password Reset Validation
  const validateReset = () => {
    const newErrors: {
      email?: string;
      otp?: string;
      newPassword?: string;
      confirmNewPassword?: string;
    } = {};

    const cleanEmail = resetEmail.trim();
    if (!cleanEmail) {
      newErrors.email = "SecOps email address is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      newErrors.email = "Please enter a valid security email format.";
    }

    const cleanOtp = resetOtp.trim();
    if (!cleanOtp) {
      newErrors.otp = "6-digit verification code is required.";
    } else if (!/^\d{6}$/.test(cleanOtp)) {
      newErrors.otp = "Verification code must be exactly 6 digits.";
    }

    if (!newPassword) {
      newErrors.newPassword = "New master password is required.";
    } else if (newPassword.length < 8) {
      newErrors.newPassword = "SecOps compliance requires minimum 8 characters.";
    }

    if (!confirmNewPassword) {
      newErrors.confirmNewPassword = "Confirm password is required.";
    } else if (newPassword !== confirmNewPassword) {
      newErrors.confirmNewPassword = "Passwords do not match.";
    }

    setResetErrors(newErrors);
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

  // Handle Password Recovery (Request OTP) Submit
  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setRecoveryError(null);

    if (!validateRecovery()) {
      return;
    }

    setIsRecoverySubmitting(true);
    try {
      const cleanEmail = recoveryEmail.trim().toLowerCase();
      await apiClient.post<{ status: string; message: string }>(
        "/api/auth/password-reset/request",
        { email: cleanEmail },
        { showToastOnError: false }
      );

      // Frosted glass toast on success matching prompt exactly
      toast.success("Recovery Code Dispatched", {
        description: "If an account exists, a reset link/OTP has been sent to your email.",
      });

      // Automatically transition to OTP verification screen with email prefilled
      setResetEmail(cleanEmail);
      setResetOtp("");
      setNewPassword("");
      setConfirmNewPassword("");
      setResetErrors({});
      setActiveTab("reset_password");
    } catch (err: any) {
      const msg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Password recovery service is temporarily unavailable.";
      setRecoveryError(msg);
      toast.error("Recovery Request Failed", {
        description: msg,
      });
    } finally {
      setIsRecoverySubmitting(false);
    }
  };

  // Handle Password Reset (Confirm OTP & Update Password) Submit
  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    if (!validateReset()) {
      return;
    }

    setIsResetSubmitting(true);
    try {
      const cleanEmail = resetEmail.trim().toLowerCase();
      const cleanOtp = resetOtp.trim();

      await apiClient.post<{ status: string; message: string }>(
        "/api/auth/password-reset/confirm",
        {
          email: cleanEmail,
          otp: cleanOtp,
          new_password: newPassword,
        },
        { showToastOnError: false }
      );

      // On success, redirect the user back to the Sign In state with a success toast
      toast.success("Master Password Updated", {
        description: "Your master password has been changed successfully. Please sign in with your new credentials.",
      });

      // Pre-fill email in login form and switch to sign in
      setLoginEmail(cleanEmail);
      setLoginPassword("");
      setResetOtp("");
      setNewPassword("");
      setConfirmNewPassword("");
      setResetErrors({});
      setActiveTab("signin");
    } catch (err: any) {
      const msg =
        err instanceof ApiError
          ? err.detail
          : err?.message || "Password reset failed. The code may be invalid or expired.";
      toast.error("Password Reset Failed", {
        description: msg,
      });
      setResetErrors((prev) => ({
        ...prev,
        otp: msg.toLowerCase().includes("code") || msg.toLowerCase().includes("otp") ? msg : prev.otp,
      }));
    } finally {
      setIsResetSubmitting(false);
    }
  };

  // Trigger backend OAuth flow
  const handleSocialClick = (provider: "github" | "google") => {
    const backendUrl = apiClient.getBaseUrl();
    window.location.href = `${backendUrl}/api/auth/oauth/${provider}/start`;
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
                  : activeTab === "register"
                  ? "Identity Provisioning Service // Zero-Trust v2"
                  : activeTab === "forgot_password"
                  ? "Identity Recovery Service // Zero-Trust OTP"
                  : "Credential Re-issuance // RFC 4226"}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-zinc-50 font-mono">
              {activeTab === "signin"
                ? "Enclave Authentication"
                : activeTab === "register"
                ? "Register SecOps Enclave"
                : activeTab === "forgot_password"
                ? "Password Recovery"
                : "Verify OTP & Reset Password"}
            </h1>
            <p className="text-xs text-slate-600 dark:text-zinc-400">
              {activeTab === "signin"
                ? "Sign in with your SecOps credentials or federated enterprise provider"
                : activeTab === "register"
                ? "Provision audited cryptographic credentials with verified analyst identity"
                : activeTab === "forgot_password"
                ? "Enter your SecOps email address to request a one-time password (OTP) verification code"
                : "Enter the 6-digit verification code sent to your email and configure your new master password"}
            </p>
          </div>

          {/* PROMINENT TABS / TOGGLE: Visible for Sign In & Register views */}
          {(activeTab === "signin" || activeTab === "register") && (
            <>
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

              {/* Social OAuth Providers with Real Backend Redirection */}
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  id="btn-oauth-github"
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
                  id="btn-oauth-google"
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
            </>
          )}

          {/* Recovery Breadcrumb: Visible when in Forgot Password or Reset Password state */}
          {(activeTab === "forgot_password" || activeTab === "reset_password") && (
            <div className="flex items-center justify-between p-2 bg-slate-100 dark:bg-zinc-950 border border-slate-200 dark:border-zinc-800 text-xs font-mono">
              <button
                type="button"
                onClick={() => handleTabChange("signin")}
                className="inline-flex items-center gap-1.5 text-slate-600 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Return to Sign In</span>
              </button>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-zinc-500">
                {activeTab === "forgot_password" ? "Step 1 of 2: OTP Request" : "Step 2 of 2: Verification"}
              </span>
            </div>
          )}

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

              {/* Login Password Field + Forgot Password Link */}
              <div className="space-y-1.5 text-left">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="password"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    Master Enclave Password
                  </label>
                  {/* Clean, subtle Forgot Password link placed directly above the input */}
                  <button
                    type="button"
                    id="link-forgot-password"
                    onClick={() => {
                      clearError();
                      setRecoveryEmail(loginEmail || "");
                      setRecoveryError(null);
                      setActiveTab("forgot_password");
                    }}
                    className="text-[10px] font-mono text-sky-600 hover:text-sky-700 dark:text-sky-400 dark:hover:text-sky-300 hover:underline cursor-pointer transition-colors"
                  >
                    Forgot Password?
                  </button>
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
              {/* Full Name Field */}
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

          {/* ========================================================= */}
          {/* TAB 3: FORGOT PASSWORD (PASSWORD RECOVERY) SCREEN/STATE */}
          {/* ========================================================= */}
          {activeTab === "forgot_password" && (
            <form onSubmit={handleRecoverySubmit} noValidate className="space-y-4 text-left">
              <div className="p-3 border border-sky-500/30 bg-sky-500/10 dark:bg-sky-500/5 text-sky-900 dark:text-sky-300 text-xs font-mono flex items-start gap-2">
                <Mail className="w-4 h-4 shrink-0 mt-0.5 text-sky-600 dark:text-sky-400" />
                <span>
                  AgentGuard will dispatch a 6-digit cryptographic OTP to this email if an account is registered. OTP expires in 10 minutes.
                </span>
              </div>

              {recoveryError && (
                <div className="p-3 border border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400 text-xs font-mono flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{recoveryError}</span>
                </div>
              )}

              {/* Recovery Email Field */}
              <div className="space-y-1.5">
                <label
                  htmlFor="recoveryEmail"
                  className="block text-[11px] font-mono uppercase tracking-wider text-slate-700 dark:text-zinc-300 font-semibold"
                >
                  SecOps Email Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="recoveryEmail"
                    name="recoveryEmail"
                    type="email"
                    autoFocus
                    required
                    autoComplete="email"
                    value={recoveryEmail}
                    onChange={(e) => {
                      setRecoveryEmail(e.target.value);
                      if (recoveryError) setRecoveryError(null);
                    }}
                    placeholder="analyst@corp.security"
                    className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border border-slate-300 dark:border-zinc-700 focus:outline-none focus:border-slate-900 dark:focus:border-zinc-100 rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600"
                  />
                </div>
              </div>

              {/* Submit Recovery Request */}
              <button
                type="submit"
                id="btn-submit-recovery"
                disabled={isRecoverySubmitting}
                className="w-full py-2.5 px-4 bg-slate-900 dark:bg-zinc-50 text-white dark:text-zinc-950 font-mono font-semibold text-xs border border-slate-900 dark:border-zinc-50 hover:bg-slate-800 dark:hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 rounded-none cursor-pointer disabled:opacity-50"
              >
                {isRecoverySubmitting ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white dark:border-zinc-950 border-t-transparent animate-spin inline-block" />
                    <span>Dispatching OTP Token...</span>
                  </>
                ) : (
                  <>
                    <KeyRound className="w-4 h-4" />
                    <span>Send Password Reset OTP</span>
                  </>
                )}
              </button>

              {/* Alternate Jump to Reset Screen if user already has an OTP */}
              <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs font-mono text-slate-600 dark:text-zinc-400">
                <button
                  type="button"
                  onClick={() => {
                    setResetEmail(recoveryEmail || loginEmail);
                    setActiveTab("reset_password");
                  }}
                  className="text-slate-900 dark:text-zinc-200 font-semibold hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  Already have an OTP code? Verify & Reset &rarr;
                </button>
                <button
                  type="button"
                  onClick={() => handleTabChange("signin")}
                  className="text-slate-500 hover:text-slate-900 dark:text-zinc-400 dark:hover:text-zinc-200 hover:underline cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {/* ========================================================= */}
          {/* TAB 4: PASSWORD RESET / OTP VERIFICATION SCREEN */}
          {/* ========================================================= */}
          {activeTab === "reset_password" && (
            <form onSubmit={handleResetSubmit} noValidate className="space-y-3.5 text-left">
              <div className="p-3 border border-emerald-500/30 bg-emerald-500/10 dark:bg-emerald-500/5 text-emerald-900 dark:text-emerald-300 text-xs font-mono flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-600 dark:text-emerald-400" />
                <span>
                  Please enter the 6-digit OTP code received by email along with your desired new password.
                </span>
              </div>

              {/* Reset Email Field */}
              <div className="space-y-1">
                <label
                  htmlFor="resetEmail"
                  className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                >
                  Account Email Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="resetEmail"
                    name="resetEmail"
                    type="email"
                    required
                    autoComplete="email"
                    value={resetEmail}
                    onChange={(e) => {
                      setResetEmail(e.target.value);
                      if (resetErrors.email) {
                        setResetErrors((prev) => ({ ...prev, email: undefined }));
                      }
                    }}
                    placeholder="analyst@corp.security"
                    className={cn(
                      "w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      resetErrors.email
                        ? "border-red-500 focus:border-red-500"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                </div>
                {resetErrors.email && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{resetErrors.email}</span>
                  </p>
                )}
              </div>

              {/* 6-Digit OTP Field */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="resetOtp"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-700 dark:text-zinc-300 font-semibold"
                  >
                    6-Digit Verification OTP <span className="text-red-500">*</span>
                  </label>
                  <span className="text-[10px] font-mono text-slate-400 dark:text-zinc-500">
                    Format: 6 Digits (e.g. 123456)
                  </span>
                </div>
                <div className="relative">
                  <KeyRound className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                  <input
                    id="resetOtp"
                    name="resetOtp"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    autoComplete="one-time-code"
                    value={resetOtp}
                    onChange={(e) => {
                      const digitsOnly = e.target.value.replace(/\D/g, "").slice(0, 6);
                      setResetOtp(digitsOnly);
                      if (resetErrors.otp) {
                        setResetErrors((prev) => ({ ...prev, otp: undefined }));
                      }
                    }}
                    placeholder="000000"
                    className={cn(
                      "w-full pl-9 pr-3 py-2 text-xs font-mono tracking-widest bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                      resetErrors.otp
                        ? "border-red-500 focus:border-red-500 ring-1 ring-red-500/20"
                        : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                    )}
                  />
                </div>
                {resetErrors.otp && (
                  <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>{resetErrors.otp}</span>
                  </p>
                )}
              </div>

              {/* Password and Confirm Password Row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* New Password */}
                <div className="space-y-1">
                  <label
                    htmlFor="newPassword"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    New Password <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                    <input
                      id="newPassword"
                      name="newPassword"
                      type={showNewPassword ? "text" : "password"}
                      value={newPassword}
                      onChange={(e) => {
                        setNewPassword(e.target.value);
                        if (resetErrors.newPassword) {
                          setResetErrors((prev) => ({ ...prev, newPassword: undefined }));
                        }
                      }}
                      placeholder="••••••••"
                      className={cn(
                        "w-full pl-9 pr-8 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                        resetErrors.newPassword
                          ? "border-red-500 focus:border-red-500"
                          : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                      )}
                    />
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        setShowNewPassword(!showNewPassword);
                      }}
                      tabIndex={-1}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors p-0.5 cursor-pointer"
                      aria-label={showNewPassword ? "Hide password" : "Show password"}
                    >
                      {showNewPassword ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  {resetErrors.newPassword && (
                    <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3 shrink-0" />
                      <span>{resetErrors.newPassword}</span>
                    </p>
                  )}
                </div>

                {/* Confirm New Password */}
                <div className="space-y-1">
                  <label
                    htmlFor="confirmNewPassword"
                    className="block text-[11px] font-mono uppercase tracking-wider text-slate-600 dark:text-zinc-400 font-medium"
                  >
                    Confirm Password <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 pointer-events-none" />
                    <input
                      id="confirmNewPassword"
                      name="confirmNewPassword"
                      type={showConfirmNewPassword ? "text" : "password"}
                      value={confirmNewPassword}
                      onChange={(e) => {
                        setConfirmNewPassword(e.target.value);
                        if (resetErrors.confirmNewPassword) {
                          setResetErrors((prev) => ({
                            ...prev,
                            confirmNewPassword: undefined,
                          }));
                        }
                      }}
                      placeholder="••••••••"
                      className={cn(
                        "w-full pl-9 pr-8 py-2 text-xs font-mono bg-slate-50 dark:bg-zinc-950 text-slate-900 dark:text-zinc-50 border rounded-none transition-colors placeholder-slate-400 dark:placeholder-zinc-600 focus:outline-none",
                        resetErrors.confirmNewPassword
                          ? "border-red-500 focus:border-red-500"
                          : "border-slate-300 dark:border-zinc-700 focus:border-slate-900 dark:focus:border-zinc-100"
                      )}
                    />
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        setShowConfirmNewPassword(!showConfirmNewPassword);
                      }}
                      tabIndex={-1}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors p-0.5 cursor-pointer"
                      aria-label={showConfirmNewPassword ? "Hide password" : "Show password"}
                    >
                      {showConfirmNewPassword ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  {resetErrors.confirmNewPassword && (
                    <p className="text-red-500 dark:text-red-400 text-[10px] font-mono mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3 shrink-0" />
                      <span>{resetErrors.confirmNewPassword}</span>
                    </p>
                  )}
                </div>
              </div>

              {/* Submit Finalize Password Change Button */}
              <button
                type="submit"
                id="btn-finalize-reset"
                disabled={isResetSubmitting}
                className="w-full mt-2 py-2.5 px-4 bg-slate-900 dark:bg-zinc-50 text-white dark:text-zinc-950 font-mono font-semibold text-xs border border-slate-900 dark:border-zinc-50 hover:bg-slate-800 dark:hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 rounded-none cursor-pointer disabled:opacity-50"
              >
                {isResetSubmitting ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white dark:border-zinc-950 border-t-transparent animate-spin inline-block" />
                    <span>Verifying OTP & Updating...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Verify OTP & Update Password</span>
                  </>
                )}
              </button>

              {/* Resend OTP / Cancel Actions */}
              <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs font-mono text-slate-600 dark:text-zinc-400">
                <button
                  type="button"
                  onClick={() => {
                    setRecoveryEmail(resetEmail);
                    setActiveTab("forgot_password");
                  }}
                  className="text-slate-900 dark:text-zinc-200 font-semibold hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Resend OTP Token</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleTabChange("signin")}
                  className="text-slate-500 hover:text-slate-900 dark:text-zinc-400 dark:hover:text-zinc-200 hover:underline cursor-pointer"
                >
                  Cancel & Return to Sign In
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
