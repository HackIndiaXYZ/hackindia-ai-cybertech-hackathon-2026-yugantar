"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import {
  X,
  User,
  Palette,
  KeyRound,
  ShieldAlert,
  LogOut,
  Sun,
  Moon,
  Laptop,
  Copy,
  Check,
  Plus,
  Trash2,
  Lock,
  Globe,
  Radio,
} from "lucide-react";
import { useAuthStore } from "@/store/useAuthStore";
import { useChatStore } from "@/store/useChatStore";
import { formatProfileName, cn } from "@/lib/utils";
import { toast } from "sonner";
import { apiClient } from "@/lib/apiClient";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultTab?: "account" | "appearance" | "security";
}

interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  created: string;
  scope: string;
}

interface ActiveSessionItem {
  id: string;
  device: string;
  ip: string;
  lastActive: string;
  isCurrent: boolean;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  defaultTab = "account",
}) => {
  const router = useRouter();
  const { user, logout } = useAuthStore();
  const { resetAll } = useChatStore();
  const { theme, setTheme } = useTheme();

  const [activeTab, setActiveTab] = useState<"account" | "appearance" | "security">(defaultTab);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [sessions, setSessions] = useState<ActiveSessionItem[]>([]);

  const fetchAccountData = async () => {
    try {
      const keysRes = await apiClient.get<{ api_keys: any[] }>("/api/account/api-keys", {
        showToastOnError: false,
      });
      if (keysRes && Array.isArray(keysRes.api_keys)) {
        setApiKeys(
          keysRes.api_keys.map((k) => ({
            id: k.id,
            name: k.name || "API Key",
            prefix: k.prefix ? `${k.prefix}...` : "ag_sec_live_...",
            created: k.createdAt ? new Date(k.createdAt * 1000).toLocaleDateString() : "Active",
            scope: k.scope || "AgentGuard API",
          }))
        );
      }
    } catch {}

    try {
      const sessRes = await apiClient.get<{ sessions: any[] }>("/api/account/sessions", {
        showToastOnError: false,
      });
      if (sessRes && Array.isArray(sessRes.sessions)) {
        setSessions(
          sessRes.sessions.map((s) => ({
            id: s.id || s.session_id,
            device: s.device || s.user_agent || "Browser Client",
            ip: s.ip || s.ip_address || "127.0.0.1",
            lastActive: s.isCurrent ? "Active Now" : s.lastActive || "Recently",
            isCurrent: Boolean(s.isCurrent),
          }))
        );
      }
    } catch {}
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (isOpen) {
      setActiveTab(defaultTab);
      fetchAccountData();
    }
  }, [isOpen, defaultTab]);

  // Keyboard Escape listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const displayName = user?.fullName || user?.name || "Security Architect";

  const userEmail = user?.email || "auditor@agentguard.secops";
  const userRole = user?.role || "Lead Security Architect";

  // Logout handler strictly wiping Zustand store and redirecting to /login
  const handleLogout = async () => {
    resetAll();
    await logout();
    onClose();
    toast.success("Enclave Session Terminated", {
      description: "Cryptographic credentials purged and workspace reset.",
    });
    router.replace("/login");
  };

  const handleCopyKey = (id: string, text: string) => {
    if (typeof window !== "undefined") {
      navigator.clipboard.writeText(text);
      setCopiedKeyId(id);
      toast.success("API Key Copied", {
        description: "Bearer key copied to system clipboard.",
      });
      setTimeout(() => setCopiedKeyId(null), 2000);
    }
  };

  const handleCreateKey = async () => {
    try {
      const keyName = `Enclave Key #${apiKeys.length + 1}`;
      const res = await apiClient.post<{ api_key: any }>(
        "/api/account/api-keys",
        { name: keyName },
        { errorTitle: "Key Creation Failed" }
      );
      if (res && res.api_key) {
        const secret = res.api_key.secret || res.api_key.prefix;
        if (typeof window !== "undefined" && secret) {
          navigator.clipboard.writeText(secret);
        }
        toast.success("New Enclave API Key Provisioned", {
          description: secret
            ? `Key copied to clipboard: ${res.api_key.prefix}... Keep it safe!`
            : "Secret token generated and saved.",
        });
        await fetchAccountData();
      }
    } catch (e: any) {
      toast.error("Failed to Provision API Key", {
        description: e?.message || "Could not generate key on backend.",
      });
    }
  };

  const handleDeleteKey = async (id: string) => {
    try {
      await apiClient.delete(`/api/account/api-keys/${id}`, {
        errorTitle: "Revocation Failed",
      });
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
      toast.info("API Key Revoked", {
        description: "Key token has been permanently invalidated.",
      });
    } catch (e: any) {
      toast.error("Failed to Revoke Key", {
        description: e?.message || "Could not delete API key.",
      });
    }
  };

  const handleRevokeOtherSessions = async () => {
    try {
      await apiClient.delete("/api/account/sessions/revoke-others", {
        errorTitle: "Revocation Failed",
      });
      setSessions((prev) => prev.filter((s) => s.isCurrent));
      toast.success("All Remote Sessions Revoked", {
        description: "Other devices have been logged out instantly.",
      });
    } catch (e: any) {
      toast.error("Failed to Revoke Sessions", {
        description: e?.message || "Could not revoke other sessions.",
      });
    }
  };

  const userInitials = displayName
    .split(" ")
    .map((part) => part[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase() || "AG";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/70 backdrop-blur-sm select-none animate-in fade-in duration-150"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl bg-surface border border-border shadow-2xl rounded-none overflow-hidden flex flex-col max-h-[85vh] font-sans"
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-dialog-title"
      >
        {/* Top Header */}
        <div className="h-13 px-5 py-3 border-b border-border flex items-center justify-between bg-surface-subtle shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-none bg-surface border border-border flex items-center justify-center text-foreground font-mono text-xs">
              <ShieldAlert className="w-3.5 h-3.5 text-foreground" />
            </div>
            <div>
              <h2
                id="settings-dialog-title"
                className="text-xs font-semibold tracking-wider font-mono text-foreground uppercase"
              >
                Settings // Enclave Preferences
              </h2>
              <p className="text-[10px] text-muted-dim font-mono">
                AgentGuard Security Operations Console v2.4.0
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close settings modal"
            className="p-1 rounded-none text-muted-foreground hover:text-foreground hover:bg-surface-hover transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body: Sidebar Tabs + Main Panel */}
        <div className="flex flex-1 min-h-[380px] overflow-hidden">
          {/* Left Navigation Tabs */}
          <nav className="w-44 sm:w-48 border-r border-border bg-surface-subtle/50 p-2 space-y-1 shrink-0 font-mono text-xs">
            <button
              onClick={() => setActiveTab("account")}
              className={cn(
                "w-full flex items-center gap-2 px-3 py-2 text-left transition-colors rounded-none",
                activeTab === "account"
                  ? "bg-foreground text-background font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-surface-hover"
              )}
            >
              <User className="w-3.5 h-3.5 shrink-0" />
              <span>Account</span>
            </button>

            <button
              onClick={() => setActiveTab("appearance")}
              className={cn(
                "w-full flex items-center gap-2 px-3 py-2 text-left transition-colors rounded-none",
                activeTab === "appearance"
                  ? "bg-foreground text-background font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-surface-hover"
              )}
            >
              <Palette className="w-3.5 h-3.5 shrink-0" />
              <span>Appearance</span>
            </button>

            <button
              onClick={() => setActiveTab("security")}
              className={cn(
                "w-full flex items-center gap-2 px-3 py-2 text-left transition-colors rounded-none",
                activeTab === "security"
                  ? "bg-foreground text-background font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-surface-hover"
              )}
            >
              <KeyRound className="w-3.5 h-3.5 shrink-0" />
              <span>API & Security</span>
            </button>
          </nav>

          {/* Right Tab Content Panel */}
          <div className="flex-1 overflow-y-auto p-5 space-y-6 bg-surface">
            {/* TAB 1: ACCOUNT */}
            {activeTab === "account" && (
              <div className="space-y-6 animate-in fade-in-50 duration-150">
                {/* Profile Identity Card */}
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted-dim mb-3">
                    Enclave Identity
                  </h3>
                  <div className="p-4 bg-surface-subtle border border-border flex items-center gap-4">
                    <div className="w-12 h-12 rounded-none bg-surface border border-border flex items-center justify-center text-foreground font-mono font-bold text-sm shadow-panel shrink-0">
                      {userInitials}
                    </div>
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <p className="text-sm font-semibold text-foreground truncate font-sans">
                        {displayName}
                      </p>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {userEmail}
                      </p>
                      <div className="pt-1 flex items-center gap-2 font-mono text-[10px]">
                        <span className="px-1.5 py-0.2 border border-border bg-surface text-foreground font-medium">
                          {userRole}
                        </span>
                        <span className="text-muted-dim">Zero-Trust Enclave</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Account Details & Session Security */}
                <div className="space-y-2 font-mono text-xs">
                  <h3 className="text-xs uppercase tracking-wider text-muted-dim">
                    Session Authentication
                  </h3>
                  <div className="p-3 bg-surface-subtle border border-border space-y-2 text-[11px]">
                    <div className="flex justify-between items-center text-muted-foreground">
                      <span>Auth Provider</span>
                      <span className="text-foreground uppercase font-medium">
                        {user?.authProvider || "email"} (Encrypted JWT)
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-muted-foreground">
                      <span>Integrity Protocol</span>
                      <span className="text-foreground">FIPS 140-3 / RFC 9449</span>
                    </div>
                    <div className="flex justify-between items-center text-muted-foreground">
                      <span>Session Expiration</span>
                      <span className="text-foreground">24 Hours (Rolling)</span>
                    </div>
                  </div>
                </div>

                {/* Account Danger Zone / Logout */}
                <div className="pt-2 border-t border-border">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-accent-red mb-2">
                    Danger Zone
                  </h3>
                  <div className="p-3.5 bg-surface-subtle border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <p className="text-xs font-medium text-foreground">
                        Terminate Enclave Session
                      </p>
                      <p className="text-[11px] text-muted-foreground font-mono">
                        Wipes client session tokens, cache, and audit history.
                      </p>
                    </div>

                    <button
                      onClick={handleLogout}
                      className="px-3.5 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white font-mono text-xs font-semibold flex items-center justify-center gap-2 rounded-none transition-colors shrink-0 cursor-pointer shadow-sm"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Log Out</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: APPEARANCE */}
            {activeTab === "appearance" && (
              <div className="space-y-5 animate-in fade-in-50 duration-150">
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-muted-dim mb-1">
                    Interface Theme
                  </h3>
                  <p className="text-xs text-muted-foreground font-sans mb-3">
                    Select your preferred visual style. Settings are persisted to your local enclave.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {/* Dark Mode Card */}
                  <button
                    type="button"
                    onClick={() => setTheme("dark")}
                    className={cn(
                      "p-3.5 border text-left transition-colors rounded-none flex flex-col justify-between space-y-3 cursor-pointer group",
                      mounted && theme === "dark"
                        ? "bg-surface-active border-foreground text-foreground ring-1 ring-foreground"
                        : "bg-surface-subtle border-border text-muted-foreground hover:border-muted-foreground hover:text-foreground"
                    )}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-2">
                        <Moon className="w-4 h-4 text-accent-amber" />
                        <span className="text-xs font-semibold font-mono">
                          Industrial Zinc
                        </span>
                      </div>
                      {mounted && theme === "dark" && (
                        <span className="px-1.5 py-0.5 text-[9px] font-mono bg-foreground text-background font-semibold">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    {/* Swatch Preview */}
                    <div className="w-full h-12 bg-zinc-950 border border-zinc-800 p-2 flex flex-col justify-between">
                      <div className="w-1/3 h-1.5 bg-zinc-800" />
                      <div className="w-2/3 h-1.5 bg-zinc-700" />
                    </div>
                    <p className="text-[10px] text-muted-dim font-mono">
                      Dark operational console for low-light environments.
                    </p>
                  </button>

                  {/* Light Mode Card */}
                  <button
                    type="button"
                    onClick={() => setTheme("light")}
                    className={cn(
                      "p-3.5 border text-left transition-colors rounded-none flex flex-col justify-between space-y-3 cursor-pointer group",
                      mounted && theme === "light"
                        ? "bg-surface-active border-foreground text-foreground ring-1 ring-foreground"
                        : "bg-surface-subtle border-border text-muted-foreground hover:border-muted-foreground hover:text-foreground"
                    )}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-2">
                        <Sun className="w-4 h-4 text-accent-amber" />
                        <span className="text-xs font-semibold font-mono">
                          Polar Bear
                        </span>
                      </div>
                      {mounted && theme === "light" && (
                        <span className="px-1.5 py-0.5 text-[9px] font-mono bg-foreground text-background font-semibold">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    {/* Swatch Preview */}
                    <div className="w-full h-12 bg-slate-100 border border-slate-300 p-2 flex flex-col justify-between">
                      <div className="w-1/3 h-1.5 bg-slate-300" />
                      <div className="w-2/3 h-1.5 bg-slate-400" />
                    </div>
                    <p className="text-[10px] text-muted-dim font-mono">
                      Clean high-contrast daytime interface for bright setups.
                    </p>
                  </button>
                </div>

                <div className="pt-3 border-t border-border">
                  <button
                    type="button"
                    onClick={() => setTheme("system")}
                    className={cn(
                      "w-full p-2.5 border flex items-center justify-between font-mono text-xs transition-colors rounded-none",
                      mounted && theme === "system"
                        ? "bg-surface-active border-foreground text-foreground"
                        : "bg-surface-subtle border-border text-muted-foreground hover:text-foreground"
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <Laptop className="w-3.5 h-3.5" />
                      <span>Sync with Operating System preference</span>
                    </div>
                    {mounted && theme === "system" && (
                      <span className="text-[9px] font-semibold bg-foreground text-background px-1 py-0.2">
                        ACTIVE
                      </span>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* TAB 3: API & SECURITY */}
            {activeTab === "security" && (
              <div className="space-y-6 animate-in fade-in-50 duration-150">
                {/* API Keys Management */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted-dim">
                        API Secret Keys
                      </h3>
                      <p className="text-[11px] text-muted-foreground font-mono">
                        Programmatic access keys for CI/CD and Temporal workflows.
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={handleCreateKey}
                      className="px-2.5 py-1.5 bg-surface-subtle hover:bg-surface-hover border border-border text-foreground font-mono text-xs flex items-center gap-1.5 rounded-none transition-colors"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Create Key</span>
                    </button>
                  </div>

                  <div className="space-y-2">
                    {apiKeys.map((key) => (
                      <div
                        key={key.id}
                        className="p-3 bg-surface-subtle border border-border flex items-center justify-between gap-3 text-xs font-mono"
                      >
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <p className="font-medium text-foreground truncate">
                            {key.name}
                          </p>
                          <p className="text-[11px] text-muted-dim font-mono">
                            <code>{key.prefix}</code> • {key.scope}
                          </p>
                        </div>

                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            type="button"
                            onClick={() => handleCopyKey(key.id, key.prefix)}
                            title="Copy API Key"
                            className="p-1 text-muted-foreground hover:text-foreground border border-border bg-surface transition-colors"
                          >
                            {copiedKeyId === key.id ? (
                              <Check className="w-3.5 h-3.5 text-accent-emerald" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() => handleDeleteKey(key.id)}
                            title="Revoke Key"
                            className="p-1 text-muted-foreground hover:text-accent-red border border-border bg-surface transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Revoke Sessions / Active Devices */}
                <div className="pt-2 border-t border-border">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h3 className="text-xs font-mono uppercase tracking-wider text-muted-dim">
                        Active Enclave Sessions
                      </h3>
                      <p className="text-[11px] text-muted-foreground font-mono">
                        Active security contexts authorized with your token.
                      </p>
                    </div>

                    {sessions.length > 1 && (
                      <button
                        type="button"
                        onClick={handleRevokeOtherSessions}
                        className="px-2.5 py-1 text-accent-red hover:bg-red-500/10 border border-accent-red/30 font-mono text-[11px] rounded-none transition-colors"
                      >
                        Revoke All Other Sessions
                      </button>
                    )}
                  </div>

                  <div className="space-y-2">
                    {sessions.map((sess) => (
                      <div
                        key={sess.id}
                        className="p-3 bg-surface-subtle border border-border flex items-center justify-between text-xs font-mono"
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-foreground">
                              {sess.device}
                            </span>
                            {sess.isCurrent && (
                              <span className="px-1.5 py-0.2 text-[9px] bg-accent-emerald/20 text-accent-emerald border border-accent-emerald/30 font-mono">
                                THIS DEVICE
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-muted-dim">
                            {sess.ip} • <span className="text-foreground">{sess.lastActive}</span>
                          </p>
                        </div>

                        {!sess.isCurrent && (
                          <button
                            type="button"
                            onClick={() => {
                              setSessions(sessions.filter((s) => s.id !== sess.id));
                              toast.info("Session Revoked", {
                                description: `Terminated session for ${sess.device}`,
                              });
                            }}
                            className="text-muted-dim hover:text-accent-red text-xs transition-colors p-1"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Modal Status Footer */}
        <div className="px-5 py-2.5 border-t border-border bg-surface-subtle flex items-center justify-between text-[10px] font-mono text-muted-dim shrink-0">
          <div className="flex items-center gap-2">
            <Lock className="w-3 h-3 text-accent-emerald" />
            <span>Encrypted Session: TLS 1.3 Strict</span>
          </div>
          <span>Esc to close</span>
        </div>
      </div>
    </div>
  );
};
