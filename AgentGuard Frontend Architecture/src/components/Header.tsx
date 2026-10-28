"use client";
//ok
import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  PanelLeftClose,
  PanelLeftOpen,
  Trash2,
  Share2,
  LogOut,
  UserCheck,
} from "lucide-react";
import { useChatStore } from "@/store/useChatStore";
import { useAuthStore } from "@/store/useAuthStore";
import { ANALYSIS_MODES, cn, formatProfileName } from "@/lib/utils";
import { toast } from "sonner";

export const Header: React.FC = () => {
  const router = useRouter();
  const { user, logout, initializeAuth } = useAuthStore();
  const {
    isSidebarOpen,
    toggleSidebar,
    currentMode,
    currentSessionId,
    sessions,
    messages,
    resetSession,
    resetAll,
    isSplitViewOpen,
    toggleSplitView,
    activeDocument,
    toggleCommandPalette,
  } = useChatStore();

  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

  const currentSession = sessions.find((s) => s.id === currentSessionId);
  const modeMeta = ANALYSIS_MODES[currentMode];
  const ModeIcon = modeMeta.icon;

  const handleShare = () => {
    if (messages.length === 0) {
      toast.info("No audit logs to export");
      return;
    }
    if (typeof window !== "undefined") {
      navigator.clipboard.writeText(window.location.href);
      toast.success("Audit session link copied");
    }
  };

  const handleLogout = async () => {
    resetAll();
    await logout();
    toast.success("Enclave Session Terminated", {
      description: "Cryptographic credentials purged. Redirecting to login...",
    });
    router.push("/login");
  };

  return (
    <header className="h-12 border-b border-border bg-surface shadow-panel px-4 flex items-center justify-between shrink-0 z-20 select-none">
      <div className="flex items-center gap-3">
        {/* Render ONLY when sidebar is closed (!isSidebarOpen) */}
        {!isSidebarOpen && (
          <>
            <button
              onClick={toggleSidebar}
              aria-label="Expand sidebar"
              title="Expand sidebar"
              className="p-1 rounded-sm text-muted-foreground hover:text-foreground hover:bg-surface-hover transition-colors"
            >
              <PanelLeftOpen className="w-4 h-4" />
            </button>
            <div className="h-4 w-[1px] bg-border" />
          </>
        )}

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-foreground truncate max-w-[200px] sm:max-w-xs md:max-w-md font-mono">
            {currentSession?.title || "New Security Audit Session"}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* Pro Analyst Split Mode Toggle Pill */}
        {activeDocument && messages.length > 0 && (
          <button
            onClick={toggleSplitView}
            title={
              isSplitViewOpen
                ? "Close Pro Analyst Split Preview"
                : "Open Pro Analyst Split Preview"
            }
            aria-label="Toggle Pro Analyst Split Preview"
            className={cn(
              "flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-mono border transition-colors",
              isSplitViewOpen
                ? "border-foreground bg-foreground text-background font-semibold"
                : "border-border bg-surface-subtle text-muted-foreground hover:text-foreground hover:bg-surface-hover"
            )}
          >
            <span>📄</span>
            <span className="hidden sm:inline">Pro Analyst:</span>
            <span>{isSplitViewOpen ? "Split ON" : "Split OFF"}</span>
          </button>
        )}

        {/* Global Command Palette Trigger Button */}
        <button
          onClick={toggleCommandPalette}
          title="Open Command Palette (Ctrl+K / ⌘K)"
          aria-label="Open Command Palette"
          className="flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-mono border border-border bg-surface-subtle text-muted-foreground hover:text-foreground hover:bg-surface-hover transition-colors"
        >
          <span className="hidden md:inline">Command</span>
          <kbd className="px-1 py-0.2 text-[9px] bg-surface border border-border text-foreground font-semibold">
            ⌘K
          </kbd>
        </button>

        {/* Active Mode Pill */}
        <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-mono border border-border bg-surface-subtle text-foreground">
          <ModeIcon className="w-3 h-3 text-muted-foreground" />
          <span>{modeMeta.label}</span>
        </div>

        {/* Temporal Cluster Status */}
        <div className="hidden lg:flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-mono border border-border bg-surface-subtle text-muted-foreground">
          <span className="w-1.5 h-1.5 rounded-none bg-accent-emerald" />
          <span>Temporal:</span>
          <span className="text-foreground">Online</span>
        </div>

        {/* Authenticated Enclave Identity & Logout */}
        {user ? (
          <div className="flex items-center gap-1.5 pl-1.5 border-l border-border">
            <div
              title={`Authenticated Auditor: ${user.fullName || user.name} (${user.email})`}
              className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-mono border border-border bg-surface-subtle text-foreground"
            >
              <UserCheck className="w-3 h-3 text-accent-emerald shrink-0" />
              <span className="truncate max-w-[150px] font-medium">
                {user.fullName || user.name}
              </span>
            </div>
            <button
              onClick={handleLogout}
              title="Terminate Enclave Session (Logout)"
              aria-label="Terminate Enclave Session"
              className="p-1 rounded-sm text-muted-foreground hover:text-accent-red hover:bg-surface-hover border border-transparent hover:border-border transition-colors flex items-center gap-1 text-[11px] font-mono"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden xl:inline text-[10px]">Logout</span>
            </button>
          </div>
        ) : null}

        {/* Actions */}
        {messages.length > 0 && (
          <div className="flex items-center gap-1">
            <button
              onClick={handleShare}
              title="Share Session"
              aria-label="Share Session"
              className="p-1.5 rounded-sm text-muted-foreground hover:text-foreground hover:bg-surface-hover border border-border transition-colors"
            >
              <Share2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={resetSession}
              title="Clear Session Messages and History"
              aria-label="Clear Session Messages and History"
              className="p-1.5 rounded-sm text-muted-foreground hover:text-accent-red hover:bg-surface-hover border border-border transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
