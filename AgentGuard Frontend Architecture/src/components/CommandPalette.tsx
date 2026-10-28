"use client";
//ok
import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import { useTheme } from "next-themes";
import {
  Shield,
  Zap,
  FileCheck,
  Sun,
  Moon,
  Trash2,
  FileText,
  Plus,
  Search,
  Terminal,
  CornerDownLeft,
} from "lucide-react";
import { useChatStore, AnalysisMode } from "@/store/useChatStore";
import { useAuthStore } from "@/store/useAuthStore";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const CommandPalette: React.FC = () => {
  const router = useRouter();
  const {
    isCommandPaletteOpen,
    setCommandPaletteOpen,
    setMode,
    resetSession,
    toggleSplitView,
    isSplitViewOpen,
    sessions,
    selectSession,
    currentMode,
  } = useChatStore();

  const { theme, setTheme } = useTheme();

  // Global Keyboard Listener for Cmd+K (Mac) or Ctrl+K (Windows)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen(!isCommandPaletteOpen);
      } else if (e.key === "Escape" && isCommandPaletteOpen) {
        e.preventDefault();
        setCommandPaletteOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isCommandPaletteOpen, setCommandPaletteOpen]);

  if (!isCommandPaletteOpen) return null;

  const handleSelectMode = (mode: AnalysisMode, label: string) => {
    setMode(mode);
    setCommandPaletteOpen(false);
    toast.success(`Active Mode: ${label}`, {
      description: "SecOps heuristics updated for upcoming execution.",
    });
  };

  const handleToggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    setCommandPaletteOpen(false);
    toast.success(
      nextTheme === "dark"
        ? "Industrial Zinc Theme Activated"
        : "Polar Bear Light Theme Activated"
    );
  };

  const handleClearHistory = () => {
    resetSession();
    setCommandPaletteOpen(false);
    toast.success("Audit Session & History Purged", {
      description: "Chat messages and audit history have been completely reset.",
    });
  };

  const handleToggleSplit = () => {
    toggleSplitView();
    setCommandPaletteOpen(false);
    toast.info(
      isSplitViewOpen
        ? "Pro Analyst Split View Closed"
        : "Pro Analyst Split View Opened"
    );
  };

  const handleNewAudit = () => {
    resetSession();
    setCommandPaletteOpen(false);
    toast.success("New Security Audit Initialized", {
      description: "Clean workspace and fresh session initialized.",
    });
  };

  const handleSelectPastSession = (id: string, title: string) => {
    selectSession(id);
    setCommandPaletteOpen(false);
    toast.info(`Switched to session: ${title}`);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] px-4 bg-black/60 backdrop-blur-sm select-none"
      onClick={() => setCommandPaletteOpen(false)}
      role="dialog"
      aria-modal="true"
      aria-label="Global Command Palette"
    >
      {/* Modal Card - Strictly Industrial, sharp slate/zinc borders */}
      <div
        className="w-full max-w-xl bg-surface border border-border shadow-2xl rounded-none overflow-hidden font-mono text-foreground"
        onClick={(e) => e.stopPropagation()}
      >
        <Command
          label="Global Command Palette"
          className="w-full flex flex-col bg-surface"
        >
          {/* Top Search Input Row */}
          <div className="flex items-center gap-2.5 px-3.5 py-3 border-b border-border bg-surface-subtle">
            <Search className="w-4 h-4 text-muted-dim shrink-0" />
            <Command.Input
              autoFocus
              placeholder="Type a command or search actions..."
              className="w-full bg-transparent text-xs font-mono text-foreground placeholder-muted-dim focus:outline-none"
            />
            <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono border border-border bg-surface text-muted-dim">
              ESC
            </kbd>
          </div>

          {/* Scrollable Command List */}
          <Command.List className="max-h-80 overflow-y-auto p-2 space-y-2 text-xs">
            <Command.Empty className="py-6 text-center text-xs text-muted-dim font-mono">
              No matching commands found.
            </Command.Empty>

            {/* 1. Core Security Modes */}
            <Command.Group
              heading="SECURITY AUDIT MODES"
              className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-dim [&_[cmdk-group-heading]]:uppercase"
            >
              <Command.Item
                onSelect={() =>
                  handleSelectMode("deep_audit", "Deep Security Audit")
                }
                className={cn(
                  "flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent rounded-none",
                  "hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border",
                  currentMode === "deep_audit" && "font-semibold"
                )}
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">🚀</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      Start Deep Security Audit
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Full STRIDE threat model, AST parsing, and zero-trust verification
                    </span>
                  </div>
                </div>
                <CornerDownLeft className="w-3.5 h-3.5 text-muted-dim opacity-60" />
              </Command.Item>

              <Command.Item
                onSelect={() =>
                  handleSelectMode("quick_scan", "Quick Vulnerability Scan")
                }
                className={cn(
                  "flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent rounded-none",
                  "hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border",
                  currentMode === "quick_scan" && "font-semibold"
                )}
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">⚡</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      Quick Vulnerability Scan
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Rapid CVE correlation and high-entropy secret detection
                    </span>
                  </div>
                </div>
                <CornerDownLeft className="w-3.5 h-3.5 text-muted-dim opacity-60" />
              </Command.Item>

              <Command.Item
                onSelect={() =>
                  handleSelectMode("policy_check", "Policy Compliance Check")
                }
                className={cn(
                  "flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent rounded-none",
                  "hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border",
                  currentMode === "policy_check" && "font-semibold"
                )}
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">📋</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      Policy Compliance Check
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Validate against SOC 2 Type II, ISO 27001, HIPAA & GDPR
                    </span>
                  </div>
                </div>
                <CornerDownLeft className="w-3.5 h-3.5 text-muted-dim opacity-60" />
              </Command.Item>
            </Command.Group>

            {/* 2. Workspace & System Actions */}
            <Command.Group
              heading="SYSTEM & WORKSPACE"
              className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-dim [&_[cmdk-group-heading]]:uppercase"
            >
              <Command.Item
                onSelect={handleToggleTheme}
                className="flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border rounded-none"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">🌓</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      Toggle Theme (Light / Dark)
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Switch between Industrial Zinc and Polar Bear Frost
                    </span>
                  </div>
                </div>
                <span className="text-[10px] font-mono border border-border px-1.5 py-0.5 text-muted-dim bg-surface-subtle">
                  {theme === "dark" ? "Dark Active" : "Light Active"}
                </span>
              </Command.Item>

              <Command.Item
                onSelect={handleClearHistory}
                className="flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border rounded-none text-accent-red"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">🗑️</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      Clear Chat History
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Reset messages and telemetry state for current session
                    </span>
                  </div>
                </div>
                <CornerDownLeft className="w-3.5 h-3.5 text-muted-dim opacity-60" />
              </Command.Item>

              <Command.Item
                onSelect={handleToggleSplit}
                className="flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border rounded-none"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">📄</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      {isSplitViewOpen
                        ? "Disable Pro Analyst Split View"
                        : "Enable Pro Analyst Split View"}
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      {isSplitViewOpen
                        ? "Hide PDF document preview pane"
                        : "Show PDF document preview side-by-side with chat"}
                    </span>
                  </div>
                </div>
                <span className="text-[10px] font-mono border border-border px-1.5 py-0.5 text-muted-dim bg-surface-subtle font-semibold">
                  {isSplitViewOpen ? "SPLIT: ON" : "SPLIT: OFF"}
                </span>
              </Command.Item>

              <Command.Item
                onSelect={handleNewAudit}
                className="flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border rounded-none"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">➕</span>
                  <div className="flex flex-col">
                    <span className="text-foreground text-xs">
                      New Security Audit Session
                    </span>
                    <span className="text-[10px] text-muted-dim">
                      Start clean analysis workspace
                    </span>
                  </div>
                </div>
                <CornerDownLeft className="w-3.5 h-3.5 text-muted-dim opacity-60" />
              </Command.Item>
            </Command.Group>

            {/* 3. Session Navigation */}
            {sessions.length > 0 && (
              <Command.Group
                heading="AUDIT SESSIONS"
                className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-dim [&_[cmdk-group-heading]]:uppercase"
              >
                {sessions.slice(0, 3).map((session) => (
                  <Command.Item
                    key={session.id}
                    onSelect={() =>
                      handleSelectPastSession(session.id, session.title)
                    }
                    className="flex items-center justify-between px-2.5 py-2 cursor-pointer transition-colors border border-transparent hover:bg-surface-hover hover:border-border data-[selected=true]:bg-surface-active data-[selected=true]:border-border rounded-none"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Terminal className="w-3.5 h-3.5 text-muted-dim shrink-0" />
                      <span className="text-foreground text-xs truncate">
                        {session.title}
                      </span>
                    </div>
                    <span className="text-[10px] text-muted-dim font-mono shrink-0">
                      {session.date}
                    </span>
                  </Command.Item>
                ))}
              </Command.Group>
            )}
          </Command.List>

          {/* Bottom Industrial Status Bar */}
          <div className="px-3.5 py-2 border-t border-border bg-surface-subtle flex items-center justify-between text-[10px] text-muted-dim select-none">
            <div className="flex items-center gap-3">
              <span>
                <kbd className="px-1 py-0.2 border border-border bg-surface text-foreground font-semibold">
                  ↑↓
                </kbd>{" "}
                navigate
              </span>
              <span>
                <kbd className="px-1 py-0.2 border border-border bg-surface text-foreground font-semibold">
                  ↵
                </kbd>{" "}
                select
              </span>
              <span>
                <kbd className="px-1 py-0.2 border border-border bg-surface text-foreground font-semibold">
                  esc
                </kbd>{" "}
                exit
              </span>
            </div>
            <span className="hidden sm:inline font-mono">
              AgentGuard CLI Engine v2.4
            </span>
          </div>
        </Command>
      </div>
    </div>
  );
};
