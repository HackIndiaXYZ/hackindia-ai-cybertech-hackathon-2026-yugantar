"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  Plus,
  Trash2,
  ChevronLeft,
  Search,
  Activity,
  History,
  Settings,
} from "lucide-react";
import { useChatStore, AnalysisMode } from "@/store/useChatStore";
import { useAuthStore } from "@/store/useAuthStore";
import { SettingsModal } from "./SettingsModal";
import { cn, formatProfileName } from "@/lib/utils";

export const Sidebar: React.FC = () => {
  const {
    sessions,
    currentSessionId,
    isSidebarOpen,
    toggleSidebar,
    startNewSession,
    selectSession,
    deleteSession,
    loadHistory,
  } = useChatStore();

  const { user, isAuthenticated } = useAuthStore();
  const [searchQuery, setSearchQuery] = useState("");
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      loadHistory();
    }
  }, [isAuthenticated, loadHistory]);

  const filteredSessions = sessions.filter((s) =>
    s.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getModeTag = (mode: AnalysisMode) => {
    switch (mode) {
      case "deep_audit":
        return "[AUDIT]";
      case "quick_scan":
        return "[SCAN]";
      case "policy_check":
        return "[POLICY]";
    }
  };

  const userDisplayName = user?.fullName || user?.name || "Security Architect";

  const userEmail = user?.email || "auditor@agentguard.secops";

  const userInitials = userDisplayName
    .split(" ")
    .map((part) => part[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase() || "AG";

  return (
    <>
      <AnimatePresence initial={false}>
        {isSidebarOpen && (
          <motion.aside
            key="sidebar-expanded"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 280, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            className="h-screen bg-surface border-r border-border shadow-panel flex flex-col relative z-30 shrink-0 overflow-hidden select-none"
          >
            {/* Top Brand Header */}
            <div className="h-12 px-4 border-b border-border flex items-center justify-between shrink-0">
              <Link
                href="/"
                title="AgentGuard Security Operations Dashboard"
                className="flex items-center gap-2.5 hover:opacity-85 transition-opacity cursor-pointer group"
              >
                <div className="w-6 h-6 rounded-none bg-surface-subtle border border-border flex items-center justify-center text-foreground group-hover:border-foreground transition-colors">
                  <ShieldAlert className="w-3.5 h-3.5" />
                </div>
                <div className="flex flex-col">
                  <span className="text-xs font-semibold tracking-wider text-foreground font-mono">
                    AGENTGUARD
                  </span>
                  <span className="text-[9px] text-muted-dim tracking-widest font-mono uppercase">
                    SecOps AI Engine
                  </span>
                </div>
              </Link>

              <button
                onClick={toggleSidebar}
                title="Collapse Sidebar"
                aria-label="Collapse Sidebar"
                className="p-1 rounded-sm text-muted-foreground hover:text-foreground hover:bg-surface-hover transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </div>

            {/* New Audit Trigger */}
            <div className="p-3 pb-2 shrink-0">
              <button
                onClick={startNewSession}
                className="w-full flex items-center justify-between px-3 py-2 bg-surface-subtle hover:bg-surface-hover active:bg-surface-active border border-border text-foreground transition-colors text-xs font-mono font-medium rounded-sm"
              >
                <span className="flex items-center gap-2">
                  <Plus className="w-3.5 h-3.5" />
                  New Security Audit
                </span>
                <kbd className="text-[10px] text-muted-dim font-mono px-1 py-0.2 bg-surface border border-border">
                  N
                </kbd>
              </button>
            </div>

            {/* Search Filter */}
            <div className="px-3 py-1.5 shrink-0">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-dim" />
                <input
                  type="text"
                  placeholder="Filter sessions..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-8 pr-2.5 py-1.5 rounded-sm text-xs bg-surface-subtle border border-border text-foreground placeholder-muted-dim focus:outline-none focus:border-muted-foreground transition-colors font-mono"
                />
              </div>
            </div>

            {/* Audit History Ledger (Zero default sessions for blank slate) */}
            <div className="flex-1 overflow-y-auto px-3 py-1 space-y-0.5">
              <div className="flex items-center justify-between px-1 py-1.5 text-[10px] font-mono tracking-wider text-muted-dim uppercase">
                <span className="flex items-center gap-1.5">
                  <History className="w-3 h-3 text-muted-dim" />
                  Audit History ({filteredSessions.length})
                </span>
              </div>

              {filteredSessions.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-dim font-mono">
                  {sessions.length === 0
                    ? "No audit sessions yet"
                    : "No matching sessions"}
                </div>
              ) : (
                filteredSessions.map((session) => {
                  const isActive = session.id === currentSessionId;

                  return (
                    <div
                      key={session.id}
                      onClick={() => selectSession(session.id)}
                      className={cn(
                        "group relative px-2.5 py-2 cursor-pointer transition-colors border text-left rounded-sm",
                        isActive
                          ? "bg-surface-active border-border text-foreground font-semibold"
                          : "bg-transparent hover:bg-surface-hover border-transparent text-muted-foreground hover:text-foreground"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs truncate font-mono font-medium leading-tight">
                            {session.title}
                          </p>
                          <div className="flex items-center gap-2 mt-1 font-mono text-[10px]">
                            <span
                              className={cn(
                                "px-1 py-0.2 rounded-none border text-[9px] font-mono",
                                isActive
                                  ? "border-border text-foreground bg-surface"
                                  : "border-border text-muted-dim"
                              )}
                            >
                              {getModeTag(session.mode)}
                            </span>
                            <span className="text-muted-dim truncate">
                              {session.date}
                            </span>
                          </div>
                        </div>

                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteSession(session.id);
                          }}
                          aria-label={`Delete ${session.title}`}
                          title="Delete Session"
                          className="opacity-0 group-hover:opacity-100 p-1 hover:text-accent-red transition-opacity text-muted-dim"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>

                      {isActive && (
                        <div className="absolute left-0 top-1 bottom-1 w-0.5 bg-foreground" />
                      )}
                    </div>
                  );
                })
              )}
            </div>

            {/* Compact System Health Status */}
            <div className="px-3 py-1.5 border-t border-border bg-surface-subtle/50 flex items-center justify-between text-[10px] font-mono text-muted-dim shrink-0">
              <span className="flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-accent-emerald" />
                Temporal Engine
              </span>
              <span className="flex items-center gap-1 text-accent-emerald font-medium">
                <span className="w-1.5 h-1.5 bg-accent-emerald inline-block" />
                Active
              </span>
            </div>

            {/* Standard AI-Style User Profile Button (Absolute Bottom of Left Sidebar) */}
            <div className="p-2 border-t border-border bg-surface-subtle shrink-0">
              <button
                type="button"
                onClick={() => setIsSettingsOpen(true)}
                title="Account Settings & Enclave Preferences"
                aria-label="Account Settings and Enclave Preferences"
                className="w-full p-2 flex items-center justify-between gap-2.5 rounded-sm bg-surface hover:bg-surface-hover active:bg-surface-active border border-border text-foreground transition-colors group cursor-pointer text-left"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  {/* User Avatar Initials */}
                  <div className="w-7 h-7 rounded-none bg-surface-subtle border border-border flex items-center justify-center font-mono font-bold text-xs text-foreground shrink-0 group-hover:border-foreground transition-colors">
                    {userInitials}
                  </div>
                  <div className="flex flex-col text-left min-w-0">
                    <span className="text-xs font-medium text-foreground truncate font-sans">
                      {userDisplayName}
                    </span>
                    <span className="text-[10px] text-muted-dim truncate font-mono">
                      {userEmail}
                    </span>
                  </div>
                </div>

                <Settings className="w-3.5 h-3.5 text-muted-dim group-hover:text-foreground shrink-0 transition-colors" />
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* High-Quality Settings Modal with Account, Appearance & API/Security Tabs */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
      />
    </>
  );
};
