"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Group, Panel, Separator } from "react-resizable-panels";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { ChatArea } from "@/components/ChatArea";
import { InputArea } from "@/components/InputArea";
import { DocumentViewer } from "@/components/DocumentViewer";
import { CommandPalette } from "@/components/CommandPalette";
import { useChatStore } from "@/store/useChatStore";
import { useAuthStore } from "@/store/useAuthStore";
import { cn } from "@/lib/utils";

export default function Home() {
  const router = useRouter();
  const { messages, activeDocument, isSplitViewOpen } = useChatStore();
  const { isAuthenticated, isInitialized, initializeAuth } = useAuthStore();
  const [mounted, setMounted] = useState(false);
  const [mobileTab, setMobileTab] = useState<"chat" | "doc">("chat");

  useEffect(() => {
    setMounted(true);
    initializeAuth();
  }, [initializeAuth]);

  // Top-Level Auth Flow Enforcement: App strictly redirects to /login if unauthenticated
  useEffect(() => {
    if (mounted && isInitialized && !isAuthenticated) {
      router.replace("/login");
    }
  }, [mounted, isInitialized, isAuthenticated, router]);

  // Prevent flash of protected UI during enclave auth validation
  if (!mounted || !isInitialized || !isAuthenticated) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-background text-foreground font-mono select-none">
        <div className="flex flex-col items-center gap-3">
          <div className="w-6 h-6 border-2 border-foreground border-t-transparent animate-spin rounded-none" />
          <span className="text-xs text-muted-dim tracking-wider uppercase">
            Verifying Enclave Authentication...
          </span>
        </div>
      </div>
    );
  }

  // Split view is active ONLY when:
  // 1. User has an active document (attached PDF)
  // 2. Chat session is active (messages.length > 0)
  // 3. isSplitViewOpen is toggled ON
  // In empty state (no messages), keeps full-width centered layout.
  const showSplitView =
    mounted && isSplitViewOpen && Boolean(activeDocument) && messages.length > 0;

  return (
    <main className="flex h-screen w-screen overflow-hidden bg-background text-foreground font-sans">
      {/* Global Command Palette (Cmd+K / Ctrl+K) */}
      <CommandPalette />

      {/* Pane 1: Collapsible Sidebar */}
      <Sidebar />

      {/* Pane 2: Main Workspace (Header + Chat Display + Input Command Center) */}
      <div className="flex-1 w-full transition-all duration-300 flex flex-col h-full min-w-0 relative overflow-hidden bg-background">
        {/* Ambient Background Radial Glow (Gemini-Style) */}
        <div
          className="pointer-events-none absolute inset-0 overflow-hidden select-none"
          aria-hidden="true"
        >
          {/* Layer 1: Smooth ambient radial gradient */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(186,230,253,0.45),rgba(224,242,254,0.18)_45%,transparent_75%)] dark:bg-[radial-gradient(ellipse_80%_80%_at_50%_38%,rgba(30,40,90,0.35),rgba(18,24,55,0.15)_45%,transparent_75%)]" />

          {/* Layer 2: Massive blurred ambient glow orb */}
          <div className="absolute top-[38%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[450px] sm:w-[850px] sm:h-[600px] rounded-full blur-[120px] pointer-events-none opacity-45 dark:opacity-20 bg-gradient-to-tr from-sky-200 via-blue-100 to-sky-100 dark:from-indigo-950 dark:via-[#1e2247] dark:to-blue-950" />
        </div>

        {/* Top Workspace Header */}
        <Header />

        {/* Dynamic Workspace Layout: Split-Screen vs Full-Width Centered Layout */}
        {showSplitView ? (
          <>
            {/* Desktop Split-Screen Pane Layout (50% Left PDF / 50% Right Chat) */}
            <div className="hidden lg:flex flex-1 min-h-0 w-full overflow-hidden relative z-10">
              <Group orientation="horizontal" className="flex-1 min-h-0 w-full">
                {/* Left Pane (50%): Dedicated Bordered PDF Document Viewer */}
                <Panel
                  defaultSize={50}
                  minSize={25}
                  maxSize={75}
                  id="left-pdf-preview-pane"
                >
                  <DocumentViewer />
                </Panel>

                {/* Resizable Divider Handle */}
                <Separator className="w-1.5 bg-border hover:bg-muted-dim transition-colors cursor-col-resize flex items-center justify-center relative select-none">
                  <div className="w-0.5 h-8 bg-muted-dim rounded-full" />
                </Separator>

                {/* Right Pane (50%): Existing Chat Area & Input Command Center */}
                <Panel
                  defaultSize={50}
                  minSize={25}
                  maxSize={75}
                  id="right-chat-command-pane"
                >
                  <div className="flex flex-col h-full min-h-0 relative overflow-hidden bg-transparent">
                    {/* Chat Area */}
                    <div className="flex-1 min-h-0 relative flex flex-col overflow-hidden bg-transparent z-10">
                      <ChatArea />
                    </div>

                    {/* Bottom Multi-Modal Input Command Center */}
                    <div className="shrink-0 z-20 bg-background border-t border-border pt-1">
                      <InputArea />
                    </div>
                  </div>
                </Panel>
              </Group>
            </div>

            {/* Mobile / Tablet Responsive Tab Switcher Layout */}
            <div className="flex lg:hidden flex-1 min-h-0 flex-col w-full overflow-hidden relative z-10">
              <div className="flex items-center justify-between border-b border-border bg-surface px-3 py-1.5 text-xs font-mono shrink-0">
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setMobileTab("doc")}
                    className={cn(
                      "px-2.5 py-1 border transition-colors",
                      mobileTab === "doc"
                        ? "bg-foreground text-background font-semibold border-foreground"
                        : "bg-surface-subtle text-muted-foreground border-border hover:text-foreground"
                    )}
                  >
                    📄 PDF Document
                  </button>
                  <button
                    onClick={() => setMobileTab("chat")}
                    className={cn(
                      "px-2.5 py-1 border transition-colors",
                      mobileTab === "chat"
                        ? "bg-foreground text-background font-semibold border-foreground"
                        : "bg-surface-subtle text-muted-foreground border-border hover:text-foreground"
                    )}
                  >
                    💬 Security Chat
                  </button>
                </div>
                <span className="text-[10px] text-muted-dim truncate max-w-[120px]">
                  {activeDocument?.name}
                </span>
              </div>

              {mobileTab === "doc" ? (
                <div className="flex-1 min-h-0">
                  <DocumentViewer />
                </div>
              ) : (
                <div className="flex-1 flex flex-col min-h-0">
                  <div className="flex-1 min-h-0 relative flex flex-col overflow-hidden bg-transparent z-10">
                    <ChatArea />
                  </div>
                  <div className="shrink-0 z-20 bg-background border-t border-border pt-1">
                    <InputArea />
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          /* Full-Width Centered Layout (Default & Empty State) */
          <div className="flex-1 flex flex-col h-full min-h-0 relative overflow-hidden bg-transparent">
            {/* Central Chat Stream Area */}
            <div className="flex-1 min-h-0 relative flex flex-col overflow-hidden bg-transparent z-10">
              <ChatArea />
            </div>

            {/* Bottom Multi-Modal Input Command Center (Solid, zero gradients) */}
            <div className="shrink-0 z-20 bg-background border-t border-border pt-1">
              <InputArea />
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
