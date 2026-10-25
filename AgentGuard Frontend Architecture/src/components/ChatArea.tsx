"use client";

import React, { useEffect, useRef, useState } from "react";
import { ArrowDown, FileText, User } from "lucide-react";
import { useChatStore, AnalysisMode } from "@/store/useChatStore";
import { AgentMessage } from "./AgentMessage";
import { TerminalLoader } from "./TerminalLoader";
import { HeroSection } from "./HeroSection";
import { ANALYSIS_MODES, formatBytes } from "@/lib/utils";
import { sanitizeInput } from "@/lib/sanitizer";

export const ChatArea: React.FC = () => {
  const { messages, isGenerating, workflowLogs } = useChatStore();

  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [showScrollBottom, setShowScrollBottom] = useState(false);

  // Auto-scroll to bottom on new messages or reset to top when empty
  const scrollToBottom = (behavior: ScrollBehavior = "smooth") => {
    messagesEndRef.current?.scrollIntoView({ behavior });
  };

  useEffect(() => {
    if (messages.length === 0) {
      if (scrollContainerRef.current) {
        scrollContainerRef.current.scrollTop = 0;
      }
      setShowScrollBottom(false);
    } else {
      scrollToBottom("smooth");
    }
  }, [messages, isGenerating, workflowLogs]);

  // Monitor user scrolling to show "scroll to bottom" button if scrolled up
  const handleScroll = () => {
    if (!scrollContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollContainerRef.current;
    const isUp = scrollHeight - scrollTop - clientHeight > 180;
    setShowScrollBottom(isUp);
  };

  // STRICT EMPTY STATE CHECK: If messages array is empty, render the centered personalized HeroSection
  if (!messages || messages.length === 0) {
    return (
      <div className="relative flex-1 h-full w-full overflow-hidden flex flex-col bg-transparent">
        <HeroSection />
      </div>
    );
  }

  return (
    <div className="relative flex-1 h-full overflow-hidden flex flex-col bg-transparent">
      {/* Scrollable Message Container */}
      <div
        ref={scrollContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-4 sm:px-6 py-6"
      >
        <div className="max-w-4xl mx-auto space-y-4 pb-4">
          {messages.map((message) => {
            if (message.role === "agent") {
              return <AgentMessage key={message.id} message={message} />;
            }

            // USER MESSAGE (Solid, sharp border container on right)
            return (
              <div
                key={message.id}
                className="flex justify-end gap-3 w-full font-sans"
              >
                <div className="max-w-2xl space-y-1.5">
                  {/* Attached File Chip */}
                  {message.attachment && (
                    <div className="flex justify-end">
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-none bg-surface border border-border shadow-panel text-foreground text-xs font-mono">
                        <FileText className="w-3.5 h-3.5 text-muted-dim" />
                        <span className="font-medium truncate max-w-[200px]">
                          {message.attachment.name}
                        </span>
                        <span className="text-[10px] text-muted-dim">
                          ({formatBytes(message.attachment.size)})
                        </span>
                      </div>
                    </div>
                  )}

                  {/* User message solid container with XSS & injection sanitization */}
                  <div className="p-3.5 rounded-none bg-surface border border-border shadow-panel text-foreground text-xs leading-relaxed">
                    <p className="whitespace-pre-wrap">
                      {sanitizeInput(message.content)}
                    </p>
                  </div>

                  <div className="flex items-center justify-end gap-2 text-[10px] font-mono text-muted-dim px-0.5">
                    {message.analysisMode && (
                      <span className="text-foreground uppercase font-medium">
                        [
                        {ANALYSIS_MODES[message.analysisMode as AnalysisMode]
                          ?.badgeLabel || message.analysisMode}
                        ]
                      </span>
                    )}
                    <span>{message.timestamp}</span>
                  </div>
                </div>

                {/* User Avatar */}
                <div className="shrink-0 pt-0.5">
                  <div className="w-7 h-7 rounded-none bg-surface border border-border shadow-panel flex items-center justify-center text-muted-foreground">
                    <User className="w-3.5 h-3.5" />
                  </div>
                </div>
              </div>
            );
          })}

          {/* DYNAMIC TEMPORAL WORKFLOW TERMINAL LOADER */}
          {isGenerating && <TerminalLoader logs={workflowLogs} />}

          <div ref={messagesEndRef} className="h-2" />
        </div>
      </div>

      {/* Floating Scroll to Bottom Trigger */}
      {showScrollBottom && (
        <button
          onClick={() => scrollToBottom("smooth")}
          className="absolute right-6 bottom-4 p-2 rounded-none bg-surface hover:bg-surface-hover border border-border shadow-panel text-foreground transition-colors z-20"
          title="Scroll to bottom"
          aria-label="Scroll to bottom"
        >
          <ArrowDown className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};
