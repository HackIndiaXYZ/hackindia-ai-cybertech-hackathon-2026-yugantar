"use client";
//ok
import React, { useState, useEffect } from "react";
import { Terminal, Shield, Cpu, FileText } from "lucide-react";
import { useChatStore, LogStep } from "@/store/useChatStore";
import { sanitizeInput, sanitizeFileName } from "@/lib/sanitizer";

export interface TerminalLoaderProps {
  logs?: LogStep[];
}

export const TerminalLoader: React.FC<TerminalLoaderProps> = ({ logs: propLogs }) => {
  const { currentMode, currentAttachment, workflowLogs: storeLogs } = useChatStore();
  const [elapsedSeconds, setElapsedSeconds] = useState(0.0);

  const logs = propLogs ?? storeLogs;

  const displayLogs =
    logs && logs.length > 0
      ? logs
      : [
          {
            step: "Temporal worker initializing sandboxed execution environment...",
            timestamp: new Date(),
          },
        ];

  useEffect(() => {
    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      setElapsedSeconds(+((performance.now() - startTime) / 1000).toFixed(1));
    }, 100);

    return () => {
      clearInterval(timerInterval);
    };
  }, []);

  return (
    <div className="w-full my-4 rounded-none border border-border bg-surface shadow-panel select-none font-mono">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-surface-subtle border-b border-border text-xs">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-muted-dim" />
          <span className="text-foreground font-medium text-[11px]">
            temporal-worker://agentguard/{currentMode}
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px]">
          <span className="text-muted-dim flex items-center gap-1">
            <Cpu className="w-3 h-3 text-muted-dim" />
            Sandboxed
          </span>
          <span className="text-foreground px-1.5 py-0.2 bg-surface border border-border">
            {elapsedSeconds.toFixed(1)}s
          </span>
        </div>
      </div>

      {/* Terminal Body */}
      <div className="p-3.5 text-xs space-y-2.5 bg-surface">
        {currentAttachment && (
          <div className="text-muted-dim pb-2 border-b border-border flex items-center gap-2 text-[11px]">
            <FileText className="w-3.5 h-3.5 text-muted-foreground" />
            <span>Target:</span>
            <span className="text-foreground font-medium">
              {sanitizeFileName(currentAttachment.name)}
            </span>
            <span className="text-muted-dim">
              ({(currentAttachment.size / 1024).toFixed(1)} KB)
            </span>
          </div>
        )}

        {/* Dynamic streamed steps history from Zustand workflowLogs */}
        <div className="space-y-1.5 text-[11px]">
          {displayLogs.map((logItem, index) => {
            const isLatest = index === displayLogs.length - 1;
            const cleanStep = sanitizeInput(logItem.step);
            return (
              <div
                key={`${logItem.step}-${index}`}
                className="flex items-start gap-2"
              >
                <span className="text-muted-dim select-none">$</span>
                <span
                  className={
                    isLatest
                      ? "text-foreground font-medium"
                      : "text-muted-dim"
                  }
                >
                  {cleanStep}
                </span>
                {isLatest && (
                  <span className="inline-block w-2 h-3.5 bg-foreground ml-1 animate-terminal-blink" />
                )}
              </div>
            );
          })}
        </div>

        {/* Industrial Pipeline Synthesis Indicator */}
        <div className="pt-2 border-t border-border flex items-center gap-2 text-[10px] text-muted-dim uppercase tracking-wider">
          <span className="w-1.5 h-1.5 bg-accent-emerald inline-block" />
          <span>Active Pipeline: Heuristic ruleset execution in progress...</span>
        </div>
      </div>
    </div>
  );
};
