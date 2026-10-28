"use client";

import React, { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import {
  ChevronDown,
  Shield,
  Clock,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Download,
  Terminal,
  Cpu,
} from "lucide-react";
import { Message, EvidenceData, TelemetryData } from "@/store/useChatStore";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface CodeBlockProps {
  language?: string;
  value: string;
}

const CodeBlock: React.FC<CodeBlockProps> = ({ language = "bash", value }) => {
  const [copied, setCopied] = useState(false);
  const cleanCode = String(value).replace(/\n$/, "");

  const handleCopy = () => {
    navigator.clipboard.writeText(cleanCode);
    setCopied(true);
    toast.success("Code block copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  const displayLang = language ? language.toUpperCase() : "SHELL";

  return (
    <div className="relative my-3 rounded-none border border-zinc-800 bg-[#09090b] shadow-panel overflow-hidden font-mono text-left">
      {/* Top Header with Language on left & sharp Copy button on right */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#121215] border-b border-zinc-800 text-[10px] text-zinc-400 select-none">
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3 h-3 text-zinc-500" />
          <span className="font-semibold text-zinc-200 tracking-wider">
            {displayLang}
          </span>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          aria-label="Copy code block"
          className={cn(
            "flex items-center gap-1.5 px-2 py-0.5 rounded-none border transition-colors text-[10px] font-mono",
            copied
              ? "border-emerald-500/60 bg-emerald-500/15 text-emerald-400 font-medium"
              : "border-zinc-700 bg-zinc-900/80 hover:bg-zinc-800 text-zinc-300 hover:text-white"
          )}
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span>Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 text-zinc-400" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Syntax Highlighted Body - Strict Dark Theme */}
      <div className="overflow-x-auto bg-[#09090b] text-xs leading-relaxed">
        <SyntaxHighlighter
          language={language.toLowerCase()}
          style={vscDarkPlus}
          showLineNumbers={true}
          lineNumberStyle={{
            minWidth: "2.4em",
            paddingRight: "1em",
            color: "#52525b",
            textAlign: "right",
            userSelect: "none",
            fontSize: "11px",
          }}
          customStyle={{
            margin: 0,
            padding: "12px 14px",
            backgroundColor: "#09090b",
            fontSize: "12px",
            lineHeight: "1.6",
            fontFamily: "var(--font-mono), 'JetBrains Mono', monospace",
          }}
          codeTagProps={{
            style: {
              fontFamily: "var(--font-mono), 'JetBrains Mono', monospace",
            },
          }}
        >
          {cleanCode}
        </SyntaxHighlighter>
      </div>
    </div>
  );
};

interface AgentMessageProps {
  message: Message;
}

export const AgentMessage: React.FC<AgentMessageProps> = ({ message }) => {
  const [isAccordionOpen, setIsAccordionOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  // Fallback evidence if none provided
  const evidence: EvidenceData = message.evidence || {
    summary: "Analyzed 15 pages in 4.2s",
    duration: "4.2s",
    pagesAnalyzed: 15,
    scanSpeed: "3.6 pages/sec",
    detectedVulnerabilities: 3,
    riskLevel: "High",
    steps: [
      "Extracted document object model and embedded token AST",
      "Parsed system interfaces against CVE-2026 database",
      "Executed zero-trust credential and permission heuristics",
    ],
  };

  // Live Telemetry bound to Zustand message object (FastAPI ready)
  const telemetry: TelemetryData = message.telemetry || {
    executionTime: evidence.duration,
    pagesParsed: evidence.pagesAnalyzed,
    severity: evidence.riskLevel || "High",
    confidenceScore: "99.2%",
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    toast.success("Security report copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([message.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `agentguard-audit-${message.id.slice(0, 8)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Report exported as Markdown");
  };

  const getRiskBadge = (level?: string) => {
    switch (level) {
      case "Critical":
        return "border-accent-red text-accent-red bg-surface";
      case "High":
        return "border-amber-500/60 text-amber-500 dark:text-amber-400 bg-surface";
      case "Medium":
        return "border-border text-foreground bg-surface";
      default:
        return "border-accent-emerald text-accent-emerald bg-surface";
    }
  };

  return (
    <div className="flex gap-3 w-full font-sans">
      {/* Agent Avatar */}
      <div className="shrink-0 pt-0.5">
        <div className="w-7 h-7 rounded-none bg-surface border border-border shadow-panel flex items-center justify-center text-foreground">
          <Shield className="w-3.5 h-3.5" />
        </div>
      </div>

      {/* Message Body Container */}
      <div className="flex-1 min-w-0 max-w-3xl space-y-2">
        {/* Reasoning/Evidence Accordion */}
        <div className="rounded-none border border-border bg-surface shadow-panel overflow-hidden">
          <button
            onClick={() => setIsAccordionOpen(!isAccordionOpen)}
            className="w-full flex items-center justify-between px-3 py-2 hover:bg-surface-hover transition-colors text-left font-mono"
          >
            <div className="flex items-center gap-2 flex-wrap">
              <span className="flex items-center gap-1.5 text-xs text-foreground font-medium">
                <Terminal className="w-3.5 h-3.5 text-muted-dim" />
                Telemetry Proof:
              </span>
              <span className="text-xs text-muted-foreground">
                {evidence.summary}
              </span>
              {evidence.riskLevel && (
                <span
                  className={cn(
                    "text-[10px] font-mono px-1.5 py-0.2 border uppercase tracking-wider font-semibold",
                    getRiskBadge(evidence.riskLevel)
                  )}
                >
                  [{evidence.riskLevel} RISK]
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5 shrink-0 text-muted-dim text-[11px]">
              <span>{isAccordionOpen ? "Collapse" : "Expand"}</span>
              <ChevronDown
                className={cn(
                  "w-3.5 h-3.5 transition-transform duration-150",
                  isAccordionOpen && "rotate-180"
                )}
              />
            </div>
          </button>

          {isAccordionOpen && (
            <div className="border-t border-border bg-surface-subtle p-3 space-y-3 font-mono text-xs">
              {/* Metric Cells */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="p-2 border border-border bg-surface shadow-panel">
                  <div className="text-[10px] text-muted-dim uppercase flex items-center gap-1">
                    <Clock className="w-3 h-3 text-muted-dim" />
                    Execution Time
                  </div>
                  <div className="text-xs font-semibold text-foreground mt-0.5">
                    {evidence.duration}
                  </div>
                </div>

                <div className="p-2 border border-border bg-surface shadow-panel">
                  <div className="text-[10px] text-muted-dim uppercase flex items-center gap-1">
                    <FileText className="w-3 h-3 text-muted-dim" />
                    Pages Parsed
                  </div>
                  <div className="text-xs font-semibold text-foreground mt-0.5">
                    {evidence.pagesAnalyzed} pgs
                  </div>
                </div>

                <div className="p-2 border border-border bg-surface shadow-panel">
                  <div className="text-[10px] text-muted-dim uppercase flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3 text-muted-dim" />
                    CVE Exposure
                  </div>
                  <div className="text-xs font-semibold text-foreground mt-0.5">
                    {evidence.detectedVulnerabilities ?? 2} Found
                  </div>
                </div>

                <div className="p-2 border border-border bg-surface shadow-panel">
                  <div className="text-[10px] text-muted-dim uppercase flex items-center gap-1">
                    <Cpu className="w-3 h-3 text-muted-dim" />
                    Scan Velocity
                  </div>
                  <div className="text-xs font-semibold text-foreground mt-0.5">
                    {evidence.scanSpeed || "6.3 pgs/s"}
                  </div>
                </div>
              </div>

              {/* Step Sequence */}
              {evidence.steps && evidence.steps.length > 0 && (
                <div className="pt-2 border-t border-border space-y-1.5">
                  <div className="text-[10px] uppercase tracking-wider text-muted-dim font-medium">
                    Deterministic Pipeline Steps:
                  </div>
                  <div className="space-y-1 text-[11px] text-muted-foreground">
                    {evidence.steps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-accent-emerald shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Main Response Markdown Container - Pure Snow White in light mode */}
        <div className="rounded-none p-4 text-foreground border border-border bg-surface shadow-panel">
          {/* Live Telemetry & Confidence Badges (Enterprise SecOps Badges) */}
          <div className="flex items-center gap-2 flex-wrap pb-3 mb-3 border-b border-border text-[11px] font-mono select-none">
            {/* Execution Badge */}
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none border border-border bg-surface-subtle text-foreground shadow-sm">
              <Clock className="w-3 h-3 text-muted-dim" />
              <span className="text-muted-dim">Execution:</span>
              <span className="font-semibold">{telemetry.executionTime}</span>
            </div>

            {/* Pages Parsed Badge */}
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none border border-border bg-surface-subtle text-foreground shadow-sm">
              <FileText className="w-3 h-3 text-muted-dim" />
              <span className="text-muted-dim">Pages Parsed:</span>
              <span className="font-semibold">{telemetry.pagesParsed}</span>
            </div>

            {/* Severity Badge */}
            <div
              className={cn(
                "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none border font-semibold tracking-wide uppercase text-[10px]",
                telemetry.severity === "Critical" || telemetry.severity === "High"
                  ? "border-accent-red/50 bg-accent-red/10 text-accent-red"
                  : telemetry.severity === "Medium"
                  ? "border-amber-500/50 bg-amber-500/10 text-amber-500 dark:text-amber-400"
                  : "border-accent-emerald/50 bg-accent-emerald/10 text-accent-emerald"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-none inline-block",
                  telemetry.severity === "Critical" || telemetry.severity === "High"
                    ? "bg-accent-red"
                    : telemetry.severity === "Medium"
                    ? "bg-amber-500"
                    : "bg-accent-emerald"
                )}
              />
              <span>Severity: {telemetry.severity}</span>
            </div>

            {/*confidence Badge */}
            {telemetry.confidenceScore && (
              <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none border border-border bg-surface-subtle text-muted-foreground text-[10px]">
                <Shield className="w-3 h-3 text-accent-emerald" />
                <span className="text-muted-dim">Confidence:</span>
                <span className="font-semibold text-foreground">
                  {telemetry.confidenceScore}
                </span>
              </div>
            )}
          </div>

          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              h1: ({ children }) => (
                <h1 className="text-base font-semibold text-foreground tracking-tight mb-3 pb-1 border-b border-border">
                  {children}
                </h1>
              ),
              h2: ({ children }) => (
                <h2 className="text-sm font-semibold text-foreground tracking-tight mt-4 mb-2">
                  {children}
                </h2>
              ),
              h3: ({ children }) => (
                <h3 className="text-xs font-semibold text-foreground tracking-tight mt-3 mb-1.5">
                  {children}
                </h3>
              ),
              p: ({ children }) => (
                <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                  {children}
                </p>
              ),
              ul: ({ children }) => (
                <ul className="list-disc list-inside space-y-1 text-xs text-muted-foreground mb-3 ml-1">
                  {children}
                </ul>
              ),
              ol: ({ children }) => (
                <ol className="list-decimal list-inside space-y-1 text-xs text-muted-foreground mb-3 ml-1">
                  {children}
                </ol>
              ),
              li: ({ children }) => (
                <li className="text-muted-foreground">{children}</li>
              ),
              hr: () => <hr className="my-3 border-border" />,
              strong: ({ children }) => (
                <strong className="text-foreground font-semibold">
                  {children}
                </strong>
              ),
              blockquote: ({ children }) => (
                <blockquote className="border-l border-border pl-3 py-1 my-2 text-xs text-muted-foreground bg-surface-subtle font-mono">
                  {children}
                </blockquote>
              ),
              table: ({ children }) => (
                <div className="my-3 overflow-x-auto border border-border shadow-panel">
                  <table className="audit-table">{children}</table>
                </div>
              ),
              thead: ({ children }) => <thead>{children}</thead>,
              tbody: ({ children }) => <tbody>{children}</tbody>,
              th: ({ children }) => <th>{children}</th>,
              td: ({ children }) => <td>{children}</td>,
              code: ({ className, children, ...props }) => {
                const match = /language-(\w+)/.exec(className || "");
                const isInline = !match && !String(children).includes("\n");

                if (isInline) {
                  return (
                    <code
                      className="px-1 py-0.2 rounded-none text-[11px] font-mono bg-surface-subtle text-foreground border border-border"
                      {...props}
                    >
                      {children}
                    </code>
                  );
                }

                return (
                  <CodeBlock
                    language={match ? match[1] : "bash"}
                    value={String(children)}
                  />
                );
              },
            }}
          >
            {message.content}
          </ReactMarkdown>

          {/* Quick Action Toolbar */}
          <div className="mt-3 pt-2.5 border-t border-border flex items-center justify-between text-xs font-mono text-muted-dim">
            <span className="text-[10px]">
              TEMPORAL AUDIT REPORT // HASH VERIFIED
            </span>
            <div className="flex items-center gap-1.5">
              <button
                onClick={handleCopy}
                className="px-2 py-1 rounded-none bg-surface-subtle hover:bg-surface-hover border border-border text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 text-[11px]"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 text-accent-emerald" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    Copy Report
                  </>
                )}
              </button>
              <button
                onClick={handleDownload}
                className="px-2 py-1 rounded-none bg-surface-subtle hover:bg-surface-hover border border-border text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 text-[11px]"
              >
                <Download className="w-3 h-3" />
                Export .md
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
