"use client";

import React, { useState, useRef, useEffect } from "react";
import {
  Send,
  Paperclip,
  FileText,
  X,
  Shield,
  Zap,
  FileCheck,
  Lock,
  Clock,
  ShieldAlert,
} from "lucide-react";
import { useChatStore, AnalysisMode, Message } from "@/store/useChatStore";
import { useRateLimitStore } from "@/store/useRateLimitStore";
import { ANALYSIS_MODES, formatBytes, cn } from "@/lib/utils";
import { sanitizeInput, validatePdfFileStrict } from "@/lib/sanitizer";
import {
  pdfFileSchema,
  analysisRequestSchema,
  sendAnalysisRequest,
} from "@/services/api";
import { toast } from "sonner";

export const InputArea: React.FC = () => {
  const {
    currentAttachment,
    currentMode,
    isGenerating,
    setAttachment,
    setMode,
    addMessage,
    addSession,
    setGenerating,
  } = useChatStore();

  const {
    isCooldownActive,
    cooldownRemaining,
    isLocked,
    lockRemaining,
    recordSubmission,
  } = useRateLimitStore();

  const [prompt, setPrompt] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-expand textarea between 36px and 120px
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      const scrollHeight = textareaRef.current.scrollHeight;
      textareaRef.current.style.height = `${Math.min(
        Math.max(scrollHeight, 38),
        120
      )}px`;
    }
  }, [prompt]);

  // Strict Multi-Layer File Validation Handler
  const validateAndAttachFile = async (file: File) => {
    // 1. Instant size limit check (> 10MB strictly rejected instantly)
    if (file.size > 10 * 1024 * 1024) {
      toast.error("File Size Limit Exceeded", {
        description: `Selected file (${formatBytes(file.size)}) exceeds the maximum 10MB limit. File rejected.`,
      });
      return false;
    }

    // 2. Strict Zod schema check
    const zodResult = pdfFileSchema.safeParse(file);
    if (!zodResult.success) {
      toast.error("Security Validation Denied", {
        description:
          zodResult.error.errors[0]?.message ||
          "Only .pdf files are accepted for security analysis.",
      });
      return false;
    }

    // 3. Client-Side Magic Bytes & MIME Inspection (Anti-Payload Masquerading)
    const inspection = await validatePdfFileStrict(file);
    if (!inspection.isValid) {
      toast.error("Security Threat Blocked", {
        description: inspection.error || "File validation failed.",
      });
      return false;
    }

    const objectUrl = URL.createObjectURL(file);
    const sanitizedFileName = inspection.sanitizedName || file.name;

    setAttachment({
      file,
      name: sanitizedFileName,
      size: file.size,
      url: objectUrl,
      pageCount: Math.max(1, Math.round(file.size / 45000)),
    });

    // Dynamically create or update session in sidebar on PDF upload
    addSession(`Audit: ${sanitizedFileName}`, "Just now");

    toast.success("PDF Staged for Audit", {
      description: `${sanitizedFileName} (${formatBytes(file.size)}) verified and queued for ${ANALYSIS_MODES[currentMode].label}.`,
    });
    return true;
  };

  // Drag and Drop Event Handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget as Node)) return;
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      await validateAndAttachFile(droppedFile);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      await validateAndAttachFile(selectedFile);
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Prevent Empty Submission: text must be non-empty OR file must be attached
  const isSubmissionBlocked = isGenerating || isCooldownActive || isLocked;
  const hasValidInput = prompt.trim().length > 0 || currentAttachment !== null;
  const canSubmit = !isSubmissionBlocked && hasValidInput;

  const handleSubmit = async () => {
    if (!canSubmit) {
      if (isLocked) {
        toast.error("Rate Limit Exceeded", {
          description: `Please wait ${lockRemaining}s before sending another audit request.`,
        });
      }
      return;
    }

    // 1. Enforce rate limiting and engage strict 3-second cooldown
    const recorded = recordSubmission();
    if (!recorded) {
      return;
    }

    const rawUserText = prompt.trim();
    // 2. Client-side XSS and Injection Sanitization
    const userText = sanitizeInput(rawUserText);
    const attachedFile = currentAttachment;
    const mode = currentMode;

    // Strict validation via Zod before API call
    const validation = analysisRequestSchema.safeParse({
      prompt: userText,
      file: attachedFile?.file || null,
      analysisMode: mode,
    });

    if (!validation.success) {
      toast.error("Validation Error", {
        description:
          validation.error.errors[0]?.message ||
          "Please enter a prompt or attach a PDF file.",
      });
      return;
    }

    const defaultPrompt = attachedFile
      ? `Conduct ${ANALYSIS_MODES[mode].label} on architectural specification: "${attachedFile.name}".`
      : "Evaluate system security boundaries.";

    const messageContent = userText.length > 0 ? userText : defaultPrompt;

    const userMessage: Message = {
      id: `usr-${Date.now()}`,
      role: "user",
      content: messageContent,
      attachment: attachedFile || undefined,
      analysisMode: mode,
      timestamp: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
    };

    // 1. Add User message to Zustand store
    addMessage(userMessage);

    // 2. Clear current input & attachment
    setPrompt("");
    setAttachment(null);
    if (textareaRef.current) {
      textareaRef.current.style.height = "38px";
    }

    // 3. Mark generation state
    setGenerating(true);

    try {
      // 4. Dispatch to FastAPI / Temporal mock service via FormData (NO JSON)
      const response = await sendAnalysisRequest({
        prompt: messageContent,
        file: attachedFile?.file || null,
        analysisMode: mode,
      });

      // 5. Add Agent message to Zustand store
      const agentMessage: Message = {
        id: `agent-${Date.now()}`,
        role: "agent",
        content: response.content,
        analysisMode: mode,
        isProcessing: false,
        evidence: response.evidence,
        telemetry: response.telemetry,
        timestamp: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
      };

      addMessage(agentMessage);
    } catch (error: any) {
      console.error("[AgentGuard Analysis Error]", error);
    } finally {
      setGenerating(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const removeFile = () => {
    setAttachment(null);
  };

  const modeOptions: {
    id: AnalysisMode;
    label: string;
    icon: typeof Shield;
  }[] = [
    { id: "deep_audit", label: "Deep Security Audit", icon: Shield },
    { id: "quick_scan", label: "Quick Vulnerability Scan", icon: Zap },
    { id: "policy_check", label: "Policy Compliance Check", icon: FileCheck },
  ];

  return (
    <div
      onDragOver={handleDragOver}
      onDragEnter={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className="relative w-full max-w-4xl mx-auto px-4 pb-4 pt-1 select-none"
    >
      {/* Hidden native file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInputChange}
        accept=".pdf,application/pdf"
        className="hidden"
      />

      {/* Drag & Drop Overlay */}
      {isDragging && (
        <div className="absolute inset-x-4 inset-y-1 z-50 rounded-none border-2 border-dashed border-foreground bg-surface flex flex-col items-center justify-center p-6 text-center pointer-events-none shadow-panel">
          <FileText className="w-8 h-8 text-foreground mb-2" />
          <h3 className="text-xs font-semibold text-foreground font-mono uppercase tracking-wider">
            Drop PDF for Ingestion
          </h3>
          <p className="text-[11px] text-muted-dim font-mono mt-1">
            Temporal worker will parse AST and token matrices (Max 10MB)
          </p>
        </div>
      )}

      {/* Command Center Card Container */}
      <div className="rounded-none bg-surface border border-border p-3 shadow-panel">
        {/* Segmented Control Mode Toggle */}
        <div className="mb-2 pb-2 border-b border-border flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-1 p-0.5 bg-surface-subtle border border-border">
            {modeOptions.map((item) => {
              const isSelected = currentMode === item.id;
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setMode(item.id)}
                  className={cn(
                    "px-2.5 py-1 text-xs font-mono transition-colors flex items-center gap-1.5 rounded-none",
                    isSelected
                      ? "bg-foreground text-background font-semibold"
                      : "text-muted-foreground hover:text-foreground hover:bg-surface-hover"
                  )}
                >
                  <Icon className="w-3 h-3" />
                  <span className="hidden sm:inline">{item.label}</span>
                  <span className="sm:hidden">
                    {item.id === "deep_audit"
                      ? "Deep"
                      : item.id === "quick_scan"
                      ? "Scan"
                      : "Policy"}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="hidden md:flex items-center gap-1.5 text-[10px] font-mono text-muted-dim pr-1">
            <Lock className="w-3 h-3 text-accent-emerald" />
            <span>Temporal Sandbox Encrypted</span>
          </div>
        </div>

        {/* File Attachment Chip */}
        {currentAttachment && (
          <div className="flex items-center gap-2 mb-2">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 bg-surface-subtle border border-border text-xs font-mono text-foreground">
              <FileText className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-medium truncate max-w-xs">
                {currentAttachment.name}
              </span>
              <span className="text-[10px] text-muted-dim">
                ({formatBytes(currentAttachment.size)})
              </span>
              <button
                type="button"
                onClick={removeFile}
                className="hover:text-accent-red ml-1 text-muted-dim"
                aria-label="Remove attached file"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Text Area & Input Row */}
        <div className="flex items-end gap-2">
          {/* File Attachment Button */}
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            title="Attach Architectural PDF (Max 10MB)"
            aria-label="Attach Architectural PDF"
            className="p-2 bg-surface-subtle hover:bg-surface-hover active:bg-surface-active border border-border text-muted-foreground hover:text-foreground transition-colors shrink-0 rounded-none"
          >
            <Paperclip className="w-4 h-4" />
          </button>

          {/* Auto-expanding Input Area */}
          <div className="flex-1 relative">
            <textarea
              ref={textareaRef}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                currentAttachment
                  ? `Specify audit parameters for ${currentAttachment.name} or press Enter...`
                  : `Enter security inquiry or drag & drop architectural PDF for ${ANALYSIS_MODES[currentMode].label}...`
              }
              rows={1}
              className="w-full resize-none bg-surface-subtle text-xs text-foreground placeholder-muted-dim px-3 py-2 border border-border focus:outline-none focus:border-muted-foreground font-mono leading-relaxed rounded-none"
            />
          </div>

          {/* Send Trigger Button with Strict 3s Cooldown & Spam Protection */}
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canSubmit}
            aria-label="Execute Security Audit"
            className={cn(
              "px-3 py-2 font-mono text-xs flex items-center justify-center gap-1.5 transition-colors shrink-0 rounded-none border select-none h-[38px]",
              isLocked
                ? "bg-accent-red/10 text-accent-red border-accent-red/40 cursor-not-allowed"
                : isCooldownActive
                ? "bg-surface-subtle text-muted-foreground border-border cursor-not-allowed opacity-90"
                : canSubmit
                ? "bg-foreground text-background hover:bg-foreground/90 border-foreground cursor-pointer font-semibold"
                : "bg-surface-subtle text-muted-dim border-border cursor-not-allowed opacity-50"
            )}
            title={
              isLocked
                ? `Rate limit active. Unlocking in ${lockRemaining}s`
                : isCooldownActive
                ? `Cooldown active (${cooldownRemaining}s remaining)`
                : !hasValidInput
                ? "Input prompt or attach PDF to execute"
                : isGenerating
                ? "Temporal workflow executing..."
                : "Execute Audit (Enter)"
            }
          >
            {isLocked ? (
              <span className="flex items-center gap-1.5 text-accent-red font-semibold text-[11px]">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Locked ({lockRemaining}s)</span>
              </span>
            ) : isCooldownActive ? (
              <span className="flex items-center gap-1.5 text-foreground font-mono text-[11px]">
                <Clock className="w-3.5 h-3.5 text-accent-amber animate-spin" />
                <span>Processing ({cooldownRemaining}s)...</span>
              </span>
            ) : isGenerating ? (
              <span className="flex items-center gap-1.5 text-[11px]">
                <span className="w-3 h-3 font-mono font-bold flex items-center justify-center text-[10px] animate-terminal-blink">
                  _
                </span>
                <span>Auditing...</span>
              </span>
            ) : (
              <>
                <span className="hidden sm:inline font-mono">Send</span>
                <Send className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>

        {/* Execution Keybinding Hints */}
        <div className="mt-2 pt-1 border-t border-border flex items-center justify-between text-[10px] font-mono text-muted-dim px-0.5">
          <span>
            Press{" "}
            <kbd className="px-1 py-0.2 bg-surface-subtle border border-border text-foreground">
              Enter
            </kbd>{" "}
            to execute,{" "}
            <kbd className="px-1 py-0.2 bg-surface-subtle border border-border text-foreground">
              Shift+Enter
            </kbd>{" "}
            for new line
          </span>
          <span className="hidden sm:inline">
            FastAPI / Temporal Engine v2.4.0
          </span>
        </div>
      </div>
    </div>
  );
};
