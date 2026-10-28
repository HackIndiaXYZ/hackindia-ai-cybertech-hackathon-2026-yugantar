"use client";
//ok
import React, { useState } from "react";
import {
  FileText,
  ZoomIn,
  ZoomOut,
  Maximize2,
  X,
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  ShieldAlert,
  Lock,
  Layers,
  ArrowRight,
} from "lucide-react";
import { useChatStore } from "@/store/useChatStore";
import { cn, formatBytes } from "@/lib/utils";
import { toast } from "sonner";

export const DocumentViewer: React.FC = () => {
  const { activeDocument, setSplitViewOpen } = useChatStore();
  const [zoomLevel, setZoomLevel] = useState(100);
  const [currentPage, setCurrentPage] = useState(1);

  const docName = activeDocument?.name || "Target_Architecture_Specification.pdf";
  const totalPages = activeDocument?.pageCount || 24;

  const handleZoomIn = () => {
    setZoomLevel((prev) => Math.min(prev + 15, 175));
  };

  const handleZoomOut = () => {
    setZoomLevel((prev) => Math.max(prev - 15, 60));
  };

  const handleResetZoom = () => {
    setZoomLevel(100);
  };

  const handleDownload = () => {
    if (activeDocument?.url) {
      const a = document.createElement("a");
      a.href = activeDocument.url;
      a.download = docName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } else {
      toast.info(`Downloading specification metadata for ${docName}`);
    }
  };

  const handleOpenNewTab = () => {
    if (activeDocument?.url) {
      window.open(activeDocument.url, "_blank");
    } else {
      toast.info("Viewing preview in Pro Analyst Pane");
    }
  };

  return (
    <div className="flex flex-col h-full w-full bg-surface-subtle border-r border-border overflow-hidden select-none">
      {/* 1. Minimal Header: 📄 [Filename] - Preview */}
      <div className="h-10 px-3 border-b border-border bg-surface flex items-center justify-between shrink-0 font-mono text-xs">
        {/* Title area */}
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-muted-foreground flex items-center gap-1 shrink-0">
            📄
          </span>
          <span className="font-semibold text-foreground truncate max-w-[180px] sm:max-w-xs md:max-w-md">
            {docName}
          </span>
          <span className="text-muted-dim text-[11px] shrink-0 font-normal">
            - Preview
          </span>
          {activeDocument?.size ? (
            <span className="hidden xl:inline text-[10px] text-muted-dim border border-border px-1 py-0.2 bg-surface-subtle">
              {formatBytes(activeDocument.size)}
            </span>
          ) : null}
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-1">
          {/* Page Pagination */}
          <div className="flex items-center gap-1 px-1.5 py-0.5 rounded-none border border-border bg-surface-subtle text-[10px] text-muted-foreground">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="hover:text-foreground disabled:opacity-40 transition-colors"
              title="Previous Page"
              aria-label="Previous Page"
            >
              <ChevronLeft className="w-3 h-3" />
            </button>
            <span className="px-1 text-foreground font-semibold">
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="hover:text-foreground disabled:opacity-40 transition-colors"
              title="Next Page"
              aria-label="Next Page"
            >
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          {/* Zoom Controls */}
          <div className="hidden sm:flex items-center gap-0.5 border border-border bg-surface-subtle text-[10px] text-muted-foreground">
            <button
              onClick={handleZoomOut}
              className="p-1 hover:text-foreground transition-colors"
              title="Zoom Out"
              aria-label="Zoom Out"
            >
              <ZoomOut className="w-3 h-3" />
            </button>
            <button
              onClick={handleResetZoom}
              className="px-1 text-[10px] hover:text-foreground font-mono"
              title="Reset Zoom"
            >
              {zoomLevel}%
            </button>
            <button
              onClick={handleZoomIn}
              className="p-1 hover:text-foreground transition-colors"
              title="Zoom In"
              aria-label="Zoom In"
            >
              <ZoomIn className="w-3 h-3" />
            </button>
          </div>

          {/* Action Icons */}
          <button
            onClick={handleDownload}
            className="p-1 rounded-sm text-muted-foreground hover:text-foreground hover:bg-surface-hover border border-transparent hover:border-border transition-colors"
            title="Download PDF"
            aria-label="Download PDF"
          >
            <Download className="w-3.5 h-3.5" />
          </button>

          {activeDocument?.url && (
            <button
              onClick={handleOpenNewTab}
              className="p-1 rounded-sm text-muted-foreground hover:text-foreground hover:bg-surface-hover border border-transparent hover:border-border transition-colors"
              title="Open in new window"
              aria-label="Open in new window"
            >
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Close Split View */}
          <button
            onClick={() => setSplitViewOpen(false)}
            className="p-1 rounded-sm text-muted-foreground hover:text-accent-red hover:bg-surface-hover border border-transparent hover:border-border transition-colors ml-1"
            title="Close Split Preview"
            aria-label="Close Split Preview"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. Document Display Container */}
      <div className="flex-1 min-h-0 overflow-auto p-4 sm:p-6 flex items-start justify-center bg-surface-subtle/50">
        {activeDocument?.url ? (
          /* Native PDF iframe for user-attached physical PDF files */
          <div
            className="w-full h-full bg-surface border border-border shadow-panel overflow-hidden transition-transform duration-100"
            style={{
              transform: `scale(${zoomLevel / 100})`,
              transformOrigin: "top center",
            }}
          >
            <iframe
              src={activeDocument.url}
              title={`Preview of ${docName}`}
              className="w-full h-full border-0 bg-surface"
            />
          </div>
        ) : (
          /* Authentic Enterprise Architecture PDF Mockup (for demo sessions) */
          <div
            className="w-full max-w-2xl bg-white text-slate-900 border border-slate-300 dark:border-zinc-800 shadow-2xl p-6 sm:p-8 font-sans transition-transform duration-100 rounded-none"
            style={{
              transform: `scale(${zoomLevel / 100})`,
              transformOrigin: "top center",
              minHeight: "720px",
            }}
          >
            {/* Top Document Header */}
            <div className="border-b-2 border-slate-900 pb-3 mb-6 flex items-start justify-between">
              <div>
                <div className="text-[10px] font-mono tracking-widest uppercase text-slate-500 font-bold">
                  CONFIDENTIAL // ENTERPRISE ARCHITECTURE SPECIFICATION
                </div>
                <h1 className="text-lg sm:text-xl font-bold tracking-tight text-slate-900 mt-1 font-mono">
                  {docName.replace(".pdf", "")}
                </h1>
                <div className="text-xs text-slate-600 font-mono mt-0.5">
                  Security Boundary Topology & Ingress Token Flow (Rev 3.4.1)
                </div>
              </div>

              <div className="text-right font-mono text-[10px] text-slate-500 shrink-0">
                <div className="px-1.5 py-0.5 bg-red-100 border border-red-300 text-red-800 font-semibold inline-block">
                  TOPOLOGY AUDIT
                </div>
                <div className="mt-1">Page {currentPage} of {totalPages}</div>
                <div>Hash: e8b9f1...4c2d</div>
              </div>
            </div>

            {/* Document Content based on page */}
            {currentPage === 1 ? (
              <div className="space-y-6">
                {/* Executive Architecture Overview */}
                <div>
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono mb-1.5 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-blue-600" />
                    1.0 Boundary Architecture Specification
                  </h2>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    This document defines the mutual authentication and token exchange boundaries for
                    the high-throughput distributed microservice ingress layer. The boundary enforces
                    cryptographic proof-of-possession tokens, distributed session synchronization, and
                    least-privilege IAM storage policies across VPC clusters.
                  </p>
                </div>

                {/* Interactive Architectural Topology Diagram */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-none space-y-3 font-mono">
                  <div className="text-[10px] font-bold tracking-wider uppercase text-slate-600 flex items-center justify-between">
                    <span>Figure 1.1: System Flow & Vulnerability Exposure Map</span>
                    <span className="text-red-600 font-bold">4 THREAT ZONES</span>
                  </div>

                  {/* Visual Node Diagram */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
                    {/* Node 1: Ingress Gateway */}
                    <div className="p-3 bg-white border border-red-300 shadow-sm relative">
                      <div className="absolute -top-2 right-2 px-1 py-0.2 bg-red-600 text-white text-[9px] font-bold">
                        SEC-01: CVSS 8.8
                      </div>
                      <div className="text-xs font-bold text-slate-900">
                        Ingress Gateway
                      </div>
                      <div className="text-[10px] text-slate-600 mt-1">
                        /api/v2/tokens/exchange
                      </div>
                      <div className="text-[9px] text-red-700 mt-2 font-semibold">
                        Missing Proof-of-Possession
                      </div>
                    </div>

                    {/* Node 2: SessionStore */}
                    <div className="p-3 bg-white border border-red-500 shadow-sm relative">
                      <div className="absolute -top-2 right-2 px-1 py-0.2 bg-red-700 text-white text-[9px] font-bold animate-pulse">
                        SEC-02: CVSS 9.2
                      </div>
                      <div className="text-xs font-bold text-slate-900">
                        SessionStore::Redis
                      </div>
                      <div className="text-[10px] text-slate-600 mt-1">
                        State Deserializer
                      </div>
                      <div className="text-[9px] text-red-700 mt-2 font-semibold">
                        Insecure Pickle Deserialization
                      </div>
                    </div>

                    {/* Node 3: S3 Bucket Vault */}
                    <div className="p-3 bg-white border border-amber-400 shadow-sm relative">
                      <div className="absolute -top-2 right-2 px-1 py-0.2 bg-amber-600 text-white text-[9px] font-bold">
                        SEC-03: CVSS 7.4
                      </div>
                      <div className="text-xs font-bold text-slate-900">
                        S3 Enclave Storage
                      </div>
                      <div className="text-[10px] text-slate-600 mt-1">
                        IAM Role Policy
                      </div>
                      <div className="text-[9px] text-amber-700 mt-2 font-semibold">
                        Wildcard s3:* Permitted
                      </div>
                    </div>
                  </div>

                  {/* Flow Arrow Bar */}
                  <div className="p-2 bg-slate-100 border border-slate-200 text-[10px] text-slate-600 flex items-center justify-between">
                    <span>Edge Client (JWT Bearer)</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                    <span>mTLS Gateway</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                    <span>Worker Mesh</span>
                  </div>
                </div>

                {/* Section 1.2: Cryptographic Token Assertions */}
                <div>
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono mb-1.5 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-emerald-600" />
                    1.2 Cryptographic Assertions & Transport Security
                  </h2>
                  <p className="text-xs text-slate-700 leading-relaxed mb-2">
                    Ephemeral session keys are generated via SHA-256 HMAC digest. Nodes establish
                    transport security via mutual TLS 1.3 with required client certificate validation:
                  </p>
                  <div className="p-3 bg-slate-900 text-slate-100 font-mono text-[11px] leading-relaxed border border-slate-800">
                    <div># Transport Layer Cipher Configuration</div>
                    <div className="text-emerald-400">TLS_AES_256_GCM_SHA384 (Enforced)</div>
                    <div className="text-red-400">TLS_RSA_WITH_AES_128_CBC_SHA256 (Deprecated finding SEC-04)</div>
                  </div>
                </div>
              </div>
            ) : (
              /* Page 2: Insecure Deserialization Code Spec */
              <div className="space-y-6">
                <div>
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono mb-1.5">
                    2.0 Vulnerability Analysis // SEC-02 Deserializer
                  </h2>
                  <p className="text-xs text-slate-700 leading-relaxed mb-3">
                    The extract below highlights the unauthenticated session state deserialization
                    routine identified in lines 122–136 of the service mesh core controller:
                  </p>

                  <div className="p-3 bg-slate-900 text-slate-100 font-mono text-[11px] leading-relaxed border border-slate-800">
                    <div className="text-slate-500"># SessionStore Controller Implementation</div>
                    <div className="text-red-400">def restore_session(payload: bytes):</div>
                    <div className="text-red-400 pl-4">return pickle.loads(payload) # FLAGGED</div>
                  </div>
                </div>

                <div className="p-3 bg-amber-50 border border-amber-200 text-xs text-amber-900">
                  <div className="font-bold font-mono text-[11px] uppercase mb-1">
                    Auditor Compliance Notice
                  </div>
                  All endpoints parsing untrusted binary blobs must implement cryptographic HMAC
                  verification before entering Python runtime deserialization routines.
                </div>
              </div>
            )}

            {/* Document Footer */}
            <div className="border-t border-slate-300 mt-8 pt-4 flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>AgentGuard Pro Analyst Engine v2.4</span>
              <span>SHA256: 7a8291...bc90</span>
              <span>Page {currentPage} of {totalPages}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
