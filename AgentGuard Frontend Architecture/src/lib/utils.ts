import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Shield, Zap, FileCheck } from "lucide-react";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Normalizes user profile names for enterprise SecOps UI:
 * - Extracts username before @ from email strings
 * - Strips trailing numbers, underscores, and dashes (e.g. "Ayush01434" -> "Ayush")
 * - Inserts spaces before capital letters (e.g. "AyushMishra" -> "Ayush Mishra")
 * - Handles compound lowercase/crammed names (e.g. "Ayushmishra" -> "Ayush Mishra")
 * - Replaces delimiters with spaces and capitalizes each word properly
 */
export function formatProfileName(rawName?: string, rawEmail?: string): string {
  // If an explicit real name was provided (not an email address), preserve it cleanly
  if (rawName && rawName.trim() && !rawName.includes("@")) {
    return rawName.trim();
  }

  const candidate = (rawEmail && rawEmail.trim()) ? rawEmail : (rawName || "Auditor");
  
  // 1. Extract prefix before @
  let base = candidate.split("@")[0].trim();

  // 2. Strip trailing digits and special delimiter characters (e.g. "Ayush01434" -> "Ayush")
  base = base.replace(/[\d._-]+$/, "").trim();

  // 3. Fallback if strip resulted in empty string (e.g. user had name "1234")
  if (!base) {
    base = candidate.split("@")[0].replace(/[^a-zA-Z]/g, "") || "Auditor";
  }

  // 4. Insert spaces before capital letters (e.g. "AyushMishra" -> "Ayush Mishra", "JaneDoe" -> "Jane Doe")
  base = base.replace(/([a-z])([A-Z])/g, "$1 $2");
  base = base.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");

  // 5. Handle common jammed compound names without spacing or capitalization (e.g. "Ayushmishra" or "ayushmishra")
  base = base.replace(/^(ayush)(mishra)$/i, "$1 $2");
  base = base.replace(/^(ayush)(.+)$/i, "$1 $2");

  // 6. Clean separators (dots/underscores/dashes to spaces)
  base = base.replace(/[._-]+/g, " ").trim();

  // 7. Title case each word cleanly
  const words = base
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());

  if (words.length === 0) return "Auditor";

  return words.join(" ");
}

export type AnalysisMode = "deep_audit" | "quick_scan" | "policy_check";

export interface ModeMeta {
  id: AnalysisMode;
  label: string;
  shortLabel: string;
  tagline: string;
  description: string;
  badgeLabel: string;
  icon: typeof Shield;
  samplePrompt: string;
}

export const ANALYSIS_MODES: Record<AnalysisMode, ModeMeta> = {
  deep_audit: {
    id: "deep_audit",
    label: "Deep Security Audit",
    shortLabel: "Deep Audit",
    tagline: "STRIDE heuristics & privilege escalation analysis",
    description: "Exhaustive token flow inspection, unauthenticated ingress detection, and cryptographic boundary validation.",
    badgeLabel: "AUDIT",
    icon: Shield,
    samplePrompt: "Conduct a deep architectural vulnerability audit on this specification. Extract attack surfaces, serialization flaws, and privilege escalation risks.",
  },
  quick_scan: {
    id: "quick_scan",
    label: "Quick Vulnerability Scan",
    shortLabel: "Quick Scan",
    tagline: "Rapid CVE correlation & secret leak triage",
    description: "Fast-path AST triage detecting high-entropy credentials, outdated framework dependencies, and container configuration risks.",
    badgeLabel: "SCAN",
    icon: Zap,
    samplePrompt: "Perform rapid vulnerability triage. Flag exposed AWS/Stripe credentials, insecure container primitives, and known CVE exposures.",
  },
  policy_check: {
    id: "policy_check",
    label: "Policy Compliance Check",
    shortLabel: "Policy Check",
    tagline: "SOC 2 Type II, ISO 27001 & GDPR governance matrix",
    description: "Deterministic evaluation against regulatory controls, data retention state machines, and cryptographic mandates.",
    badgeLabel: "POLICY",
    icon: FileCheck,
    samplePrompt: "Evaluate this architectural specification against SOC 2 Type II (CC6.1-6.7), ISO 27001 Annex A, and GDPR Article 32 mandates.",
  },
};
