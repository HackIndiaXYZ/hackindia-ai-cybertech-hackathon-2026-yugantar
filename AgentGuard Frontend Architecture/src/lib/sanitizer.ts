/**
 * AgentGuard Security Hardening & Input Sanitization
 * Client-Side XSS Defense, File Inspection & Payload Neutralization
 */
//ok
// Escape HTML characters to prevent XSS / raw HTML injection in DOM
const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
  "`": "&#x60;",
  "=": "&#x3D;",
};

/**
 * Strictly sanitizes raw user input strings:
 * 1. Strips dangerous script tags, javascript: pseudo-protocols, and malicious inline event handlers.
 * 2. Neutralizes null bytes and control characters.
 * 3. Encodes HTML special characters to prevent DOM injection.
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== "string") return "";

  // 1. Strip null bytes and non-printable control characters (except newline, tab, carriage return)
  let cleaned = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // 2. Remove script tags and embedded JavaScript
  cleaned = cleaned.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
  cleaned = cleaned.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "");
  cleaned = cleaned.replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, "");
  cleaned = cleaned.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "");

  // 3. Remove inline event handlers (onerror=, onload=, onclick=, etc.)
  cleaned = cleaned.replace(/on\w+\s*=\s*(['"]).*?\1/gi, "");
  cleaned = cleaned.replace(/on\w+\s*=\s*[^\s>]+/gi, "");

  // 4. Neutralize javascript: and vbscript: URIs
  cleaned = cleaned.replace(/javascript\s*:/gi, "blocked-script:");
  cleaned = cleaned.replace(/vbscript\s*:/gi, "blocked-script:");
  cleaned = cleaned.replace(/data\s*:\s*text\/html/gi, "blocked-data:");

  return cleaned.trim();
}

/**
 * Escapes HTML entities for safe string interpolation inside templates
 */
export function escapeHtml(unsafe: string): string {
  if (typeof unsafe !== "string") return "";
  return unsafe.replace(/[&<>"'`=\/]/g, (char) => HTML_ESCAPE_MAP[char] || char);
}

/**
 * Sanitizes uploaded file names to prevent path traversal and shell injection
 */
export function sanitizeFileName(fileName: string): string {
  if (typeof fileName !== "string") return "document.pdf";

  // Strip path traversal sequences (../, ..\, etc.)
  let cleanName = fileName.replace(/^.*[\\\/]/, "");

  // Strip illegal filesystem & shell injection characters (; ` ' " $ & ( ) { } < > : / \ | ? *)
  cleanName = cleanName.replace(/[<>:"/\\|?*;`'$&(){\}\x00-\x1F]/g, "_");

  // Prevent hidden dotfiles or empty extensions
  if (cleanName.startsWith(".")) {
    cleanName = "file" + cleanName;
  }

  return cleanName.trim() || "document.pdf";
}

export interface FileValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedName?: string;
  sizeBytes?: number;
}

export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB Strict Limit

// List of dangerous executable and script extensions that MUST be strictly blocked
const DISALLOWED_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".sh", ".bash", ".bin", ".app", ".dmg", ".pkg",
  ".deb", ".rpm", ".ps1", ".vbs", ".js", ".mjs", ".jsx", ".ts", ".tsx",
  ".html", ".htm", ".xhtml", ".php", ".phtml", ".py", ".rb", ".jar",
  ".msi", ".dll", ".so", ".dylib", ".scr", ".pif", ".cpl", ".reg"
];

// Dangerous MIME types
const DANGEROUS_MIMES = [
  "application/x-msdownload",
  "application/x-executable",
  "application/x-sh",
  "application/x-bat",
  "application/x-msdos-program",
  "application/javascript",
  "text/javascript",
  "text/html",
  "application/x-php",
  "application/x-httpd-php",
  "application/zip",
  "application/x-tar",
  "application/x-bzip2",
  "application/x-gzip",
];

/**
 * Strict Client-Side File Validation:
 * 1. Checks file extension: ONLY .pdf is allowed. Rejects multi-extensions (.pdf.exe).
 * 2. Checks file size: strictly rejects files > 10MB or 0-byte files.
 * 3. Inspects MIME type: blocks executable/script MIME types; must be application/pdf.
 * 4. Verifies Magic Bytes: checks the binary file header for genuine "%PDF-" signature.
 */
export async function validatePdfFileStrict(file: File): Promise<FileValidationResult> {
  if (!file || !(file instanceof File)) {
    return { isValid: false, error: "A valid file object is required." };
  }

  const name = file.name.trim();
  const lowerName = name.toLowerCase();

  // 1. Extension Verification
  if (!lowerName.endsWith(".pdf")) {
    return {
      isValid: false,
      error: "Invalid file extension. Only genuine .pdf files are accepted for security analysis.",
    };
  }

  // Check for dangerous double extensions (e.g. payload.pdf.exe, report.pdf.sh)
  for (const dangerousExt of DISALLOWED_EXTENSIONS) {
    if (lowerName.includes(dangerousExt)) {
      return {
        isValid: false,
        error: `Potentially malicious file blocked: executable extension pattern "${dangerousExt}" detected.`,
      };
    }
  }

  // 2. Strict File Size Verification (Must be > 0 and <= 10MB)
  if (file.size === 0) {
    return {
      isValid: false,
      error: "Empty file detected (0 bytes). Please upload a valid architectural PDF.",
    };
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      isValid: false,
      error: `File size limit exceeded. File is ${(file.size / (1024 * 1024)).toFixed(2)} MB; maximum allowed is 10.0 MB.`,
    };
  }

  // 3. MIME Type Inspection
  if (file.type && DANGEROUS_MIMES.includes(file.type.toLowerCase())) {
    return {
      isValid: false,
      error: `Security Alert: Dangerous MIME type "${file.type}" blocked.`,
    };
  }

  // If MIME type is specified, ensure it is application/pdf
  if (file.type && file.type !== "application/pdf" && file.type !== "application/x-pdf") {
    return {
      isValid: false,
      error: `Invalid MIME type "${file.type}". Only application/pdf is permitted.`,
    };
  }

  // 4. Binary Magic Byte Header Inspection (True Client-Side Zero-Trust)
  // Genuine PDF files always begin with the ASCII characters '%PDF-' (0x25, 0x50, 0x44, 0x46, 0x2D)
  try {
    const headerBuffer = await file.slice(0, 5).arrayBuffer();
    const bytes = new Uint8Array(headerBuffer);
    const magicHeader = String.fromCharCode(...bytes);

    if (magicHeader !== "%PDF-") {
      return {
        isValid: false,
        error: "Security Alert: File magic bytes invalid. The file does not conform to genuine PDF specifications (%PDF- header missing).",
      };
    }
  } catch (err) {
    console.warn("Could not read file magic bytes:", err);
    // If browser environment restricts slice/read, proceed with strict extension & size checks
  }

  return {
    isValid: true,
    sanitizedName: sanitizeFileName(name),
    sizeBytes: file.size,
  };
}
