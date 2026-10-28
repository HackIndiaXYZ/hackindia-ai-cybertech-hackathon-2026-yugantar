# AgentGuard Frontend Architecture 🛡️⚡

> Production-grade, cyber-security styled AI Chat Interface engineered for complex PDF vulnerability analysis, automated threat modeling, and seamless **FastAPI / Temporal** workflow orchestration.

---

## 🚀 Tech Stack

- **Framework:** Next.js 14+ (App Router), React 18, TypeScript (Strict Mode).
- **Styling:** Tailwind CSS, Glassmorphism, Custom Cyber Security theme (`#070a11` void black, `#00f0ff` neon cyan, `#00ff9d` emerald, `#ffb800` amber, `#ff3366` crimson).
- **Animations:** Framer Motion for spring transitions, collapsible rail motions, and drag-and-drop overlays.
- **State Management:** Zustand (`src/store/useChatStore.ts`) strictly adhering to the architectural contract without prop-drilling.
- **Icons:** `lucide-react` (cyber security and terminal iconography).
- **Markdown Rendering:** `react-markdown` with `remark-gfm` (supporting security tables, code blocks, lists, and risk badges).
- **Feedback & Notifications:** `sonner` with dark cybersecurity styling.

---

## 🏛️ System Architecture & Key Components

### 1. Collapsible 2-Pane Cyber Layout
- **Sidebar (`src/components/Sidebar.tsx`):**
  - **New Audit / New Chat Button:** Prominent glowing action button to instantly initialize a clean temporal workflow session.
  - **Historical Sessions:** Interactive audit log showing prior security assessments categorized with mode badges (`Deep Audit`, `Quick Scan`, `Policy Check`), relative timestamps, and one-click deletion.
  - **Session Filter:** Search audit sessions in real-time.
  - **Collapsible:** Smooth Framer Motion collapse/expand to maximize the analysis viewport, with an ultra-compact mini-rail when collapsed.
  - **System Telemetry:** Real-time status indicators for Temporal Engine (`Active`) and FastAPI Gateway (`200 OK`).

- **Workspace Header (`src/components/Header.tsx`):**
  - Displays the active audit session title.
  - Segmented active mode badge.
  - Quick share and clear session actions.

### 2. Main Chat Display (`src/components/ChatArea.tsx`)
- **Sequential Message Stream:**
  - **User Messages:** Right-aligned cyber bubble with attached PDF badge (filename and size) and timestamp.
  - **AI Agent Messages (`src/components/AgentMessage.tsx`):**
    - **Reasoning / Evidence Accordion:** Collapsible accordion positioned directly above the main response text (e.g., *"Analyzed 15 pages in 4.2s"*), expanding to reveal execution duration, pages analyzed, scan velocity, detected CVE indicators, and step-by-step pipeline proof.
    - **Rich Markdown Engine:** Styled markdown tables, syntax-highlighted code blocks with copy-to-clipboard, threat matrices, and risk tags (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`).
    - **Report Export:** One-click download of generated security reports as `.md`.
- **Empty State:**
  - Center glowing AgentGuard shield logo with 3 Quick-Start Action Cards:
    1. **Deep Security Audit:** Heuristic vulnerability analysis, STRIDE threat modeling & privilege escalation vectors.
    2. **Quick Vulnerability Scan:** High-entropy secret detection (leaked API keys) & CVE database triage.
    3. **Policy Compliance Check:** ISO 27001, SOC 2 Type II, HIPAA & GDPR governance validation.
  - Clicking any card selects the mode and triggers a live demonstration audit.
- **Auto-scroll:**
  - Smooth auto-scrolling to the bottom as messages stream in.
  - Floating *"Scroll to bottom"* button appears when the user scrolls up.

### 3. The Input Command Center (`src/components/InputArea.tsx`) - *CRITICAL*
1. **Drag & Drop:**
   - The entire input container accepts dragged `.pdf` files with an animated glassmorphism dropzone HUD and cyber-glow borders.
2. **File Validation:**
   - Instantly rejects non-PDF file formats with a Sonner toast notification.
   - Instantly rejects files larger than 10MB (`> 10MB`) with a clear error notification.
3. **File Chip:**
   - Renders a distinct UI chip `[📄 filename.pdf (Size) ✕]` directly above the text area when attached.
   - Includes an interactive remove button (`✕`).
4. **3-Mode Selector (Segmented Control):**
   - High-tech toggle group immediately above the text input:
     - 🛡️ *Deep Security Audit*
     - ⚡ *Quick Vulnerability Scan*
     - 📋 *Policy Compliance Check*
   - Selected mode updates Zustand state and is dispatched alongside the file/text.
5. **Auto-Expanding Text Area:**
   - Expands dynamically from min 1 line (40px) up to 6 lines (140px).
   - `Enter` submits the audit query; `Shift + Enter` inserts a new line.
6. **Submission Guard:**
   - The Send button is strictly disabled if **both** the text input is empty **and** no PDF is attached.

### 4. Temporal Workflow Loader (`src/components/TemporalWorkflowLoader.tsx`)
- Triggered when `isGenerating === true`.
- Renders a terminal-style executing sequence mimicking Temporal distributed activities:
  - `> AgentGuard initializing Temporal workflow worker sandbox...`
  - `> Ingesting PDF binary payload & calculating SHA-256 cryptographic digest...`
  - `> Parsing document AST structure, layout tables & embedded code blocks...`
  - `> Executing deterministic security heuristics against CVE-2026 database...`
  - `> Synthesizing structured Markdown remediation report...`
- Includes live stopwatch timer and pulsing skeleton loading preview bars.

### 5. Zustand Store Specification (`src/store/useChatStore.ts`)
Strictly conforms to the requested data model:
```typescript
type AnalysisMode = 'deep_audit' | 'quick_scan' | 'policy_check';

interface Attachment {
  file: File;
  name: string;
  size: number;
}

interface Message {
  id: string;
  role: 'user' | 'agent';
  content: string;
  attachment?: Attachment;
  analysisMode?: AnalysisMode;
  isProcessing?: boolean;
}

interface ChatStore {
  messages: Message[];
  currentAttachment: Attachment | null;
  currentMode: AnalysisMode;
  isGenerating: boolean;
  
  setAttachment: (file: Attachment | null) => void;
  setMode: (mode: AnalysisMode) => void;
  addMessage: (message: Message) => void;
  updateAgentMessage: (id: string, content: string, isProcessing: boolean) => void;
  setGenerating: (status: boolean) => void;
}
```

### 6. FastAPI / Temporal Integration Protocol (`src/services/api.ts`)
- Prepared specifically for future FastAPI endpoints:
  - Multi-part form data constraint: PDFs are sent as physical `File` objects inside `FormData`, never serialized as JSON.
  - Appends `prompt`, `file` (if attached), and `analysis_mode`.
  - Telemetry logging grouped in browser console with detailed inspection of keys and payload types.

---

## 🛠️ Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Run the Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) (or `http://localhost:3001` if port 3000 is occupied).

### 3. Production Build
```bash
npm run build
npm start
```
