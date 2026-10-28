import { create } from "zustand";
import {
  fetchUserHistory,
  deleteHistorySession,
  clearUserHistory,
  createHistorySession,
} from "@/services/api";
//ok
export type AnalysisMode = "deep_audit" | "quick_scan" | "policy_check";

export interface LogStep {
  step: string;
  timestamp: Date;
}

export interface Attachment {
  file: File;
  name: string;
  size: number;
  url?: string;
  pageCount?: number;
}

export interface EvidenceData {
  summary: string;
  duration: string;
  pagesAnalyzed: number;
  scanSpeed?: string;
  detectedVulnerabilities?: number;
  riskLevel?: "Low" | "Medium" | "High" | "Critical";
  steps?: string[];
  cveCount?: number;
  complianceScore?: string;
}

export interface TelemetryData {
  executionTime?: string;
  pagesParsed?: number;
  severity?: "High" | "Medium" | "Low" | "Critical";
  confidenceScore?: string;
}

export interface Message {
  id: string;
  role: "user" | "agent";
  content: string;
  attachment?: Attachment;
  analysisMode?: AnalysisMode;
  isProcessing?: boolean;
  evidence?: EvidenceData;
  telemetry?: TelemetryData;
  timestamp?: string;
}

export interface DocumentInfo {
  name: string;
  url?: string;
  size?: number;
  pageCount?: number;
}

export interface ChatSession {
  id: string;
  title: string;
  date: string;
  mode: AnalysisMode;
  messages: Message[];
  createdAt: number;
  updatedAt?: number;
}

export interface ChatStore {
  // Required core state
  messages: Message[];
  currentMode: AnalysisMode;
  isGenerating: boolean;
  workflowLogs: LogStep[]; // For the terminal loader
  currentAttachment: Attachment | null;
  sessions: ChatSession[];
  auditSessions: ChatSession[]; // Dynamic Chat History
  currentSessionId: string;
  isSidebarOpen: boolean;
  isSplitViewOpen: boolean;
  activeDocument: DocumentInfo | null;
  isCommandPaletteOpen: boolean;

  // Required core actions
  loadHistory: () => Promise<void>;
  addSession: (title?: string, timestamp?: string) => string;
  setMode: (mode: AnalysisMode) => void;
  addMessage: (msg: Message) => void;
  setGenerating: (status: boolean) => void;
  addWorkflowLog: (log: string) => void;
  clearWorkflowLogs: () => void;
  setAttachment: (attachment: Attachment | null) => void;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setSplitViewOpen: (open: boolean) => void;
  toggleSplitView: () => void;
  setActiveDocument: (doc: DocumentInfo | null) => void;
  setCommandPaletteOpen: (open: boolean) => void;
  toggleCommandPalette: () => void;
  startNewSession: () => void;
  selectSession: (sessionId: string) => void;
  deleteSession: (sessionId: string) => void;
  clearMessages: () => void;
  resetSession: () => void;
  resetAll: () => void;
  updateAgentMessage: (
    id: string,
    content: string,
    isProcessing: boolean,
    evidence?: EvidenceData,
    telemetry?: TelemetryData
  ) => void;
}

export const useChatStore = create<ChatStore>((set, get) => ({
  // Real AI Blank Slate: Zero default dummy data
  messages: [],
  currentMode: "deep_audit",
  isGenerating: false,
  workflowLogs: [],
  currentAttachment: null,
  sessions: [],
  auditSessions: [],
  currentSessionId: `session-${Date.now()}`,
  isSidebarOpen: true,
  isSplitViewOpen: false,
  activeDocument: null,
  isCommandPaletteOpen: false,

  loadHistory: async () => {
    try {
      const result = await fetchUserHistory(50);
      if (result && Array.isArray(result.sessions)) {
        const formatted: ChatSession[] = result.sessions.map((s: any) => ({
          id: s.id || s.sessionId || s.client_session_id,
          title: s.title || "Security Audit Session",
          date: s.date || "Saved Session",
          mode: (s.mode as AnalysisMode) || "deep_audit",
          messages: Array.isArray(s.messages) ? s.messages : [],
          createdAt: typeof s.createdAt === "number" ? s.createdAt : Date.now(),
          updatedAt: typeof s.updatedAt === "number" ? s.updatedAt : Date.now(),
        }));
        set({ sessions: formatted, auditSessions: formatted });
      }
    } catch {
      // Ignored if user is unauthenticated or server is offline
    }
  },

  addSession: (title?: string, timestamp?: string) => {
    const state = get();
    const id = state.currentSessionId || `session-${Date.now()}`;
    const existingIndex = state.sessions.findIndex((s) => s.id === id);

    const sessionTitle =
      title ||
      (state.activeDocument ? `PDF: ${state.activeDocument.name}` : "New Security Audit");
    const sessionDate = timestamp || "Just now";

    if (existingIndex >= 0) {
      const updatedSessions = [...state.sessions];
      updatedSessions[existingIndex] = {
        ...updatedSessions[existingIndex],
        title: sessionTitle,
        date: sessionDate,
      };
      set({ sessions: updatedSessions, auditSessions: updatedSessions });
      return id;
    }

    const newSession: ChatSession = {
      id,
      title: sessionTitle,
      date: sessionDate,
      mode: state.currentMode,
      messages: state.messages,
      createdAt: Date.now(),
    };

    const updatedSessions = [newSession, ...state.sessions];
    set({
      sessions: updatedSessions,
      auditSessions: updatedSessions,
      currentSessionId: id,
    });

    // Best-effort stage to backend database
    createHistorySession(id, sessionTitle, state.currentMode).catch(() => {});

    return id;
  },

  setMode: (mode: AnalysisMode) => {
    set({ currentMode: mode });
  },

  setSplitViewOpen: (open: boolean) => {
    set({ isSplitViewOpen: open });
  },

  toggleSplitView: () => {
    set((state) => ({ isSplitViewOpen: !state.isSplitViewOpen }));
  },

  setActiveDocument: (doc: DocumentInfo | null) => {
    set({ activeDocument: doc });
  },

  setCommandPaletteOpen: (open: boolean) => {
    set({ isCommandPaletteOpen: open });
  },

  toggleCommandPalette: () => {
    set((state) => ({ isCommandPaletteOpen: !state.isCommandPaletteOpen }));
  },

  addMessage: (msg: Message) => {
    set((state) => {
      const updatedMessages = [...state.messages, msg];

      const sessionIndex = state.sessions.findIndex(
        (s) => s.id === state.currentSessionId
      );

      let updatedSessions = [...state.sessions];
      if (sessionIndex >= 0) {
        updatedSessions[sessionIndex] = {
          ...updatedSessions[sessionIndex],
          messages: updatedMessages,
          date: "Just now",
        };
      } else {
        const title =
          typeof msg.content === "string" && msg.content.length > 32
            ? `${msg.content.substring(0, 32)}...`
            : msg.content || (msg.attachment ? `PDF: ${msg.attachment.name}` : "PDF Security Audit");

        const newSession: ChatSession = {
          id: state.currentSessionId,
          title,
          date: "Just now",
          mode: state.currentMode,
          messages: updatedMessages,
          createdAt: Date.now(),
        };
        updatedSessions = [newSession, ...updatedSessions];
      }

      const hasAttachment = Boolean(msg.attachment);
      const newActiveDoc = msg.attachment
        ? {
            name: msg.attachment.name,
            url: msg.attachment.url,
            size: msg.attachment.size,
            pageCount: msg.attachment.pageCount || 1,
          }
        : state.activeDocument;

      return {
        messages: updatedMessages,
        sessions: updatedSessions,
        auditSessions: updatedSessions,
        ...(hasAttachment
          ? {
              activeDocument: newActiveDoc,
              isSplitViewOpen: true,
            }
          : {}),
      };
    });
  },

  setGenerating: (status: boolean) => {
    set({ isGenerating: status });
  },

  addWorkflowLog: (log: string) => {
    set((state) => ({
      workflowLogs: [
        ...state.workflowLogs,
        { step: log, timestamp: new Date() },
      ],
    }));
  },

  clearWorkflowLogs: () => {
    set({ workflowLogs: [] });
  },

  setAttachment: (attachment: Attachment | null) => {
    set({ currentAttachment: attachment });
  },

  toggleSidebar: () => {
    set((state) => ({ isSidebarOpen: !state.isSidebarOpen }));
  },

  setSidebarOpen: (open: boolean) => {
    set({ isSidebarOpen: open });
  },

  startNewSession: () => {
    set({
      messages: [],
      currentAttachment: null,
      activeDocument: null,
      isSplitViewOpen: false,
      isGenerating: false,
      workflowLogs: [],
      currentSessionId: `session-${Date.now()}`,
      isCommandPaletteOpen: false,
    });
  },

  selectSession: (sessionId: string) => {
    const session = get().sessions.find((s) => s.id === sessionId);
    if (session) {
      const docMsg = session.messages.find((m) => m.attachment);
      const activeDoc = docMsg?.attachment
        ? {
            name: docMsg.attachment.name,
            url: docMsg.attachment.url,
            size: docMsg.attachment.size,
            pageCount: docMsg.attachment.pageCount || 1,
          }
        : null;

      set({
        currentSessionId: session.id,
        messages: session.messages,
        currentMode: session.mode,
        currentAttachment: null,
        activeDocument: activeDoc,
        isSplitViewOpen: session.messages.length > 0 && activeDoc !== null,
        isGenerating: false,
        workflowLogs: [],
      });
    }
  },

  deleteSession: (sessionId: string) => {
    // Revoke on backend database
    deleteHistorySession(sessionId).catch(() => {});

    set((state) => {
      const remainingSessions = state.sessions.filter(
        (s) => s.id !== sessionId
      );
      const isDeletingActive = state.currentSessionId === sessionId;

      return {
        sessions: remainingSessions,
        auditSessions: remainingSessions,
        ...(isDeletingActive
          ? {
              currentSessionId: `session-${Date.now()}`,
              messages: [],
              currentAttachment: null,
              activeDocument: null,
              isSplitViewOpen: false,
              isGenerating: false,
              workflowLogs: [],
            }
          : {}),
      };
    });
  },

  resetSession: () => {
    get().startNewSession();
  },

  clearMessages: () => {
    get().startNewSession();
  },

  resetAll: () => {
    clearUserHistory().catch(() => {});
    set({
      messages: [],
      sessions: [],
      auditSessions: [],
      currentAttachment: null,
      activeDocument: null,
      isSplitViewOpen: false,
      isGenerating: false,
      workflowLogs: [],
      currentSessionId: `session-${Date.now()}`,
      isCommandPaletteOpen: false,
    });
  },

  updateAgentMessage: (
    id: string,
    content: string,
    isProcessing: boolean,
    evidence?: EvidenceData,
    telemetry?: TelemetryData
  ) => {
    set((state) => {
      const updatedMessages = state.messages.map((msg) =>
        msg.id === id
          ? {
              ...msg,
              content,
              isProcessing,
              ...(evidence ? { evidence } : {}),
              ...(telemetry ? { telemetry } : {}),
            }
          : msg
      );

      const updatedSessions = state.sessions.map((s) =>
        s.id === state.currentSessionId
          ? { ...s, messages: updatedMessages }
          : s
      );

      return {
        messages: updatedMessages,
        sessions: updatedSessions,
        auditSessions: updatedSessions,
      };
    });
  },
}));
