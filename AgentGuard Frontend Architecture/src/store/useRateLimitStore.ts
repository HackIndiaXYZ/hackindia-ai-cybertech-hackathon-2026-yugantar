import { create } from "zustand";
import { toast } from "sonner";

export const COOLDOWN_DURATION_SECONDS = 3; // Strict 3s cooldown
export const SPAM_THRESHOLD_COUNT = 5; // Max 5 requests
export const SPAM_WINDOW_MS = 60 * 1000; // Within 60 seconds
export const LOCKOUT_DURATION_SECONDS = 15; // Lockout penalty duration
//ok
interface RateLimitState {
  isCooldownActive: boolean;
  cooldownRemaining: number;
  isLocked: boolean;
  lockRemaining: number;
  timestamps: number[];

  // Core Actions
  canSubmit: () => { allowed: boolean; reason?: "cooldown" | "rate_limited"; remainingSeconds?: number };
  recordSubmission: () => boolean;
  reset: () => void;
}

let cooldownTimer: NodeJS.Timeout | null = null;
let lockTimer: NodeJS.Timeout | null = null;

export const useRateLimitStore = create<RateLimitState>((set, get) => ({
  isCooldownActive: false,
  cooldownRemaining: 0,
  isLocked: false,
  lockRemaining: 0,
  timestamps: [],

  canSubmit: () => {
    const { isLocked, isCooldownActive, cooldownRemaining, lockRemaining, timestamps } = get();

    // 1. Check if submission mechanism is locked due to spam
    if (isLocked) {
      return {
        allowed: false,
        reason: "rate_limited",
        remainingSeconds: lockRemaining,
      };
    }

    // 2. Check active 3-second button cooldown
    if (isCooldownActive) {
      return {
        allowed: false,
        reason: "cooldown",
        remainingSeconds: cooldownRemaining,
      };
    }

    // 3. Check sliding window timestamps
    const now = Date.now();
    const activeTimestamps = timestamps.filter((t) => now - t < SPAM_WINDOW_MS);
    if (activeTimestamps.length >= SPAM_THRESHOLD_COUNT) {
      return {
        allowed: false,
        reason: "rate_limited",
        remainingSeconds: Math.ceil((SPAM_WINDOW_MS - (now - activeTimestamps[0])) / 1000),
      };
    }

    return { allowed: true };
  },

  recordSubmission: () => {
    const { canSubmit } = get();
    const check = canSubmit();

    const now = Date.now();
    const recentTimestamps = get().timestamps.filter((t) => now - t < SPAM_WINDOW_MS);

    // If already in cooldown, block double submission silently
    if (check.reason === "cooldown") {
      return false;
    }

    // Check if triggering the 6th rapid-fire request within 60 seconds
    if (recentTimestamps.length >= SPAM_THRESHOLD_COUNT || check.reason === "rate_limited") {
      // Engage lockout mechanism
      if (lockTimer) clearInterval(lockTimer);

      set({
        isLocked: true,
        lockRemaining: LOCKOUT_DURATION_SECONDS,
        timestamps: [...recentTimestamps, now],
      });

      // Strict requirement: Trigger clear UI warning toast
      toast.error("Rate limit exceeded. Please wait before sending another audit request.", {
        id: "rate-limit-toast",
        description: `Threshold of ${SPAM_THRESHOLD_COUNT} requests per minute exceeded. Cooldown active for ${LOCKOUT_DURATION_SECONDS}s.`,
        duration: 5000,
      });

      lockTimer = setInterval(() => {
        const remaining = get().lockRemaining - 1;
        if (remaining <= 0) {
          if (lockTimer) clearInterval(lockTimer);
          set({ isLocked: false, lockRemaining: 0 });
          toast.success("Rate limit reset. Audit submission mechanism unlocked.", {
            duration: 3000,
          });
        } else {
          set({ lockRemaining: remaining });
        }
      }, 1000);

      return false;
    }

    // Record legitimate submission
    const updatedTimestamps = [...recentTimestamps, now];

    // Engage strict 3-second cooldown
    if (cooldownTimer) clearInterval(cooldownTimer);

    set({
      timestamps: updatedTimestamps,
      isCooldownActive: true,
      cooldownRemaining: COOLDOWN_DURATION_SECONDS,
    });

    cooldownTimer = setInterval(() => {
      const remaining = get().cooldownRemaining - 1;
      if (remaining <= 0) {
        if (cooldownTimer) clearInterval(cooldownTimer);
        set({ isCooldownActive: false, cooldownRemaining: 0 });
      } else {
        set({ cooldownRemaining: remaining });
      }
    }, 1000);

    return true;
  },

  reset: () => {
    if (cooldownTimer) clearInterval(cooldownTimer);
    if (lockTimer) clearInterval(lockTimer);
    set({
      isCooldownActive: false,
      cooldownRemaining: 0,
      isLocked: false,
      lockRemaining: 0,
      timestamps: [],
    });
  },
}));
