"use client";

import React from "react";
import { ShieldAlert } from "lucide-react";
import { useAuthStore } from "@/store/useAuthStore";

export const HeroSection: React.FC = () => {
  const { user } = useAuthStore();
  const userName = user?.fullName || user?.name || "Security Architect";

  return (
    <div className="flex-1 h-full w-full flex flex-col items-center justify-center py-8 px-4 sm:px-6 text-center select-none">
      <div className="max-w-xl flex flex-col items-center space-y-4">
        {/* Minimal Enclave Brand Badge */}
        <div className="w-10 h-10 rounded-none bg-surface border border-border shadow-panel flex items-center justify-center text-foreground">
          <ShieldAlert className="w-5 h-5 text-foreground" />
        </div>

        {/* Clean Typography Personalized Greeting */}
        <div className="space-y-1.5">
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-light text-zinc-600 dark:text-zinc-400 tracking-tight">
            Welcome back, <span className="font-normal text-zinc-900 dark:text-zinc-100">{userName}</span>
          </h1>
          <p className="text-xs text-muted-dim font-mono max-w-md mx-auto">
            Upload an architectural diagram, cloud specification, or penetration report to initiate autonomous security analysis.
          </p>
        </div>
      </div>
    </div>
  );
};
