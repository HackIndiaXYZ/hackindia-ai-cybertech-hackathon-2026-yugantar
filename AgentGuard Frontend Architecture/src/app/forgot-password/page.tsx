"use client";

import React, { Suspense } from "react";
import { Auth } from "@/components/Auth";

export default function ForgotPasswordPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-slate-50 dark:bg-zinc-950" />}>
      <Auth initialTab="forgot_password" />
    </Suspense>
  );
}
