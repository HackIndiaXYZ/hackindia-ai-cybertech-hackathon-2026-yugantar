import { NextResponse } from "next/server";
import { cookies } from "next/headers";

const BACKEND_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const res = await fetch(`${BACKEND_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    if (!res.ok) {
      return NextResponse.json(
        { success: false, error: data.detail || "Authentication failed" },
        { status: res.status }
      );
    }

    if (data.access_token) {
      const cookieStore = cookies();
      cookieStore.set("agentguard_auth_token", data.access_token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
        maxAge: data.expires_in || 60 * 60 * 24,
      });
    }

    return NextResponse.json({
      success: true,
      ...data,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: error?.message || "Authentication service unavailable" },
      { status: 503 }
    );
  }
}
