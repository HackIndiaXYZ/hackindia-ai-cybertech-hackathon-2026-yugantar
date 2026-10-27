import { NextResponse } from "next/server";

const BACKEND_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function GET() {
  return NextResponse.redirect(`${BACKEND_URL}/api/auth/oauth/google/start`);
}
