import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/ThemeProvider";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "AgentGuard | Autonomous PDF Security Architecture Audit Engine",
  description:
    "Industrial-grade security operations console for architectural PDF threat modeling, CVE heuristics, and Temporal workflow execution.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${inter.variable} ${jetbrainsMono.variable}`}
    >
      <body className="bg-background text-foreground antialiased font-sans selection:bg-surface-active selection:text-foreground">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false}>
          {children}
          <Toaster
            position="top-right"
            theme="system"
            toastOptions={{
              className:
                "bg-zinc-950/80 backdrop-blur-md border border-zinc-800 text-zinc-100 font-mono shadow-2xl rounded-none text-xs",
              style: {
                background: "rgba(9, 9, 11, 0.8)",
                backdropFilter: "blur(12px)",
                WebkitBackdropFilter: "blur(12px)",
                border: "1px solid #27272a",
                color: "#f4f4f5",
                fontFamily: "var(--font-mono), JetBrains Mono, monospace",
                fontSize: "12px",
                borderRadius: "0px",
              },
            }}
          />
        </ThemeProvider>
      </body>
    </html>
  );
}
