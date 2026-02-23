import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { Sidebar } from "@/components/sidebar";
import { PageHeader } from "@/components/page-header";
import { Separator } from "@/components/ui/separator";
import { Toaster } from "@/components/sonner";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Poirot - Data Security Posture Management",
  description: "Dashboard for Hawk-Eye Scanner - Detect and manage sensitive data",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="es" suppressHydrationWarning>
      <body className={inter.className}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <div className="min-h-screen bg-muted/30">
            {/* Inset Layout */}
            <div className="flex min-h-screen gap-4 p-4">
              {/* Sidebar Inset */}
              <Sidebar className="rounded-xl border bg-background shadow-sm" />
              
              {/* Main Content Area */}
              <div className="flex flex-1 flex-col rounded-xl border bg-background shadow-sm">
                {/* Header */}
                <PageHeader />
                <Separator />
                {/* Main Content */}
                <main className="flex-1 p-6">{children}</main>
              </div>
            </div>
          </div>
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
