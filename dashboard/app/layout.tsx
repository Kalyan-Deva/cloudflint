import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cloudveil",
  description: "Edge proxy control",
};

const nav = [
  { href: "/", label: "Overview" },
  { href: "/zones", label: "Zones" },
  { href: "/waf", label: "WAF" },
  { href: "/logs", label: "Logs" },
  { href: "/config", label: "Config" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen flex flex-col">
          <header className="border-b hair sticky top-0 z-10 bg-base">
            <div className="mx-auto max-w-[1180px] px-6 h-12 flex items-center gap-7">
              <Link href="/" className="flex items-center gap-2 shrink-0">
                <Veil />
                <span className="font-semibold tracking-tight">Cloudveil</span>
              </Link>
              <nav className="flex items-center gap-5 text-[13px]">
                {nav.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="text-muted hover:text-text transition-colors"
                  >
                    {item.label}
                  </Link>
                ))}
              </nav>
            </div>
          </header>

          <main className="mx-auto w-full max-w-[1180px] px-6 py-7 flex-1">
            {children}
          </main>

          <footer className="border-t hair">
            <div className="mx-auto max-w-[1180px] px-6 py-3 text-[12px] text-muted">
              Control plane on :9000 · edge admin on :9001 — neither is authenticated,
              keep them internal.
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}

/* A veil: something drawn across, with what is behind it just visible. */
function Veil() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path
        d="M2 5.2c1.6-1.4 3.3-2.1 5-2.1s3.4.7 5 2.1"
        stroke="var(--color-accent)"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <path
        d="M2.6 8.4c1.5-1.2 3-1.8 4.4-1.8s2.9.6 4.4 1.8"
        stroke="var(--color-accent)"
        strokeWidth="1.4"
        strokeLinecap="round"
        opacity="0.62"
      />
      <path
        d="M3.4 11.4c1.3-1 2.5-1.5 3.6-1.5s2.3.5 3.6 1.5"
        stroke="var(--color-accent)"
        strokeWidth="1.2"
        strokeLinecap="round"
        opacity="0.34"
      />
    </svg>
  );
}
