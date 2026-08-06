import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import '@/styles/globals.css';
import { Providers } from '@/components/providers';
import { DirectionSetter } from '@/components/shared/DirectionSetter';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});

export const metadata: Metadata = {
  title: {
    default: process.env.NEXT_PUBLIC_APP_NAME || 'Minisource App',
    template: `%s | ${process.env.NEXT_PUBLIC_APP_NAME || 'Minisource App'}`,
  },
  description: 'A modern Next.js application built with Minisource frontend template',
  keywords: ['nextjs', 'react', 'typescript', 'tailwindcss'],
  authors: [{ name: 'Minisource Team' }],
  creator: 'Minisource',
  icons: {
    icon: '/favicon.ico',
    shortcut: '/favicon-16x16.png',
    apple: '/apple-touch-icon.png',
  },
  manifest: '/manifest.json',
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: 'white' },
    { media: '(prefers-color-scheme: dark)', color: 'black' },
  ],
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} font-sans antialiased`}>
        <Providers>
          <DirectionSetter />
          {children}
        </Providers>
      </body>
    </html>
  );
}
