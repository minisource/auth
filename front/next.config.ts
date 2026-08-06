import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Serve the entire app under /auth (behind the gateway), mirroring the
  // notifier frontend pattern (basePath: '/notifier').
  basePath: '/auth',

  // Enable React strict mode for better development experience
  reactStrictMode: true,

  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },

  // Enable production source maps for debugging
  productionBrowserSourceMaps: false,

  // Disable typed routes for compatibility with dynamic nav items
  // typedRoutes: false,
  output: 'standalone',

  // Experimental features
  experimental: {
    // Optimize package imports
    optimizePackageImports: ['lucide-react', '@radix-ui/react-icons', '@minisource/ui', '@minisource/auth-ui'],
  },
  transpilePackages: ['@minisource/tokens', '@minisource/ui', '@minisource/auth-ui'],

  // Image configuration
  images: {
    // Add your CDN domains here
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**.example.com',
      },
    ],
    // Image optimization settings
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    minimumCacheTTL: 60,
  },

  // Environment variables available on the client
  env: {
    NEXT_PUBLIC_APP_NAME: process.env.NEXT_PUBLIC_APP_NAME,
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  },

  // Headers configuration
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
          {
            key: 'X-Frame-Options',
            value: 'SAMEORIGIN',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },

  // Redirects (add your redirects here)
  async redirects() {
    return [];
  },

  // Rewrites (add your rewrites here)
  async rewrites() {
    return [];
  },

  // Webpack configuration
  webpack: (config) => {
    // Add custom webpack configurations here
    return config;
  },
};

export default nextConfig;
