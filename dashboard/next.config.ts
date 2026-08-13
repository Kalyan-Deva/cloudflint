import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // This app is the root, whatever is in the folders above it. Next otherwise infers a
  // workspace root by looking upwards for lockfiles, and any stray one - in a home
  // directory, say - makes a production build fail while resolving pages.
  outputFileTracingRoot: __dirname,

  // The dashboard talks to the backends only through its own /api routes.
  env: {
    CLOUDVEIL_CP: process.env.CLOUDVEIL_CP ?? "http://127.0.0.1:9000",
    CLOUDVEIL_EDGE: process.env.CLOUDVEIL_EDGE ?? "http://127.0.0.1:9001",
    CLOUDVEIL_API_TOKEN: process.env.CLOUDVEIL_API_TOKEN ?? "",
    CLOUDVEIL_ADMIN_TOKEN: process.env.CLOUDVEIL_ADMIN_TOKEN ?? "",
  },
};

export default nextConfig;
