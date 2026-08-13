import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The dashboard talks to the backends only through its own /api routes.
  env: {
    CLOUDVEIL_CP: process.env.CLOUDVEIL_CP ?? "http://127.0.0.1:9000",
    CLOUDVEIL_EDGE: process.env.CLOUDVEIL_EDGE ?? "http://127.0.0.1:9001",
    CLOUDVEIL_API_TOKEN: process.env.CLOUDVEIL_API_TOKEN ?? "",
    CLOUDVEIL_ADMIN_TOKEN: process.env.CLOUDVEIL_ADMIN_TOKEN ?? "",
  },
};

export default nextConfig;
