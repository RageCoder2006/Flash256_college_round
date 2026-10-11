import type { NextConfig } from "next";

const config: NextConfig = { reactStrictMode: true, distDir: process.env.NEXT_DIST_DIR || ".next" };
export default config;
