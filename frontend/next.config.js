/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${process.env.API_INTERNAL_URL || "http://localhost:8000"}/v1/:path*` }];
  },
};
module.exports = nextConfig;
