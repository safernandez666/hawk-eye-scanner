/** @type {import('next').NextConfig} */
const isExport = process.env.NEXT_OUTPUT === "export";

const nextConfig = {
  // En Docker: export estático (nginx sirve los archivos)
  // En dev: server mode con rewrites para proxy API
  ...(isExport && { output: "export" }),

  // Solo en dev: proxy /api al backend Flask
  ...(!isExport && {
    async rewrites() {
      return [
        {
          source: "/api/:path*",
          destination: "http://localhost:5001/api/:path*",
        },
      ];
    },
  }),
};

export default nextConfig;
