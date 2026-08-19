import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5200,
    allowedHosts: [".manus.computer"],
    proxy: {
      "/api": "http://127.0.0.1:4900",
      "/health": "http://127.0.0.1:4900",
      "/metrics": "http://127.0.0.1:4900"
    }
  }
});
