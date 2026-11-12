import { defineConfig } from "vite";

export default defineConfig({
  base: "/verify/",
  server: {
    port: 5174,
    proxy: {
      "/v1": "http://localhost:8788",
    },
  },
});
