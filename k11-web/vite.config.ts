import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 3000,
    proxy: {
      "/k11.K11": {
        target: "http://localhost:1100",
        changeOrigin: true,
      },
    },
  },
});
