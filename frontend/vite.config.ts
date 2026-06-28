import { defineConfig } from "vite";
import react from '@vitejs/plugin-react'
import tailwindcss from "@tailwindcss/vite";
import path from "path"
import { fileURLToPath } from "url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000, // Завжди запускати на 3000
    strictPort: true, // Впасти з помилкою, якщо порт 3000 зайнятий (щоб ти не шукав його по інших портах)
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})