import { defineConfig } from "tsdown";

export default defineConfig({
  clean: true,
  dts: { eager: true, sourcemap: false },
  entry: ["src/index.ts", "src/client.ts", "src/identity-digest.ts"],
  format: ["esm"],
  outDir: "dist",
  platform: "neutral",
  root: "src",
  sourcemap: false,
  target: "es2022",
  unbundle: true,
});
