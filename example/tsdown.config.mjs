export default {
  clean: true,
  deps: { alwaysBundle: [/.*/] },
  entry: ["client.ts"],
  format: ["esm"],
  outDir: "dist",
  platform: "browser",
  sourcemap: false,
  target: "es2022",
};
