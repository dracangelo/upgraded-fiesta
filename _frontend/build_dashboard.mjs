import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const outputPath = resolve(root, "internal/api/dashboard_dist.html");
const htmlTemplate = await readFile(resolve(import.meta.dirname, "index.template.html"), "utf8");
const css = await readFile(resolve(import.meta.dirname, "dashboard.css"), "utf8");
const dashboard = await readFile(resolve(import.meta.dirname, "dashboard.jsx"), "utf8");
const result = await build({
  stdin: { contents: dashboard, loader: "jsx", resolveDir: import.meta.dirname, sourcefile: "dashboard.jsx" },
  bundle: true,
  minify: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: ["es2020"],
  legalComments: "none",
});
const bundle = new TextDecoder().decode(result.outputFiles[0].contents).replaceAll("</script", "<\\/script");
const html = htmlTemplate
  .replace("<!-- ENUMSCAN_STYLE -->", `<style>${css}</style>`)
  .replace("<!-- ENUMSCAN_SCRIPT -->", `<script>${bundle}</script>`);
await writeFile(outputPath, html, { encoding: "utf8", mode: 0o644 });
console.log(`Built ${outputPath}`);
