import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "node_modules/pyodide");
const target = resolve(root, "public/runtime");
const files = [
  "pyodide.mjs",
  "pyodide.mjs.map",
  "pyodide.asm.js",
  "pyodide.asm.wasm",
  "pyodide-lock.json",
];

await mkdir(target, { recursive: true });
await Promise.all(files.map((file) => copyFile(resolve(source, file), resolve(target, file))));
await copyFile(resolve(source, "python_stdlib.zip"), resolve(target, "python_stdlib.data"));
