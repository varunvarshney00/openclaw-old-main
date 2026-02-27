#!/usr/bin/env node
/**
 * Cross-platform Node.js port of scripts/bundle-a2ui.sh.
 *
 * Bundles the A2UI canvas component using tsc + rolldown.
 * Uses content-hashing to skip rebuilds when inputs haven't changed.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

const HASH_FILE = path.join(repoRoot, "src", "canvas-host", "a2ui", ".bundle.hash");
const OUTPUT_FILE = path.join(repoRoot, "src", "canvas-host", "a2ui", "a2ui.bundle.js");
const A2UI_RENDERER_DIR = path.join(repoRoot, "vendor", "a2ui", "renderers", "lit");
const A2UI_APP_DIR = path.join(repoRoot, "apps", "shared", "OpenClawKit", "Tools", "CanvasA2UI");

// ── Source availability check ─────────────────────────────────────────
// Docker builds exclude vendor/apps via .dockerignore.
// In that environment we keep a prebuilt bundle if it exists.
if (!fs.existsSync(A2UI_RENDERER_DIR) || !fs.existsSync(A2UI_APP_DIR)) {
  if (fs.existsSync(OUTPUT_FILE)) {
    console.log("A2UI sources missing; keeping prebuilt bundle.");
    process.exit(0);
  }
  console.error(`A2UI sources missing and no prebuilt bundle found at: ${OUTPUT_FILE}`);
  process.exit(1);
}

// ── Content hashing ───────────────────────────────────────────────────
const INPUT_PATHS = [
  path.join(repoRoot, "package.json"),
  path.join(repoRoot, "pnpm-lock.yaml"),
  A2UI_RENDERER_DIR,
  A2UI_APP_DIR,
];

async function walk(entryPath) {
  const st = await fs.promises.stat(entryPath);
  if (st.isDirectory()) {
    const entries = await fs.promises.readdir(entryPath);
    const results = [];
    for (const entry of entries) {
      results.push(...(await walk(path.join(entryPath, entry))));
    }
    return results;
  }
  return [entryPath];
}

function normalize(p) {
  return p.split(path.sep).join("/");
}

async function computeHash() {
  const files = [];
  for (const input of INPUT_PATHS) {
    files.push(...(await walk(input)));
  }
  files.sort((a, b) => normalize(a).localeCompare(normalize(b)));

  const hash = createHash("sha256");
  for (const filePath of files) {
    const rel = normalize(path.relative(repoRoot, filePath));
    hash.update(rel);
    hash.update("\0");
    hash.update(await fs.promises.readFile(filePath));
    hash.update("\0");
  }
  return hash.digest("hex");
}

// ── Helpers ───────────────────────────────────────────────────────────
function resolveRunner() {
  const key = process.platform === "win32" ? "Path" : "PATH";
  const dirs = (process.env[key] ?? process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const extensions =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
      : [""];

  for (const dir of dirs) {
    for (const ext of extensions) {
      const candidate = path.join(dir, `pnpm${ext}`);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  throw new Error("Cannot find pnpm on PATH");
}

function exec(cmd, args) {
  const useShell = process.platform === "win32" && /\.(cmd|bat|com)$/i.test(cmd);
  const resolved = useShell && cmd.includes(" ") ? `"${cmd}"` : cmd;
  execFileSync(resolved, args, {
    cwd: repoRoot,
    stdio: "inherit",
    ...(useShell ? { shell: true } : {}),
  });
}

// ── Main ──────────────────────────────────────────────────────────────
async function main() {
  const currentHash = await computeHash();

  if (fs.existsSync(HASH_FILE)) {
    const previousHash = fs.readFileSync(HASH_FILE, "utf-8").trim();
    if (previousHash === currentHash && fs.existsSync(OUTPUT_FILE)) {
      console.log("A2UI bundle up to date; skipping.");
      process.exit(0);
    }
  }

  const pnpm = resolveRunner();
  const tsconfigPath = path.join(A2UI_RENDERER_DIR, "tsconfig.json");
  const rolldownConfigPath = path.join(A2UI_APP_DIR, "rolldown.config.mjs");

  exec(pnpm, ["-s", "exec", "tsc", "-p", tsconfigPath]);
  exec(pnpm, ["-s", "dlx", "rolldown", "-c", rolldownConfigPath]);

  // Ensure output directory exists before writing hash
  fs.mkdirSync(path.dirname(HASH_FILE), { recursive: true });
  fs.writeFileSync(HASH_FILE, currentHash, "utf-8");
}

main().catch((err) => {
  console.error("A2UI bundling failed. Re-run with: pnpm canvas:a2ui:bundle");
  console.error("If this persists, verify pnpm deps and try again.");
  console.error(err);
  process.exit(1);
});
