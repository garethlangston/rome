// Self-host build helper (fork-only). The workflow points first-party/example apps at
// workspace:* for @rome-os/app-runtime and @rome-os/app-web-sdk while `pnpm add` runs, so the
// lockfile keeps upstream's workspace links. This script then puts each app's package.json
// back to its original content (from git) and writes the original specifier into the lockfile,
// so --frozen-lockfile passes and packed app bundles stay installable outside the workspace.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";

const SDKS = ["@rome-os/app-runtime", "@rome-os/app-web-sdk"];
const FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const specs = new Map(); // importer -> Map(dep -> original specifier)

for (const root of ["rome_apps", "example_apps"]) {
  if (!existsSync(root)) continue;
  for (const name of readdirSync(root)) {
    const file = `${root}/${name}/package.json`;
    if (!existsSync(file)) continue;
    const original = execFileSync("git", ["show", `HEAD:${file}`], { encoding: "utf8" });
    writeFileSync(file, original);
    const pkg = JSON.parse(original);
    const m = new Map();
    for (const f of FIELDS) for (const d of SDKS) if (pkg[f]?.[d]) m.set(d, pkg[f][d]);
    if (m.size) specs.set(`${root}/${name}`, m);
  }
}

const lines = readFileSync("pnpm-lock.yaml", "utf8").split("\n");
let section = "",
  importer = "",
  dep = "",
  changed = 0,
  found = 0;
for (let i = 0; i < lines.length; i++) {
  const l = lines[i];
  if (/^\S/.test(l)) {
    section = l.replace(/:.*$/, "");
    importer = "";
    continue;
  }
  if (section !== "importers") continue;
  let m;
  if ((m = /^  (\S.*):$/.exec(l))) {
    importer = m[1].replace(/^'|'$/g, "");
    dep = "";
    continue;
  }
  if ((m = /^      '?([^':]+(?::[^':]+)?)'?:$/.exec(l))) {
    dep = m[1];
    continue;
  }
  if ((m = /^        specifier: (.*)$/.exec(l)) && specs.get(importer)?.has(dep)) {
    const want = specs.get(importer).get(dep);
    found++;
    if (m[1] !== want) {
      lines[i] = `        specifier: ${/^[\^~\w]/.test(want) ? want : `'${want}'`}`;
      changed++;
    }
  }
}
writeFileSync("pnpm-lock.yaml", lines.join("\n"));
const restored = [...specs.values()].reduce((n, m) => n + m.size, 0);
console.log(
  `restored ${restored} app SDK specifiers in package.json; found ${found}, rewrote ${changed} lockfile specifiers`,
);
if (found !== restored) {
  console.error("mismatch: some lockfile specifiers were not found");
  process.exit(1);
}
