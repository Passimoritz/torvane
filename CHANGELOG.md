# Changelog

## 0.3.0 – 2026-11-21 · Vigil is now Torvane

**New name, same app.** Vigil is now called **Torvane**. Settings, credentials, history and findings are kept: Torvane keeps using the existing data folder (`%APPDATA%\vigil`, portable: `VigilData`). The GitHub repository moved to `Passimoritz/torvane`, and old links and `git pull` are redirected automatically. Installer updates over an existing Vigil installation keep working.

### New interface
- Calm design system, guided flow (choose target → settings → check → results), finding details answered in three questions: *the problem, how dangerous, how to fix*
- New logo and icon set, a separate animation for each check step, a timeline of technical details with a raw-log switch
- Profiles in the settings: *Fast & cheap*, *Balanced*, *Maximum depth*

### Far fewer false alarms
- Measured on 22 clean real-world projects: from 10,880 down to 23 serious hits, benchmark unchanged (49/49)
- Project file `torvane.yml` / `vigil.yml` (`testDirs`, `vendorDirs`, `generatedDirs`, `ignore`, `disabledRules`, `severity`, `failOn`)
- Exceptions in the code, always with a reason: `torvane-ignore: <rule> <reason>`, `torvane-ignore-file:`
- Vendored and generated code is labelled, each rule has a measured hit rate, and an evidence check confirms AI findings
- `npm run fp` measures false alarms in CI against a fixed budget

### More detection
- Application security: missing authorization compared with neighbouring routes, IDOR per route, CSRF and rate limits project-wide, uploads, SSRF via variables, React/Svelte XSS, Electron flags/IPC, browser-extension manifests, Minecraft plugins, Android `exported`, GitHub Actions secrets
- Data flow across files for Java and Django, deleted secret files in Git history
- Project map for the AI, presets for local models (Ollama `num_ctx`), monthly AI budget per project with an 80 % notice
- Code mask (only send what is needed to the AI), signed rule packs (Ed25519), faster rule checks with a cache and threads

### For developers
- `--staged`, `--install-hook` (pre-commit) and `.pre-commit-hooks.yaml`
- GitHub Action (`uses: Passimoritz/torvane@v0.3.0`) with SARIF and optional pull-request comments
- `--watch` (check on save), `--pr-review`, `--issues`, `--rules-only`, `--fail-on` (ignores dev-only findings)
- Regression-test draft for a suggested fix
- Self-check of Torvane in CI (`npm run selfscan`), release with SBOM and `SHA256SUMS`, Linux packages (AppImage, .deb)

### Server edition
- **Torvane Server** (separate repository) runs this app unchanged in the browser – behind a hardened password-only login, for Linux, Windows Server and Docker.

## 0.1 – 0.2 · as Vigil (November 2026, no published release)
- First versions: rules, vulnerability databases, local or cloud AI with cross-check, reports, scheduled checks, Greenbone OpenVAS (optional), pause and resume, tool updates, code-signing setup (SignPath)
