# Contributing

Splash accepts changes to the language core, capability host, workflow engine,
or compatibility import only when the security boundary remains explicit.

- Do not register filesystem, subprocess, raw socket, or HTTP server modules
  in `splash-core`.
- Add effects as reviewed tool adapters in `splash-capabilities` with limits,
  audit coverage, and a documented containment strategy.
- Preserve Makepad provenance. Changes below `vendor/makepad/` need an entry
  in `vendor/makepad/PATCHES.md` and an upstream-sync note.
- Keep new language behavior in an executable fixture or regression test.

Before opening a change, run the checks in `docs/development.md`.
