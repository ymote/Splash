#!/usr/bin/env python3
"""
Mutation-test the L0 checker: which of its rules does the suite actually hold?

A passing suite proves the code does what the tests say. It does not prove a
test would notice if the code stopped. Four review rounds on this branch found
guarantees that were false within hours and two tests of mine that could not
fail, so "the suite is green" has repeatedly meant less than it looked like.

This answers the harder question mechanically: disable one rule, run the suite,
see whether anything goes red.

    ./mutate.py              # every rule
    ./mutate.py <substring>  # only rules whose id matches
    ./mutate.py --list       # show the rule table without running

WHAT THIS REPLACED, AND WHY. The first version mutated a diagnostic's TEXT by
filtering it inside Diagnostics::push, and reported "42 rules, 0 unprotected".
That number was not sound, for five reasons a reviewer had to point out:

  - Rules that also set `valid` or the level directly were unaffected by a text
    filter, so they reported unprotected while being perfectly well held.
  - Its five documented exceptions matched ZERO of the strings it generated, so
    relabelling them as "verified by hand" was cosmetic.
  - It found messages by keyword, and missed the six rules that matter most —
    the capability allowlist, provenance, laundering, recursion.
  - One substring could suppress several rules, so a test for any one of them
    flattered all of them.
  - With no baseline run, a compile error counted as a rule being caught.

So each rule below names a BEHAVIOUR and an edit that disables it, the edit must
apply at exactly one site, and a mutation that fails to build is reported as
unusable rather than counted as held. A stale patch string is loud, not silent:
that is the property the previous version lacked.
"""

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "crates/octoscript-ui-l0/src/lib.rs"


@dataclass(frozen=True)
class Rule:
    """One enforcement, and an edit that disables it."""

    ident: str
    claim: str
    find: str
    replace: str


RULES = [
    # ── capability confinement (§1, §4) ──────────────────────────────────────
    Rule("source-allowlist", "a card may only name a catalogued capability",
         "let Some(accepted) = catalog::source(&source.helper) else {",
         "let Some(accepted) = catalog::source(&source.helper).or(Some(&[][..])) else {"),
    Rule("source-arg-paths", "a source argument's path must be declared",
         "None => check_path(path, scope, source.line, 1, sink),",
         "None => { let _ = (path, scope); }"),

    Rule("source-state-collision", "a source and card state may not share a name",
         "if let Some(source) = card.sources.iter().find(|s| s.name == state.path) {",
         "if let Some(source) = card.sources.iter().find(|s| s.name == state.path).filter(|_| false) {"),
    # Mutating to "never report" rather than "always report": the risk is a dead
    # fetch going unnoticed, which is how `series` and `aqi` both survived a
    # catalog correction that made them unreachable.
    Rule("unread-source", "a declared source nothing reads is reported",
         "if !read.contains(&source.name) && !read.contains(&root_of(&source.name)) {",
         "if false {"),

    # ── the no-facts rule (§4) ───────────────────────────────────────────────
    Rule("data-laundering", "a literal may not reach a data position through a prop",
         "if matches!(arg.value, Operand::Str(_) | Operand::Num(_))",
         "if false"),
    Rule("model-copy-render", "model-authored text may not be rendered",
         "if decl.provenance == Provenance::ModelCopy {",
         "if false {"),
    Rule("model-copy-transition", "model-authored text may not be written into state",
         "Some(decl) if decl.provenance == Provenance::ModelCopy => {",
         "Some(decl) if false => {"),

    # ── termination (§6) ─────────────────────────────────────────────────────
    Rule("acyclic", "the declaration graph is acyclic",
         "if next == name.as_str() {",
         "if false {"),
    Rule("depth-realize", "realization depth is bounded",
         "if self.nodes >= self.limits.max_nodes || self.depth >= self.limits.max_depth {",
         "if self.nodes >= self.limits.max_nodes {"),

    # ── identity (§5.1, §5.7) ────────────────────────────────────────────────
    Rule("duplicate-keys", "duplicate loop keys are reported and disambiguated",
         "let item_key = if seen_keys.contains(&item_key) {",
         "let item_key = if false {"),
    Rule("key-names-binder", "a loop key names the loop's binder",
         "if root != *binder {",
         "if false {"),
    # Reverts to POSITIONAL numbering — a shared counter across siblings — which
    # is what the fix replaced. Dropping only the name prefix does not revert
    # anything, because the counter is already per-name.
    Rule("sibling-ordinals", "identity survives an insertion above",
         """    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    children
        .iter()
        .map(|child| {
            let n = seen.entry(child.name.as_str()).or_insert(0);
            let segment = format!("{}#{}", child.name, *n);
            *n += 1;
            (segment, child)
        })
        .collect()""",
         """    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let _ = &mut seen;
    children
        .iter()
        .enumerate()
        .map(|(i, child)| (format!("{i}"), child))
        .collect()"""),

    # ── transitions (§3) ─────────────────────────────────────────────────────
    Rule("payload-shape", "a payload must fit the state it is written to",
         "Some(v) if value_fits_shape(&state.shape, v) => v.clone(),",
         "Some(v) => v.clone(),"),
    Rule("initial-fits", "a declared initial fits its shape",
         "let fits = value_fits_shape(&state.shape, initial);",
         "let fits = true;"),
    Rule("schema-initials", "a changed initial resets live state",
         '"{}:{:?}:{:?}:{:?}",\n                s.path, s.shape, s.initial, s.initial_path',
         '"{}:{:?}",\n                s.path, s.shape'),

    # ── component contracts (§5.2) ───────────────────────────────────────────
    Rule("card-state-private", "a component may not read card state",
         "if scope.forbidden_state.contains(&root) {",
         "if false {"),

    # ── reconciliation (§5.10.1) ─────────────────────────────────────────────
    # Mutating to `true` (reuse everything) rather than `false` because that is
    # the direction the first implementation got wrong: it checked a node's own
    # key and let a clean root short-circuit its dirty children. The suite must
    # notice a patch that reuses a subtree a change did touch.
    Rule("patch-reuse", "a subtree is reused only when nothing under it is dirty",
         """        !touches_dirty(&n.key)
            && n.children
                .iter()
                .all(|c| subtree_is_clean(c, touches_dirty))""",
         "        let _ = (n, touches_dirty);\n        true"),

    # ── level and header (§7) ────────────────────────────────────────────────
    Rule("header-level", "a declared level must match the derived one",
         "if !matches {",
         "if false {"),
    Rule("header-duplicates", "a header may not contradict itself",
         "for message in &header.contradictions {",
         "for message in std::iter::empty::<&String>() {"),
]


def suite():
    """(built, passed). built=False means the mutation did not compile."""
    r = subprocess.run(
        ["cargo", "test", "-q", "-p", "octoscript-ui-l0", "--test", "profile"],
        cwd=ROOT, capture_output=True, text=True,
    )
    out = r.stdout + r.stderr
    built = "error[E" not in out and "could not compile" not in out
    return built, r.returncode == 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    only = args[0] if args else None
    rules = [r for r in RULES if not only or only in r.ident]

    if "--list" in sys.argv:
        for r in rules:
            print(f"  {r.ident:<24} {r.claim}")
        return 0

    original = SRC.read_text()

    # Baseline. Without it a pre-existing failure reads as every rule being
    # held — the most flattering possible way to be wrong.
    print("baseline… ", end="", flush=True)
    built, passed = suite()
    if not (built and passed):
        print("FAILED — fix the suite first; mutation results would be meaningless")
        return 2
    print("green\n")

    held, unprotected, unusable = [], [], []
    try:
        for i, rule in enumerate(rules, 1):
            hits = original.count(rule.find)
            if hits != 1:
                unusable.append((rule.ident, f"patch matches {hits} sites, expected 1"))
                print(f"  [{i:2}/{len(rules)}] STALE     {rule.ident} ({hits} matches)")
                continue

            SRC.write_text(original.replace(rule.find, rule.replace, 1))
            built, passed = suite()
            SRC.write_text(original)

            if not built:
                unusable.append((rule.ident, "mutation did not compile"))
                print(f"  [{i:2}/{len(rules)}] NO-BUILD  {rule.ident}")
            elif passed:
                unprotected.append(rule)
                print(f"  [{i:2}/{len(rules)}] SURVIVED  {rule.ident} — {rule.claim}")
            else:
                held.append(rule)
                print(f"  [{i:2}/{len(rules)}] held      {rule.ident}")
    finally:
        SRC.write_text(original)

    print(f"\n{'=' * 74}")
    print(f"held: {len(held)}    UNPROTECTED: {len(unprotected)}    unusable: {len(unusable)}")
    print(f"\nThis covers {len(RULES)} named rules. It is NOT a coverage percentage:\n"
          "a rule absent from the table is untested by this harness and unmentioned\n"
          "by its output, which is how the previous version came to claim full\n"
          "coverage while missing the six rules that mattered most.")
    if unprotected:
        print("\nRules no test would notice regressing:\n")
        for r in unprotected:
            print(f"  - {r.ident}: {r.claim}")
    if unusable:
        print("\nMutations that could not be applied. These are NOT held — they are\n"
              "untested, and a stale patch string is the likeliest reason:\n")
        for ident, why in unusable:
            print(f"  - {ident}: {why}")
    return 1 if (unprotected or unusable) else 0


if __name__ == "__main__":
    sys.exit(main())
