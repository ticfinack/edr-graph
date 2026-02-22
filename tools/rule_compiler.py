#!/usr/bin/env python3
"""Sigma Rule Compiler for edr-graph Stage 2 Fast-Path Blocklist.

Translates SigmaHQ rules into native edr-graph blocklist format.
Focus: Linux LOLBin executions and process chain detections.

Usage:
    python tools/rule_compiler.py [OPTIONS]
"""

import argparse
import datetime
import logging
import os
import re
import subprocess
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Sigma levels in ascending order
LEVEL_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Supported Sigma detection fields (lowercased)
SUPPORTED_FIELDS = {"image", "parentimage", "targetfilename"}

IMAGE_FIELDS = {"image"}
PARENT_IMAGE_FIELDS = {"parentimage"}
FILE_FIELDS = {"targetfilename"}

# ---------------------------------------------------------------------------
# Blast Shield — hardcoded failsafe against unscoped SIGKILL of OS-critical
# or extremely common binaries.  These may ONLY appear in process_name rules
# that carry a non-empty chain_filter.  Any unscoped match is dropped with a
# loud warning regardless of what the Sigma source says.
# ---------------------------------------------------------------------------
UNSCOPED_DANGER_BINARIES = frozenset([
    # OS-critical — unscoped kill = system breakage
    "rm", "unlink", "john",
    "bash", "sh", "python", "python3", "perl",
    "awk", "sed", "systemctl", "journalctl",
    # Dual-use DevSecOps — defer to Stage 3 LLM for context
    "*teamserver*", "httpx", "legion", "nuclei", "*sniper*", "hashcat",
])


# ---------------------------------------------------------------------------
# Sigma repo helpers
# ---------------------------------------------------------------------------

def fetch_sigma_repo(sigma_dir: str) -> str:
    """Clone SigmaHQ repo (depth 1) if not already present."""
    sigma_path = Path(sigma_dir)
    if sigma_path.exists() and (sigma_path / "rules").exists():
        logger.info("Using existing SigmaHQ checkout at %s", sigma_dir)
        return sigma_dir

    logger.info("Cloning SigmaHQ to %s ...", sigma_dir)
    subprocess.run(
        [
            "git", "clone", "--depth", "1",
            "https://github.com/SigmaHQ/sigma.git", sigma_dir,
        ],
        check=True,
        capture_output=True,
    )
    return sigma_dir


def get_sigma_commit(sigma_dir: str) -> str:
    """Return HEAD commit hash of the Sigma repo."""
    try:
        result = subprocess.run(
            ["git", "-C", sigma_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


# ---------------------------------------------------------------------------
# Rule discovery & parsing
# ---------------------------------------------------------------------------

def find_rules(sigma_dir: str) -> list[Path]:
    """Find all Sigma YAML rule files under the repo."""
    sigma_path = Path(sigma_dir)
    found: list[Path] = []
    for subdir in ("rules", "rules-emerging-threats", "rules-threat-hunting"):
        base = sigma_path / subdir
        if not base.exists():
            continue
        for root, _dirs, files in os.walk(base):
            for f in files:
                if f.endswith((".yml", ".yaml")):
                    found.append(Path(root) / f)
    logger.info("Found %d YAML files to scan", len(found))
    return found


def parse_sigma_rule(path: Path) -> dict | None:
    """Parse a Sigma YAML file. Returns rule dict or None on error."""
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return None
        if not all(k in data for k in ("title", "detection", "logsource")):
            return None
        data["_path"] = str(path)
        return data
    except Exception as exc:
        logger.debug("Failed to parse %s: %s", path, exc)
        return None


def filter_rule(
    rule: dict,
    min_level: str,
    statuses: list[str],
    categories: list[str],
    products: list[str],
) -> bool:
    """Return True if the rule passes level / status / logsource filters."""
    if rule.get("status", "").lower() not in statuses:
        return False
    if LEVEL_ORDER.get(rule.get("level", "").lower(), -1) < LEVEL_ORDER.get(min_level, 0):
        return False
    ls = rule.get("logsource", {})
    if categories and ls.get("category", "").lower() not in categories:
        return False
    if products and ls.get("product", "").lower() not in products:
        return False
    return True


# ---------------------------------------------------------------------------
# Field / modifier helpers
# ---------------------------------------------------------------------------

def _parse_field_key(key: str) -> tuple[str, str]:
    """Parse ``Field|modifier1|modifier2`` → (field_lower, primary_modifier).

    The primary modifier is the first value-matching modifier found
    (endswith, contains, startswith, re).  Everything else (all, utf16le,
    base64offset …) is ignored.
    """
    parts = key.split("|")
    field = parts[0].lower()
    modifier = ""
    for p in parts[1:]:
        pl = p.lower()
        if pl in ("endswith", "contains", "startswith", "re"):
            modifier = pl
            break
    return field, modifier


def _sigma_modifier_to_fnmatch(
    value: str, modifier: str, *, is_image: bool = False,
) -> str | None:
    """Convert a Sigma value + modifier to an fnmatch pattern.

    For Image / ParentImage fields (*is_image=True*), extracts the
    basename (after the last ``/``).

    Returns *None* for untranslatable modifiers (``re``) or when
    basename extraction yields a wildcard-only / empty pattern (e.g.
    ``ParentImage|startswith: /tmp/`` → would become ``*``).
    """
    value = str(value)
    if modifier == "endswith":
        if is_image:
            result = value.rsplit("/", 1)[-1]
            return result or None
        return "*" + value
    if modifier == "contains":
        if is_image:
            basename = value.rsplit("/", 1)[-1]
            if not basename:
                return None
            return "*" + basename + "*"
        return "*" + value + "*"
    if modifier == "startswith":
        if is_image:
            basename = value.rsplit("/", 1)[-1]
            if not basename:
                return None
            return basename + "*"
        return value + "*"
    if modifier == "re":
        return None  # regex — cannot translate
    # exact / no modifier
    if is_image:
        result = value.rsplit("/", 1)[-1]
        return result or None
    return value


def _build_chain_filter(parent_pattern: str, child_pattern: str) -> str:
    """Build ``** > parent > child`` chain filter string."""
    return f"** > {parent_pattern} > {child_pattern}"


def _ensure_list(val: object) -> list:
    """Wrap scalars in a list; pass lists through."""
    if isinstance(val, list):
        return val
    return [val]


# ---------------------------------------------------------------------------
# Selection-block analysis
# ---------------------------------------------------------------------------

def _has_unsupported_fields(selection: dict) -> bool:
    """True if the selection contains ANY field we cannot translate."""
    for key in selection:
        if key == "condition":
            continue
        field, modifier = _parse_field_key(key)
        if field not in SUPPORTED_FIELDS:
            return True
        if modifier == "re":
            return True
    return False


def _translate_selection(selection: dict, sigma_rule: dict) -> list[dict]:
    """Translate one selection block → list of edr-graph rule dicts."""
    if _has_unsupported_fields(selection):
        return []

    image_patterns: list[str] = []
    parent_patterns: list[str] = []
    file_patterns: list[str] = []

    # Track which field categories are present in the selection
    has_image = False
    has_parent = False
    has_file = False

    for key, values in selection.items():
        if key == "condition":
            continue
        field, modifier = _parse_field_key(key)
        if field in IMAGE_FIELDS:
            has_image = True
        elif field in PARENT_IMAGE_FIELDS:
            has_parent = True
        elif field in FILE_FIELDS:
            has_file = True
        for v in _ensure_list(values):
            pat = _sigma_modifier_to_fnmatch(str(v), modifier, is_image=(field in IMAGE_FIELDS | PARENT_IMAGE_FIELDS))
            if pat is None:
                continue
            if field in IMAGE_FIELDS:
                image_patterns.append(pat)
            elif field in PARENT_IMAGE_FIELDS:
                parent_patterns.append(pat)
            elif field in FILE_FIELDS:
                file_patterns.append(pat)

    # ROE: if a field category was present but ALL its values were
    # untranslatable, skip the entire selection (no partial translations)
    if has_image and not image_patterns:
        return []
    if has_parent and not parent_patterns:
        return []
    if has_file and not file_patterns:
        return []

    if not image_patterns and not file_patterns:
        return []

    rule_id = str(sigma_rule.get("id", "unknown"))[:8]
    title = sigma_rule.get("title", "Unknown")
    level = sigma_rule.get("level", "unknown")
    tags = [t for t in sigma_rule.get("tags", []) if isinstance(t, str)]
    desc = f"Sigma: {title} [{rule_id}] ({level})"

    rules: list[dict] = []

    # Image-based rules
    for img in image_patterns:
        if parent_patterns:
            for par in parent_patterns:
                rules.append({
                    "rule_type": "process_name",
                    "pattern": img,
                    "description": desc,
                    "chain_filter": _build_chain_filter(par, img),
                    "tags": tags,
                })
        else:
            rules.append({
                "rule_type": "process_name",
                "pattern": img,
                "description": desc,
                "chain_filter": "",
                "tags": tags,
            })

    # File-based rules
    for fp in file_patterns:
        rules.append({
            "rule_type": "file_path",
            "pattern": fp,
            "description": desc,
            "chain_filter": "",
            "tags": tags,
        })

    return rules


# ---------------------------------------------------------------------------
# Condition parser
# ---------------------------------------------------------------------------

def _parse_condition(condition: str) -> dict:
    """Parse a Sigma condition string into a structured dict."""
    condition = condition.strip()

    # "1 of selection_*" | "1 of selection*" | "1 of them"
    m = re.match(r"1\s+of\s+(selection_?\*|them)", condition)
    if m:
        return {"type": "1_of", "target": m.group(1)}

    # "all of selection_*" | "all of selection*" | "all of them"
    m = re.match(r"all\s+of\s+(selection_?\*|them)", condition)
    if m:
        return {"type": "all_of", "target": m.group(1)}

    # "selection and not filter …"
    m = re.match(r"(\w+)\s+and\s+not\s+", condition)
    if m:
        return {"type": "and_not", "selection": m.group(1)}

    # simple single-word
    if re.match(r"^\w+$", condition):
        return {"type": "simple", "selection": condition}

    # "sel1 or sel2 …"
    parts = re.split(r"\s+or\s+", condition)
    if len(parts) > 1 and all(re.match(r"^\w+$", p.strip()) for p in parts):
        return {"type": "or", "selections": [p.strip() for p in parts]}

    # "sel1 and sel2 …"
    parts = re.split(r"\s+and\s+", condition)
    if len(parts) > 1 and all(re.match(r"^\w+$", p.strip()) for p in parts):
        return {"type": "and", "selections": [p.strip() for p in parts]}

    return {"type": "complex", "raw": condition}


def _get_selection_blocks(detection: dict) -> dict[str, dict | list]:
    """Extract named selection/filter blocks from a Sigma detection section.

    Blocks may be dicts (normal) or lists-of-dicts (Sigma OR shorthand).
    Both forms are returned so the AND pre-scan can inspect them.
    """
    return {
        k: v for k, v in detection.items()
        if k != "condition" and isinstance(v, (dict, list))
    }


def _block_has_unsupported_fields(block: dict | list) -> bool:
    """Check a selection block (dict or list-of-dicts) for unsupported fields."""
    if isinstance(block, dict):
        return _has_unsupported_fields(block)
    if isinstance(block, list):
        for item in block:
            if isinstance(item, dict) and _has_unsupported_fields(item):
                return True
    return False


# ---------------------------------------------------------------------------
# Top-level rule translator
# ---------------------------------------------------------------------------

def translate_rule(sigma_rule: dict) -> tuple[list[dict], str]:
    """Translate one Sigma rule → (edr-graph rules, skip_reason).

    *skip_reason* is empty string on success.
    """
    detection = sigma_rule.get("detection", {})
    condition_str = detection.get("condition", "")
    if not condition_str:
        return [], "no condition"

    cond = _parse_condition(condition_str)
    blocks = _get_selection_blocks(detection)

    if cond["type"] == "simple":
        name = cond["selection"]
        block = blocks.get(name)
        if block is None or not isinstance(block, dict):
            return [], f"selection '{name}' not found or not a dict"
        rules = _translate_selection(block, sigma_rule)
        return (rules, "") if rules else ([], "unsupported fields in selection")

    if cond["type"] == "and_not":
        name = cond["selection"]
        block = blocks.get(name)
        if block is None or not isinstance(block, dict):
            return [], f"selection '{name}' not found or not a dict"
        rules = _translate_selection(block, sigma_rule)
        return (rules, "") if rules else ([], "unsupported fields in selection")

    if cond["type"] == "1_of":
        target = cond["target"]
        all_rules: list[dict] = []
        for bname, block in blocks.items():
            if target == "them" or bname.startswith("selection"):
                if isinstance(block, dict):
                    all_rules.extend(_translate_selection(block, sigma_rule))
        return (all_rules, "") if all_rules else ([], "no translatable selection blocks")

    if cond["type"] == "all_of":
        target = cond["target"]
        # AND semantics: ALL blocks must be fully supported — pre-scan
        # first.  If ANY block (dict or list-of-dicts) has unsupported
        # fields the entire rule is poisoned.
        and_blocks: list[dict | list] = []
        for bname, block in blocks.items():
            if target == "them" or bname.startswith("selection"):
                and_blocks.append(block)
        if not and_blocks:
            return [], "no selection blocks found"
        for block in and_blocks:
            if _block_has_unsupported_fields(block):
                return [], "unsupported fields in AND-combined selection"
        # Only merge dict blocks (list blocks passed the check but
        # cannot contribute Image/ParentImage patterns to the merge)
        merged: dict = {}
        for block in and_blocks:
            if isinstance(block, dict):
                merged.update(block)
        if not merged:
            return [], "untranslatable AND-combined selection"
        translated = _translate_selection(merged, sigma_rule)
        return (translated, "") if translated else ([], "untranslatable AND-combined selection")

    if cond["type"] == "or":
        all_rules = []
        for sname in cond["selections"]:
            block = blocks.get(sname)
            if isinstance(block, dict):
                all_rules.extend(_translate_selection(block, sigma_rule))
        return (all_rules, "") if all_rules else ([], "no translatable selections in OR")

    if cond["type"] == "and":
        # AND semantics: pre-scan ALL blocks (dict or list), then merge
        # dict blocks and translate.
        and_blocks: list[dict | list] = []
        for sname in cond["selections"]:
            if sname not in blocks:
                return [], f"selection '{sname}' not found"
            and_blocks.append(blocks[sname])
        for block in and_blocks:
            if _block_has_unsupported_fields(block):
                return [], "unsupported fields in AND-combined selection"
        merged: dict = {}
        for block in and_blocks:
            if isinstance(block, dict):
                merged.update(block)
        if not merged:
            return [], "no selection blocks in AND"
        translated = _translate_selection(merged, sigma_rule)
        return (translated, "") if translated else ([], "untranslatable AND-combined selection")

    return [], f"complex condition: {condition_str}"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(rules: list[dict], metadata: dict, path: str) -> None:
    """Write compiled rules to YAML file."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    header = (
        "# Auto-generated by tools/rule_compiler.py from SigmaHQ\n"
        "# Source: https://github.com/SigmaHQ/sigma\n"
        f"# Generated: {metadata['generated_at']}\n"
        f"# Stats: {metadata['total_compiled']} rules compiled, "
        f"{metadata['total_skipped']} skipped\n\n"
    )

    doc = {"metadata": metadata, "rules": rules}
    with open(out, "w") as fh:
        fh.write(header)
        yaml.dump(doc, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)

    logger.info("Wrote %d rules to %s", len(rules), path)


def print_stats(
    compiled: list[dict],
    skipped: list[tuple[str, str]],
    verbose: bool = False,
) -> None:
    """Print compilation statistics to stdout."""
    print(f"\n{'=' * 60}")
    print("Sigma Rule Compiler Results")
    print(f"{'=' * 60}")
    print(f"  Compiled:  {len(compiled)} rules")
    print(f"  Skipped:   {len(skipped)} rules")
    print(f"{'=' * 60}")

    if verbose and skipped:
        print("\nSkipped rules:")
        for title, reason in skipped[:50]:
            print(f"  - {title}: {reason}")
        if len(skipped) > 50:
            print(f"  ... and {len(skipped) - 50} more")

    if verbose and compiled:
        types: dict[str, int] = {}
        for r in compiled:
            rt = r["rule_type"]
            types[rt] = types.get(rt, 0) + 1
        print("\nRules by type:")
        for rt, count in sorted(types.items()):
            print(f"  {rt}: {count}")
        scoped = sum(1 for r in compiled if r.get("chain_filter"))
        print(f"  (with chain_filter: {scoped})")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Compile SigmaHQ rules into edr-graph Stage 2 blocklist format",
    )
    parser.add_argument(
        "--sigma-dir", default="/tmp/sigma",
        help="Path to SigmaHQ checkout (default: clones to /tmp/sigma)",
    )
    parser.add_argument(
        "--output", default="rules/defaults/stage2_blocklist.yml",
        help="Output YAML path (default: rules/defaults/stage2_blocklist.yml)",
    )
    parser.add_argument(
        "--categories", default="process_creation",
        help="Comma-separated logsource categories (default: process_creation)",
    )
    parser.add_argument(
        "--products", default="linux",
        help="Comma-separated logsource products (default: linux)",
    )
    parser.add_argument(
        "--min-level", default="high",
        help="Minimum Sigma level: low|medium|high|critical (default: high)",
    )
    parser.add_argument(
        "--status", default="stable",
        help="Comma-separated allowed statuses (default: stable)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print stats only")
    parser.add_argument("--verbose", action="store_true", help="Per-rule details")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    categories = [c.strip().lower() for c in args.categories.split(",")]
    products = [p.strip().lower() for p in args.products.split(",")]
    statuses = [s.strip().lower() for s in args.status.split(",")]
    min_level = args.min_level.lower()

    sigma_dir = fetch_sigma_repo(args.sigma_dir)
    sigma_commit = get_sigma_commit(sigma_dir)

    rule_files = find_rules(sigma_dir)

    compiled_rules: list[dict] = []
    skipped_rules: list[tuple[str, str]] = []

    for path in rule_files:
        rule = parse_sigma_rule(path)
        if rule is None:
            continue
        if not filter_rule(rule, min_level, statuses, categories, products):
            skipped_rules.append((
                rule.get("title", str(path)),
                "filtered (level/status/logsource)",
            ))
            continue
        translated, skip_reason = translate_rule(rule)
        if translated:
            compiled_rules.extend(translated)
            if args.verbose:
                logger.info(
                    "Compiled: %s -> %d rules", rule.get("title"), len(translated),
                )
        else:
            skipped_rules.append((rule.get("title", str(path)), skip_reason))
            if args.verbose:
                logger.debug("Skipped: %s -- %s", rule.get("title"), skip_reason)

    # Deduplicate by (rule_type, pattern, chain_filter)
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for r in compiled_rules:
        key = (r["rule_type"], r["pattern"], r["chain_filter"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    compiled_rules = unique

    # ---- Blast Shield: reject unscoped process_name rules for dangerous
    # binaries that would cause catastrophic Blue-on-Blue if globally blocked.
    shielded: list[dict] = []
    safe: list[dict] = []
    for r in compiled_rules:
        if (
            r["rule_type"] == "process_name"
            and not r.get("chain_filter")
            and r["pattern"].lower() in UNSCOPED_DANGER_BINARIES
        ):
            shielded.append(r)
            logger.warning(
                "BLAST SHIELD: dropped unscoped process_name '%s' (%s)",
                r["pattern"], r["description"],
            )
        else:
            safe.append(r)
    if shielded:
        for r in shielded:
            skipped_rules.append((r["description"], "blast-shield: unscoped danger binary"))
    compiled_rules = safe

    print_stats(compiled_rules, skipped_rules, verbose=args.verbose)

    if not args.dry_run:
        metadata = {
            "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "sigma_commit": sigma_commit,
            "total_compiled": len(compiled_rules),
            "total_skipped": len(skipped_rules),
        }
        write_output(compiled_rules, metadata, args.output)
        print(f"\nOutput written to: {args.output}")
    else:
        print("\n(dry-run: no output written)")


if __name__ == "__main__":
    main()
