"""Unit tests for tools/rule_compiler.py — Sigma-to-edr-graph translation."""


import yaml

from tools.rule_compiler import (
    UNSCOPED_DANGER_BINARIES,
    _block_has_unsupported_fields,
    _build_chain_filter,
    _has_unsupported_fields,
    _parse_condition,
    _parse_field_key,
    _sigma_modifier_to_fnmatch,
    filter_rule,
    translate_rule,
    write_output,
)

# ---------------------------------------------------------------------------
# Helper: build a minimal Sigma rule dict
# ---------------------------------------------------------------------------

def _sigma(
    detection: dict,
    *,
    title: str = "Test Rule",
    rule_id: str = "abcd1234-0000-0000-0000-000000000000",
    level: str = "high",
    status: str = "stable",
    product: str = "linux",
    category: str = "process_creation",
    tags: list[str] | None = None,
) -> dict:
    return {
        "title": title,
        "id": rule_id,
        "status": status,
        "level": level,
        "logsource": {"category": category, "product": product},
        "detection": detection,
        "tags": tags or ["attack.execution"],
    }


# ===================================================================
# _parse_field_key
# ===================================================================

class TestParseFieldKey:
    def test_simple(self):
        assert _parse_field_key("Image") == ("image", "")

    def test_endswith(self):
        assert _parse_field_key("Image|endswith") == ("image", "endswith")

    def test_contains(self):
        assert _parse_field_key("CommandLine|contains") == ("commandline", "contains")

    def test_compound_modifier(self):
        assert _parse_field_key("CommandLine|contains|all") == ("commandline", "contains")

    def test_encoding_modifier(self):
        assert _parse_field_key("Image|endswith|utf16le") == ("image", "endswith")


# ===================================================================
# _sigma_modifier_to_fnmatch
# ===================================================================

class TestSigmaModifierToFnmatch:
    def test_endswith_image(self):
        assert _sigma_modifier_to_fnmatch("/bash", "endswith", is_image=True) == "bash"

    def test_endswith_non_image(self):
        assert _sigma_modifier_to_fnmatch(".log", "endswith", is_image=False) == "*.log"

    def test_contains_image(self):
        assert _sigma_modifier_to_fnmatch("python", "contains", is_image=True) == "*python*"

    def test_contains_non_image(self):
        assert _sigma_modifier_to_fnmatch("/etc/shadow", "contains", is_image=False) == "*/etc/shadow*"

    def test_startswith_image(self):
        assert _sigma_modifier_to_fnmatch("/usr/bin/py", "startswith", is_image=True) == "py*"

    def test_startswith_non_image(self):
        assert _sigma_modifier_to_fnmatch("/tmp/", "startswith", is_image=False) == "/tmp/*"

    def test_exact_image(self):
        assert _sigma_modifier_to_fnmatch("/usr/bin/perl", "", is_image=True) == "perl"

    def test_exact_non_image(self):
        assert _sigma_modifier_to_fnmatch("/etc/passwd", "", is_image=False) == "/etc/passwd"

    def test_re_returns_none(self):
        assert _sigma_modifier_to_fnmatch(".*bash.*", "re", is_image=True) is None


# ===================================================================
# _build_chain_filter
# ===================================================================

def test_build_chain_filter():
    assert _build_chain_filter("apache2", "bash") == "** > apache2 > bash"


# ===================================================================
# _has_unsupported_fields
# ===================================================================

class TestHasUnsupportedFields:
    def test_image_only(self):
        assert not _has_unsupported_fields({"Image|endswith": "/bash"})

    def test_commandline(self):
        assert _has_unsupported_fields({"CommandLine|contains": "evil"})

    def test_image_and_commandline(self):
        assert _has_unsupported_fields({
            "Image|endswith": "/bash",
            "CommandLine|contains": "-c",
        })

    def test_parent_and_image(self):
        assert not _has_unsupported_fields({
            "ParentImage|endswith": "/apache2",
            "Image|endswith": "/bash",
        })

    def test_regex_modifier_unsupported(self):
        assert _has_unsupported_fields({"Image|re": ".*evil.*"})

    def test_targetfilename(self):
        assert not _has_unsupported_fields({"TargetFilename|contains": "/etc/shadow"})


# ===================================================================
# translate_rule — core tests
# ===================================================================

class TestImageEndswithToProcessName:
    """Image|endswith: '/bash' -> process_name: 'bash'"""

    def test_basic(self):
        rule = _sigma({
            "selection": {"Image|endswith": "/bash"},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["rule_type"] == "process_name"
        assert result[0]["pattern"] == "bash"
        assert result[0]["chain_filter"] == ""


class TestImageContainsToGlob:
    """Image|contains: 'python' -> process_name: '*python*'"""

    def test_basic(self):
        rule = _sigma({
            "selection": {"Image|contains": "python"},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["rule_type"] == "process_name"
        assert result[0]["pattern"] == "*python*"


class TestParentImageCreatesChainFilter:
    """ParentImage + Image -> chain_filter: '** > parent > child'"""

    def test_basic(self):
        rule = _sigma({
            "selection": {
                "ParentImage|endswith": "/apache2",
                "Image|endswith": "/bash",
            },
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["rule_type"] == "process_name"
        assert result[0]["pattern"] == "bash"
        assert result[0]["chain_filter"] == "** > apache2 > bash"


class TestCommandLineOnlySkipped:
    """Rule with only CommandLine -> empty result."""

    def test_commandline_only(self):
        rule = _sigma({
            "selection": {"CommandLine|contains": "evil-command"},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason


class TestImageAndCommandLineSkipped:
    """Image AND CommandLine in same selection -> SKIP entire rule (ROE)."""

    def test_and_condition(self):
        rule = _sigma({
            "selection": {
                "Image|endswith": "/bash",
                "CommandLine|contains": "-c",
            },
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason


class TestMultipleImageValuesExpand:
    """Image|endswith: ['/bash', '/sh', '/dash'] -> 3 rules."""

    def test_three_values(self):
        rule = _sigma({
            "selection": {"Image|endswith": ["/bash", "/sh", "/dash"]},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 3
        patterns = {r["pattern"] for r in result}
        assert patterns == {"bash", "sh", "dash"}

    def test_with_parent_cross_product(self):
        rule = _sigma({
            "selection": {
                "ParentImage|endswith": ["/apache2", "/nginx"],
                "Image|endswith": ["/bash", "/sh"],
            },
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        # 2 parents x 2 children = 4 rules
        assert len(result) == 4
        chains = {r["chain_filter"] for r in result}
        assert "** > apache2 > bash" in chains
        assert "** > apache2 > sh" in chains
        assert "** > nginx > bash" in chains
        assert "** > nginx > sh" in chains


class TestFilterByLevel:
    """level: medium skipped when min_level=high."""

    def test_below_min(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            level="medium",
        )
        assert not filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])

    def test_at_min(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            level="high",
        )
        assert filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])

    def test_above_min(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            level="critical",
        )
        assert filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])


class TestFilterByStatus:
    """status: experimental skipped when statuses=[stable]."""

    def test_experimental_skipped(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            status="experimental",
        )
        assert not filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])

    def test_stable_accepted(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            status="stable",
        )
        assert filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])

    def test_test_skipped(self):
        rule = _sigma(
            {"selection": {"Image|endswith": "/bash"}, "condition": "selection"},
            status="test",
        )
        assert not filter_rule(rule, "high", ["stable"], ["process_creation"], ["linux"])


class TestOneOfSelectionExpansion:
    """condition: '1 of selection_*' with 2 selections -> 2+ rules."""

    def test_two_selections(self):
        rule = _sigma({
            "selection_web": {"Image|endswith": "/bash", "ParentImage|endswith": "/apache2"},
            "selection_ftp": {"Image|endswith": "/sh", "ParentImage|endswith": "/vsftpd"},
            "condition": "1 of selection_*",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) >= 2
        patterns = {r["pattern"] for r in result}
        assert "bash" in patterns
        assert "sh" in patterns

    def test_mixed_supported_unsupported(self):
        """One selection has CommandLine (skipped), other is translatable."""
        rule = _sigma({
            "selection_good": {"Image|endswith": "/ncat"},
            "selection_bad": {"CommandLine|contains": "evil"},
            "condition": "1 of selection_*",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["pattern"] == "ncat"


class TestFilePathRule:
    """TargetFilename|contains: '/etc/shadow' -> file_path: '*/etc/shadow*'"""

    def test_basic(self):
        rule = _sigma(
            {
                "selection": {"TargetFilename|contains": "/etc/shadow"},
                "condition": "selection",
            },
            category="file_event",
        )
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["rule_type"] == "file_path"
        assert result[0]["pattern"] == "*/etc/shadow*"


class TestDescriptionIncludesSigmaId:
    """Output description contains Sigma rule ID (first 8 chars) and level."""

    def test_format(self):
        rule = _sigma(
            {
                "selection": {"Image|endswith": "/bash"},
                "condition": "selection",
            },
            title="Suspicious Shell Spawn",
            rule_id="d18839c3-1234-5678-9abc-def012345678",
            level="critical",
        )
        result, _ = translate_rule(rule)
        assert len(result) == 1
        desc = result[0]["description"]
        assert "Suspicious Shell Spawn" in desc
        assert "d18839c3" in desc
        assert "critical" in desc


class TestOutputYamlStructure:
    """Generated YAML has 'metadata' and 'rules' keys."""

    def test_structure(self, tmp_path):
        rules = [
            {
                "rule_type": "process_name",
                "pattern": "bash",
                "description": "Test",
                "chain_filter": "",
                "tags": ["attack.execution"],
            },
        ]
        metadata = {
            "generated_at": "2026-02-22T00:00:00+00:00",
            "sigma_commit": "abc123",
            "total_compiled": 1,
            "total_skipped": 0,
        }
        outpath = tmp_path / "out.yml"
        write_output(rules, metadata, str(outpath))

        with open(outpath) as fh:
            content = fh.read()

        # Header comments present
        assert "Auto-generated" in content
        assert "SigmaHQ" in content

        # Parse YAML (skip comment lines)
        doc = yaml.safe_load(content)
        assert "metadata" in doc
        assert "rules" in doc
        assert doc["metadata"]["total_compiled"] == 1
        assert len(doc["rules"]) == 1
        assert doc["rules"][0]["rule_type"] == "process_name"


# ===================================================================
# Condition parser
# ===================================================================

class TestParseCondition:
    def test_simple(self):
        c = _parse_condition("selection")
        assert c["type"] == "simple"
        assert c["selection"] == "selection"

    def test_and_not(self):
        c = _parse_condition("selection and not filter")
        assert c["type"] == "and_not"
        assert c["selection"] == "selection"

    def test_1_of(self):
        c = _parse_condition("1 of selection_*")
        assert c["type"] == "1_of"

    def test_all_of(self):
        c = _parse_condition("all of selection_*")
        assert c["type"] == "all_of"

    def test_or(self):
        c = _parse_condition("sel1 or sel2")
        assert c["type"] == "or"
        assert c["selections"] == ["sel1", "sel2"]

    def test_and(self):
        c = _parse_condition("sel1 and sel2")
        assert c["type"] == "and"
        assert c["selections"] == ["sel1", "sel2"]

    def test_complex(self):
        c = _parse_condition("(sel1 or sel2) and not filter")
        assert c["type"] == "complex"


# ===================================================================
# Edge cases & AND-condition enforcement
# ===================================================================

class TestAndNotDropsFilter:
    """'selection and not filter' translates selection, drops NOT-filter."""

    def test_filter_ignored(self):
        rule = _sigma({
            "selection": {"Image|endswith": "/ncat"},
            "filter": {"CommandLine|contains": "--version"},
            "condition": "selection and not filter",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["pattern"] == "ncat"


class TestAllOfAndCondition:
    """all of selection_* — ALL must be fully supported or skip."""

    def test_all_supported(self):
        rule = _sigma({
            "selection_parent": {"ParentImage|endswith": "/nginx"},
            "selection_child": {"Image|endswith": "/bash"},
            "condition": "all of selection_*",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["pattern"] == "bash"
        assert result[0]["chain_filter"] == "** > nginx > bash"

    def test_one_unsupported(self):
        rule = _sigma({
            "selection_good": {"Image|endswith": "/bash"},
            "selection_bad": {"CommandLine|contains": "evil"},
            "condition": "all of selection_*",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason


class TestExactImagePath:
    """Exact Image path extracts basename."""

    def test_full_path(self):
        rule = _sigma({
            "selection": {"Image": "/usr/bin/perl"},
            "condition": "selection",
        })
        result, _ = translate_rule(rule)
        assert len(result) == 1
        assert result[0]["pattern"] == "perl"


class TestTagsPropagated:
    """Tags from Sigma rule appear in output."""

    def test_tags(self):
        rule = _sigma(
            {
                "selection": {"Image|endswith": "/bash"},
                "condition": "selection",
            },
            tags=["attack.execution", "attack.t1059"],
        )
        result, _ = translate_rule(rule)
        assert result[0]["tags"] == ["attack.execution", "attack.t1059"]


class TestUntranslatableParentPathSkipped:
    """ParentImage|startswith: '/tmp/' -> empty basename -> skip entire rule."""

    def test_path_only_parent(self):
        rule = _sigma({
            "selection": {
                "Image|endswith": ["/bash", "/sh"],
                "ParentImage|startswith": "/tmp/",
            },
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        # Must NOT produce unscoped bash/sh rules — Blue-on-Blue
        assert result == []


class TestInterBlockAndLogic:
    """When blocks are AND-combined, unsupported fields in ANY block
    must poison the entire rule — no translating the 'good half'."""

    def test_history_file_deletion_scenario(self):
        """Reproduces the rm/unlink/shred catastrophe:
        selection_tools has Image (supported), selection_target has
        CommandLine (unsupported).  With 'all of selection*' the
        entire rule must be skipped."""
        rule = _sigma({
            "selection_tools": {
                "Image|endswith": ["/rm", "/unlink", "/shred"],
            },
            "selection_target": {
                "CommandLine|contains": [".bash_history", ".zsh_history"],
            },
            "condition": "all of selection*",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason

    def test_explicit_and_with_mixed_blocks(self):
        """sel1 and sel2 — sel2 has CommandLine → skip."""
        rule = _sigma({
            "sel1": {"Image|endswith": "/curl"},
            "sel2": {"CommandLine|contains": "http://evil"},
            "condition": "sel1 and sel2",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason

    def test_list_of_dicts_block_detected(self):
        """Reproduces real SigmaHQ structure: selection_history is a YAML
        list-of-dicts (Sigma OR shorthand) containing CommandLine.
        Must poison the entire 'all of selection*' rule."""
        rule = _sigma({
            "selection": {
                "Image|endswith": ["/rm", "/unlink", "/shred"],
            },
            # List-of-dicts — Sigma OR shorthand for the history patterns
            "selection_history": [
                {"CommandLine|contains": ["/.bash_history", "/.zsh_history"]},
                {"CommandLine|endswith": ["_history", ".history"]},
            ],
            "condition": "all of selection*",
        })
        result, reason = translate_rule(rule)
        assert result == []
        assert "unsupported" in reason

    def test_block_has_unsupported_fields_list(self):
        """_block_has_unsupported_fields handles list-of-dicts."""
        block = [
            {"CommandLine|contains": "evil"},
            {"Image|endswith": "/bash"},
        ]
        assert _block_has_unsupported_fields(block) is True

        clean_block = [
            {"Image|endswith": "/bash"},
        ]
        assert _block_has_unsupported_fields(clean_block) is False

    def test_all_supported_blocks_still_merge(self):
        """AND of pure Image + ParentImage blocks still works."""
        rule = _sigma({
            "selection_parent": {"ParentImage|endswith": "/apache2"},
            "selection_child": {"Image|endswith": "/bash"},
            "condition": "all of selection_*",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["chain_filter"] == "** > apache2 > bash"


class TestBlastShield:
    """UNSCOPED_DANGER_BINARIES failsafe — last line of defense."""

    def test_constant_contains_expected_binaries(self):
        for name in ("rm", "unlink", "john", "bash", "sh", "python",
                      "python3", "perl", "awk", "sed", "systemctl",
                      "journalctl",
                      # Dual-use DevSecOps
                      "*teamserver*", "httpx", "legion", "nuclei",
                      "*sniper*", "hashcat"):
            assert name in UNSCOPED_DANGER_BINARIES

    def test_unscoped_bash_blocked(self):
        """translate_rule may emit 'bash' without chain — blast shield
        must catch it at the main() layer. Verify the rule itself."""
        rule = _sigma({
            "selection": {"Image|endswith": "/bash"},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        # translate_rule doesn't know about blast shield — it emits the rule
        assert len(result) == 1
        assert result[0]["pattern"] == "bash"
        assert result[0]["chain_filter"] == ""
        # The blast shield is applied in main(), not translate_rule.
        # Verify the pattern IS in the danger list:
        assert result[0]["pattern"].lower() in UNSCOPED_DANGER_BINARIES

    def test_scoped_bash_allowed(self):
        """bash WITH chain_filter must NOT be blocked."""
        rule = _sigma({
            "selection": {
                "ParentImage|endswith": "/apache2",
                "Image|endswith": "/bash",
            },
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["pattern"] == "bash"
        assert result[0]["chain_filter"] == "** > apache2 > bash"
        # chain_filter present → blast shield won't touch it

    def test_safe_binary_unscoped_allowed(self):
        """Binaries NOT in danger list pass through unscoped."""
        rule = _sigma({
            "selection": {"Image|endswith": "/crackmapexec"},
            "condition": "selection",
        })
        result, reason = translate_rule(rule)
        assert reason == ""
        assert len(result) == 1
        assert result[0]["pattern"] == "crackmapexec"
        assert result[0]["chain_filter"] == ""
        assert result[0]["pattern"].lower() not in UNSCOPED_DANGER_BINARIES


class TestNoDetectionSkipped:
    """Rule with no condition -> skip."""

    def test_empty_condition(self):
        rule = _sigma({"selection": {"Image|endswith": "/bash"}})
        # Remove condition
        rule["detection"].pop("condition", None)
        result, reason = translate_rule(rule)
        assert result == []
        assert "no condition" in reason
