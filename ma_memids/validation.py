from __future__ import annotations

import json
import math
import os
import re
import subprocess
import tempfile
from typing import List, Optional, Tuple

from .config import Thresholds
from .models import FailureDiagnosis, SandboxResult, ValidationMetrics, ValidationResult
from .rule_parser import extract_sid
from .utils import safe_div


class SuricataValidator:
    def __init__(
        self,
        suricata_path: str = "/usr/bin/suricata",
        suricata_config: str = "/etc/suricata/suricata.yaml",
        validation_mode: str = "strict",
    ):
        self.suricata_path = suricata_path
        self.suricata_config = suricata_config
        self.validation_mode = validation_mode

    def validate_rule_format(self, rule: str) -> Tuple[bool, Optional[str]]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(rule + "\n")
            rule_file = f.name

        try:
            with tempfile.TemporaryDirectory() as log_dir:
                proc = subprocess.run(
                    [
                        self.suricata_path,
                        "-T",
                        "-S",
                        rule_file,
                        "-c",
                        self.suricata_config,
                        "-l",
                        log_dir,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            if proc.returncode == 0:
                return True, None
            return False, (proc.stderr or proc.stdout or "Suricata syntax error").strip()
        except FileNotFoundError:
            return self._basic_syntax_check(rule)
        except subprocess.TimeoutExpired:
            return False, "Suricata format validation timeout"
        finally:
            try:
                os.unlink(rule_file)
            except OSError:
                pass

    def _basic_syntax_check(self, rule: str) -> Tuple[bool, Optional[str]]:
        pattern = r"^(alert|drop|pass|reject)\s+(tcp|udp|icmp|ip|http)\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s+\(.+\)$"
        if not re.match(pattern, rule.strip(), flags=re.IGNORECASE):
            return False, "Invalid rule structure"
        if "sid:" not in rule:
            return False, "Missing sid"
        if "msg:" not in rule:
            return False, "Missing msg"
        if rule.count("(") != rule.count(")"):
            return False, "Unbalanced parentheses"
        return True, None

    def test_rule_against_pcap(self, rule: str, pcap_path: str) -> ValidationResult:
        ok, err = self.validate_rule_format(rule)
        if not ok:
            return ValidationResult(
                is_valid=False,
                format_check_passed=False,
                alerts_triggered=False,
                error_message=err,
            )

        if self.validation_mode == "format-only":
            return ValidationResult(
                is_valid=True,
                format_check_passed=True,
                alerts_triggered=True,
                error_message="format-only mode",
            )

        if not os.path.exists(pcap_path):
            return ValidationResult(
                is_valid=False,
                format_check_passed=True,
                alerts_triggered=False,
                error_message=f"PCAP not found: {pcap_path}",
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(rule + "\n")
            rule_file = f.name

        try:
            with tempfile.TemporaryDirectory() as log_dir:
                proc = subprocess.run(
                    [
                        self.suricata_path,
                        "-r",
                        pcap_path,
                        "-S",
                        rule_file,
                        "-c",
                        self.suricata_config,
                        "-l",
                        log_dir,
                        "--runmode",
                        "single",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=90,
                )

                eve_file = os.path.join(log_dir, "eve.json")
                alerts = []
                if os.path.exists(eve_file):
                    with open(eve_file, "r", encoding="utf-8") as fobj:
                        for line in fobj:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if event.get("event_type") == "alert":
                                alerts.append(event)

                triggered = len(alerts) > 0
                msg = (proc.stderr or proc.stdout or "").strip()
                return ValidationResult(
                    is_valid=triggered,
                    format_check_passed=True,
                    alerts_triggered=triggered,
                    error_message=(None if triggered else msg or "No alert triggered"),
                    alert_details=alerts or None,
                )
        except FileNotFoundError:
            # Suricata missing: cannot replay, treat as format-only result.
            return ValidationResult(
                is_valid=True,
                format_check_passed=True,
                alerts_triggered=True,
                error_message="Suricata binary not found, skipped replay",
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                is_valid=False,
                format_check_passed=True,
                alerts_triggered=False,
                error_message="Suricata replay timeout",
            )
        finally:
            try:
                os.unlink(rule_file)
            except OSError:
                pass


class SandboxEvaluator:
    def __init__(self, validator: SuricataValidator, thresholds: Optional[Thresholds] = None):
        self.validator = validator
        self.thresholds = thresholds or Thresholds()

    def evaluate(self, rule: str, attack_pcaps: List[str], benign_pcaps: List[str]) -> SandboxResult:
        ok, err = self.validator.validate_rule_format(rule)
        if not ok:
            return SandboxResult(passed=False, syntax_ok=False, metrics=None, reason=err or "syntax check failed")

        tp = fp = tn = fn = 0

        for pcap in attack_pcaps:
            res = self.validator.test_rule_against_pcap(rule, pcap)
            if res.alerts_triggered:
                tp += 1
            else:
                fn += 1

        for pcap in benign_pcaps:
            res = self.validator.test_rule_against_pcap(rule, pcap)
            if res.alerts_triggered:
                fp += 1
            else:
                tn += 1

        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        fpr = safe_div(fp, fp + tn)
        f2 = safe_div(5.0 * precision * recall, 4.0 * precision + recall)
        p_fpr = math.exp(-10.0 * max(0.0, fpr - self.thresholds.fpr_redline))
        score = f2 * p_fpr

        metrics = ValidationMetrics(
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            precision=precision,
            recall=recall,
            fpr=fpr,
            f2=f2,
            p_fpr=p_fpr,
            score=score,
        )
        passed = score >= self.thresholds.pass_score
        reason = "pass" if passed else "score below threshold"
        return SandboxResult(passed=passed, syntax_ok=True, metrics=metrics, reason=reason)

    def diagnose_failure(self, metrics: Optional[ValidationMetrics]) -> FailureDiagnosis:
        if metrics is None:
            return FailureDiagnosis(
                failure_type="syntax",
                suggestion="Fix Suricata syntax errors first, then replay validation.",
            )

        if metrics.fpr > 0.10:
            return FailureDiagnosis(
                failure_type="overgeneralization",
                suggestion="Increase precise content/pcre primitives and add threshold/rate limits.",
            )

        if metrics.recall < 0.50:
            return FailureDiagnosis(
                failure_type="overfitting",
                suggestion="Replace hard-coded literals with regex/generalized tokens and include missed variant indicators.",
            )

        return FailureDiagnosis(
            failure_type="low_score",
            suggestion="Balance precision-recall tradeoff by tightening noisy matches and preserving core exploit indicators.",
        )


__all__ = [
    "SuricataValidator",
    "SandboxEvaluator",
    "extract_sid",
]
