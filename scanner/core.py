import re
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ScanResult:
    is_safe: bool
    risk_score: int
    matched_rules: List[str] = field(default_factory=list)
    category: Optional[str] = None
    decoded_payloads: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class SecurityScanner:
    """Enterprise-grade heuristic security engine for LLM and Agent workflows."""

    PATTERNS = {
        "SEC-001: SYSTEM_OVERRIDE": [
            r"(?i)\b(?:ignore|disregard|forget|bypass|override)\b\s+(?:all\s+)?(?:previous|prior|system|above)\s+(?:instructions|prompts|rules|commands)",
            r"(?i)\byou\s+are\s+no\s+longer\s+(?:bound|restricted|an\s+ai)",
            r"(?i)\bstart\s+fresh\s+and\s+do\s+not\s+follow\s+any\s+prior",
        ],
        "SEC-002: DELIMITER_ESCAPE": [
            r"(?i)<\/?(?:system|instruction|admin|developer_prompt|prompt)>",
            r"(?i)```(?:system|admin|override)\b",
            r"(?i)---(?:BEGIN|END)\s+(?:SYSTEM|RULES|PROMPT)---",
        ],
        "SEC-003: JAILBREAK_ROLEPLAY": [
            r"(?i)\b(?:DAN|Do\s+Anything\s+Now)\b",
            r"(?i)\bjailbreak\s+mode\s+(?:enabled|activated|on)",
            r"(?i)\bact\s+as\s+(?:an?\s+unrestricted|an\s+evil|an\s+uncensored)\b",
            r"(?i)\bfor\s+(?:hypothetical|educational|research)\s+purposes\s+only,?\s+how\s+would\s+an\s+attacker",
        ],
        "SEC-004: EXFILTRATION": [
            r"(?i)\b(?:print|display|reveal|leak|show|output)\s+(?:your\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+rules|api\s+keys?)",
            r"(?i)\bwhat\s+(?:is|are)\s+the\s+exact\s+words?\s+of\s+your\s+(?:instructions|prompt)",
        ],
        "SEC-005: TOOL_POISONING": [
            r"(?i)(?:;|&&|\|\|)\s*(?:rm\s+-rf|curl\s+|wget\s+|chmod\s+|bash\s+-i|nc\s+)",
            r"(?i)(?:UNION\s+ALL\s+SELECT|DROP\s+TABLE|--\s*$|OR\s+1=1)",
            r"(?:\.\.\/|\.\.\\){2,}",
        ]
    }

    def _inspect_encoded_payloads(self, text: str) -> List[str]:
        decoded = []
        # Find potential base64 blocks (length >= 16)
        candidates = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', text)
        for cand in candidates:
            try:
                raw = base64.b64decode(cand, validate=True).decode('utf-8', errors='ignore')
                if len(raw) >= 6 and any(c.isalpha() for c in raw):
                    decoded.append(raw)
            except Exception:
                continue
        return decoded

    def scan_prompt(self, text: str) -> ScanResult:
        if not text or not text.strip():
            return ScanResult(is_safe=True, risk_score=0)

        matched_rules = []
        decoded_payloads = self._inspect_encoded_payloads(text)
        
        # Test original text and any unmasked payloads
        corpus = [text] + decoded_payloads

        for item in corpus:
            for rule_name, regex_list in self.PATTERNS.items():
                for pattern in regex_list:
                    if re.search(pattern, item):
                        if rule_name not in matched_rules:
                            matched_rules.append(rule_name)

        if not matched_rules:
            return ScanResult(is_safe=True, risk_score=0, decoded_payloads=decoded_payloads)

        score = min(100, len(matched_rules) * 35)
        primary_category = matched_rules[0].split(":")[1].strip()

        return ScanResult(
            is_safe=False,
            risk_score=score,
            matched_rules=matched_rules,
            category=primary_category,
            decoded_payloads=decoded_payloads,
            details={"matches_count": len(matched_rules)}
        )

    def scan_tool_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> ScanResult:
        """Inspects parameters sent to an MCP or function tool."""
        flat_values = []
        def _extract(val):
            if isinstance(val, str):
                flat_values.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    _extract(v)
            elif isinstance(val, list):
                for v in val:
                    _extract(v)

        _extract(parameters)
        combined_text = "\n".join(flat_values)
        res = self.scan_prompt(combined_text)
        res.details["tool_name"] = tool_name
        return res
