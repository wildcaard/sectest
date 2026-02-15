import json
import logging

from security_agent.ai.llm_client import get_llm_client

logger = logging.getLogger("security_agent")


class RiskAssessor:
    """Uses LLM (Anthropic, OpenAI, or Ollama) to perform intelligent risk assessment of scan findings."""

    def __init__(self, config: dict):
        self.config = config.get("ai", {})
        self.enabled = self.config.get("enabled", True)
        self.max_tokens = self.config.get("max_tokens", 4096)
        self._llm_client = get_llm_client(config)
        if self._llm_client is None and self.enabled:
            self.enabled = False

    def _fallback_assessment(self, vulnerabilities: list) -> dict:
        """Simple algorithmic risk calculation when AI is unavailable."""
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = v.severity.value.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        raw_score = sum(
            count * severity_weights.get(sev, 0)
            for sev, count in severity_counts.items()
        )
        composite_score = min(100, raw_score)

        if composite_score >= 75:
            risk_level = "Critical"
        elif composite_score >= 50:
            risk_level = "High"
        elif composite_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Build basic top risks from highest severity findings
        top_risks = []
        for v in sorted(
            vulnerabilities,
            key=lambda x: list(severity_weights.keys()).index(
                x.severity.value.lower()
                if x.severity.value.lower() in severity_weights
                else "info"
            ),
        )[:3]:
            top_risks.append(f"[{v.severity.value.upper()}] {v.title}")

        # Build remediation priorities from severity order
        remediation_priorities = []
        for v in sorted(
            vulnerabilities,
            key=lambda x: list(severity_weights.keys()).index(
                x.severity.value.lower()
                if x.severity.value.lower() in severity_weights
                else "info"
            ),
        ):
            entry = f"Fix {v.title} ({v.severity.value})"
            if entry not in remediation_priorities:
                remediation_priorities.append(entry)

        total = len(vulnerabilities)
        crit = severity_counts["critical"]
        high = severity_counts["high"]
        executive_summary = (
            f"Scan identified {total} vulnerabilities: "
            f"{crit} critical, {high} high severity. "
            f"Overall risk level is {risk_level} with a composite score of {composite_score}/100."
        )

        return {
            "composite_score": composite_score,
            "risk_level": risk_level,
            "executive_summary": executive_summary,
            "top_risks": top_risks,
            "remediation_priorities": remediation_priorities,
            "attack_chains": [],
        }

    async def assess_risk(
        self, vulnerabilities: list, target_url: str, tech_stack: dict
    ) -> dict:
        """Perform an AI-powered risk assessment of all findings.

        Returns a dict with composite_score, risk_level, executive_summary,
        top_risks, remediation_priorities, and attack_chains.
        Falls back to algorithmic calculation if AI is unavailable.
        """
        if not vulnerabilities:
            return {
                "composite_score": 0,
                "risk_level": "Low",
                "executive_summary": "No vulnerabilities were identified during the scan.",
                "top_risks": [],
                "remediation_priorities": [],
                "attack_chains": [],
            }

        if not self.enabled or not self._llm_client:
            return self._fallback_assessment(vulnerabilities)

        findings_data = []
        for v in vulnerabilities:
            findings_data.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "category": v.category.value,
                "description": v.description,
                "url": v.url,
                "cvss_score": v.cvss_score,
                "cwe_id": v.cwe_id,
            })

        prompt = f"""You are a senior security risk analyst. Perform a comprehensive risk assessment based on the following vulnerability scan results for {target_url}.

Technology Stack: {json.dumps(tech_stack, indent=2)}

Findings:
{json.dumps(findings_data, indent=2)}

Provide a risk assessment in JSON format with the following structure:
{{
    "composite_score": <number 0-100 representing overall risk>,
    "risk_level": "<Critical|High|Medium|Low>",
    "executive_summary": "<2-3 sentence executive summary suitable for non-technical stakeholders>",
    "top_risks": ["<description of risk 1>", "<description of risk 2>", "<description of risk 3>"],
    "remediation_priorities": ["<ordered list of remediation actions, highest priority first>"],
    "attack_chains": [
        {{
            "chain_name": "<descriptive name for the attack chain>",
            "steps": ["<step 1>", "<step 2>", "..."],
            "combined_severity": "<Critical|High|Medium|Low>",
            "description": "<how these vulnerabilities can be chained together>"
        }}
    ]
}}

Consider:
- How vulnerabilities could be chained together for greater impact
- The technology stack's known weaknesses
- Real-world attacker methodology
- Business impact potential

Respond with ONLY the JSON object, no additional text."""

        try:
            result_text = await self._llm_client.complete(prompt, self.max_tokens)
            # Handle markdown code blocks in response
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]

            assessment = json.loads(result_text)

            # Validate required keys and set defaults
            required_keys = {
                "composite_score": 0,
                "risk_level": "Medium",
                "executive_summary": "",
                "top_risks": [],
                "remediation_priorities": [],
                "attack_chains": [],
            }
            for key, default in required_keys.items():
                if key not in assessment:
                    assessment[key] = default

            # Clamp composite score to 0-100
            assessment["composite_score"] = max(
                0, min(100, int(assessment["composite_score"]))
            )

            return assessment

        except json.JSONDecodeError:
            logger.warning(
                "Failed to parse AI risk assessment response as JSON. "
                "Falling back to algorithmic assessment."
            )
            return self._fallback_assessment(vulnerabilities)
        except Exception as e:
            logger.warning(
                f"AI risk assessment failed: {e}. Falling back to algorithmic assessment."
            )
            return self._fallback_assessment(vulnerabilities)
