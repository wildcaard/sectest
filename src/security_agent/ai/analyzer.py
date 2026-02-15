import json
import logging
from typing import Optional

from security_agent.ai.llm_client import get_llm_client

logger = logging.getLogger("security_agent")


class VulnerabilityAnalyzer:
    """Uses LLM (Anthropic, OpenAI, or Ollama) to analyze and correlate vulnerability findings."""

    def __init__(self, config: dict):
        self.config = config.get("ai", {})
        self.enabled = self.config.get("enabled", True)
        self.max_tokens = self.config.get("max_tokens", 4096)
        self._llm_client = get_llm_client(config)
        if self._llm_client is None and self.enabled:
            self.enabled = False

    async def analyze_findings(
        self, vulnerabilities: list, target_url: str, tech_stack: dict
    ) -> list:
        """Analyze vulnerability findings using Claude for correlation and assessment.

        Returns the vulnerabilities list with ai_analysis field populated.
        """
        if not self.enabled or not vulnerabilities or not self._llm_client:
            return vulnerabilities

        findings_data = []
        for v in vulnerabilities:
            findings_data.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "category": v.category.value,
                "description": v.description,
                "evidence": v.evidence[:500],  # Truncate for token limit
                "cvss_score": v.cvss_score,
                "cwe_id": v.cwe_id,
            })

        prompt = f"""You are an expert web security analyst. Analyze the following vulnerability findings from an automated scan of {target_url}.

Technology Stack Detected: {json.dumps(tech_stack, indent=2)}

Raw Findings:
{json.dumps(findings_data, indent=2)}

For each finding (reference by id), provide:
1. Validation assessment (true positive / likely false positive / needs verification)
2. Real-world exploitability assessment (low/medium/high)
3. Business impact analysis (1-2 sentences)
4. Related findings that could be chained together (list finding ids)
5. Priority ranking (1 = highest priority)

Respond in JSON format as a list of objects with keys: id, validation, exploitability, business_impact, related_findings, priority"""

        try:
            result_text = await self._llm_client.complete(prompt, self.max_tokens)
            # Try to parse JSON from response
            # Handle case where response might have markdown code blocks
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]

            analyses = json.loads(result_text)

            # Map analyses back to vulnerabilities
            analysis_map = {a["id"]: a for a in analyses}
            for vuln in vulnerabilities:
                if vuln.id in analysis_map:
                    a = analysis_map[vuln.id]
                    vuln.ai_analysis = (
                        f"Validation: {a.get('validation', 'N/A')}\n"
                        f"Exploitability: {a.get('exploitability', 'N/A')}\n"
                        f"Impact: {a.get('business_impact', 'N/A')}\n"
                        f"Priority: {a.get('priority', 'N/A')}"
                    )
                    if a.get("validation") == "likely false positive":
                        vuln.false_positive_likelihood = "high"

        except json.JSONDecodeError:
            logger.warning("Failed to parse AI analysis response as JSON")
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")

        return vulnerabilities
