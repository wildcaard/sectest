import json
import logging
from collections import defaultdict

from security_agent.ai.llm_client import get_llm_client

logger = logging.getLogger("security_agent")


class FixSuggester:
    """Uses LLM (Anthropic, OpenAI, or Ollama) to generate fix and remediation suggestions."""

    def __init__(self, config: dict):
        self.config = config.get("ai", {})
        self.enabled = self.config.get("enabled", True)
        self.max_tokens = self.config.get("max_tokens", 4096)
        self._llm_client = get_llm_client(config)
        if self._llm_client is None and self.enabled:
            self.enabled = False

    async def suggest_fixes(
        self, vulnerabilities: list, target_url: str, tech_stack: dict
    ) -> list:
        """Generate fix suggestions for vulnerabilities using Claude.

        Groups vulnerabilities by category to reduce API calls.
        Returns the vulnerabilities list with ai_fix_suggestion and remediation fields populated.
        """
        if not self.enabled or not vulnerabilities or not self._llm_client:
            return vulnerabilities

        # Group vulnerabilities by category to reduce API calls
        grouped = defaultdict(list)
        for v in vulnerabilities:
            grouped[v.category.value].append(v)

        for category, vulns in grouped.items():
            findings_data = []
            for v in vulns:
                findings_data.append({
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description,
                    "evidence": v.evidence[:500],
                    "url": v.url,
                    "cwe_id": v.cwe_id,
                })

            prompt = f"""You are an expert web security engineer. Provide detailed fix suggestions for the following {category} vulnerabilities found on {target_url}.

Technology Stack: {json.dumps(tech_stack, indent=2)}

Vulnerabilities:
{json.dumps(findings_data, indent=2)}

For each vulnerability (reference by id), provide:
1. immediate_fix: A quick mitigation that can be applied right away (1-2 sentences)
2. long_term_solution: A proper long-term fix with code examples appropriate for the detected technology stack
3. server_config: Any server-specific configuration changes needed (e.g., nginx, Apache, IIS directives)
4. testing_steps: Steps to verify the fix has been applied correctly (numbered list as a string)
5. references: Links to official documentation or security guides (list of URLs)

Respond in JSON format as a list of objects with keys: id, immediate_fix, long_term_solution, server_config, testing_steps, references"""

            try:
                result_text = await self._llm_client.complete(prompt, self.max_tokens)
                # Handle markdown code blocks in response
                if "```json" in result_text:
                    result_text = result_text.split("```json")[1].split("```")[0]
                elif "```" in result_text:
                    result_text = result_text.split("```")[1].split("```")[0]

                suggestions = json.loads(result_text)

                # Map suggestions back to vulnerabilities
                suggestion_map = {s["id"]: s for s in suggestions}
                for vuln in vulns:
                    if vuln.id in suggestion_map:
                        s = suggestion_map[vuln.id]
                        vuln.ai_fix_suggestion = (
                            f"Immediate Fix: {s.get('immediate_fix', 'N/A')}\n\n"
                            f"Long-term Solution:\n{s.get('long_term_solution', 'N/A')}\n\n"
                            f"Server Configuration:\n{s.get('server_config', 'N/A')}\n\n"
                            f"Testing Steps:\n{s.get('testing_steps', 'N/A')}\n\n"
                            f"References:\n"
                            + "\n".join(
                                f"- {ref}" for ref in s.get("references", [])
                            )
                        )
                        vuln.remediation = s.get("immediate_fix", "")

            except json.JSONDecodeError:
                logger.warning(
                    f"Failed to parse AI fix suggestion response as JSON for category: {category}"
                )
            except Exception as e:
                logger.warning(f"AI fix suggestion failed for category {category}: {e}")

        return vulnerabilities
