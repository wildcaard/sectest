"""SQL Injection detection scanner - passive analysis only."""

import re
from urllib.parse import urlparse, parse_qs

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class SQLiScanner(BaseScanner):
    """Passive SQL injection detection scanner that identifies error messages and potential injection points."""

    DB_ERROR_PATTERNS: list[tuple[str, str]] = [
        (r"You have an error in your SQL syntax", "MySQL"),
        (r"Warning:.*mysql_", "MySQL (PHP)"),
        (r"MySqlException", "MySQL (.NET)"),
        (r"com\.mysql\.jdbc", "MySQL (Java)"),
        (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
        (r"pg_query\(\).*ERROR", "PostgreSQL (PHP)"),
        (r"PSQLException", "PostgreSQL (Java)"),
        (r"Unclosed quotation mark after the character string", "MSSQL"),
        (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
        (r"SqlException", "MSSQL (.NET)"),
        (r"mssql_query\(\)", "MSSQL (PHP)"),
        (r"ORA-\d{5}", "Oracle"),
        (r"oracle\.jdbc", "Oracle (Java)"),
        (r"SQLITE_ERROR", "SQLite"),
        (r"sqlite3\.OperationalError", "SQLite (Python)"),
        (r"SQLite3::SQLException", "SQLite (Ruby)"),
        (r"near \".*?\": syntax error", "SQLite"),
        (r"SQL syntax.*?error", "Generic SQL"),
        (r"valid MySQL result", "MySQL"),
        (r"supplied argument is not a valid", "Generic DB"),
        (r"Syntax error.*?in query expression", "MS Access"),
        (r"Driver.*?SQL[\-\_\s]*Server", "MSSQL Driver"),
        (r"javax\.persistence", "JPA/Hibernate"),
    ]

    SUSPICIOUS_PARAM_NAMES: list[str] = [
        "id", "user_id", "uid", "pid", "cid", "nid",
        "cat", "category", "page", "item", "product",
        "order", "sort", "column", "table", "query",
        "search", "q", "keyword", "filter", "where",
        "select", "from", "limit", "offset", "count",
        "type", "status", "action", "name", "username",
    ]

    @property
    def name(self) -> str:
        return "SQL Injection Scanner"

    @property
    def description(self) -> str:
        return "Detects potential SQL injection vulnerabilities through passive analysis"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute passive SQL injection detection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text

            self._check_db_error_messages(target_url, body)
            self._check_url_parameters(target_url, body)
            self._check_form_fields(target_url, body)
            self._check_numeric_params(target_url)
            self._check_raw_sql_patterns(target_url, body)

        except Exception:
            pass

        return self.vulnerabilities

    def _check_db_error_messages(self, target_url: str, body: str) -> None:
        """Look for database error messages in the response."""
        try:
            for pattern, db_type in self.DB_ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    self.add_vulnerability(Vulnerability(
                        title=f"Database Error Message Exposed ({db_type})",
                        severity=Severity.CRITICAL,
                        category=VulnerabilityCategory.INJECTION,
                        description=(
                            f"A {db_type} database error message was found in the response. "
                            "This indicates that SQL queries may be improperly handled and that "
                            "detailed error information is being leaked to users, which aids SQL injection attacks."
                        ),
                        evidence=f"Matched pattern: {match.group(0)[:200]}",
                        url=target_url,
                        remediation=(
                            "Use parameterized queries or prepared statements. "
                            "Implement generic error pages that do not expose database details."
                        ),
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 Injection",
                        false_positive_likelihood="low",
                    ))
                    # Report only the first DB error match to avoid noise
                    return
        except Exception:
            pass

    def _check_url_parameters(self, target_url: str, body: str) -> None:
        """Identify URL parameters that might interact with a database."""
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)

            suspicious_found: list[str] = []
            for param_name in params:
                param_lower = param_name.lower()
                if param_lower in self.SUSPICIOUS_PARAM_NAMES:
                    suspicious_found.append(param_name)

            if suspicious_found:
                self.add_vulnerability(Vulnerability(
                    title="Potential SQL Injection Points in URL Parameters",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.INJECTION,
                    description=(
                        f"The URL contains {len(suspicious_found)} parameter(s) with names commonly "
                        "associated with database queries. These parameters may be vulnerable to "
                        "SQL injection if not properly parameterized."
                    ),
                    evidence=f"Suspicious parameters: {', '.join(suspicious_found)}",
                    url=target_url,
                    remediation="Use parameterized queries for all database interactions involving user input.",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 Injection",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_form_fields(self, target_url: str, body: str) -> None:
        """Identify form fields that might interact with a database."""
        try:
            forms = re.findall(r"<form[^>]*>(.*?)</form>", body, re.DOTALL | re.IGNORECASE)

            for form_index, form_content in enumerate(forms):
                input_names: list[str] = re.findall(
                    r'<input[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
                    form_content,
                    re.IGNORECASE,
                )
                select_names: list[str] = re.findall(
                    r'<select[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
                    form_content,
                    re.IGNORECASE,
                )
                all_fields = input_names + select_names

                suspicious_fields: list[str] = [
                    f for f in all_fields if f.lower() in self.SUSPICIOUS_PARAM_NAMES
                ]

                if suspicious_fields:
                    self.add_vulnerability(Vulnerability(
                        title=f"Potential SQL Injection Points in Form #{form_index + 1}",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.INJECTION,
                        description=(
                            f"Form #{form_index + 1} contains field(s) with names commonly associated "
                            "with database queries that could be SQL injection points."
                        ),
                        evidence=f"Suspicious form fields: {', '.join(suspicious_fields)}",
                        url=target_url,
                        remediation="Use parameterized queries for all database interactions involving user input.",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 Injection",
                        false_positive_likelihood="medium",
                    ))
        except Exception:
            pass

    def _check_numeric_params(self, target_url: str) -> None:
        """Check for numeric URL parameters that may lack proper validation."""
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)

            numeric_params: list[str] = []
            for param_name, values in params.items():
                for value in values:
                    if value.isdigit():
                        numeric_params.append(f"{param_name}={value}")

            if numeric_params:
                self.add_vulnerability(Vulnerability(
                    title="Numeric URL Parameters Detected",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.INJECTION,
                    description=(
                        "The URL contains numeric parameters that are commonly used as database "
                        "record identifiers. Without proper type validation and parameterized queries, "
                        "these could be vulnerable to SQL injection."
                    ),
                    evidence=f"Numeric parameters: {', '.join(numeric_params)}",
                    url=target_url,
                    remediation=(
                        "Validate that numeric parameters contain only integers. "
                        "Use parameterized queries even for numeric values."
                    ),
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 Injection",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_raw_sql_patterns(self, target_url: str, body: str) -> None:
        """Look for patterns suggesting raw SQL usage in error output or debug info."""
        try:
            raw_sql_patterns: list[tuple[str, str]] = [
                (r"SELECT\s+.*?\s+FROM\s+", "SELECT statement"),
                (r"INSERT\s+INTO\s+", "INSERT statement"),
                (r"UPDATE\s+\w+\s+SET\s+", "UPDATE statement"),
                (r"DELETE\s+FROM\s+", "DELETE statement"),
                (r"UNION\s+SELECT", "UNION SELECT"),
                (r"WHERE\s+\w+\s*=\s*'", "WHERE clause with string literal"),
            ]

            found_patterns: list[str] = []
            for pattern, description in raw_sql_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    found_patterns.append(description)

            if found_patterns:
                self.add_vulnerability(Vulnerability(
                    title="Raw SQL Patterns Visible in Response",
                    severity=Severity.CRITICAL,
                    category=VulnerabilityCategory.INJECTION,
                    description=(
                        "The response body contains patterns that appear to be raw SQL statements. "
                        "This may indicate debug output, verbose error handling, or SQL injection."
                    ),
                    evidence=f"SQL patterns found: {', '.join(found_patterns)}",
                    url=target_url,
                    remediation=(
                        "Never expose SQL queries in responses. Use parameterized queries "
                        "and implement proper error handling."
                    ),
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 Injection",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass
