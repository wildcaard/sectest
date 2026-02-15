from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

from security_agent.models.vulnerability import Vulnerability, Severity


@dataclass
class ScanResult:
    target_url: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    profile: str = "standard"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    technologies_detected: dict = field(default_factory=dict)
    scanners_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    phase_approvals: dict = field(default_factory=dict)
    human_reviewed: bool = False
    total_requests: int = 0

    @property
    def duration(self) -> str:
        if not self.end_time:
            return "In progress"
        start = datetime.fromisoformat(self.start_time)
        end = datetime.fromisoformat(self.end_time)
        delta = end - start
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    @property
    def security_score(self) -> int:
        if not self.vulnerabilities:
            return 100
        penalty = 0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 1}
        for vuln in self.vulnerabilities:
            penalty += weights.get(vuln.severity.value, 0)
        return max(0, min(100, 100 - penalty))

    @property
    def grade(self) -> str:
        score = self.security_score
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 70: return "C"
        if score >= 50: return "D"
        return "F"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "profile": self.profile,
            "security_score": self.security_score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "technologies_detected": self.technologies_detected,
            "scanners_run": self.scanners_run,
            "errors": self.errors,
            "human_reviewed": self.human_reviewed,
            "total_requests": self.total_requests,
        }
