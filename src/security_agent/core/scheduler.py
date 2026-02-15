import asyncio
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from security_agent.scanners.base import BaseScanner

console = Console()


class ScanScheduler:
    """Manages scanner execution order and concurrency within phases."""

    def __init__(self, config: dict):
        self.config = config
        self.max_concurrent = config.get("scan", {}).get("max_concurrent", 5)

    async def run_phase(
        self,
        scanners: list[BaseScanner],
        target_url: str,
        progress: Optional[Progress] = None,
        phase_task_id=None,
    ) -> dict[str, list]:
        """Run all scanners for a phase concurrently (bounded)."""
        results = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_single(scanner: BaseScanner):
            async with semaphore:
                try:
                    vulns = await scanner.scan(target_url)
                    results[scanner.name] = vulns
                except Exception as e:
                    console.print(f"[red]Scanner '{scanner.name}' failed: {e}[/]")
                    results[scanner.name] = []
                finally:
                    if progress and phase_task_id is not None:
                        progress.update(phase_task_id, advance=1)

        tasks = [asyncio.create_task(run_single(s)) for s in scanners]
        await asyncio.gather(*tasks)
        return results
