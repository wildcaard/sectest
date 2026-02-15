import asyncio
from typing import Optional
import httpx
from rich.console import Console

console = Console()


class HttpClient:
    """Configured async HTTP client with retries and rate limiting."""

    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get("timeout", 30)
        self.user_agent = config.get("user_agent", "SecurityAgent/1.0")
        self.follow_redirects = config.get("follow_redirects", True)
        self.max_redirects = config.get("max_redirects", 5)
        self.verify_ssl = config.get("verify_ssl", True)
        self.request_count = 0
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limit = config.get("rate_limit", 10)
        self._semaphore = asyncio.Semaphore(config.get("max_concurrent", 5))
        self._rate_lock = asyncio.Lock()
        self._last_request_time = 0.0

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
            verify=self.verify_ssl,
            headers={"User-Agent": self.user_agent},
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def _rate_limit_wait(self):
        if self._rate_limit <= 0:
            return
        async with self._rate_lock:
            now = asyncio.get_event_loop().time()
            min_interval = 1.0 / self._rate_limit
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = asyncio.get_event_loop().time()

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("OPTIONS", url, **kwargs)

    async def _request(
        self, method: str, url: str, retries: int = 2, **kwargs
    ) -> Optional[httpx.Response]:
        async with self._semaphore:
            for attempt in range(retries + 1):
                try:
                    await self._rate_limit_wait()
                    if not self._client:
                        raise RuntimeError("HttpClient not initialized. Use 'async with'.")
                    response = await self._client.request(method, url, **kwargs)
                    self.request_count += 1
                    return response
                except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError) as e:
                    if attempt < retries:
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                    else:
                        console.print(f"[dim red]Request failed: {method} {url} - {e}[/]")
                        return None
                except Exception as e:
                    console.print(f"[dim red]Unexpected error: {method} {url} - {e}[/]")
                    return None
