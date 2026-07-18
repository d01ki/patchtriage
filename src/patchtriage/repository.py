"""Repository URL normalization and provider-backed SBOM retrieval.

The GitHub provider deliberately uses the Dependency Graph SBOM API instead
of cloning or executing repository content.  Generic HTTPS Git URLs can be
normalized for use by another provider, but this module never fetches them.

An exported SBOM describes the dependencies GitHub knows about.  It is useful
input, not evidence that every manifest was discovered or that a repository is
free of vulnerabilities.  The returned provenance makes that boundary
explicit.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx


GITHUB_HOST = "github.com"
GITHUB_API_ROOT = "https://api.github.com"
DEFAULT_MAX_SBOM_BYTES = 32 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 45.0

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SEGMENT_SAFE = "-._~!$&'()*+,;=:@"


class RepositoryError(Exception):
    """Base class for repository import failures."""


class RepositoryURLValidationError(RepositoryError, ValueError):
    """The supplied URL is not an unambiguous HTTPS repository URL."""


class UnsupportedRepositoryProvider(RepositoryError):
    """The URL is valid, but no retrieval provider is available for it."""


class RepositoryFetchError(RepositoryError):
    """The provider could not be reached or returned an unexpected response."""


class RepositoryNotFoundError(RepositoryFetchError):
    """The repository or its provider-generated SBOM was not found."""


class RepositoryAccessDeniedError(RepositoryFetchError):
    """The provider rejected authentication or access."""


class RepositoryRateLimitError(RepositoryFetchError):
    """The provider rate limit was reached."""

    def __init__(self, message: str, *, retry_after: str | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RepositoryResponseError(RepositoryFetchError):
    """The provider returned malformed or unsupported SBOM data."""


class RepositoryTooLargeError(RepositoryResponseError):
    """The provider response exceeded the configured size limit."""


@dataclass(frozen=True)
class RepositoryReference:
    """A normalized repository reference without credentials or query data."""

    original_url: str
    normalized_url: str
    provider: str
    host: str
    repository: str
    owner: str | None = None
    name: str | None = None
    ref: str | None = None
    selector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryProvenance:
    """Where an imported SBOM came from and what it can substantiate."""

    provider: str
    repository: str
    ref: str
    resolved_url: str
    api_url: str
    format: str
    component_count: int
    coverage_status: str
    warnings: tuple[str, ...]
    retrieved_at: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["warnings"] = list(self.warnings)
        return data


@dataclass(frozen=True)
class RepositorySbom:
    """Serialized SPDX content suitable for the existing SBOM ingest path."""

    content: str
    provenance: RepositoryProvenance


def _canonical_host(host: str) -> str:
    try:
        canonical = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise RepositoryURLValidationError(
            "repository URL contains an invalid host name") from exc
    if not canonical or canonical.endswith("."):
        raise RepositoryURLValidationError(
            "repository URL must contain an unambiguous host name")
    return canonical


def _decoded_segments(path: str) -> list[str]:
    if "\\" in path or _BAD_PERCENT_RE.search(path):
        raise RepositoryURLValidationError(
            "repository URL contains an invalid path encoding")
    segments: list[str] = []
    for raw_segment in path.split("/"):
        if not raw_segment:
            continue
        segment = unquote(raw_segment)
        if (segment in (".", "..") or "/" in segment or "\\" in segment
                or any(ord(char) < 32 or ord(char) == 127
                       for char in segment)):
            raise RepositoryURLValidationError(
                "repository URL contains an unsafe path segment")
        segments.append(segment)
    return segments


def _encoded_path(segments: list[str]) -> str:
    return "/" + "/".join(quote(segment, safe=_SEGMENT_SAFE)
                            for segment in segments)


def normalize_repository_url(value: str) -> RepositoryReference:
    """Validate and canonicalize a GitHub or generic HTTPS Git URL.

    GitHub URLs resolve to their repository root.  A ``tree/<ref>`` suffix is
    retained as requested provenance, although GitHub's Dependency Graph SBOM
    endpoint itself cannot promise a ref-specific snapshot.

    Generic HTTPS URLs are normalized only.  They remain unsupported by
    :func:`fetch_repository_sbom`, which prevents this module from becoming an
    arbitrary outbound request or clone primitive.
    """
    if not isinstance(value, str) or not value.strip():
        raise RepositoryURLValidationError("repository URL is required")
    candidate = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise RepositoryURLValidationError(
            "repository URL contains control characters")
    if "\\" in candidate:
        raise RepositoryURLValidationError(
            "repository URL must use forward slashes")

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise RepositoryURLValidationError(
            "repository URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise RepositoryURLValidationError(
            "repository URL must use HTTPS")
    if not parsed.netloc or not parsed.hostname:
        raise RepositoryURLValidationError(
            "repository URL must include a host name")
    if parsed.username is not None or parsed.password is not None:
        raise RepositoryURLValidationError(
            "repository URL must not contain user information")
    if parsed.fragment:
        raise RepositoryURLValidationError(
            "repository URL must not contain a fragment")
    if parsed.query:
        raise RepositoryURLValidationError(
            "repository URL must not contain query parameters")

    host = _canonical_host(parsed.hostname)
    segments = _decoded_segments(parsed.path)
    if not segments:
        raise RepositoryURLValidationError(
            "repository URL must include a repository path")

    if host == GITHUB_HOST:
        if port not in (None, 443):
            raise RepositoryURLValidationError(
                "github.com repository URLs may not use a custom port")
        if len(segments) < 2:
            raise RepositoryURLValidationError(
                "GitHub URL must include both owner and repository")
        owner, name = segments[0], segments[1]
        if name.lower().endswith(".git"):
            name = name[:-4]
        if not _OWNER_RE.fullmatch(owner) or "--" in owner:
            raise RepositoryURLValidationError(
                "GitHub URL contains an invalid owner name")
        if (not _REPOSITORY_RE.fullmatch(name)
                or name in (".", "..") or name.endswith(".git")):
            raise RepositoryURLValidationError(
                "GitHub URL contains an invalid repository name")

        ref: str | None = None
        selector: str | None = None
        extra = segments[2:]
        if extra:
            selector = extra[0].lower()
            if selector != "tree" or len(extra) < 2:
                raise RepositoryURLValidationError(
                    "GitHub URL must point to the repository root or tree/<ref>")
            ref = "/".join(extra[1:])
        normalized = f"https://{GITHUB_HOST}/{owner}/{name}"
        return RepositoryReference(
            original_url=candidate,
            normalized_url=normalized,
            provider="github",
            host=host,
            repository=f"{owner}/{name}",
            owner=owner,
            name=name,
            ref=ref,
            selector=selector,
        )

    if len(segments) < 2:
        raise RepositoryURLValidationError(
            "generic Git repository URL must include a repository path")
    if port is not None and not 1 <= port <= 65535:
        raise RepositoryURLValidationError(
            "repository URL contains an invalid port")
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port in (None, 443) else f"{display_host}:{port}"
    normalized_path = _encoded_path(segments).rstrip("/")
    normalized = urlunsplit(("https", netloc, normalized_path, "", ""))
    return RepositoryReference(
        original_url=candidate,
        normalized_url=normalized,
        provider="generic_https_git",
        host=host,
        repository="/".join(segments),
    )


def _error_detail(raw: bytes) -> str:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return payload["message"][:300]
    return ""


def _raise_for_github_status(response: httpx.Response, raw: bytes) -> None:
    status = response.status_code
    detail = _error_detail(raw)
    suffix = f": {detail}" if detail else ""
    if status == 404:
        raise RepositoryNotFoundError(
            "GitHub repository or Dependency Graph SBOM was not found; "
            "confirm that the repository is visible to the configured "
            f"credentials and dependency graph data is available{suffix}")
    if status == 429 or (
            status == 403
            and response.headers.get("x-ratelimit-remaining") == "0"):
        retry_after = (response.headers.get("retry-after")
                       or response.headers.get("x-ratelimit-reset"))
        raise RepositoryRateLimitError(
            "GitHub API rate limit reached; retry later or configure "
            f"GITHUB_TOKEN{suffix}", retry_after=retry_after)
    if status in (401, 403):
        raise RepositoryAccessDeniedError(
            "GitHub denied access to the repository SBOM; confirm repository "
            f"visibility and GITHUB_TOKEN permissions{suffix}")
    if 300 <= status < 400:
        raise RepositoryFetchError(
            "GitHub API returned an unexpected redirect; repository import "
            "did not follow it")
    raise RepositoryFetchError(
        f"GitHub SBOM API returned HTTP {status}{suffix}")


def _read_response(response: httpx.Response, max_bytes: int) -> bytes:
    length = response.headers.get("content-length")
    if length:
        try:
            if int(length) > max_bytes:
                raise RepositoryTooLargeError(
                    f"GitHub SBOM exceeds the {max_bytes}-byte import limit")
        except ValueError:
            pass
    parts: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise RepositoryTooLargeError(
                f"GitHub SBOM exceeds the {max_bytes}-byte import limit")
        parts.append(chunk)
    return b"".join(parts)


def _read_error_response(response: httpx.Response) -> bytes:
    """Read only enough provider error text to classify it safely.

    A provider error body is diagnostic rather than an SBOM.  Its size must
    not turn a known 404/403/429 into the less useful "SBOM too large" error.
    """
    remaining = 64 * 1024
    parts: list[bytes] = []
    for chunk in response.iter_bytes():
        if remaining <= 0:
            break
        parts.append(chunk[:remaining])
        remaining -= len(parts[-1])
    return b"".join(parts)


def _parse_github_sbom(raw: bytes) -> tuple[dict[str, Any], int]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise RepositoryResponseError(
            "GitHub SBOM response is not UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise RepositoryResponseError(
            "GitHub SBOM response is not valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("sbom"), dict):
        raise RepositoryResponseError(
            "GitHub SBOM response is missing the 'sbom' object")
    sbom = payload["sbom"]
    if not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
        raise RepositoryResponseError(
            "GitHub SBOM response is not a recognized SPDX document")
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise RepositoryResponseError(
            "GitHub SPDX document is missing its packages list")
    if any(not isinstance(package, dict) for package in packages):
        raise RepositoryResponseError(
            "GitHub SPDX document contains an invalid package entry")
    return sbom, len(packages)


def fetch_github_sbom(
    repository: str | RepositoryReference,
    *,
    github_token: str | None = None,
    client: httpx.Client | None = None,
    max_bytes: int = DEFAULT_MAX_SBOM_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> RepositorySbom:
    """Fetch a GitHub repository's provider-generated SPDX SBOM.

    ``client`` is injectable for policy-specific transports and deterministic
    tests. Public repositories need no token; a local operator may supply one
    for a repository it authorizes. Redirects are never followed so an
    Authorization header cannot be forwarded to another origin.
    """
    reference = (normalize_repository_url(repository)
                 if isinstance(repository, str) else repository)
    if reference.provider != "github" or not reference.owner or not reference.name:
        raise UnsupportedRepositoryProvider(
            f"repository provider '{reference.provider}' is not supported; "
            "this importer currently supports github.com repositories")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    api_url = (
        f"{GITHUB_API_ROOT}/repos/{quote(reference.owner, safe='')}/"
        f"{quote(reference.name, safe='')}/dependency-graph/sbom"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "patchtriage/0.6",
    }
    token = github_token if github_token is not None else os.environ.get(
        "GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    owns_client = client is None
    client = client or httpx.Client()
    try:
        try:
            with client.stream(
                "GET", api_url, headers=headers, timeout=timeout,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raw_error = _read_error_response(response)
                    _raise_for_github_status(response, raw_error)
                raw = _read_response(response, max_bytes)
        except httpx.TimeoutException as exc:
            raise RepositoryFetchError(
                "GitHub SBOM request timed out") from exc
        except httpx.RequestError as exc:
            raise RepositoryFetchError(
                f"GitHub SBOM request failed: {exc.__class__.__name__}") from exc
    finally:
        if owns_client:
            client.close()

    sbom, component_count = _parse_github_sbom(raw)
    warnings = [
        "Coverage is limited to dependencies represented in GitHub's "
        "Dependency Graph; it is not proof that every manifest was discovered "
        "or that the repository has no vulnerable components."
    ]
    coverage_status = "provider_reported"
    if reference.ref:
        coverage_status = "partial"
        warnings.append(
            "The GitHub Dependency Graph SBOM endpoint does not accept a ref; "
            f"the requested tree ref '{reference.ref}' was not independently "
            "resolved and the exported graph may represent the default branch."
        )
    if component_count == 0:
        coverage_status = "incomplete"
        warnings.append(
            "GitHub returned an SPDX document with zero packages; treat this "
            "as incomplete coverage, not a clean vulnerability result."
        )

    provenance = RepositoryProvenance(
        provider="github_dependency_graph",
        repository=reference.repository,
        ref=reference.ref or "default_branch",
        resolved_url=reference.normalized_url,
        api_url=api_url,
        format="spdx",
        component_count=component_count,
        coverage_status=coverage_status,
        warnings=tuple(warnings),
        retrieved_at=datetime.now(timezone.utc).isoformat(),
    )
    return RepositorySbom(
        content=json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True),
        provenance=provenance,
    )


def fetch_repository_sbom(
    repository: str | RepositoryReference,
    **kwargs: Any,
) -> RepositorySbom:
    """Dispatch to a safe provider, explicitly rejecting generic Git URLs."""
    reference = (normalize_repository_url(repository)
                 if isinstance(repository, str) else repository)
    if reference.provider != "github":
        raise UnsupportedRepositoryProvider(
            f"repository provider '{reference.provider}' is not supported; "
            "only github.com Dependency Graph SBOM imports are available")
    return fetch_github_sbom(reference, **kwargs)
