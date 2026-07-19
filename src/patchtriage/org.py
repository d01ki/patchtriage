"""GitHub owner (organization or user) repository listing for fleet import.

This module answers one question safely: which public repositories does a
GitHub account own?  It never clones, never follows redirects, and reuses the
error taxonomy of :mod:`patchtriage.repository` so callers handle a rate limit
or an access failure the same way for one repository or fifty.

The ``/users/{owner}/repos`` endpoint serves both user and organization
accounts (organizations are accounts in the GitHub API), so one code path
covers both without probing account types.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .repository import (
    GITHUB_API_ROOT,
    GITHUB_HOST,
    RepositoryAccessDeniedError,
    RepositoryFetchError,
    RepositoryNotFoundError,
    RepositoryRateLimitError,
    RepositoryResponseError,
    RepositoryURLValidationError,
)

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")

DEFAULT_LIST_TIMEOUT_SECONDS = 30.0
DEFAULT_REPO_LIMIT = 10
MAX_REPO_LIMIT = 100
_PER_PAGE = 100
_MAX_PAGES = 5  # 500 repositories scanned is plenty for a triage fleet.


@dataclass(frozen=True)
class OwnerReference:
    """A validated GitHub account whose public repositories may be listed."""

    original_url: str
    normalized_url: str
    owner: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OwnerRepo:
    """One listed repository, reduced to what fleet import needs."""

    full_name: str
    html_url: str
    default_branch: str
    pushed_at: str
    fork: bool
    archived: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OwnerListing:
    """The selected repositories plus what was filtered and why.

    ``skipped_forks``/``skipped_archived`` keep the boundary visible: a fleet
    result must be explainable as "these repositories, chosen by this rule",
    never a silent subset.
    """

    reference: OwnerReference
    repositories: tuple[OwnerRepo, ...]
    total_listed: int
    skipped_forks: int
    skipped_archived: int
    truncated: bool
    retrieved_at: str
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference": self.reference.to_dict(),
            "repositories": [repo.to_dict() for repo in self.repositories],
            "total_listed": self.total_listed,
            "skipped_forks": self.skipped_forks,
            "skipped_archived": self.skipped_archived,
            "truncated": self.truncated,
            "retrieved_at": self.retrieved_at,
            "warnings": list(self.warnings),
        }


def normalize_owner_url(value: str) -> OwnerReference:
    """Validate ``https://github.com/OWNER`` and nothing broader.

    A URL with an owner *and* repository belongs to the single-repository
    importer; rejecting it here keeps the two entry points unambiguous.
    """
    if not isinstance(value, str) or not value.strip():
        raise RepositoryURLValidationError("organization URL is required")
    candidate = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise RepositoryURLValidationError(
            "organization URL contains control characters")
    if "\\" in candidate:
        raise RepositoryURLValidationError(
            "organization URL must use forward slashes")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise RepositoryURLValidationError(
            "organization URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise RepositoryURLValidationError("organization URL must use HTTPS")
    if (parsed.hostname or "").lower() != GITHUB_HOST:
        raise RepositoryURLValidationError(
            "organization import currently supports github.com accounts only")
    if port not in (None, 443):
        raise RepositoryURLValidationError(
            "github.com organization URLs may not use a custom port")
    if parsed.username is not None or parsed.password is not None:
        raise RepositoryURLValidationError(
            "organization URL must not contain user information")
    if parsed.query or parsed.fragment:
        raise RepositoryURLValidationError(
            "organization URL must not contain query or fragment parts")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) != 1:
        raise RepositoryURLValidationError(
            "organization URL must be https://github.com/<owner>; "
            "a specific repository belongs in the repository importer")
    owner = segments[0]
    if not _OWNER_RE.fullmatch(owner) or "--" in owner:
        raise RepositoryURLValidationError(
            "organization URL contains an invalid account name")
    return OwnerReference(
        original_url=candidate,
        normalized_url=f"https://{GITHUB_HOST}/{owner}",
        owner=owner,
    )


def _raise_for_list_status(response: httpx.Response) -> None:
    status = response.status_code
    if status == 404:
        raise RepositoryNotFoundError(
            "GitHub account was not found or has no visible repositories")
    if status == 429 or (
            status == 403
            and response.headers.get("x-ratelimit-remaining") == "0"):
        retry_after = (response.headers.get("retry-after")
                       or response.headers.get("x-ratelimit-reset"))
        raise RepositoryRateLimitError(
            "GitHub API rate limit reached while listing repositories; "
            "retry later or configure GITHUB_TOKEN", retry_after=retry_after)
    if status in (401, 403):
        raise RepositoryAccessDeniedError(
            "GitHub denied the repository listing request")
    if 300 <= status < 400:
        raise RepositoryFetchError(
            "GitHub API returned an unexpected redirect; the repository "
            "listing did not follow it")
    raise RepositoryFetchError(
        f"GitHub repository listing returned HTTP {status}")


def _parse_repo_entry(entry: Any) -> OwnerRepo | None:
    if not isinstance(entry, dict):
        return None
    full_name = entry.get("full_name")
    html_url = entry.get("html_url")
    if not isinstance(full_name, str) or "/" not in full_name:
        return None
    if not isinstance(html_url, str) or not html_url.startswith(
            f"https://{GITHUB_HOST}/"):
        return None
    return OwnerRepo(
        full_name=full_name,
        html_url=html_url,
        default_branch=str(entry.get("default_branch") or ""),
        pushed_at=str(entry.get("pushed_at") or ""),
        fork=bool(entry.get("fork")),
        archived=bool(entry.get("archived")),
    )


def list_owner_repositories(
    owner: str | OwnerReference,
    *,
    github_token: str | None = None,
    client: httpx.Client | None = None,
    limit: int = DEFAULT_REPO_LIMIT,
    include_forks: bool = False,
    include_archived: bool = False,
    timeout: float = DEFAULT_LIST_TIMEOUT_SECONDS,
) -> OwnerListing:
    """List an account's public repositories, newest activity first.

    ``limit`` bounds the *selected* repositories.  Forks default to skipped
    because a fork's dependency graph usually restates its upstream and would
    double-count the fleet; archived repositories default to skipped because
    they no longer receive the patches this tool schedules.
    """
    reference = (normalize_owner_url(owner)
                 if isinstance(owner, str) else owner)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    limit = min(limit, MAX_REPO_LIMIT)
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "patchtriage/0.6",
    }
    token = github_token if github_token is not None else os.environ.get(
        "GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    selected: list[OwnerRepo] = []
    total_listed = 0
    skipped_forks = 0
    skipped_archived = 0
    truncated = False
    warnings: list[str] = []

    owns_client = client is None
    client = client or httpx.Client()
    try:
        for page in range(1, _MAX_PAGES + 1):
            url = (
                f"{GITHUB_API_ROOT}/users/{quote(reference.owner, safe='')}"
                f"/repos"
            )
            try:
                response = client.get(
                    url,
                    params={
                        "per_page": _PER_PAGE,
                        "page": page,
                        "sort": "pushed",
                        "direction": "desc",
                    },
                    headers=headers,
                    timeout=timeout,
                    follow_redirects=False,
                )
            except httpx.TimeoutException as exc:
                raise RepositoryFetchError(
                    "GitHub repository listing timed out") from exc
            except httpx.RequestError as exc:
                raise RepositoryFetchError(
                    "GitHub repository listing failed: "
                    f"{exc.__class__.__name__}") from exc
            if response.status_code != 200:
                _raise_for_list_status(response)
            try:
                payload = json.loads(response.content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RepositoryResponseError(
                    "GitHub repository listing is not valid JSON") from exc
            if not isinstance(payload, list):
                raise RepositoryResponseError(
                    "GitHub repository listing has an unexpected shape")

            for entry in payload:
                repo = _parse_repo_entry(entry)
                if repo is None:
                    continue
                total_listed += 1
                if repo.fork and not include_forks:
                    skipped_forks += 1
                    continue
                if repo.archived and not include_archived:
                    skipped_archived += 1
                    continue
                if len(selected) >= limit:
                    truncated = True
                    continue
                selected.append(repo)

            if len(payload) < _PER_PAGE:
                break
        else:
            truncated = True
            warnings.append(
                f"Listing stopped after {_MAX_PAGES * _PER_PAGE} repositories; "
                "the account owns more than were examined.")
    finally:
        if owns_client:
            client.close()

    if truncated and len(selected) >= limit:
        warnings.append(
            f"Repository selection was capped at {limit}; additional "
            "repositories exist and were not imported.")
    return OwnerListing(
        reference=reference,
        repositories=tuple(selected),
        total_listed=total_listed,
        skipped_forks=skipped_forks,
        skipped_archived=skipped_archived,
        truncated=truncated,
        retrieved_at=datetime.now(timezone.utc).isoformat(),
        warnings=tuple(warnings),
    )
