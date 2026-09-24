"""토큰 기반 인증·RBAC(사전준비 버전). 1주차에 계정 DB + Argon2id 비밀번호 로그인으로 확장한다.

토큰 원문은 저장하지 않고 SHA-256 해시만 설정에 둔다(SAFETRACE_API_TOKENS='{"<sha256>":"user:role"}').
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status


class Role(StrEnum):
    VIEWER = "viewer"
    INVESTIGATOR = "investigator"
    REVIEWER = "reviewer"
    AUTOMATION = "automation"  # 자동화 계정: 접수는 가능, 판정 확정 불가


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenRegistry:
    def __init__(self, mapping: dict[str, str]) -> None:
        self._by_hash: dict[str, Principal] = {}
        for h, spec in mapping.items():
            user, _, role = spec.partition(":")
            self._by_hash[h.lower()] = Principal(user_id=user[:64], role=Role(role))

    @classmethod
    def from_env(cls) -> TokenRegistry:
        raw = os.environ.get("SAFETRACE_API_TOKENS", "{}")
        return cls(json.loads(raw))

    def resolve(self, token: str) -> Principal | None:
        h = token_hash(token)
        for known, principal in self._by_hash.items():
            if hmac.compare_digest(known, h):
                return principal
        return None


_registry: TokenRegistry | None = None


def set_registry(reg: TokenRegistry) -> None:
    global _registry
    _registry = reg


def current_principal(authorization: Annotated[str, Header()] = "") -> Principal:
    if _registry is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")
    p = _registry.resolve(authorization.removeprefix("Bearer ").strip())
    if p is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")
    return p


def require(*roles: Role):
    def dep(p: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if p.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return p

    return dep


ANY = (Role.VIEWER, Role.INVESTIGATOR, Role.REVIEWER, Role.AUTOMATION)
SUBMITTERS = (Role.INVESTIGATOR, Role.REVIEWER, Role.AUTOMATION)
