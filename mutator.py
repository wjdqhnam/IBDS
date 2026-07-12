from __future__ import annotations

import random
import re
from collections import defaultdict
from typing import Callable, List, Optional, Tuple

# XSS — ZAP CrossSiteScriptingScanRule.mutateAttack() 포팅

class Mutation:
    """ZAP Mutation 클래스 포팅. check_original=True면 재검색 문자열은 원본 문자를 유지한다
    (서버가 대체 문자를 원본으로 되돌리는 유니코드 정규화 케이스를 노리기 위함)."""

    __slots__ = ("original", "mutation", "check_original")

    def __init__(self, original: str, mutation: str, check_original: bool = False):
        self.original = original
        self.mutation = mutation
        self.check_original = check_original


_FULL_WIDTH_LT = "＜"
_FULL_WIDTH_GT = "＞"

# ZAP CrossSiteScriptingScanRule.MUTATIONS 그대로 포팅
_XSS_MUTATIONS: List[List[Mutation]] = [
    [Mutation("(", "`"), Mutation(")", "`")],
    [Mutation("<", _FULL_WIDTH_LT, True), Mutation(">", _FULL_WIDTH_GT, True)],
    [
        Mutation("(", "`"),
        Mutation(")", "`"),
        Mutation("<", _FULL_WIDTH_LT, True),
        Mutation(">", _FULL_WIDTH_GT, True),
    ],
]


def _apply_xss_group(payload: str, group: List[Mutation]) -> Tuple[str, str]:
    """그룹을 payload에 적용해 (mutated_attack, mutated_evidence) 반환."""
    mutated_attack = payload
    mutated_evidence = payload
    for m in group:
        mutated_attack = mutated_attack.replace(m.original, m.mutation)
        if not m.check_original:
            mutated_evidence = mutated_evidence.replace(m.original, m.mutation)
    return mutated_attack, mutated_evidence


def detect_filtered_group(payload: str, response_body: str) -> Optional[int]:
    """실패한(미반사) XSS 공격의 response_body에서 문자 필터링 흔적을 찾는다.

    그룹의 원본 문자를 전부 제거한 필터본이 response_body에 나타나면 해당 그룹 index를 반환.
    """
    if not payload or not response_body:
        return None

    for idx, group in enumerate(_XSS_MUTATIONS):
        original_chars = [m.original for m in group]
        if not any(c in payload for c in original_chars):
            continue

        filtered = payload
        for c in original_chars:
            filtered = filtered.replace(c, "")

        if filtered and filtered in response_body:
            return idx

    return None

# SQLi — sqlmap tamper 스크립트 포팅 (핵심 11개)

# sqlmap kb.keywords 대응 — randomcase/multiplespaces/randomcomments가 참조하는 SQL 예약어 집합
_SQL_KEYWORDS = {
    "SELECT", "UNION", "ALL", "AND", "OR", "NOT", "WHERE", "FROM", "ORDER", "BY",
    "GROUP", "HAVING", "LIMIT", "OFFSET", "IN", "EXISTS", "BETWEEN", "LIKE", "NULL",
    "AS", "DISTINCT", "INTO", "VALUES", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
    "ALTER", "JOIN", "CASE", "WHEN", "THEN", "ELSE", "END", "IS", "TOP", "WAITFOR",
    "DELAY", "SLEEP", "ASC", "DESC", "MID", "SUBSTRING", "CONCAT", "CAST", "CONVERT",
    "IF", "GREATEST", "LEAST", "CHAR", "NULLIF",
}


def _tamper_space2comment(payload: str) -> str:
    """sqlmap space2comment.py 포팅 — 공백을 /**/ 로 치환 (따옴표 내부 값은 보존)."""
    if not payload:
        return payload
    out: List[str] = []
    quote = doublequote = firstspace = False
    for i, ch in enumerate(payload):
        if not firstspace:
            if ch.isspace():
                firstspace = True
                out.append("/**/")
                continue
        elif ch == "'" and (i == 0 or payload[i - 1] != "\\"):
            quote = not quote
        elif ch == '"' and (i == 0 or payload[i - 1] != "\\"):
            doublequote = not doublequote
        elif ch == " " and not doublequote and not quote:
            out.append("/**/")
            continue
        out.append(ch)
    return "".join(out)


def _tamper_multiplespaces(payload: str) -> str:
    """sqlmap multiplespaces.py 포팅 — SQL 키워드 앞뒤에 무작위 개수의 공백 추가."""
    if not payload:
        return payload
    out = payload
    words: List[str] = []
    for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
        word = match.group()
        if word.upper() in _SQL_KEYWORDS and word not in words:
            words.append(word)
    for word in words:
        esc = re.escape(word)
        out = re.sub(
            r"(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % esc,
            lambda m, w=word: " " * random.randint(1, 4) + w + " " * random.randint(1, 4),
            out,
        )
        out = re.sub(
            r"(?<=\W)%s(?=[(])" % esc,
            lambda m, w=word: " " * random.randint(1, 4) + w,
            out,
        )
    return out


def _tamper_randomcase(payload: str) -> str:
    """sqlmap randomcase.py 포팅 — 키워드를 무작위 대소문자로 치환 (정규식 기반 WAF 우회)."""
    if not payload:
        return payload
    out = payload
    for match in re.finditer(r"\b[A-Za-z_]{2,}\b", out):
        word = match.group()
        if word.upper() not in _SQL_KEYWORDS:
            continue
        if re.search(r"(?i)[`\"'\[]%s[`\"'\]]" % re.escape(word), out) is not None:
            continue
        mixed = "".join(c.upper() if random.randint(0, 1) else c.lower() for c in word)
        if mixed in (mixed.lower(), mixed.upper()):
            mixed = word[0].upper() + word[1:].lower()
        out = re.sub(r"\b%s\b" % re.escape(word), mixed, out)
    return out


def _tamper_randomcomments(payload: str) -> str:
    """sqlmap randomcomments.py 포팅 — 키워드 내부에 /**/ 삽입 (예: SELECT -> S/**/ELECT)."""
    if not payload:
        return payload
    out = payload
    for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
        word = match.group()
        if len(word) < 2 or word.upper() not in _SQL_KEYWORDS:
            continue
        mixed = word[0]
        for i in range(1, len(word) - 1):
            mixed += ("/**/" if random.randint(0, 1) else "") + word[i]
        mixed += word[-1]
        if "/**/" not in mixed:
            idx = random.randint(1, len(word) - 1)
            mixed = word[:idx] + "/**/" + word[idx:]
        out = re.sub(r"\b%s\b" % re.escape(word), mixed, out)
    return out


def _tamper_apostrophemask(payload: str) -> str:
    """sqlmap apostrophemask.py 응용 — ' → 전각 아포스트로피(U+FF07, 이중인코딩 방지용 raw 문자)."""
    if not payload:
        return payload
    return payload.replace("'", "＇")


def _tamper_equaltolike(payload: str) -> str:
    """sqlmap equaltolike.py 포팅 — '=' → ' LIKE ' ('=' 문자 필터링 WAF 우회)."""
    if not payload:
        return payload
    return re.sub(r"\s*(?<![<>!=])=(?!=)\s*", " LIKE ", payload)


def _tamper_unionalltounion(payload: str) -> str:
    """sqlmap unionalltounion.py 포팅 — 'UNION ALL SELECT' → 'UNION SELECT'."""
    if not payload:
        return payload
    return re.sub(r"(?i)UNION\s+ALL\s+SELECT", "UNION SELECT", payload)


def _tamper_symboliclogical(payload: str) -> str:
    """sqlmap symboliclogical.py 응용 — AND/OR → &&/|| (이중인코딩 방지용 raw 문자)."""
    if not payload:
        return payload
    out = re.sub(r"(?i)\bOR\b", "||", payload)
    out = re.sub(r"(?i)\bAND\b", "&&", out)
    return out


def _tamper_between(payload: str) -> str:
    """sqlmap between.py 포팅 — '>' → 'NOT BETWEEN 0 AND', '=' → 'BETWEEN ... AND ...'."""
    if not payload:
        return payload
    out = payload
    match = re.search(
        r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(?:AND|OR)\b)([^>]+?)\s*(?<!<)>(?!=)\s*([^>]+)\s*\Z",
        payload,
    )
    if match:
        replacement = f"{match.group(2)} {match.group(3)} NOT BETWEEN 0 AND {match.group(4)}"
        out = out.replace(match.group(0), replacement)
    else:
        out = re.sub(
            r"\s*(?<!<)>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))",
            r" NOT BETWEEN 0 AND \1",
            payload,
        )

    if out == payload:
        match = re.search(
            r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(?:AND|OR)\b)([^=]+?)\s*(?<![<>!])=(?!=)\s*([\w()]+)\s*",
            payload,
        )
        if match:
            replacement = f"{match.group(2)} {match.group(3)} BETWEEN {match.group(4)} AND {match.group(4)}"
            out = out.replace(match.group(0), replacement)

    return out


def _tamper_greatest(payload: str) -> str:
    """sqlmap greatest.py 포팅 — '>' → 'GREATEST(a,b+1)=a' (표준 SQL 함수라 DBMS 호환성 넓음)."""
    if not payload:
        return payload
    match = re.search(r"(?i)(\b(?:AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)
    if not match:
        return payload
    replacement = f"{match.group(1)}GREATEST({match.group(2)},{match.group(3)}+1)={match.group(2)}"
    return payload.replace(match.group(0), replacement)


def _tamper_modsecurityversioned(payload: str) -> str:
    """sqlmap modsecurityversioned.py 포팅 — MySQL 버전 코멘트로 쿼리 전체를 감싸 ModSecurity WAF 우회."""
    if not payload:
        return payload
    postfix = ""
    body = payload
    for comment in ("#", "--", "/*"):
        if comment in body:
            idx = body.find(comment)
            postfix = body[idx:]
            body = body[:idx]
            break
    if " " not in body:
        return payload
    space_idx = body.find(" ")
    version = random.randint(0, 9999)
    return f"{body[:space_idx]} /*!30{version}{body[space_idx + 1:]}*/{postfix}"


_SQLI_TAMPERS: List[Tuple[str, Callable[[str], str]]] = [
    ("space2comment", _tamper_space2comment),
    ("multiplespaces", _tamper_multiplespaces),
    ("randomcase", _tamper_randomcase),
    ("randomcomments", _tamper_randomcomments),
    ("apostrophemask", _tamper_apostrophemask),
    ("equaltolike", _tamper_equaltolike),
    ("unionalltounion", _tamper_unionalltounion),
    ("symboliclogical", _tamper_symboliclogical),
    ("between", _tamper_between),
    ("greatest", _tamper_greatest),
    ("modsecurityversioned", _tamper_modsecurityversioned),
]


def apply_sqli_tampers(payload: str) -> List[Tuple[str, str]]:
    """payload에 11개 tamper를 각각 적용, 실제로 변화가 생긴 (이름, 변형payload)만 반환."""
    out: List[Tuple[str, str]] = []
    for name, func in _SQLI_TAMPERS:
        try:
            mutated = func(payload)
        except Exception:
            continue
        if mutated and mutated != payload:
            out.append((name, mutated))
    return out


# 공통 진입점


def build_mutated_tasks(
    results: List[dict],
    tasks: List[dict],
    findings: List[dict],
) -> List[dict]:
    """실패/모호 시도 → 변형 task 목록 (XSS는 필터링 흔적 있는 실패 건, SQLi는 candidate 건만)."""
    if not tasks:
        return []

    task_index: dict[tuple, dict] = {
        (t.get("url"), t.get("inject_param"), t.get("payload")): t
        for t in tasks
    }

    out: List[dict] = []
    seen: set[tuple] = set()

    # ── XSS: 실패 + 필터링 흔적 ──────────────────────────────────────────
    hit_keys = {(f.get("url"), f.get("param"), f.get("payload")) for f in findings}

    for r in results or []:
        if r.get("error"):
            continue
        if (r.get("meta") or {}).get("vuln_scan") != "xss":
            continue

        key = (r.get("url"), r.get("inject_param"), r.get("payload"))
        if key in hit_keys:
            continue  # 이미 성공 — 변형 불필요

        payload = r.get("payload") or ""
        group_idx = detect_filtered_group(payload, r.get("response_body") or "")
        if group_idx is None:
            continue

        orig_task = task_index.get(key)
        if not orig_task:
            continue

        mutated_attack, mutated_evidence = _apply_xss_group(payload, _XSS_MUTATIONS[group_idx])
        if mutated_attack == payload:
            continue

        mkey = (key[0], key[1], mutated_attack)
        if mkey in seen:
            continue
        seen.add(mkey)

        task = dict(orig_task)
        task["id"] = f"mut_{orig_task.get('id', 'x')}_xss_g{group_idx + 1}"
        task["payload"] = mutated_attack
        task["payload_family"] = f"mutated_xss_g{group_idx + 1}"
        task["meta"] = {
            **(orig_task.get("meta") or {}),
            "mutation_group": group_idx + 1,
            "mutation_expected_evidence": mutated_evidence,
            "original_payload": payload,
        }
        out.append(task)

    # ── SQLi: candidate(모호) 판정 → tamper 재시도 ───────────────────────
    # boolean/orderby는 (url, param) 그룹 전체(TRUE/FALSE 쌍 등)를 비교해 판정하므로,
    # finding에 남은 대표 payload 하나만 변형하면 비교 짝이 없어 그룹 전체를 함께 변형한다.
    group_tasks_idx: dict[tuple, list[dict]] = defaultdict(list)
    for t in tasks:
        if t.get("payload_type") in ("SQLI_BOOLEAN", "SQLI_ORDERBY"):
            group_tasks_idx[(t.get("url"), t.get("inject_param"))].append(t)

    def _renamed_family(orig_family: str, tamper_name: str) -> str:
        """_bool_classify가 인식하는 _true/_false suffix를 유지한 채 tamper 이름을 붙인다."""
        if orig_family.endswith("_true"):
            prefix = "or_" if orig_family.startswith("or_") else ""
            return f"{prefix}tamper_{tamper_name}_true"
        if orig_family.endswith("_false"):
            return f"tamper_{tamper_name}_false"
        return f"tamper_{tamper_name}"

    for f in findings:
        if f.get("vuln_type") != "SQLI" or f.get("confidence") != "candidate":
            continue

        method = f.get("method")
        group_key = (f.get("url"), f.get("param"))

        if method in ("boolean", "orderby"):
            group = group_tasks_idx.get(group_key, [])
            if not group:
                continue

            applicable_names = [name for name, _ in apply_sqli_tampers(f.get("payload") or "")]
            for name in applicable_names:
                func = dict(_SQLI_TAMPERS)[name]
                for t in group:
                    orig_payload = t.get("payload") or ""
                    try:
                        mutated = func(orig_payload)
                    except Exception:
                        continue
                    if not mutated or mutated == orig_payload:
                        continue

                    mkey = (t.get("url"), t.get("inject_param"), mutated)
                    if mkey in seen:
                        continue
                    seen.add(mkey)

                    task = dict(t)
                    task["id"] = f"mut_{t.get('id', 'x')}_sqli_{name}"
                    task["payload"] = mutated
                    task["payload_family"] = _renamed_family(t.get("payload_family") or "", name)
                    task["meta"] = {
                        **(t.get("meta") or {}),
                        "tamper": name,
                        "original_payload": orig_payload,
                    }
                    out.append(task)
        else:
            # 현재 analyzer는 boolean/orderby 외 candidate를 만들지 않지만, 단건 판정 대비 폴백
            key = (f.get("url"), f.get("param"), f.get("payload"))
            orig_task = task_index.get(key)
            if not orig_task:
                continue
            for name, mutated in apply_sqli_tampers(f.get("payload") or ""):
                mkey = (key[0], key[1], mutated)
                if mkey in seen:
                    continue
                seen.add(mkey)

                task = dict(orig_task)
                task["id"] = f"mut_{orig_task.get('id', 'x')}_sqli_{name}"
                task["payload"] = mutated
                task["payload_family"] = f"tamper_{name}"
                task["meta"] = {
                    **(orig_task.get("meta") or {}),
                    "tamper": name,
                    "original_payload": f.get("payload"),
                }
                out.append(task)

    return out
