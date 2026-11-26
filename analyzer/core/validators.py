"""Checksum / structure validators used to cut false positives for national-ID and card patterns."""
from __future__ import annotations

import re

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

PAN_HOLDER_TYPES = set("ABCFGHJLPT")  # 4th character of an Indian PAN (entity type)


def verhoeff_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if not digits:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def aadhaar_valid(number: str) -> bool:
    digits = re.sub(r"\s", "", number)
    return bool(re.fullmatch(r"[2-9][0-9]{11}", digits)) and verhoeff_valid(digits)


def pan_valid(pan: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]", pan))


def luhn_valid(number: str) -> bool:
    digits = re.sub(r"[\s-]", "", number)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:      # 0000000000000 style filler
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
