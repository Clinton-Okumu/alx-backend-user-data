#!/usr/bin/env python3
"""
Module for handling log message obfuscation using regex.
Contains utilities to filter sensitive information in log messages.
"""

import re
from typing import List


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str) -> str:
    """
    Returns an obfuscated log message with specified fields redacted.
    """
    pattern = f'({"|".join(fields)})=[^{separator}]*'
    return re.sub(pattern, f'\\1={redaction}', message)
