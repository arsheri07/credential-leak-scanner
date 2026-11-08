"""Shannon entropy helpers.

Real secrets (API keys, tokens) are long random strings, so their characters
are spread evenly across the alphabet and their entropy per character is high.
Ordinary words and placeholder values ("changeme", "your-key-here") are not.
"""

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of `text` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
