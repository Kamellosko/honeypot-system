"""Apply native unified diffs independently, including the bounded-work fallback."""
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def apply(old, diff):
    if not diff:
        return old
    original = old.splitlines(keepends=True)
    lines = []
    for line in diff.splitlines(keepends=True):
        if line.startswith('\\ No newline at end of file'):
            assert lines[-1].endswith('\n')
            lines[-1] = lines[-1][:-1]
        else:
            lines.append(line)
    assert lines[:2] == ['--- old\n', '+++ new\n']
    result, pos, index = [], 0, 2
    while index < len(lines):
        match = re.fullmatch(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n', lines[index])
        assert match
        start, removed, new_start, added = map(int, match.groups())
        target = start - (removed > 0)
        assert target >= pos
        result.extend(original[pos:target])
        pos = target
        assert len(result) == new_start - (added > 0)
        old_count = new_count = 0
        index += 1
        while index < len(lines) and not lines[index].startswith('@@ '):
            line = lines[index]
            assert line[0] in ' +-'
            if line[0] != '+':
                assert line[1:] == original[pos]
                pos += 1
                old_count += 1
            if line[0] != '-':
                result.append(line[1:])
                new_count += 1
            index += 1
        assert (old_count, new_count) == (removed, added)
    result.extend(original[pos:])
    return ''.join(result)


rng = random.Random(5701)
cases = [('', 'new'), ('old', ''), ('old', 'new'), ('a\nb', 'a\nc'), ('a\n', 'a')]
for _ in range(120):
    old = ''.join(rng.choice(['alpha\n', 'beta\n', 'żółw\n', '\\"\n']) for _ in range(rng.randrange(40)))
    new = ''.join(rng.choice(['alpha\n', 'beta\n', 'żółw\n', '\\"\n']) for _ in range(rng.randrange(40)))
    cases.append((old, new))
cases.append((''.join(f'old{i}\n' for i in range(1200)), ''.join(f'new{i}\n' for i in range(1200))))
with tempfile.TemporaryDirectory(prefix='hp-diff-roundtrip-') as directory:
    a, b = Path(directory) / 'old', Path(directory) / 'new'
    for old, new in cases:
        a.write_text(old)
        b.write_text(new)
        report = json.loads(subprocess.check_output([sys.argv[1], str(a), str(b)], text=True))
        assert apply(old, report['diff']) == new
print(f'PASS native diff round-trip: {len(cases)} cases')
