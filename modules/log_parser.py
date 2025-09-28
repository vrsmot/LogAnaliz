import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

def parse_log_file(path):
    ips, hashes = set(), set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            # ищем IP
            for ip in IP_RE.findall(line):
                if all(0 <= int(x) <= 255 for x in ip.split(".")):
                    ips.add(ip)
            # ищем SHA256
            for h in HASH_RE.findall(line):
                hashes.add(h.lower())
    return ips, hashes
