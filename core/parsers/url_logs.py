def parse_url_log(content: str, log_type: str) -> list[dict]:
    if not content:
        return []

    entries = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        parts = stripped.rsplit(" ", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            continue

        domain, count = parts[0].strip(), int(parts[1])
        entries.append({"domain": domain, "count": count, "log_type": log_type})

    return sorted(entries, key=lambda item: item["count"], reverse=True)
