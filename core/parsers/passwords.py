from core.parsers.identity import classify_identifier, extract_domain_from_host


def parse_passwords(content: str, source_file: str) -> list[dict]:
    if not content:
        return []

    entries = []
    current = {}

    def flush():
        if current.get("login") or current.get("password") or current.get("host"):
            entries.append(dict(current))

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("Soft:"):
            flush()
            current = {
                "browser": stripped.split(":", 1)[1].strip(),
                "source_file": source_file,
            }
            continue

        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "host":
            current["host"] = value
            current["service_domain"] = extract_domain_from_host(value)
        elif key == "login":
            current["login"] = value
            id_type, normalized = classify_identifier(value)
            current["login_type"] = id_type
            current["login_normalized"] = normalized
        elif key == "password":
            current["password"] = value

    flush()

    return entries
