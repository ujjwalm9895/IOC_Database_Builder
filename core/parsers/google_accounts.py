def parse_google_accounts(content: str, source_file: str, browser: str | None = None) -> list[dict]:
    if not content:
        return []

    accounts = []

    for line in content.splitlines():
        token = line.strip()
        if not token or ":" not in token:
            continue

        token_id, token_value = token.split(":", 1)
        accounts.append(
            {
                "token_id": token_id.strip(),
                "token_preview": token_value[:40] + ("..." if len(token_value) > 40 else ""),
                "browser": browser,
                "source_file": source_file,
                "risk": "critical",
                "note": "Active Google OAuth refresh token — account takeover possible",
            }
        )

    return accounts
