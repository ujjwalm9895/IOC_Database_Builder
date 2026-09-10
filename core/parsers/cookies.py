SENSITIVE_COOKIE_DOMAINS = {
    "accounts.google.com",
    "mail.google.com",
    "myaccount.google.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "microsoft.com",
    "login.live.com",
    "account.live.com",
    "github.com",
    "amazon.com",
    "paypal.com",
    "binance.com",
    "coinbase.com",
    "epassport.gov.bd",
    "pcc.police.gov.bd",
    "raims.oep.gov.bd",
    "visa.gov.bd",
}


def _domain_matches(domain: str, target: str) -> bool:
    domain = domain.lstrip(".").lower()
    target = target.lower()
    return domain == target or domain.endswith(f".{target}")


def parse_cookies(content: str, source_file: str, browser: str | None = None) -> list[dict]:
    if not content:
        return []

    sessions = []

    for line in content.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        domain, _flag, path, secure, expiry, name, value = parts[:7]
        domain_clean = domain.lstrip(".").lower()

        matched = next(
            (target for target in SENSITIVE_COOKIE_DOMAINS if _domain_matches(domain_clean, target)),
            None,
        )
        if not matched:
            continue

        sessions.append(
            {
                "domain": domain_clean,
                "service": matched,
                "cookie_name": name,
                "cookie_value_preview": value[:80] + ("..." if len(value) > 80 else ""),
                "expires": expiry,
                "secure": secure.upper() == "TRUE",
                "browser": browser,
                "source_file": source_file,
            }
        )

    return sessions
