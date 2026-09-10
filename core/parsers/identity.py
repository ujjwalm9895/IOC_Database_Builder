import re
from urllib.parse import urlparse


EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:0\d{10}|\d{11,14})(?!\d)"
)

IDENTITY_FIELD_HINTS = {
    "email",
    "identifier",
    "personal_email",
    "email_id",
    "new-email",
    "new-account",
    "usernameentry",
    "login",
    "username",
    "phone",
    "phonenumber",
    "personal_mobile",
    "mobile_no",
    "home_phone",
    "national_id",
    "nid_no",
}


def normalize_email(value: str) -> str | None:
    value = value.strip().lower()
    if EMAIL_RE.fullmatch(value):
        return value
    return None


def normalize_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 10 or len(digits) > 15:
        return None
    return digits


def extract_domain_from_host(host: str) -> str | None:
    if not host:
        return None

    host = host.strip()

    if host.startswith("android://"):
        match = re.search(r"@([^/]+)/?", host)
        return match.group(1).lower() if match else None

    if "://" not in host:
        host = f"https://{host}"

    try:
        parsed = urlparse(host)
    except ValueError:
        return None

    domain = (parsed.netloc or parsed.path.split("/")[0]).lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain or None


def extract_identities(text: str) -> dict:
    emails = sorted({m.group(0).lower() for m in EMAIL_RE.finditer(text or "")})
    phones = sorted({normalize_phone(m.group(0)) for m in PHONE_RE.finditer(text or "")} - {None})
    return {"emails": emails, "phones": phones}


def classify_identifier(value: str) -> tuple[str, str]:
    email = normalize_email(value)
    if email:
        return "email", email

    phone = normalize_phone(value)
    if phone:
        return "phone", phone

    return "username", value.strip().lower()


def is_identity_autofill_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in IDENTITY_FIELD_HINTS or "email" in normalized or "phone" in normalized
