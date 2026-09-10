from core.parsers.identity import (
    classify_identifier,
    extract_identities,
    is_identity_autofill_key,
    normalize_email,
)


SENSITIVE_AUTOFILL_KEYS = {
    "name",
    "father_name",
    "mother_name",
    "present_address",
    "permanent_address",
    "national_id",
    "nid_no",
    "blood_group",
    "religion",
    "spouse_name",
    "designation",
    "pinumber",
    "p_token_no",
}


def parse_autofill(content: str, source_file: str, browser: str | None = None) -> dict:
    if not content:
        return {"fields": [], "identity_fields": [], "linked_emails": [], "linked_phones": []}

    fields = []
    identity_fields = []
    linked_emails = set()
    linked_phones = set()

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or " " not in stripped:
            continue

        key, value = stripped.split(" ", 1)
        key = key.strip()
        value = value.strip()
        if not value or value.upper() == "N/A":
            continue

        field = {
            "key": key,
            "value": value,
            "browser": browser,
            "source_file": source_file,
        }
        fields.append(field)

        normalized_key = key.lower().replace("_", "").replace("-", "")
        if is_identity_autofill_key(key) or normalized_key in SENSITIVE_AUTOFILL_KEYS:
            identity_fields.append(field)

        email = normalize_email(value)
        if email:
            linked_emails.add(email)

        id_type, normalized = classify_identifier(value)
        if id_type == "phone":
            linked_phones.add(normalized)

    text_identities = extract_identities(content)
    linked_emails.update(text_identities["emails"])
    linked_phones.update(text_identities["phones"])

    return {
        "fields": fields,
        "identity_fields": identity_fields,
        "linked_emails": sorted(linked_emails),
        "linked_phones": sorted(linked_phones),
    }
