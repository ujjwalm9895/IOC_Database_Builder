from datetime import datetime, timezone
from pathlib import Path

from core.file_reader import FileReader
from core.parsers import (
    parse_autofill,
    parse_cookies,
    parse_google_accounts,
    parse_information,
    parse_passwords,
    parse_url_log,
)
from core.parsers.identity import classify_identifier, normalize_email


HIGH_RISK_DOMAINS = {
    "accounts.google.com",
    "mail.google.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "paypal.com",
    "binance.com",
    "coinbase.com",
    "epassport.gov.bd",
    "pcc.police.gov.bd",
    "raims.oep.gov.bd",
    "visa.gov.bd",
    "auth.openai.com",
    "login.live.com",
    "account.live.com",
}


IDENTITY_AUTOFILL_KEYS = {
    "personal_email",
    "email_id",
    "email",
    "identifier",
    "new-email",
    "new-account",
}


def _browser_from_filename(filename: str) -> str | None:
    name = filename.replace("_passwords.txt", "").replace("_logins.txt", "")
    name = name.replace(".txt", "")
    if name in {"passwords", "passwords_unique"}:
        return None
    return name.replace("_", " ")


class ClientReportBuilder:

    def __init__(self, output_folder: Path | str | None = None):
        self.output_folder = Path(output_folder) if output_folder else None

    def build(self, cases: list[dict], email_filter: str | None = None, domain_filter: str | None = None) -> dict:
        report = {
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "filters": {
                "email": email_filter,
                "domain": domain_filter,
            },
            "summary": {},
            "cases": [],
            "clients_by_email": {},
            "clients_by_domain": {},
            "unlinked_credentials": [],
        }

        email_index: dict[str, dict] = {}
        domain_index: dict[str, dict] = {}

        for case in cases:
            case_report = self._process_case(case)
            report["cases"].append(case_report)

            self._index_case(case_report, email_index, domain_index)

        report["clients_by_email"] = self._finalize_clients(email_index, email_filter, domain_filter)
        report["clients_by_domain"] = self._group_by_email_domain(report["clients_by_email"])

        if email_filter or domain_filter:
            relevant_cases = set()
            for client in report["clients_by_email"].values():
                for machine in client["affected_machines"]:
                    relevant_cases.add(machine["case_name"])
                for cred in client["compromised_accounts"]:
                    relevant_cases.add(cred["case_name"])

            report["cases"] = [
                case for case in report["cases"] if case["case_name"] in relevant_cases
            ]

        report["summary"] = self._build_summary(report)

        return report

    def save(self, report: dict, filename: str = "client_report.json") -> Path:
        if not self.output_folder:
            raise ValueError("output_folder is required to save report")

        self.output_folder.mkdir(parents=True, exist_ok=True)
        output = self.output_folder / filename

        import json

        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)

        return output

    def _process_case(self, case: dict) -> dict:
        case_data = {
            "case_name": case["case_name"],
            "path": case["path"],
            "machine_info": {},
            "credentials": [],
            "autofill_identities": [],
            "google_tokens": [],
            "session_cookies": [],
            "browsing_profile": {},
            "linked_emails": set(),
            "linked_phones": set(),
        }

        for file_path in case["files"]:
            path = Path(file_path)
            data = FileReader.read(path)
            content = data.get("content") or ""
            name_lower = path.name.lower()
            parent_lower = path.parent.name.lower()

            if name_lower == "information.txt":
                case_data["machine_info"] = parse_information(content)
                continue

            if "password" in name_lower and path.suffix == ".txt":
                entries = parse_passwords(content, path.name)
                for entry in entries:
                    entry["case_name"] = case["case_name"]
                    case_data["credentials"].append(entry)
                    self._track_identifier(case_data, entry.get("login_normalized"), entry.get("login_type"))
                continue

            if parent_lower == "autofill" or name_lower.startswith("autofill"):
                browser = _browser_from_filename(path.stem)
                parsed = parse_autofill(content, path.name, browser)
                for field in parsed["identity_fields"]:
                    field["case_name"] = case["case_name"]
                    case_data["autofill_identities"].append(field)
                case_data["linked_emails"].update(parsed["linked_emails"])
                case_data["linked_phones"].update(parsed["linked_phones"])
                continue

            if parent_lower == "googleaccounts":
                browser = _browser_from_filename(path.stem)
                tokens = parse_google_accounts(content, path.name, browser)
                for token in tokens:
                    token["case_name"] = case["case_name"]
                    case_data["google_tokens"].append(token)
                continue

            if parent_lower == "cookies":
                browser = _browser_from_filename(path.stem)
                cookies = parse_cookies(content, path.name, browser)
                for cookie in cookies:
                    cookie["case_name"] = case["case_name"]
                    case_data["session_cookies"].append(cookie)
                continue

            if name_lower.startswith("url_uniq_") and name_lower.endswith(".log"):
                log_type = name_lower.replace("url_uniq_", "").replace(".log", "")
                case_data["browsing_profile"][log_type] = parse_url_log(content, log_type)
                continue

        for log_type, entries in case_data["browsing_profile"].items():
            case_data["browsing_profile"][log_type] = entries[:20]

        case_data["linked_emails"] = sorted(case_data["linked_emails"])
        case_data["linked_phones"] = sorted(case_data["linked_phones"])
        case_data["risk_assessment"] = self._assess_case_risk(case_data)

        if case_data["machine_info"].get("processes"):
            case_data["machine_info"]["process_count"] = len(case_data["machine_info"]["processes"])
            del case_data["machine_info"]["processes"]

        return case_data

    def _track_identifier(self, case_data: dict, normalized: str | None, id_type: str | None):
        if not normalized:
            return
        if id_type == "email":
            case_data["linked_emails"].add(normalized)
        elif id_type == "phone":
            case_data["linked_phones"].add(normalized)

    def _assess_case_risk(self, case_data: dict) -> dict:
        credentials = case_data["credentials"]
        services = {
            cred.get("service_domain")
            for cred in credentials
            if cred.get("service_domain")
        }
        high_risk_hits = sorted(services.intersection(HIGH_RISK_DOMAINS))

        password_values = [cred["password"] for cred in credentials if cred.get("password")]
        reused_passwords = len(password_values) - len(set(password_values))

        risk_score = 0
        risk_score += min(len(credentials) * 2, 30)
        risk_score += len(case_data["google_tokens"]) * 20
        risk_score += len(high_risk_hits) * 8
        risk_score += len(case_data["session_cookies"]) // 5
        risk_score += reused_passwords * 5

        if risk_score >= 60:
            level = "critical"
        elif risk_score >= 35:
            level = "high"
        elif risk_score >= 15:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "score": risk_score,
            "credential_count": len(credentials),
            "unique_services": len(services),
            "high_risk_services": high_risk_hits,
            "google_tokens_found": len(case_data["google_tokens"]),
            "session_cookies_found": len(case_data["session_cookies"]),
            "password_reuse_instances": reused_passwords,
        }

    def _case_emails(self, case_report: dict) -> set[str]:
        emails = set()

        for cred in case_report["credentials"]:
            if cred.get("login_type") == "email" and cred.get("login_normalized"):
                emails.add(cred["login_normalized"])

        for field in case_report["autofill_identities"]:
            if field.get("key", "").lower() in IDENTITY_AUTOFILL_KEYS:
                email = normalize_email(field.get("value", ""))
                if email:
                    emails.add(email)

        return emails

    def _index_case(self, case_report: dict, email_index: dict, domain_index: dict):
        case_name = case_report["case_name"]
        machine = case_report.get("machine_info", {}).get("system", {})
        case_emails = self._case_emails(case_report)

        machine_context = {
            "case_name": case_name,
            "ip_address": machine.get("ip_address"),
            "country": machine.get("country"),
            "computer_name": machine.get("computer_name"),
            "user_name": machine.get("user_name"),
            "infection_date": machine.get("infection_date"),
            "os": machine.get("os"),
            "risk_level": case_report["risk_assessment"]["level"],
        }

        for cred in case_report["credentials"]:
            login = cred.get("login", "")
            id_type, normalized = classify_identifier(login)

            if id_type == "email":
                client = self._get_email_client(email_index, normalized)
                client["compromised_accounts"].append(self._credential_record(cred, case_name))
                client["affected_machines"].append(machine_context)
                client["services_compromised"].add(cred.get("service_domain") or "unknown")
                if cred.get("password"):
                    client["passwords_exposed"].add(cred["password"])

            elif id_type == "phone" and case_emails:
                for email in case_emails:
                    client = self._get_email_client(email_index, email)
                    client["related_usernames"].add(login)

        for email in case_emails:
            client = self._get_email_client(email_index, email)
            client["affected_machines"].append(machine_context)

            for field in case_report["autofill_identities"]:
                value = field.get("value", "").lower()
                if email in value or field.get("key", "").lower() in IDENTITY_AUTOFILL_KEYS:
                    client["autofill_leaks"].append(
                        {
                            "key": field["key"],
                            "value": field["value"],
                            "case_name": case_name,
                            "source_file": field["source_file"],
                        }
                    )

        if case_emails:
            for token in case_report["google_tokens"]:
                for email in case_emails:
                    client = self._get_email_client(email_index, email)
                    client["google_tokens"].append({**token, "linked_email": email})

            for cookie in case_report["session_cookies"]:
                for email in case_emails:
                    client = self._get_email_client(email_index, email)
                    client["active_sessions"].append({**cookie, "linked_email": email})

    def _get_email_client(self, email_index: dict, email: str) -> dict:
        if email not in email_index:
            domain = email.split("@", 1)[1]
            email_index[email] = {
                "identifier": email,
                "identifier_type": "email",
                "email_domain": domain,
                "compromised_accounts": [],
                "autofill_leaks": [],
                "google_tokens": [],
                "active_sessions": [],
                "affected_machines": [],
                "services_compromised": set(),
                "passwords_exposed": set(),
                "related_usernames": set(),
            }
        return email_index[email]

    def _credential_record(self, cred: dict, case_name: str) -> dict:
        return {
            "service_domain": cred.get("service_domain"),
            "host": cred.get("host"),
            "login": cred.get("login"),
            "login_type": cred.get("login_type"),
            "password": cred.get("password"),
            "browser": cred.get("browser"),
            "case_name": case_name,
            "source_file": cred.get("source_file"),
        }

    def _finalize_clients(
        self,
        email_index: dict,
        email_filter: str | None,
        domain_filter: str | None,
    ) -> dict:
        clients = {}

        for email, data in email_index.items():
            if email_filter and email != email_filter.lower():
                continue
            if domain_filter and data["email_domain"] != domain_filter.lower():
                continue

            unique_machines = []
            seen = set()
            for machine in data["affected_machines"]:
                key = machine["case_name"]
                if key not in seen:
                    seen.add(key)
                    unique_machines.append(machine)

            passwords = sorted(data["passwords_exposed"])
            services = data["services_compromised"] - {None}

            risk_score = 0
            risk_score += len(data["compromised_accounts"]) * 3
            risk_score += len(data["google_tokens"]) * 25
            risk_score += len(services.intersection(HIGH_RISK_DOMAINS)) * 10
            risk_score += max(0, len(passwords) - 1) * 8

            if risk_score >= 50:
                risk_level = "critical"
            elif risk_score >= 25:
                risk_level = "high"
            elif risk_score >= 10:
                risk_level = "medium"
            else:
                risk_level = "low"

            clients[email] = {
                "identifier": email,
                "identifier_type": "email",
                "email_domain": data["email_domain"],
                "risk_level": risk_level,
                "risk_score": risk_score,
                "summary": {
                    "total_credentials": len(data["compromised_accounts"]),
                    "unique_passwords": len(passwords),
                    "services_compromised": sorted(services),
                    "machines_affected": len(unique_machines),
                    "google_tokens": len(data["google_tokens"]),
                    "active_sessions": len(data["active_sessions"]),
                    "autofill_fields_leaked": len(data["autofill_leaks"]),
                    "related_usernames": sorted(data["related_usernames"]),
                },
                "compromised_accounts": data["compromised_accounts"],
                "autofill_leaks": data["autofill_leaks"],
                "google_tokens": data["google_tokens"],
                "active_sessions": data["active_sessions"],
                "affected_machines": unique_machines,
            }

        return clients

    def _group_by_email_domain(self, clients_by_email: dict) -> dict:
        grouped = {}

        for email, client in clients_by_email.items():
            domain = client["email_domain"]
            if domain not in grouped:
                grouped[domain] = {
                    "domain": domain,
                    "emails_affected": [],
                    "total_credentials": 0,
                    "highest_risk_level": "low",
                }

            grouped[domain]["emails_affected"].append(email)
            grouped[domain]["total_credentials"] += client["summary"]["total_credentials"]

            levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            if levels[client["risk_level"]] > levels[grouped[domain]["highest_risk_level"]]:
                grouped[domain]["highest_risk_level"] = client["risk_level"]

        for domain in grouped:
            grouped[domain]["emails_affected"] = sorted(grouped[domain]["emails_affected"])

        return grouped

    def _build_summary(self, report: dict) -> dict:
        clients = report["clients_by_email"]
        all_services = set()
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for client in clients.values():
            risk_counts[client["risk_level"]] += 1
            all_services.update(client["summary"]["services_compromised"])

        return {
            "total_cases": len(report["cases"]),
            "total_unique_emails": len(clients),
            "total_domains": len(report["clients_by_domain"]),
            "total_credentials": sum(c["summary"]["total_credentials"] for c in clients.values()),
            "total_google_tokens": sum(c["summary"]["google_tokens"] for c in clients.values()),
            "risk_breakdown": risk_counts,
            "unique_services_compromised": sorted(all_services),
        }
