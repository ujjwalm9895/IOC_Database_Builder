import re


INFO_KEYS = {
    "IP": "ip_address",
    "Country": "country",
    "Date": "infection_date",
    "MachineID": "machine_id",
    "GUID": "guid",
    "HWID": "hwid",
    "Path": "malware_path",
    "MD5": "malware_md5",
    "Work Dir": "work_dir",
    "Windows": "os",
    "Computer Name": "computer_name",
    "User Name": "user_name",
    "Display Resolution": "display_resolution",
    "Local Time": "local_time",
    "Antivirus": "antivirus",
}


def parse_information(content: str) -> dict:
    if not content:
        return {}

    result = {
        "stealer": None,
        "system": {},
        "hardware": {},
        "processes": [],
    }

    section = "header"

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("------------") and "STEALER" in stripped:
            result["stealer"] = stripped.strip("-")
            continue

        if stripped == "[Hardware]":
            section = "hardware"
            continue

        if stripped == "[Processes]":
            section = "processes"
            continue

        if section == "hardware" and ":" in stripped:
            key, value = stripped.split(":", 1)
            result["hardware"][key.strip()] = value.strip()
            continue

        if section == "processes":
            match = re.match(r"\[(\d+)\]\s+(.+)", stripped)
            if match:
                result["processes"].append(
                    {"pid": int(match.group(1)), "name": match.group(2).strip()}
                )
            continue

        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            mapped = INFO_KEYS.get(key)
            if mapped:
                result["system"][mapped] = value

    return result
