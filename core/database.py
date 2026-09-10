import json
from pathlib import Path

from core.file_reader import FileReader


class DatabaseBuilder:

    def __init__(self, output_folder):

        self.output_folder = Path(output_folder)

        self.output_folder.mkdir(parents=True, exist_ok=True)

    def build(self, cases):

        database = {
            "total_cases": len(cases),
            "cases": []
        }

        for case in cases:

            case_data = {
                "case_name": case["case_name"],
                "path": case["path"],
                "total_files": case["total_files"],
                "files": []
            }

            for file in case["files"]:

                file_data = FileReader.read(file)

                case_data["files"].append(file_data)

            database["cases"].append(case_data)

        return database

    def save(self, database, filename="database.json"):

        output = self.output_folder / filename

        with open(output, "w", encoding="utf-8") as f:
            json.dump(database, f, indent=4, ensure_ascii=False)

        print(f"\nDatabase saved to:\n{output}")