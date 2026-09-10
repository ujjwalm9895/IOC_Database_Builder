from pathlib import Path


class FolderScanner:

    CASE_MARKER = "information.txt"

    def __init__(self, root_folder):
        self.root = Path(root_folder)

    def get_cases(self):
        if not self.root.exists():
            raise FileNotFoundError(f"{self.root} not found.")

        cases = []

        if (self.root / self.CASE_MARKER).exists():
            return [self.root]

        for marker in self.root.rglob(self.CASE_MARKER):
            cases.append(marker.parent)

        if not cases:
            for item in self.root.iterdir():
                if item.is_dir():
                    cases.append(item)

        unique_cases = sorted({case.resolve() for case in cases})
        return unique_cases

    def get_files(self, case_folder):
        files = []

        for file in case_folder.rglob("*"):
            if file.is_file():
                files.append(file)

        return sorted(files)

    def scan(self):
        database = []
        cases = self.get_cases()

        for case in cases:
            files = self.get_files(case)

            database.append(
                {
                    "case_name": case.name,
                    "path": str(case),
                    "total_files": len(files),
                    "files": [str(f) for f in files],
                }
            )

        return database
