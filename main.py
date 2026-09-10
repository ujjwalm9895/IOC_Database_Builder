from config import INPUT_FOLDER
from core.scanner import FolderScanner
from core.file_reader import FileReader


def main():

    scanner = FolderScanner(INPUT_FOLDER)

    cases = scanner.scan()

    print(f"Cases Found: {len(cases)}")

    for case in cases:

        print(f"\nCASE : {case['case_name']}")
        print("=" * 70)

        for file in case["files"]:

            data = FileReader.read(file)

            print(f"\n{data['name']}")
            print(f"Size : {data['size']} bytes")
            print(f"Encoding : {data['encoding']}")
            print(f"MD5 : {data['md5']}")

            if data["content"]:
                print(data["content"][:150])