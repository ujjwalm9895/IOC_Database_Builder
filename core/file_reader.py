from pathlib import Path
import hashlib


class FileReader:

    @staticmethod
    def get_hash(path: Path):
        md5 = hashlib.md5()

        with open(path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)

        return md5.hexdigest()

    @staticmethod
    def read_text(path: Path):

        encodings = [
            "utf-8",
            "utf-16",
            "utf-16-le",
            "utf-16-be",
            "latin-1",
            "cp1252",
        ]

        for enc in encodings:
            try:
                with open(path, "r", encoding=enc) as f:
                    return f.read(), enc
            except:
                pass

        return None, None

    @classmethod
    def read(cls, path):

        path = Path(path)

        size = path.stat().st_size

        md5 = cls.get_hash(path)

        content, encoding = cls.read_text(path)

        return {
            "name": path.name,
            "extension": path.suffix,
            "path": str(path),
            "size": size,
            "md5": md5,
            "encoding": encoding,
            "content": content,
        }