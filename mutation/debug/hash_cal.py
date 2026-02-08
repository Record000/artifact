
import hashlib
file_path = "./my_repo/manifest.mft"
with open(file_path, "rb") as f:
    data = f.read()
    hash = hashlib.sha256(data).hexdigest()
    print("file_name: ", file_path)
    print("hash: ", hash)

