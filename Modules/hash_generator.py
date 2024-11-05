import hashlib

class Hashing:
    @staticmethod
    def generate_hash(type: str, data: str) -> str:
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
            "sha3_224": hashlib.sha3_224,
            "sha3_256": hashlib.sha3_256,
            "sha3_384": hashlib.sha3_384,
            "sha3_512": hashlib.sha3_512,
            "blake2b": hashlib.blake2b,
            "blake2s": hashlib.blake2s,
        }
        hash_function = hash_functions.get(type.lower())
        if hash_function is None:
            raise ValueError(f"Tipo de hash '{type}' no soportado.")

        hash_object = hash_function(data.encode())
        return hash_object.hexdigest()