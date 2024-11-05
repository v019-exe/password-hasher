import hashlib
import bcrypt

class Cracker:
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

    @staticmethod
    def crack_hash(hash_to_crack: str, file: str, hash_type: str):
        try:
            with open(file, "r") as f:
                passwords = f.readlines()
        except FileNotFoundError:
            print(f"El archivo '{file}' no se encontró.")
            return None

        for password in passwords:
            password = password.strip()

            if hash_type in Cracker.hash_functions:
                hashed = Cracker.hash_functions[hash_type](password.encode()).hexdigest()
            elif hash_type == 'bcrypt':
                if bcrypt.checkpw(password.encode(), hash_to_crack.encode()):
                    print(f"¡Contraseña encontrada! La contraseña es: {password}")
                    return password
            else:
                print(f"Tipo de hash '{hash_type}' no soportado.")
                return None
            
            if hashed == hash_to_crack:
                print(f"¡Contraseña encontrada! La contraseña es: {password}")
                return password

        print("No se encontró ninguna coincidencia.")
        return None
