import re

class ID:
    def detectar_tipo_hash(hash_str):
        hash_str = hash_str.strip().lower()

        patrones_hash = {
            "MD5": r'^[a-f0-9]{32}$',
            "SHA-1": r'^[a-f0-9]{40}$',
            "SHA-224": r'^[a-f0-9]{56}$',
            "SHA-256": r'^[a-f0-9]{64}$',
            "SHA-384": r'^[a-f0-9]{96}$',
            "SHA-512": r'^[a-f0-9]{128}$',
            "RIPEMD-160": r'^[a-f0-9]{40}$',
            "BLAKE2b": r'^[a-f0-9]{128}$',
            "BLAKE2s": r'^[a-f0-9]{64}$',
            "Whirlpool": r'^[a-f0-9]{128}$',
            "Tiger": r'^[a-f0-9]{48}$',
            "GOST": r'^[a-f0-9]{32}$',
            "Argon2": r'^[a-f0-9]{64}$'
        }

        tipos_detectados = []

        for tipo, patron in patrones_hash.items():
            if re.match(patron, hash_str):
                tipos_detectados.append(tipo)

        if tipos_detectados:
            return tipos_detectados
        return ["Tipo de hash desconocido"]


