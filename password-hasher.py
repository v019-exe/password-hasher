import argparse
from Modules.hash_generator import Hashing
from Modules.cracker import Cracker
from Modules.hash_identifier import ID

def parse_args():
    parser = argparse.ArgumentParser(
        description="Herramienta para generar hashes con soporte opcional para sal y para crackear hashes.",
        usage="password-hasher --hash <data> --type <hash_type> [OPTIONS]"
    )

    parser.add_argument(
        '--hash', '-hs', required=True, type=str,
        help="El texto o dato que deseas hashear o el hash a crackear."
    )

    parser.add_argument(
        '--type', '-t', required=False, type=str, choices=['md5', 'sha1', 'sha256', 'sha512', 'bcrypt'],
        help="Especifica el tipo de hash a generar (md5, sha1, sha256, sha512, bcrypt etc.) o el tipo de hash a crackear."
    )

    parser.add_argument(
        '--salt', '-s', action='store_true',
        help="Genera una sal automáticamente y la incluye en el hash (solo aplicable a bcrypt)."
    )

    parser.add_argument(
        '--crack', '-c', action='store_true',
        help="Argumento para indicar que quieres crackear un hash"
    )

    parser.add_argument(
        '--wordlist', '-w', type=str,
        help="Diccionario"
    )

    parser.add_argument(
        '--check', '-chk', action='store_true',
        help="Verifica el tipo de hash usando expresiones regulares"
    )

    args = parser.parse_args()

    if args.type != 'bcrypt' and args.salt:
        parser.error("El argumento --salt solo se aplica al tipo de hash 'bcrypt'.")

    if args.crack and not args.wordlist:
        parser.error("Debes proporcionar un archivo de palabras con --wordlist para crackear el hash.")
        
    if args.check and not args.hash:
        parser.error("Debes proporcionar un hash con --hash para verificar su tipo.")

    return args

if __name__ == "__main__":
    args = parse_args()

    if args.crack:
        cracked_password = Cracker.crack_hash(args.hash, args.wordlist, args.type)
        if cracked_password:
            print(f"Contraseña crackeada: {cracked_password}")
        else:
            print("No se encontró ninguna coincidencia.")
    else:
        if args.check:
            checker = ID.detectar_tipo_hash(args.hash)
            print(checker)
        elif args.type != 'bcrypt' or not args.salt:
            hash_result = Hashing.generate_hash(args.type, args.hash)
            print("Hash generado:", hash_result)
        elif args.type == 'bcrypt' and args.salt:
            salted_hash = Hashing.generate_salt_hash(args.hash)
            print("Hash con sal generado:", salted_hash)

