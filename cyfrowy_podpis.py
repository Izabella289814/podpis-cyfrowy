from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import argparse

def generate_keys(private_key_file, public_key_file): #generowanie klucza prywatnego RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    #pobieranie klucza publicznego z klucza prywatnego
    public_key = private_key.public_key()

    #zapis klucza prywatnego do pliku
    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    #zapis klucza publicznego do pliku
    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("wygenerowano pare kluczy RSA")
    print(f"klucz prywatny zapisano do pliku: {private_key_file}")
    print(f"klucz publiczny zapisano do pliku: {public_key_file}")

def sign_file(input_file, private_key_file, signature_file):
    #odczyt pliku do odczytania
    with open(input_file, "rb") as f:
        data = f.read()

    #odczyt klucza prywatnego
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    #utworzenie podpisu cyfrowego
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    #zapis podpisu do pliku
    with open(signature_file, "wb") as f:
        f.write(signature)

    print("plik zostal podpisany cyfrowo")
    print(f"podpis zapisano w pliku: {signature_file}")

def verify_signature(input_file, public_key_file, signature_file):
    #odczyt pliku
    with open(input_file, "rb") as f:
        data = f.read()

    #odczyt podpisu
    with open(signature_file, "rb") as f:
        signature = f.read()

    #odczyt klucza publicznego
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    #weryfikacja podpisu
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("podpis jest poprawny. plik nie zostal zmieniony")
    except InvalidSignature:
        print("podpis jest niepoprawny. plik zostal zmieniony albo uzyto zlego klucza")

def main():
    parser = argparse.ArgumentParser(description="podpis cyfrowy pliku przy uzyciu RSA i SHA-256")
    parser.add_argument(
        "mode",
        choices=["genkeys", "sign", "verify"],
        help="tryb dzialania: genkeys, sign albo verify"
    )
    parser.add_argument("file1", help="pierwszy plik zalezny od trybu")
    parser.add_argument("file2", help="drugi plik zalezny od trybu")
    parser.add_argument("file3", nargs="?", help="trzeci plik zalezny od trybu")

    args = parser.parse_args()

    if args.mode == "genkeys":
        generate_keys(args.file1, args.file2)

    elif args.mode == "sign":
        if args.file3 is None:
            print("blad: tryb sign wymaga: plik_wejsciowy klucz_prywatny podpis")
        else:
            sign_file(args.file1, args.file2, args.file3)

    elif args.mode == "verify":
        if args.file3 is None:
            print("blad: tryb verify wymaga: plik_wejsciowy klucz_publiczny podpis")
        else:
            verify_signature(args.file1, args.file2, args.file3)


if __name__ == "__main__":
    main()