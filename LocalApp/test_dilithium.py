import importlib
import importlib.util

try:
    pqcrypto_spec = importlib.util.find_spec('pqcrypto')
    if pqcrypto_spec is not None:
        pqcrypto = importlib.import_module('pqcrypto')
        print("pqcrypto loaded. Submodules:", dir(pqcrypto))
        sign_spec = importlib.util.find_spec('pqcrypto.sign')
        if sign_spec is not None:
            pqcrypto_sign = importlib.import_module('pqcrypto.sign')
            print("pqcrypto.sign loaded. Submodules:", dir(pqcrypto_sign))
            dilithium2_spec = importlib.util.find_spec('pqcrypto.sign.dilithium2')
            if dilithium2_spec is not None:
                pqcrypto_dilithium2 = importlib.import_module('pqcrypto.sign.dilithium2')
                print("pqcrypto.sign.dilithium2 loaded. Functions:", dir(pqcrypto_dilithium2))
                # Test Dilithium keygen, sign, verify
                public_key, secret_key = pqcrypto_dilithium2.generate_keypair()
                print("Public key:", public_key.hex())
                print("Secret key:", secret_key.hex())
                message = b"Hello, post-quantum world!"
                signature = pqcrypto_dilithium2.sign(message, secret_key)
                print("Signature:", signature.hex())
                try:
                    pqcrypto_dilithium2.verify(message, signature, public_key)
                    print("Chữ ký hợp lệ!")
                except Exception as e:
                    print("Chữ ký không hợp lệ:", e)
            else:
                print("pqcrypto.sign.dilithium2 module NOT found.")
        else:
            print("pqcrypto.sign module NOT found.")
    else:
        print("pqcrypto module NOT found.")
except Exception as e:
    print("Error loading pqcrypto or submodules:", e) 