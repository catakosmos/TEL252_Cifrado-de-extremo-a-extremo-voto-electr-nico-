from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP # Se agregó PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha256
import json

# Parámetros Globales
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 16 # 128 bits
NONCE_LENGTH = 16

class CryptoService:
    def __init__(self):
        # 1. Par de llaves RSA para el Voto Ciego
        self.key = RSA.generate(RSA_KEY_SIZE)
        self.public_key = self.key.public_key()
        self.modulus = self.key.n
        self.exponent = self.key.e

        # 2. Llave AES: Se elimina la generación aquí. La provee el cliente (E2EE Híbrido).

    ## --- Descifrado de la Llave de Sesión (RSA-OAEP) ---
    def rsa_decrypt_key(self, encrypted_key_bytes):
        """Descifra la clave AES de sesión (K_sess) usando la llave privada RSA del servidor."""
        cipher_rsa = PKCS1_OAEP.new(self.key)
        try:
            # La llave de sesión descifrada
            session_key = cipher_rsa.decrypt(encrypted_key_bytes)
            return session_key
        except ValueError:
            return None # Falló la verificación OAEP o el descifrado

    ## --- Firma Ciega RSA (Servidor) ---
    def blind_sign(self, blinded_message_bytes):
        """
        FIRMA CIEGA (s = m^d mod n). 
        El mensaje 'blinded_message_bytes' ya es el valor cegado.
        CORRECCIÓN CRÍTICA: NO SE DEBE HASHEAR AQUÍ.
        """
        # 1. Convertir bytes a entero
        m_int = bytes_to_long(blinded_message_bytes)
        
        # 2. Firmar (exponenciación con exponente privado)
        signature = pow(m_int, self.key.d, self.modulus)
        
        # El tamaño de la firma es de 256 bytes
        return long_to_bytes(signature, RSA_KEY_SIZE // 8)

    ## --- Verificación de Firma Descegada (Servidor) ---
    def verify_unblinded_signature(self, original_data_bytes, signature_bytes):
        """
        Verifica la firma descegada: m = s^e mod n.
        CORRECCIÓN CRÍTICA: Se compara S^e mod N directamente con el mensaje original M.
        """
        # 1. Aplicar la llave pública a la firma (S^e mod N)
        signature_int = bytes_to_long(signature_bytes)
        recovered_message_int = pow(signature_int, self.exponent, self.modulus)
        
        # 2. Obtener el valor entero del mensaje original (nonce+ciphertext+tag)
        original_message_int = bytes_to_long(original_data_bytes)
        
        # 3. Comparar: si S^e mod N es igual al mensaje original M, la firma es válida.
        return original_message_int == recovered_message_int