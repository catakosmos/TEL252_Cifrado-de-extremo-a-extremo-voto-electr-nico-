from flask import Flask, request, jsonify
from crypto import CryptoService
import base64
import os
import json
from Crypto.Cipher import AES

# Inicializar el servicio criptográfico (genera llaves únicas RSA para la sesión del servidor)
service = CryptoService()
VOTES = {} # {blind_factor_hex: encrypted_vote_payload} (Base de datos de votos)

def create_app():
    app = Flask(__name__)

    @app.route("/public_key", methods=["GET"])
    def get_public_key():
        """Entrega la llave pública RSA (N, E) para el cegado y el cifrado de la llave AES."""
        return jsonify({
            # Usamos 256 bytes (2048 bits) para el tamaño del módulo RSA.
            "modulus": base64.b64encode(service.modulus.to_bytes(256, 'big')).decode(), 
            "exponent": service.exponent,
            "aes_key_info": "Use RSA-OAEP to encrypt a random AES session key (K_sess) before use."
        })

    @app.route("/request_signature", methods=["POST"])
    def request_signature():
        """Ruta para firmar ciegamente el mensaje cifrado."""
        data = request.get_json()
        if not data or "blinded_hash" not in data:
            return jsonify({"error": "Missing 'blinded_hash' field"}), 400

        try:
            blinded_hash_bytes = base64.b64decode(data["blinded_hash"])
            # Llama a la versión corregida de blind_sign que no hashea dos veces.
            signature_bytes = service.blind_sign(blinded_hash_bytes)
            
            # La firma ciega se entrega como base64
            return jsonify({
                "blind_signature": base64.b64encode(signature_bytes).decode()
            })
        except Exception as e:
            print(f"Error in request_signature: {e}")
            return jsonify({"error": "Invalid blinded hash format or internal server error"}), 500


    @app.route("/vote", methods=["POST"])
    def cast_vote():
        """Ruta para emitir el voto (cifrado) con la firma descegada (E2EE Híbrido)."""
        data = request.get_json()
        # Ahora esperamos la llave AES Cifrada (encrypted_aes_key)
        required_fields = ["nonce", "ciphertext", "tag", "signature", "blind_factor", "encrypted_aes_key"]
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields for voting"}), 400
        
        try:
            # Decodificar todos los componentes
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
            tag = base64.b64decode(data["tag"])
            signature_bytes = base64.b64decode(data["signature"])
            blind_factor = data["blind_factor"] 
            encrypted_aes_key = base64.b64decode(data["encrypted_aes_key"])

            # 1. Descifrar la llave de sesión AES (K_sess) usando la llave privada RSA
            session_key = service.rsa_decrypt_key(encrypted_aes_key)
            if session_key is None:
                # Esto falla si el padding RSA no es válido (ej: llave pública incorrecta o manipulación)
                return jsonify({"error": "Failed to decrypt session key (Invalid RSA Padding or Key)"}), 400

            # 2. Generar el mensaje original (cifrado) para verificación de firma
            original_data_bytes = nonce + ciphertext + tag
            
            # 3. Verificar la firma descegada (confirma que es un voto legítimo y único)
            if not service.verify_unblinded_signature(original_data_bytes, signature_bytes):
                return jsonify({"error": "Invalid signature: Vote rejected"}), 401

            # 4. Verificar unicidad (usando el blind_factor como ID único)
            if blind_factor in VOTES:
                 return jsonify({"error": "Vote already cast with this key"}), 409

            # 5. Descifrar el voto USANDO LA LLAVE DE SESIÓN (K_sess)
            try:
                cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
                data_bytes = cipher.decrypt_and_verify(ciphertext, tag)
                decrypted_vote = json.loads(data_bytes.decode('utf-8'))
            except ValueError:
                 # Esto falla si el tag (integridad AES) no coincide
                return jsonify({"error": "Decryption failed (AES Integrity Check Failed)"}), 500

            # 6. Almacenar el voto (e.g., para el conteo final)
            VOTES[blind_factor] = {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
                "decrypted_vote_example": decrypted_vote # Solo para demostración del descifrado
            }
            
            return jsonify({"message": "Vote successfully cast and recorded.", "vote_id": blind_factor}), 200

        except Exception as e:
            # Imprimir error interno para depuración en el servidor
            print(f"Server Error during vote processing: {e}")
            return jsonify({"error": f"Internal Server Error: {type(e).__name__}"}), 500 

    # ESTA ES LA LÍNEA CRÍTICA: DEBE ESTAR AL FINAL DE create_app()
    return app

if __name__ == "__main__":
    # La aplicación ahora se asignará correctamente porque create_app() retorna 'app'.
    app = create_app()
    print("Servidor iniciado. Clave pública disponible en /public_key.")
    # Usamos use_reloader=False para entornos como Jupyter (aunque es opcional)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
