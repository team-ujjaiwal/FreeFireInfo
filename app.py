from flask import Flask, jsonify
from zitado_pb2 import GetPlayerPersonalShowRequest
from uid_generator_pb2 import UID
import requests
from secret import key, iv
from Crypto.Cipher import AES
import base64

app = Flask(__name__)


def create_protobuf(uid, region):
    data = GetPlayerPersonalShowRequest()
    data.uid = uid
    data.server = region
    return data


def protobuf_to_hex(data):
    return data.SerializeToString().hex()


def encrypt_aes(hex_string, key, iv):
    raw = bytes.fromhex(hex_string)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    padded = raw + (16 - len(raw) % 16) * bytes([16 - len(raw) % 16])
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')


def token():
    try:
        tokens = requests.get("http://147.93.123.53:5001/token").json()
        return tokens['token']
    except Exception as e:
        return None


def apis(encrypted_data, token):
    if not token:
        return None
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'FreeFire/1.99.1 (Linux; U; Android 10; IN)',
        'Authorization': token
    }
    try:
        response = requests.post('https://clientbp.ggblueshark.com/GetPlayerPersonalShow',
                                 data=encrypted_data, headers=headers)
        return response.content
    except Exception:
        return None


def decode_hex(data):
    final_data = UID()
    final_data.ParseFromString(data)
    return final_data


@app.route('/<uid>', methods=['GET'])
def main(uid):
    try:
        uid_int = int(uid)
        region = 1

        # Protobuf
        protobuf_data = create_protobuf(uid_int, region)
        hex_data = protobuf_to_hex(protobuf_data)

        # AES Encryption
        encrypted_hex = encrypt_aes(hex_data, key, iv)

        # Token + API Call
        jwt = token()
        if not jwt:
            return jsonify({"error": "Token fetch failed"}), 500

        response_data = apis(encrypted_hex, jwt)
        if not response_data:
            return jsonify({"error": "API call failed or returned nothing"}), 500

        # Decode protobuf
        try:
            decoded = decode_hex(response_data)
        except Exception as e:
            return jsonify({"error": "Decoding error", "details": str(e)}), 500

        # Build response
        result = {}
        if decoded.basicinfo:
            result['basicinfo'] = []
            for info in decoded.basicinfo:
                result['basicinfo'].append({
                    'username': info.username,
                    'region': info.region,
                    'level': info.level,
                    'Exp': info.Exp,
                    'bio': decoded.bioinfo[0].bio if decoded.bioinfo else None,
                    'banner': info.banner,
                    'avatar': info.avatar,
                    'brrankscore': info.brrankscore,
                    'BadgeCount': info.BadgeCount,
                    'likes': info.likes,
                    'lastlogin': info.lastlogin,
                    'csrankpoint': info.csrankpoint,
                    'csrankscore': info.csrankscore,
                    'brrankpoint': info.brrankpoint,
                })

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": "Unexpected server error", "details": str(e)}), 500


if __name__ == '__main__':
    app.run()