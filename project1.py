from flask import Flask, jsonify, request
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

# Generate a RSA key pair 
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# expiration time for keys
key_expiration_time = 3600  

# store user data 
users = {
    "userABC": {
        "password": "password123",
        "roles": ["admin"]
    }
}

# retrieve the JWKS
@app.route('/jwks', methods=['GET'])
def get_jwks():
    jwks = {
        "keys": [
            {
                "kid": "1",
                "kty": "RSA",
                "n": public_key.public_numbers().n,
                "e": public_key.public_numbers().e,
                "use": "sig",
                "alg": "RS256"
            }
        ]
    }
    return jsonify(jwks)

# user authentication
@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users or users[username]['password'] != password:
        return jsonify({"message": "Authentication failed"}), 401

    # JWT token
    token = jwt.encode(
        {
            "sub": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=key_expiration_time),
            "iss": "your_issuer",
            "aud": "your_audience",
            "kid": "1"  
        },
        private_key,
        algorithm="RS256"
    )

    return jsonify({"access_token": token.decode('utf-8')})

# Main function
if __name__ == '__main__':
    app.run(debug=True)
