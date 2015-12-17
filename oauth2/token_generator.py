from cryptography.hazmat.primitives import serialization
import base64
import jwt
import time
import uuid


class TokenGenerator(object):

    @staticmethod
    def decode_token(token, public_key):
        return jwt.decode(token, key=public_key, options={'verify_aud': False}, algorithms=['RS256'])

    @staticmethod
    def get_token(private_key, jwt_headers, jwt_claim_set, algorithm='RS256'): # key_id, base_url, audience, tenant_id):

        encoded_data = jwt.encode(
            jwt_claim_set,
            private_key,
            algorithm=algorithm,
            headers=jwt_headers)

        return encoded_data
