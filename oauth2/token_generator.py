import jwt


class TokenGenerator(object):
    @staticmethod
    def decode_token(token, public_key=None, options={}):
        return jwt.decode(token, key=public_key, options=options, algorithms=['RS256'])

    @staticmethod
    def get_token(private_key, jwt_headers, jwt_claim_set, algorithm='RS256'): # key_id, base_url, audience, tenant_id):
        encoded_data = jwt.encode(
            jwt_claim_set,
            private_key,
            algorithm=algorithm,
            headers=jwt_headers)

        return encoded_data
