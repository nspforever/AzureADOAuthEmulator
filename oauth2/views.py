
import os
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from django.shortcuts import render
from django.views.generic.base import View
from oauth2.token_generator import TokenGenerator
from django.http import HttpResponse, JsonResponse
from cryptography.hazmat.primitives import hashes
from django.views.decorators.csrf import csrf_exempt
import json
import base64
import uuid
import time
import ast


# Create your views here.
class OAuthTokenView(View):
    private_key = open('E:\\dev\\python\\aad_emulator\\AdalOAuthTokenSigningCert.key', 'rb').read().decode('utf-8')
    public_cert = open('E:\\dev\\python\\aad_emulator\\b64ceradal.cer', 'rb' ).read()
    cert = load_pem_x509_certificate(public_cert, default_backend())
    public_key = cert.public_key()
    base_url = 'https://sts.windows-ppe.net/{0}/'
    cert_thumbprint = cert.fingerprint(hashes.SHA1())
    base64_encoded_thumbprint = base64.b64encode(cert_thumbprint).decode('utf-8')
    key_id = base64_encoded_thumbprint.split('=')[0].replace('+', '-')
    key_id = key_id.replace('/', '_')

    def post(self, request):
        jwt_id = str(uuid.uuid4())
        unix_time_now = int(time.time())
        unix_time_nbf = int(time.time()) - 5 * 60 # Make this a configuration
        unix_time_exp = int(time.time()) + 2 * 3600 # Make this configuration
        jwt_headers = {
            'kid': OAuthTokenView.key_id,
            'x5t': OAuthTokenView.key_id,
        }

        """
        claims = request.POST['client_assertion'].split('.')[1] + '='
        claims_set = base64.b64decode(claims)
        ast.literal_eval(claims_set)
        """

        audience = request.POST['resource']

        tenant_id = 'abc'
        app_id = request.POST['client_id']
        issuer = OAuthTokenView.base_url.format(tenant_id)

        jwt_claim_set = {
            "iss": issuer,
            "aud": audience,
            "jti": jwt_id, # Need randomly generate this JWT ID
            "nbf": unix_time_nbf,
            "iat": unix_time_now,
            "exp": unix_time_exp,
            "appid": app_id,
            "appidacr": '2',
            "idp": issuer,
            "tid": tenant_id,
            "ver": '1.0',
            }

        token = TokenGenerator.get_token(OAuthTokenView.private_key, jwt_headers, jwt_claim_set)

        json = {
            'token_type': 'Bearer',
            'expires_in': '3600',
            'scope': 'user_impersonation',
            'expires_on': '1450316583',
            'not_before': '1450312683',
            'resource': 'https://sdfpilot.outlook.com/',
            'access_token': token.decode('utf-8')
        }

        return JsonResponse(json)


