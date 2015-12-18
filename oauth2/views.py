
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
import xml.etree.ElementTree as ET

import json
import base64
import uuid
import time
import ast
from aad_emulator import settings
# urlparse is renamed as urllib.parse in Python 3
from urllib.parse import urlparse

# Create your views here.
class OAuthTokenView(View):
    #E:\\dev\\python\\aad_emulator\\AdalOAuthTokenSigningCert.key
    private_key = open(settings.OAUTH2['private_key_path'], 'rb').read().decode('utf-8')
    #'E:\\dev\\python\\aad_emulator\\b64ceradal.cer'
    public_cert = open(settings.OAUTH2['public_certificate_path'], 'rb' ).read()
    cert = load_pem_x509_certificate(public_cert, default_backend())
    public_key = cert.public_key()

    cert_thumbprint = cert.fingerprint(hashes.SHA1())
    base64_encoded_thumbprint = base64.b64encode(cert_thumbprint).decode('utf-8')
    key_id = base64_encoded_thumbprint.split('=')[0].replace('+', '-')
    key_id = key_id.replace('/', '_')

    def post(self, request, *args, **kwargs):
        jwt_id = str(uuid.uuid4())
        unix_time_now = int(time.time())
        unix_time_nbf = int(time.time()) - settings.OAUTH2['nbf']
        unix_time_exp = int(time.time()) + settings.OAUTH2['exp']
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

        tenant = kwargs['tenant']
        app_id = request.POST['client_id']

        issuer = '{}://{}/{}/'.format(request.scheme, request.META['HTTP_HOST'], tenant)

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
            "tid": tenant,
            "ver": '1.0',
            }

        token = TokenGenerator.get_token(OAuthTokenView.private_key, jwt_headers, jwt_claim_set)

        json = {
            'token_type': 'Bearer',
            'expires_in': settings.OAUTH2['exp'],
            'scope': 'user_impersonation',
            'expires_on': unix_time_exp,
            'not_before': unix_time_nbf,
            'resource': audience,
            'access_token': token.decode('utf-8')
        }

        return JsonResponse(json)


class FederationMetadataView(View):
    ns = {
        'key': 'http://www.w3.org/2000/09/xmldsig#',
        'metadata': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'addr': 'http://www.w3.org/2005/08/addressing',
        'fed': 'http://docs.oasis-open.org/wsfed/federation/200706'
    }

    #ET.register_namespace('', ns['metadata'])
    #ET.register_namespace('', ns['key'])
    #ET.register_namespace('fed', ns['fed'])
    # in Python 2 should be ns.iteritems()
    for _, namespace in ns.items():
        ET.register_namespace('', namespace)



    def get(self, request, *args, **kwargs):
        public_cert = open(settings.OAUTH2['public_certificate_path'], 'rb' ).read()
        cert = load_pem_x509_certificate(public_cert, default_backend())
        public_key = 'abc'#cert.public_key().encode('utf-8')
        entityId = '{}://{}/'.format(request.scheme, request.META['HTTP_HOST']) + '{tenantid}/'



        metadata_doc = ET.parse('./oauth2/FederationMetaTemplate.xml')
        root = metadata_doc.getroot()
        root.set('entityID', entityId)

        # in Python 2 should be ns.iteritems()
        #for _, namespace in ns.items():
        #    ET.register_namespace('', namespace)


        cert_xpath = 'metadata:RoleDescriptor/metadata:KeyDescriptor/key:KeyInfo/key:X509Data/key:X509Certificate'

        for cert in root.findall(cert_xpath, ns):
            cert.text = public_key

        addr_xpath = 'metadata:RoleDescriptor/*/addr:EndpointReference/addr:Address'

        for addr in root.findall(addr_xpath, ns):
            uri = urlparse(addr.text)
            addr.text = '{}://{}{}'.format(request.scheme, request.META['HTTP_HOST'], uri.path)

        return HttpResponse(ET.tostring(root))








        #MIIFGDCCBIGgAwIBAgIKNKPmQgABAAKDCjANBgkqhkiG9w0BAQUFADCBgTETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEUMBIGCgmSJomT8ixkARkWBGNvcnAxFzAVBgoJkiaJk/IsZAEZFgdyZWRtb25kMSAwHgYDVQQDExdNUyBQYXNzcG9ydCBUZXN0IFN1YiBDQTAeFw0xNDA3MjIyMDQwMDJaFw0zMTEyMTMyMjI2MDdaMBkxFzAVBgNVBAMTDkp3dFNpZ25pbmdDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sYVkDRd5RC/is1YileqmhvmkqgfW/g3Y4TF4uGdviMEcXxqYOkpZOMWGp9pHXmw8J0PDpoyzL4mEd23TLeBjNPfsalk06FPc/hPEvGulwjEjobum2hzVmoh5Vwvj1mi5tMYK9y/676M0yXXRgwi7PjsnUCkUA2y5FeFCmMp06RDIYrgJTc2hooomBUlwKdLhje+k6h9oXZVOtA7pkLDlIltSxocrJbUH9WL9mHRnYYvpvHCEykRfonM+Rg30gTPZv4D40DEynMPODU7/qjPmi8RZWlqyMsxk8vnt4NfY6WtdYpuD25b3WK8Yxg6YNGVaLH6cTToO5Lhc154cZ+DtQIDAQABo4ICeDCCAnQwDgYDVR0PAQH/BAQDAgQwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBQtY57NsXrpBuZr+PKUocAmVd6rCjAfBgNVHSMEGDAWgBRqZnhiCk/0nKi3X9VmNI8zceQrEzCB0AYDVR0fBIHIMIHFMIHCoIG/oIG8hl9odHRwOi8vcHB0ZXN0c3ViY2EucmVkbW9uZC5jb3JwLm1pY3Jvc29mdC5jb20vQ2VydEVucm9sbC9NUyUyMFBhc3Nwb3J0JTIwVGVzdCUyMFN1YiUyMENBKDEpLmNybIZZZmlsZTovL1xccHB0ZXN0c3ViY2EucmVkbW9uZC5jb3JwLm1pY3Jvc29mdC5jb21cQ2VydEVucm9sbFxNUyBQYXNzcG9ydCBUZXN0IFN1YiBDQSgxKS5jcmwwggE4BggrBgEFBQcBAQSCASowggEmMIGTBggrBgEFBQcwAoaBhmh0dHA6Ly9wcHRlc3RzdWJjYS5yZWRtb25kLmNvcnAubWljcm9zb2Z0LmNvbS9DZXJ0RW5yb2xsL3BwdGVzdHN1YmNhLnJlZG1vbmQuY29ycC5taWNyb3NvZnQuY29tX01TJTIwUGFzc3BvcnQlMjBUZXN0JTIwU3ViJTIwQ0EoMSkuY3J0MIGNBggrBgEFBQcwAoaBgGZpbGU6Ly9cXHBwdGVzdHN1YmNhLnJlZG1vbmQuY29ycC5taWNyb3NvZnQuY29tXENlcnRFbnJvbGxccHB0ZXN0c3ViY2EucmVkbW9uZC5jb3JwLm1pY3Jvc29mdC5jb21fTVMgUGFzc3BvcnQgVGVzdCBTdWIgQ0EoMSkuY3J0MA0GCSqGSIb3DQEBBQUAA4GBAHYI/76nUaqvH4bx/pjp5zwKd3L/EcjlmzGPDjq3wK/b5F72eB//R0eDiSlXrh/bi8DZVgiLHCqf5+v2jkhWkA6U5OMkG1a1Z/iHIpCVDVPMKyk6pRhDkZdnog7e6xztiZNXGabYoOg0Uy51yyLFu/5mFarygmgl8RTJjYjBQYrJ
