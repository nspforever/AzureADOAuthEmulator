from aad_emulator import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from django.http import HttpResponse, JsonResponse
from django.views.generic.base import View
from oauth2.token_generator import TokenGenerator
# urlparse is renamed as urllib.parse in Python 3
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import base64
import time
import uuid


# Create your views here.
class OAuthTokenView(View):
    private_key = open(settings.OAUTH2['private_key_path'], 'r').read()
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

        scheme = ('HTTP_X_FORWARDED_PROTO' in request.META and request.META['HTTP_X_FORWARDED_PROTO']) or request.scheme
        issuer = '{}://{}/{}/'.format(scheme, request.META['HTTP_HOST'], tenant)

        options = {'verify_aud': False, 'verify_signature': False}
        client_assertion = TokenGenerator.decode_token(request.POST['client_assertion'], options=options)
        appid = client_assertion['sub']

        jwt_claim_set = {
            "iss": issuer,
            "aud": audience,
            "jti": jwt_id,
            "nbf": unix_time_nbf,
            "iat": unix_time_now,
            "exp": unix_time_exp,
            "appid": appid,
            "appidacr": '2',
            "idp": issuer,
            "tid": tenant,
            "ver": '1.0',
            }

        jwt_claim_set["roles"] = ["Directory.ReadWrite.All", ""]

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
        'keyinfo': 'http://www.w3.org/2000/09/xmldsig#',
        'metadata': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'addr': 'http://www.w3.org/2005/08/addressing',
        'fed': 'http://docs.oasis-open.org/wsfed/federation/200706',
        'auth': 'http://docs.oasis-open.org/wsfed/authorization/200706',
    }

    # in Python 2 should be ns.iteritems()
    for prefix, namespace in ns.items():
        ET.register_namespace(prefix, namespace)

    public_cert = open(settings.OAUTH2['public_certificate_path'], 'r').read().splitlines()
    public_key = "".join(public_cert[1:-1])

    def get(self, request, *args, **kwargs):
        scheme = ('HTTP_X_FORWARDED_PROTO' in request.META and request.META['HTTP_X_FORWARDED_PROTO']) or request.scheme

        entityId = '{}://{}/'.format(scheme, request.META['HTTP_HOST']) + '{tenantid}/'
        metadata_doc = ET.parse('./oauth2/FederationMetaTemplate.xml')
        root = metadata_doc.getroot()
        root.set('entityID', entityId)

        cert_xpath = '*/metadata:KeyDescriptor/keyinfo:KeyInfo/keyinfo:X509Data/keyinfo:X509Certificate'

        for cert in root.findall(cert_xpath, FederationMetadataView.ns):
            cert.text = FederationMetadataView.public_key

        addr_xpath = 'metadata:RoleDescriptor/*/addr:EndpointReference/addr:Address'

        for addr in root.findall(addr_xpath, FederationMetadataView.ns):
            uri = urlparse(addr.text)
            addr.text = '{}://{}{}'.format(scheme, request.META['HTTP_HOST'], uri.path)

        res = HttpResponse(ET.tostring(root))

        res['Content-Type'] = 'text/xml; charset=utf-8'
        res['Cache-Control'] = 'no-cache, no-store'
        res['Pragma'] = 'no-cache'
        res['Expires'] = -1
        res['Vary'] = 'Accept-Encoding'
        res['Content-Length'] = len(res.content)
        res['X-Content-Type-Options'] = 'nosniff'
        return res

