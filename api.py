import requests
import base45
import base64
from typing import Dict, Tuple, Optional
from cose.keys import cosekey, ec2, keyops, curves
from cryptojwt import utils as cjwt_utils
import zlib
from cose.messages import CoseMessage
from pyasn1.codec.ber import decoder as asn1_decoder
from cose.headers import Algorithm, KID

class MysejahteraPrivateAPI:
    # This public is used to verify the certificate signature
    public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbP5zZhl/Nfvfk9Ocmj4kVz6BnMesxexyPMHW+vbveCzQwCj4MOkQaQcC932W3+f5/FV2081EKlp2zhL9ks0qLQ=="

    def __init__(self, username, password, auth_token=None):
        self.auth_token = None
        self.username = username
        self.password = password
        self.api_url = "https://mysejahtera.malaysia.gov.my/"

        self.headers = {
            'accept': 'application/json',
            'referer': 'https://mysejahtera.malaysia.gov.my/home',
            'user-agent': 'MySejahtera/1.0.45 (iPhone; iOS 14.6; Scale/3.00)',
            'accept-language': 'en-MY;q=1, ms-MY;q=0.9'
        }

    def login(self):
        multipart_form_data = {
            'username': (None, self.username),
            'password': (None, self.password)
        }
        response = requests.post(f'{self.api_url}epms/login', files=multipart_form_data)

        if 'X-AUTH-TOKEN' not in response.headers:
            raise Exception("Login Failed!")

        self.auth_token = response.headers['X-AUTH-TOKEN']

    def digital_cert(self):
        if self.auth_token is None:
            raise Exception("Auth Token is empty! Please run the login first.")

        headers = self.headers
        headers['x-auth-token'] = self.auth_token
        response = requests.request("GET", f"{self.api_url}epms/v1/mobileApp/vaccineSignedCertQrCodeUrl",
                                    headers=headers)
        return response.json()

    @staticmethod
    def public_ec_key_points(public_key: bytes) -> Tuple[str, str]:
        """
        This code adapted from: https://stackoverflow.com/a/59537764/1548275
        """
        public_key_asn1, _remainder = asn1_decoder.decode(public_key)
        public_key_bytes = public_key_asn1[1].asOctets()

        off = 0
        if public_key_bytes[off] != 0x04:
            raise ValueError("EC public key is not an uncompressed point")
        off += 1

        size_bytes = (len(public_key_bytes) - 1) // 2

        x_bin = public_key_bytes[off:off + size_bytes]
        x = int.from_bytes(x_bin, 'big', signed=False)
        off += size_bytes

        y_bin = public_key_bytes[off:off + size_bytes]
        y = int.from_bytes(y_bin, 'big', signed=False)
        off += size_bytes

        bl = (x.bit_length() + 7) // 8
        bytes_val = x.to_bytes(bl, 'big')
        x_str = base64.b64encode(bytes_val, altchars='-_'.encode()).decode()

        bl = (y.bit_length() + 7) // 8
        bytes_val = y.to_bytes(bl, 'big')
        y_str = base64.b64encode(bytes_val, altchars='-_'.encode()).decode()

        return x_str, y_str

    @staticmethod
    def cosekey_from_jwk_dict(jwk_dict: Dict) -> cosekey.CoseKey:
        """
        Create CoseKey from JWK
        Adapted from https://github.com/hannob/vacdec
        """
        # Read key and return CoseKey
        if jwk_dict["kty"] != "EC":
            raise ValueError("Only EC keys supported")
        if jwk_dict["crv"] != "P-256":
            raise ValueError("Only P-256 supported")

        key = ec2.EC2(
            crv=curves.P256,
            x=cjwt_utils.b64d(jwk_dict["x"].encode()),
            y=cjwt_utils.b64d(jwk_dict["y"].encode()),
        )
        key.key_ops = [keyops.VerifyOp]
        if "kid" in jwk_dict:
            key.kid = bytes(jwk_dict["kid"], "UTF-8")

        return key

    @staticmethod
    def verify_signature(cose_msg: CoseMessage) -> bool:
        x, y = MysejahteraPrivateAPI.public_ec_key_points(base64.b64decode(MysejahteraPrivateAPI.public_key))
        key_dict = {'crv': "P-256",
                    'kid': cose_msg.phdr[KID].hex(),
                    'kty': "EC",
                    'x': x,
                    'y': y,
                    }
        jwt_key = MysejahteraPrivateAPI.cosekey_from_jwk_dict(key_dict)
        cose_msg.key = jwt_key
        if not cose_msg.verify_signature():
            return False

        return True

    @staticmethod
    def decode_vaccine_cert(payload: str) -> CoseMessage:
        assert payload[0:3] == "HC1"
        # Strip HC1 since it's the magic value for this vaccine cert
        b45data = payload[4:]
        # Decode the data
        zlibdata = base45.b45decode(b45data)
        # Uncompress the data
        decompressed = zlib.decompress(zlibdata)
        return CoseMessage.decode(decompressed)
