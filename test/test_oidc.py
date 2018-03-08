"""
pykube.oidc unittests
"""
import base64
import logging
import json

from . import TestCase
from pykube import oidc

logger = logging.getLogger(__name__)


class TestOIDC(TestCase):
    def test_pad_b64(self):
        """Check that the correct padding is applied to unpadded b64 strings"""
        test1 = {"value": b"any carnal pleasure.",
                 "unpadded": "YW55IGNhcm5hbCBwbGVhc3VyZS4",
                 "padded": "YW55IGNhcm5hbCBwbGVhc3VyZS4="}
        test2 = {"value": b"any carnal pleasure",
                 "unpadded": "YW55IGNhcm5hbCBwbGVhc3VyZQ",
                 "padded": "YW55IGNhcm5hbCBwbGVhc3VyZQ=="}
        test3 = {"value": b"any carnal pleasur",
                 "unpadded": "YW55IGNhcm5hbCBwbGVhc3Vy",
                 "padded": "YW55IGNhcm5hbCBwbGVhc3Vy"}

        for test in [test1, test2, test3]:
            padded = oidc._pad_b64(test["unpadded"])
            self.assertEqual(test["padded"], padded)
            value = base64.b64decode(padded)
            self.assertEqual(test["value"], value)

    def _payload_to_b64(self, payload):
        payload_j = json.dumps(payload)
        payload_b = payload_j.encode('utf-8')
        payload_b64 = base64.b64encode(payload_b)
        return payload_b64.decode('utf-8')

    def test_id_token_expired(self):
        """Does the token expiry check work?"""
        id_token_fmt = 'YW55IGNhcm5hbCBwbGVhc3VyZS4.{}.YW55IGNhcm5hbCBwbGVhc3VyZS4'

        payload_expired = {'exp': 0}
        payload_expired_b64 = self._payload_to_b64(payload_expired)
        id_token_expired = id_token_fmt.format(payload_expired_b64)
        self.assertTrue(oidc._id_token_expired(id_token_expired))

        payload_valid = {'exp': 99999999999}
        payload_valid_b64 = self._payload_to_b64(payload_valid)
        id_token_valid = id_token_fmt.format(payload_valid_b64)
        self.assertFalse(oidc._id_token_expired(id_token_valid))
