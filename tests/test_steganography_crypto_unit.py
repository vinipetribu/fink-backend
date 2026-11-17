"""AES integration for the LSB frame without requiring a running HTTP stack."""

import unittest
from uuid import uuid4

from pydantic import ValidationError

from app.crypto_lab.aes_service import CryptoService
from app.crypto_lab.errors import DecryptionError
from app.crypto_lab.schemas import CryptoEnvelope, StegoEmbedRequest, StegoExtractRequest
from app.crypto_lab.steganography import embed, extract
from tests.test_steganography_unit import make_png


class StegoCryptoIntegration(unittest.TestCase):
    def test_roundtrip_and_ownership(self):
        owner, other = uuid4(), uuid4()
        service = CryptoService()
        envelope = service.encrypt('conteúdo fictício 💳', owner).envelope
        encoded = envelope.model_dump_json().encode()
        image = embed(make_png(128, 128, 6), encoded)
        recovered = CryptoEnvelope.model_validate_json(extract(image))
        self.assertEqual(service.decrypt(recovered, owner).text, 'conteúdo fictício 💳')
        with self.assertRaises(DecryptionError):
            service.decrypt(recovered, other)

    def test_schemas_reject_bad_base64_and_extra_data(self):
        with self.assertRaises(ValidationError):
            StegoExtractRequest(image_png='!')
        with self.assertRaises(ValidationError):
            StegoExtractRequest(image_png='eA==', extra='secret')


if __name__ == '__main__':
    unittest.main()
