"""
Encryption & Secure Multi-Party Utilities
=========================================

Provides encryption primitives for privacy-critical operations:

1. Symmetric encryption (AES-GCM) for model deltas, logs, alerts
2. Secure aggregation stub for federated learning (protect individual updates)
3. Homomorphic encryption placeholder (additive/FHE for future weighted averages)

Configuration keys (from privacy.encryption):
- symmetric_enabled: bool
- aes_key_length: 256
- secure_aggregation: bool (MVP: simple masking; future: real masked aggregation)

Dependencies:
- cryptography (for AES-GCM)
- Optional: tenseal or pyfhe for homomorphic (commented for MVP)

All methods return bytes or dicts with ciphertext + metadata.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantumguard.models.quantum_resistant import QuantumResistantCrypto
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class PrivacyEncryption:
    """
    Encryption utilities for privacy-preserving operations.

    - Symmetric AES-GCM for encrypting payloads
    - Secure aggregation stub (additive masking for federated updates)
    - Homomorphic placeholder (future: allow computation on encrypted gradients)
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.symmetric_enabled: bool = config.get("symmetric_enabled", True)
        self.aes_key_length: int = config.get("aes_key_length", 256)

        self.pq_crypto: Optional[QuantumResistantCrypto] = None
        if config.get("post_quantum_enabled", True):
            self.pq_crypto = QuantumResistantCrypto(config.get("post_quantum", {}))

        # Master key derivation (in real prod: derive from secure secret store)
        self._master_key_material = os.urandom(32)  # Replace with proper key management
        self.logger.info("PrivacyEncryption initialized", aes_key_length=self.aes_key_length)

    def derive_key(self, salt: bytes, info: bytes = b"quantumguard") -> bytes:
        """Derive AES key using HKDF from master material."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.aes_key_length // 8,
            salt=salt,
            info=info,
        )
        return hkdf.derive(self._master_key_material)

    def encrypt_symmetric(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        context: str = "general"
    ) -> Dict[str, bytes]:
        """
        Encrypt data with AES-GCM.

        Returns:
            {
                "ciphertext": bytes,
                "nonce": bytes,
                "tag": bytes,
                "salt": bytes (for key derivation)
            }
        """
        if not self.symmetric_enabled:
            return {"ciphertext": plaintext, "nonce": b"", "tag": b"", "salt": b""}

        salt = os.urandom(16)
        key = self.derive_key(salt, info=context.encode())

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        result = {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": b"",  # AESGCM includes tag in ciphertext
            "salt": salt,
        }

        self.logger.debug("Symmetric encryption completed", context=context, size=len(plaintext))
        return result

    def decrypt_symmetric(
        self,
        ciphertext: bytes,
        nonce: bytes,
        salt: bytes,
        associated_data: Optional[bytes] = None,
        context: str = "general"
    ) -> bytes:
        """Decrypt AES-GCM ciphertext."""
        if not self.symmetric_enabled:
            return ciphertext

        key = self.derive_key(salt, info=context.encode())
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            self.logger.debug("Symmetric decryption successful", context=context)
            return plaintext
        except Exception as e:
            self.logger.error("Decryption failed", error=str(e))
            raise ValueError("Decryption failed – invalid key/nonce/ciphertext") from e

    def secure_aggregate_updates(self, client_updates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Secure aggregation stub for federated learning.

        MVP: simple additive masking (each client adds random mask, server removes sum of masks)
        Future: real secure multi-party computation or secret sharing.

        Assumes each client_update is {"parameters": NDArrays, "mask": NDArrays}
        """
        if len(client_updates) == 0:
            raise ValueError("No client updates provided")

        # Placeholder: sum masked updates (real impl would use additive secret sharing)
        aggregated = {}
        for key in client_updates[0]["parameters"]:
            aggregated[key] = sum(up["parameters"][key] for up in client_updates)  # Dummy sum

        logger.info("Secure aggregation completed (stub)", num_clients=len(client_updates))
        return {"aggregated_parameters": aggregated}

    def homomorphic_add(self, enc_a: bytes, enc_b: bytes) -> bytes:
        """
        Placeholder for homomorphic addition (future FHE).

        In MVP: just returns concatenated (real version would use TenSEAL or PyFHE)
        """
        self.logger.warning("Homomorphic add called – placeholder only")
        return enc_a + b"|||" + enc_b  # Dummy concatenation

    def protect_model_delta(self, delta: Dict[str, Any], recipient_pubkey: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Protect a model update delta before sending to server (hybrid PQ + symmetric).

        Steps:
        1. Serialize delta
        2. Encrypt with AES-GCM
        3. Optionally encapsulate shared secret with PQ KEM
        """
        # Placeholder serialization (real: torch.save to BytesIO)
        serialized = str(delta).encode()  # Dummy

        enc_result = self.encrypt_symmetric(serialized, context="model_delta")

        protected = {
            "encrypted_delta": enc_result["ciphertext"],
            "nonce": enc_result["nonce"],
            "salt": enc_result["salt"],
        }

        if recipient_pubkey and self.pq_crypto:
            # PQ encapsulation for key exchange
            ciphertext, shared_secret = self.pq_crypto.encapsulate(recipient_pubkey)
            protected["pq_ciphertext"] = ciphertext
            # Use shared_secret to derive AES key in real hybrid

        logger.debug("Model delta protected")
        return protected
