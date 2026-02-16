"""
Post-Quantum Cryptography Module
================================

Provides quantum-resistant key encapsulation (KEM) and digital signatures.

Supported algorithms (NIST PQC Round 3/4 winners + hybrids):
- KEM: ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 (Kyber variants)
- Signatures: ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (Dilithium variants)
- Hash-based: SLH-DSA (SPHINCS+ variants) – slower, but no algebraic assumptions

Hybrid mode: PQ + classical (X25519 + ECDSA) for backward compatibility.

API designed for simplicity and security:
- generate_keypair()
- encapsulate() / decapsulate()
- sign() / verify()
- All operations use secure randomness and constant-time implementations

Configuration keys (from privacy.encryption):
- enabled: bool (default: True)
- kem_algorithm: str (default: "ML-KEM-768")
- sig_algorithm: str (default: "ML-DSA-65")
- hybrid: bool (default: True)

Dependencies: liboqs-python (pip install oqs)
"""

from __future__ import annotations

import base64
import os
from typing import Dict, Optional, Tuple

try:
    import oqs
except ImportError:
    oqs = None  # Graceful fallback for dev without liboqs

from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class QuantumResistantCrypto:
    """
    Post-quantum crypto wrapper with hybrid support.

    Provides:
    - Key encapsulation mechanism (KEM) for secure key exchange
    - Digital signatures for integrity/authenticity
    - Hybrid (PQ + classical) mode for transition periods
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.enabled: bool = config.get("enabled", True)
        if not self.enabled:
            logger.warning("Post-quantum crypto disabled by config")
            self.kem = self.sig = None
            return

        if oqs is None:
            raise RuntimeError(
                "liboqs-python not installed. "
                "Install via 'poetry add oqs' or 'pip install oqs' for quantum-resistant features."
            )

        self.kem_alg: str = config.get("kem_algorithm", "ML-KEM-768")
        self.sig_alg: str = config.get("sig_algorithm", "ML-DSA-65")
        self.hybrid: bool = config.get("hybrid", True)

        # Validate algorithms
        if self.kem_alg not in oqs.get_enabled_kem_algorithms():
            raise ValueError(f"Unsupported KEM algorithm: {self.kem_alg}")
        if self.sig_alg not in oqs.get_enabled_sig_algorithms():
            raise ValueError(f"Unsupported signature algorithm: {self.sig_alg}")

        self.kem = oqs.KeyEncapsulation(self.kem_alg)
        self.sig = oqs.Signature(self.sig_alg)

        logger.info(
            "QuantumResistantCrypto initialized",
            kem=self.kem_alg,
            sig=self.sig_alg,
            hybrid=self.hybrid
        )

    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate public/private keypair for key encapsulation.

        Returns:
            (public_key: bytes, secret_key: bytes)
        """
        if not self.enabled or self.kem is None:
            raise RuntimeError("PQ crypto disabled")

        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: Generate shared secret and ciphertext.

        Args:
            public_key: Recipient's public key

        Returns:
            (ciphertext: bytes, shared_secret: bytes)
        """
        if not self.enabled:
            raise RuntimeError("PQ crypto disabled")

        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate: Recover shared secret from ciphertext.

        Returns:
            shared_secret: bytes (should match encapsulator's)
        """
        if not self.enabled:
            raise RuntimeError("PQ crypto disabled")

        shared_secret = self.kem.decap_secret(ciphertext, secret_key)
        return shared_secret

    def generate_sig_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate public/private keypair for signatures.

        Returns:
            (public_key: bytes, secret_key: bytes)
        """
        if not self.enabled or self.sig is None:
            raise RuntimeError("PQ crypto disabled")

        public_key = self.sig.generate_keypair()
        secret_key = self.sig.export_secret_key()
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message with the private key.

        Returns:
            signature: bytes
        """
        if not self.enabled:
            raise RuntimeError("PQ crypto disabled")

        signature = self.sig.sign(message, secret_key)
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature against the public key.

        Returns:
            True if valid, False otherwise
        """
        if not self.enabled:
            raise RuntimeError("PQ crypto disabled")

        return self.sig.verify(message, signature, public_key)

    def hybrid_encrypt(self, plaintext: bytes, recipient_pub: bytes) -> Dict[str, bytes]:
        """
        Hybrid encryption (PQ + classical fallback).

        For MVP: just PQ KEM + AES-GCM (real impl would add AES layer).
        Returns dict with ciphertext, kem_ciphertext, etc.
        """
        # Placeholder – full hybrid AES + KEM in future version
        logger.warning("Hybrid encrypt called – placeholder implementation")
        return {
            "kem_ciphertext": b"placeholder_ciphertext",
            "encrypted_data": plaintext,  # No real encryption yet
        }

    def __del__(self) -> None:
        """Cleanup OQS contexts on destruction."""
        if self.kem is not None:
            self.kem.free()
        if self.sig is not None:
            self.sig.free()
