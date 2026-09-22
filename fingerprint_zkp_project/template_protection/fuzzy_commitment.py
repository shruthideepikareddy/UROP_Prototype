"""
Fuzzy Commitment Template Protection Scheme.
Binds a cryptographically secure random secret to biometric binary template B.
Helper Data W = B XOR Codeword(C)
Commitment H = SHA256(C)
Recovery: C' = B' XOR W = Codeword(C) XOR (B XOR B')
ECC Decoder recovers C if Hamming_Distance(B, B') is within tiled majority-vote capacity.
"""

import hashlib
import numpy as np

from features.template import BITS_PER_SECTOR, N_SECTORS, iter_binary_alignments
from .error_correction import BlockECC
from .key_generation import generate_secret_key


class FuzzyCommitment:
    def __init__(self, secret_bits=64, vector_bits=256, max_global_error_rate=0.22):
        self.secret_bits = secret_bits
        self.vector_bits = vector_bits
        self.max_global_error_rate = max_global_error_rate
        self.ecc = BlockECC(message_bits=secret_bits, codeword_bits=vector_bits)

    @staticmethod
    def hash_secret(secret_vector):
        secret_bytes = np.packbits(secret_vector).tobytes()
        return hashlib.sha256(secret_bytes).hexdigest()

    def enroll(self, biometric_vector):
        biometric_vector = np.array(biometric_vector, dtype=np.uint8)
        if len(biometric_vector) != self.vector_bits:
            raise ValueError(f"Expected biometric vector length {self.vector_bits}, got {len(biometric_vector)}")

        _, secret = generate_secret_key(bit_length=self.secret_bits)
        codeword = self.ecc.encode(secret)
        helper_data = np.bitwise_xor(biometric_vector, codeword)
        commitment = self.hash_secret(secret)

        # Step 5: Compute Public Key PK = g^S mod p (Schnorr group generator)
        secret_int = int.from_bytes(np.packbits(secret).tobytes(), byteorder='big')
        # Standard safe prime generator
        p_safe = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
            16
        )
        g_safe = 2
        public_key = pow(g_safe, secret_int, p_safe)

        return {
            "helper_data": helper_data,
            "commitment": commitment,
            "secret": secret,
            "public_key": hex(public_key)
        }

    def recover_secret(self, query_biometric_vector, helper_data, stored_commitment, max_global_error_rate=Ellipsis):
        """
        Attempts to recover secret key C using query biometric vector B' and stored helper data W.
        Tries cyclic FingerCode sector rotations so a residual in-plane rotation does not break a genuine match.
        Enforces privacy-preserving global error threshold check without storing raw templates.
        
        Returns:
            dict containing:
                - success (bool): True if SHA256(recovered_C) == stored_commitment and error_rate <= max_global_error_rate
                - recovered_secret (np.ndarray or None)
                - errors_corrected (int)
                - error_rate (float): Global bit difference ratio d_H(B', B) / vector_bits
                - hash_matched (bool)
                - within_global_limit (bool)
                - candidate_hash (str)
                - residual_errors (int)
        """
        if max_global_error_rate is Ellipsis:
            max_global_error_rate = self.max_global_error_rate

        query_biometric_vector = np.array(query_biometric_vector, dtype=np.uint8)
        helper_data = np.array(helper_data, dtype=np.uint8)

        best_hash_matched = None
        best_any = None

        alignments = list(iter_binary_alignments(query_biometric_vector, N_SECTORS, BITS_PER_SECTOR)) if len(query_biometric_vector) == 256 else [query_biometric_vector]

        for aligned in alignments:
            noisy_codeword = np.bitwise_xor(aligned, helper_data)
            recovered_secret, corrected_errors, _ = self.ecc.decode(noisy_codeword)
            candidate_hash = self.hash_secret(recovered_secret)
            hash_matched = (candidate_hash == stored_commitment)

            reconstructed = self.ecc.encode(recovered_secret)
            residual = int(np.sum(noisy_codeword != reconstructed))

            error_rate = corrected_errors / float(self.vector_bits)
            within_global_limit = (max_global_error_rate is None) or (error_rate <= max_global_error_rate)
            is_valid = hash_matched and within_global_limit

            res = {
                "success": is_valid,
                "recovered_secret": recovered_secret if is_valid else None,
                "errors_corrected": corrected_errors,
                "error_rate": error_rate,
                "hash_matched": hash_matched,
                "within_global_limit": within_global_limit,
                "candidate_hash": candidate_hash,
                "residual_errors": residual,
            }

            if is_valid:
                return res

            if hash_matched:
                if best_hash_matched is None or residual < best_hash_matched["residual_errors"]:
                    best_hash_matched = res
            elif best_any is None or residual < best_any["residual_errors"]:
                best_any = res

        if best_hash_matched is not None:
            return best_hash_matched

        return best_any if best_any is not None else {
            "success": False,
            "recovered_secret": None,
            "errors_corrected": 0,
            "error_rate": 1.0,
            "hash_matched": False,
            "within_global_limit": False,
            "candidate_hash": "",
            "residual_errors": self.vector_bits,
        }


