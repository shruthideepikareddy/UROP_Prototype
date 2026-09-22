"""
Unit tests for Fuzzy Commitment Template Protection and ECC modules.
"""

import numpy as np
from template_protection import generate_secret_key, BlockECC, FuzzyCommitment

def test_secret_key_generation():
    bytes_val, bits_val = generate_secret_key(bit_length=64)
    assert len(bytes_val) == 8
    assert len(bits_val) == 64
    assert set(np.unique(bits_val)).issubset({0, 1})

def test_block_ecc():
    ecc = BlockECC(message_bits=64, codeword_bits=256)
    secret = np.random.choice([0, 1], size=64).astype(np.uint8)
    codeword = ecc.encode(secret)
    assert len(codeword) == 256

    # Burst noise in a handful of codeword bits.
    noisy = codeword.copy()
    noisy[0:5] = 1 - noisy[0:5]

    recovered, corrected, success = ecc.decode(noisy)
    assert success is True
    assert np.array_equal(recovered, secret)

    # Destroy one logical replica (64 interleaved positions). Remaining copies vote.
    noisy_replica = codeword.copy()
    replica0 = ecc.inv[:64]
    noisy_replica[replica0] = 1 - noisy_replica[replica0]
    recovered2, _, _ = ecc.decode(noisy_replica)
    assert np.array_equal(recovered2, secret)

def test_fuzzy_commitment_enrollment_and_recovery():
    fc = FuzzyCommitment(secret_bits=64, vector_bits=256)
    b_enrolled = np.random.choice([0, 1], size=256).astype(np.uint8)

    enrollment = fc.enroll(b_enrolled)
    helper = enrollment["helper_data"]
    commitment = enrollment["commitment"]

    # 1. Exact match query
    res_exact = fc.recover_secret(b_enrolled, helper, commitment)
    assert res_exact["success"] is True
    assert np.array_equal(res_exact["recovered_secret"], enrollment["secret"])

    # 2. Query with intra-user noise plus a residual polar-sector rotation
    b_noisy = b_enrolled.copy()
    b_noisy[[0, 4, 8, 12, 16]] = 1 - b_noisy[[0, 4, 8, 12, 16]]
    b_rotated = np.roll(b_noisy, 16)
    res_noisy = fc.recover_secret(b_rotated, helper, commitment)
    assert res_noisy["success"] is True

    # 3. Impostor query with completely different binary vector
    b_impostor = np.random.choice([0, 1], size=256).astype(np.uint8)
    res_impostor = fc.recover_secret(b_impostor, helper, commitment)
    assert res_impostor["success"] is False

def test_global_error_rate_threshold_gate():
    # Secret K=16 bits, codeword N=64 (Repetition factor 4)
    # Block size = 4 bits. Max errors per block = (4-1)//2 = 1 bit per block.
    # 16 blocks total. Max error rate 0.20 (<= 12 bits flipped overall out of 64).
    fc = FuzzyCommitment(secret_bits=16, vector_bits=64, max_global_error_rate=0.20)
    b_enrolled = np.zeros(64, dtype=np.uint8)
    enrollment = fc.enroll(b_enrolled)
    helper = enrollment["helper_data"]
    commitment = enrollment["commitment"]

    # 1. Flip 1 bit in block 0 (Total 1 error out of 64 = 1.56% <= 20% -> PASS)
    b_low_error = b_enrolled.copy()
    b_low_error[0] = 1
    res_pass = fc.recover_secret(b_low_error, helper, commitment)
    assert res_pass["hash_matched"] is True
    assert res_pass["within_global_limit"] is True
    assert res_pass["success"] is True

    # 2. Flip 1 bit in 14 blocks (block indices 0..13)
    # Total 14 errors out of 64 = 21.875% > 20%.
    # Each of those 14 blocks has 1 bit error <= max 1 error per block, so ECC block decoding recovers secret!
    # BUT total error rate is 21.875% > 20%, so global error gate MUST REJECT!
    b_high_error = b_enrolled.copy()
    flip_indices = fc.ecc.inv[:14]
    b_high_error[flip_indices] = 1


    res_reject = fc.recover_secret(b_high_error, helper, commitment)
    assert res_reject["hash_matched"] is True, "ECC block decoding should match hash"
    assert res_reject["within_global_limit"] is False, "Global error gate should trigger"
    assert res_reject["success"] is False, "Overall success must be False"

