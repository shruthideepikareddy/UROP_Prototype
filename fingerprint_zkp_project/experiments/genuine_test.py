"""
Genuine Authentication Experiment Module.
Evaluates genuine verification across different captures of the same finger (Image A -> Image B, C, D...)
and single-capture baseline verification. Calculates exact Hamming distances d_H(B1, B2).
"""

import os
import glob
import numpy as np

from features.resnet_extractor import ResNet50FeatureExtractor
from features.binarization import get_binarizer
from template_protection.fuzzy_commitment import FuzzyCommitment

def run_genuine_test(dataset_path=None, binarization_method="standardized", secret_bits=128):
    if dataset_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dataset_path = os.path.join(base_dir, "data", "raw")

    print(f"[*] Running Genuine Cross-Capture Test on: {dataset_path}")
    print(f"[*] Configuration: Binarization={binarization_method}, Secret K={secret_bits} bits")

    extractor = ResNet50FeatureExtractor()
    
    # Load multi-impression dataset (e.g. 101_1.tif, 101_2.tif...)
    image_files = glob.glob(os.path.join(dataset_path, "*.*"))
    dataset = {}
    for f in image_files:
        name = os.path.splitext(os.path.basename(f))[0]
        parts = name.split('_')
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            s_id, smp_id = int(parts[0]), int(parts[1])
            if s_id not in dataset:
                dataset[s_id] = {}
            dataset[s_id][smp_id] = f

    subjects = sorted(dataset.keys())
    print(f"[*] Detected {len(subjects)} subjects with multiple impressions.")

    # Extract raw 2048-dim features
    raw_feats = {}
    enrollment_feats = []
    for s_id in subjects:
        raw_feats[s_id] = {}
        for smp_id in sorted(dataset[s_id].keys()):
            feat = extractor.extract_feature(dataset[s_id][smp_id])
            raw_feats[s_id][smp_id] = feat
            if smp_id == 1:
                enrollment_feats.append(feat)

    # Fit binarizer (zero test-set leakage)
    binarizer = get_binarizer(binarization_method, enrollment_features=np.array(enrollment_feats))
    
    binary_feats = {}
    for s_id in subjects:
        binary_feats[s_id] = {}
        for smp_id in raw_feats[s_id]:
            binary_feats[s_id][smp_id] = binarizer.transform(raw_feats[s_id][smp_id])

    # Fuzzy Commitment Setup
    fc = FuzzyCommitment(secret_bits=secret_bits, vector_bits=2048)

    # Enroll Impression 1 for each subject
    db = {}
    for s_id in subjects:
        db[s_id] = fc.enroll(binary_feats[s_id][1])

    # Authenticate Impressions 2..N against Impression 1
    total_trials = 0
    successful_recoveries = 0
    hamming_distances = []

    print(f"\n{'Subj':<5} | {'Enroll Smp':<10} | {'Query Smp':<10} | {'Hamming Dist (bits)':<20} | {'BER (%)':<10} | {'Secret Recovered'}")
    print("-" * 80)

    for s_id in subjects:
        b_enroll = binary_feats[s_id][1]
        for smp_id in sorted(binary_feats[s_id].keys()):
            if smp_id == 1:
                continue
            total_trials += 1
            b_query = binary_feats[s_id][smp_id]
            d_h = int(np.sum(b_enroll != b_query))
            ber = (d_h / 2048.0) * 100.0
            hamming_distances.append(d_h)

            rec = fc.recover_secret(b_query, db[s_id]["helper_data"], db[s_id]["commitment"])
            if rec["success"]:
                successful_recoveries += 1

            status = "[OK] ACCEPTED" if rec["success"] else "[X] REJECTED"
            print(f"{s_id:<5} | {1:<10} | {smp_id:<10} | {d_h:<20} | {ber:<10.2f} | {status}")

    gar = (successful_recoveries / total_trials) * 100.0 if total_trials > 0 else 0.0
    frr = 100.0 - gar
    avg_dh = np.mean(hamming_distances) if hamming_distances else 0.0

    print("-" * 80)
    print(f"[*] Genuine Cross-Capture Trials: {total_trials}")
    print(f"[*] Successful Secret Recoveries: {successful_recoveries}")
    print(f"[*] Genuine Acceptance Rate (GAR): {gar:.2f}%")
    print(f"[*] False Rejection Rate (FRR): {frr:.2f}%")
    print(f"[*] Average Intra-Subject Hamming Distance: {avg_dh:.1f} bits ({avg_dh/2048*100:.2f}% BER)")

    return {
        "trials": total_trials,
        "recoveries": successful_recoveries,
        "gar": gar,
        "frr": frr,
        "avg_hamming": avg_dh
    }

if __name__ == "__main__":
    run_genuine_test()
