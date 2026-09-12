"""
Dataset Loader for UROP Project.
Handles loading real fingerprint datasets (e.g. FVC format {subject_id}_{sample_id}.ext or subject subfolders in Fingerprint_dataset).
"""
import os
import glob
import re
import numpy as np
import cv2

class FingerprintDataset:
    def __init__(self, data_dir=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if data_dir is None:
            # Check candidate dataset directories: Fingerprint_dataset first, then data/raw
            candidate_dirs = [
                os.path.join(base_dir, "Fingerprint_dataset"),
                os.path.join(base_dir, "data", "raw")
            ]
            for candidate in candidate_dirs:
                if os.path.exists(candidate) and len(os.listdir(candidate)) > 0:
                    data_dir = candidate
                    break
            if data_dir is None:
                data_dir = os.path.join(base_dir, "data", "raw")

        self.data_dir = data_dir

    def load_dataset(self):
        """
        Loads fingerprint images from self.data_dir.
        Supports:
        - Direct flat directory with files named {subject_id}_{sample_id}.ext
        - Nested subject directories (e.g. Fingerprint_dataset/Fingerprint_dataset/1/108_L0_0.bmp)
        Returns:
            dict: {subject_id: {sample_id: image_matrix}}
        """
        if not os.path.exists(self.data_dir):
            print(f"[DatasetLoader] Error: Directory does not exist: {self.data_dir}")
            return {}

        valid_exts = ('*.png', '*.jpg', '*.jpeg', '*.tif', '*.tiff', '*.bmp')
        image_paths = []

        # Recursively search for image files
        for root, _, _ in os.walk(self.data_dir):
            for ext in valid_exts:
                image_paths.extend(glob.glob(os.path.join(root, ext)))
                image_paths.extend(glob.glob(os.path.join(root, ext.upper())))

        # Deduplicate paths
        image_paths = list(set(image_paths))

        if not image_paths:
            print(f"[DatasetLoader] Error: No fingerprint images found in {self.data_dir}")
            return {}

        dataset = {}
        pattern = re.compile(r'(\d+)_(\d+)')

        for path in sorted(image_paths):
            filename = os.path.basename(path)
            name_part = os.path.splitext(filename)[0]
            
            # Check parent folder name if it's a numeric subject ID (e.g., .../1/image.bmp)
            parent_dir = os.path.basename(os.path.dirname(path))
            if parent_dir.isdigit():
                subject_id = int(parent_dir)
                match = pattern.search(name_part)
                sample_id = int(match.group(2)) if match else 1
            else:
                match = pattern.search(name_part)
                if match:
                    subject_id = int(match.group(1))
                    sample_id = int(match.group(2))
                else:
                    subject_id = abs(hash(name_part[:len(name_part)//2])) % 1000
                    sample_id = abs(hash(name_part)) % 10 + 1

            img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
            if img is not None:
                if subject_id not in dataset:
                    dataset[subject_id] = {}
                dataset[subject_id][sample_id] = img

        print(f"[DatasetLoader] Successfully loaded {sum(len(v) for v in dataset.values())} real images across {len(dataset)} subjects from {self.data_dir}.")
        return dataset

if __name__ == "__main__":
    loader = FingerprintDataset()
    ds = loader.load_dataset()
    print("Dataset subjects count:", len(ds.keys()))

