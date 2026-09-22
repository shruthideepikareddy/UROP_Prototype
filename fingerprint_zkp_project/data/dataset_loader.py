"""
Dataset Loader for UROP Project.
Handles loading real fingerprint datasets (e.g. FVC format {subject_id}_{sample_id}.ext,
subject subfolders in Fingerprint_dataset, or provided train/test zips).
"""
import os
import glob
import re
import numpy as np
import cv2


SUBJECT_L0_RE = re.compile(r"^(\d+)_L\d+_(\d+)$", re.IGNORECASE)
SUBJECT_SAMPLE_RE = re.compile(r"^(\d+)_(\d+)$")


def parse_fingerprint_stem(stem):
    """
    Returns (subject_id, sample_id) or None.
    """
    m = SUBJECT_L0_RE.match(stem)
    if m:
        return int(m.group(1)), int(m.group(2))
    m = SUBJECT_SAMPLE_RE.match(stem)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


class FingerprintDataset:
    def __init__(self, data_dir=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if data_dir is None:
            # Check candidate dataset directories: Fingerprint_dataset first, then data/raw
            candidate_dirs = [
                os.path.join(base_dir, "Fingerprint_dataset"),
                os.path.join(base_dir, "data", "raw"),
            ]
            for candidate in candidate_dirs:
                if os.path.exists(candidate) and len(os.listdir(candidate)) > 0:
                    data_dir = candidate
                    break
            if data_dir is None:
                splits = default_split_dirs()
                data_dir = splits["test"]
        self.data_dir = data_dir

    def load_dataset(self, max_subjects=None):
        """
        Loads fingerprint images from self.data_dir (recursive).
        Supports:
        - Direct flat directory with files named {subject_id}_{sample_id}.ext
        - Nested subject directories (e.g. Fingerprint_dataset/1/108_L0_0.bmp)
        Returns:
            dict: {subject_id: {sample_id: image_matrix}}
        """
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir, exist_ok=True)

        valid_exts = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
        image_paths = []
        for root, _, files in os.walk(self.data_dir):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in valid_exts:
                    image_paths.append(os.path.join(root, fname))

        if not image_paths:
            print(f"[DatasetLoader] No fingerprint images found in {self.data_dir}. Generating synthetic dataset...")
            self.generate_synthetic_dataset(num_subjects=10, samples_per_subject=8)
            return self.load_dataset(max_subjects=max_subjects)

        dataset = {}
        for path in sorted(image_paths):
            filename = os.path.basename(path)
            stem = os.path.splitext(filename)[0]
            parsed = parse_fingerprint_stem(stem)
            if parsed:
                subject_id, sample_id = parsed
            else:
                parent = os.path.basename(os.path.dirname(path))
                if parent.isdigit():
                    subject_id = int(parent)
                    parsed_sub = parse_fingerprint_stem(stem)
                    sample_id = parsed_sub[1] if parsed_sub else abs(hash(stem)) % 100 + 1
                else:
                    subject_id = abs(hash(stem[: max(1, len(stem) // 2)])) % 1000
                    sample_id = abs(hash(stem)) % 10 + 1

            img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
            if img is None:
                continue
            if subject_id not in dataset:
                dataset[subject_id] = {}
            dataset[subject_id][sample_id] = img

        if max_subjects is not None:
            keep = sorted(dataset.keys())[: int(max_subjects)]
            dataset = {k: dataset[k] for k in keep}

        print(
            f"[DatasetLoader] Successfully loaded {sum(len(v) for v in dataset.values())} "
            f"images across {len(dataset)} subjects from {self.data_dir}."
        )
        return dataset

    def generate_synthetic_dataset(self, num_subjects=10, samples_per_subject=8, img_shape=(300, 300)):
        """
        Generates realistic synthetic fingerprint patterns using Gabor wavelets and ridge patterns
        with subject-specific core patterns and intra-class noise/rotation/translation.
        """
        print(
            f"[DatasetLoader] Generating synthetic fingerprint dataset "
            f"({num_subjects} subjects, {samples_per_subject} samples/subject)..."
        )
        os.makedirs(self.data_dir, exist_ok=True)
        h, w = img_shape

        for s in range(1, num_subjects + 1):
            base_freq = 0.08 + (s % 5) * 0.015
            center_x, center_y = w // 2 + (s * 7) % 20 - 10, h // 2 + (s * 11) % 20 - 10
            spiral_factor = 0.5 + (s * 0.3) % 1.5

            for sample in range(1, samples_per_subject + 1):
                angle_offset = np.random.normal(0, 0.08)
                dx = np.random.randint(-5, 6)
                dy = np.random.randint(-5, 6)

                y_grid, x_grid = np.ogrid[:h, :w]
                xc = x_grid - (center_x + dx)
                yc = y_grid - (center_y + dy)

                r = np.sqrt(xc**2 + yc**2) + 1e-5
                theta = np.arctan2(yc, xc) + angle_offset
                phase = 2 * np.pi * base_freq * (r + spiral_factor * theta * 10)
                ridges = np.sin(phase)
                img = ((ridges + 1) / 2.0 * 200 + 30).astype(np.uint8)

                ellipse_mask = ((xc / (w * 0.4)) ** 2 + (yc / (h * 0.45)) ** 2) <= 1.0
                img[~ellipse_mask] = 255

                noise = np.random.normal(0, 8, img.shape).astype(np.int16)
                img = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)

                filename = f"{s:03d}_{sample}.png"
                filepath = os.path.join(self.data_dir, filename)
                cv2.imwrite(filepath, img)

        print(f"[DatasetLoader] Synthetic dataset successfully written to {self.data_dir}")


def ensure_split_extracted():
    """
    Extracts fp_training.zip / fp_testing.zip from the project root if needed.
    """
    import zipfile

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(base_dir)
    mapping = {
        "fp_training": ["fp_training.zip"],
        "fp_testing": ["fp_testing.zip"],
    }
    for folder, zip_names in mapping.items():
        dest = os.path.join(base_dir, "data", folder)
        has_images = False
        if os.path.isdir(dest):
            for _root, _dirs, files in os.walk(dest):
                if any(f.lower().endswith((".bmp", ".tif", ".png", ".jpg")) for f in files):
                    has_images = True
                    break
        if has_images:
            continue
        os.makedirs(dest, exist_ok=True)
        zip_path = None
        for name in zip_names:
            for candidate in (
                os.path.join(base_dir, name),
                os.path.join(repo_root, name),
                os.path.join(os.path.dirname(repo_root), name),
            ):
                if os.path.isfile(candidate):
                    zip_path = candidate
                    break
            if zip_path:
                break
        if zip_path is None:
            continue
        print(f"[DatasetLoader] Extracting {zip_path} -> {dest}")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest)


def default_split_dirs():
    ensure_split_extracted()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "train": os.path.join(base_dir, "data", "fp_training"),
        "test": os.path.join(base_dir, "data", "fp_testing"),
        "raw": os.path.join(base_dir, "data", "raw"),
    }

if __name__ == "__main__":
    loader = FingerprintDataset()
    ds = loader.load_dataset()
    print("Dataset subjects count:", len(ds.keys()))

