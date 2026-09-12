"""
Biometric Feature Binarization Module.
Provides modular, configurable binarization strategies for continuous feature vectors:
1. MedianBinarizer: Per-sample median thresholding (balanced 50% 1s per vector).
2. StandardizedBinarizer: Channel-wise zero-mean whitening using enrollment-only statistics
   (prevents test-set data leakage).
"""

import numpy as np

class BaseBinarizer:
    def fit(self, features):
        """Fit any parameters on the enrollment/training dataset."""
        pass

    def transform(self, feature_vector):
        """Transform a single 1D or 2D continuous feature array into binary {0, 1}."""
        raise NotImplementedError

class MedianBinarizer(BaseBinarizer):
    """
    Performs per-sample median thresholding.
    Sets bits to 1 where feature >= median(feature), ensuring equal distribution of 0s and 1s.
    """
    def transform(self, feature_vector):
        f = np.asarray(feature_vector, dtype=np.float32)
        if f.ndim == 1:
            thresh = np.median(f)
            return (f >= thresh).astype(np.uint8)
        elif f.ndim == 2:
            thresh = np.median(f, axis=1, keepdims=True)
            return (f >= thresh).astype(np.uint8)
        else:
            raise ValueError(f"Unsupported feature dimension: {f.ndim}")

class StandardizedBinarizer(BaseBinarizer):
    """
    Performs channel-wise zero-mean standardization based strictly on reference/enrollment population.
    Avoids test-sample data leakage by learning mean/std only from enrolled vectors.
    """
    def __init__(self):
        self.mean_vector = None
        self.is_fitted = False

    def fit(self, enrollment_features):
        """
        Computes the channel-wise mean across enrollment samples.
        Args:
            enrollment_features (np.ndarray): Shape (num_enrolled_samples, feature_dim).
        """
        feats = np.asarray(enrollment_features, dtype=np.float32)
        self.mean_vector = np.mean(feats, axis=0)
        self.is_fitted = True
        return self

    def transform(self, feature_vector):
        if not self.is_fitted or self.mean_vector is None:
            raise RuntimeError("StandardizedBinarizer must be fit on enrollment data before transform.")
        f = np.asarray(feature_vector, dtype=np.float32)
        return (f >= self.mean_vector).astype(np.uint8)

def get_binarizer(method="standardized", enrollment_features=None):
    """
    Factory function to get a configured binarizer.
    """
    if method == "median":
        return MedianBinarizer()
    elif method in ("standardized", "whitened"):
        binarizer = StandardizedBinarizer()
        if enrollment_features is not None:
            binarizer.fit(enrollment_features)
        return binarizer
    else:
        raise ValueError(f"Unknown binarization method: {method}")
