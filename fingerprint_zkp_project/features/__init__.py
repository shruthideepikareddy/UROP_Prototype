from .minutiae import Minutia, extract_minutiae, filter_spurious_minutiae
from .template import BiometricTemplate, build_template, iter_binary_alignments
from .binarization import MedianBinarizer, StandardizedBinarizer, get_binarizer

try:
    from .resnet_extractor import ResNet50FeatureExtractor
except ImportError:
    ResNet50FeatureExtractor = None

__all__ = [
    "Minutia",
    "extract_minutiae",
    "filter_spurious_minutiae",
    "BiometricTemplate",
    "build_template",
    "iter_binary_alignments",
    "ResNet50FeatureExtractor",
    "MedianBinarizer",
    "StandardizedBinarizer",
    "get_binarizer",
]

