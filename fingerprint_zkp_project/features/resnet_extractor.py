"""
ResNet-50 Deep Feature Extractor for Fingerprint Biometrics.
Extracts 2048-dimensional embeddings from the Global Average Pooling (GAP) layer
and binarizes them into fixed-length binary vectors for Fuzzy Commitment.
"""

import os
import cv2
import numpy as np
import torch
import torch.nn as nn
import torchvision.models as models
from torchvision.models import ResNet50_Weights
from torchvision import transforms

class ResNet50FeatureExtractor:
    def __init__(self, device=None):
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        # Load pretrained ResNet-50
        weights = ResNet50_Weights.DEFAULT
        base_model = models.resnet50(weights=weights)
        
        # Keep layers up to Global Average Pooling (avgpool), stripping the final fc (1000-class) layer
        # Output shape from avgpool is (batch, 2048, 1, 1) -> flattened to (batch, 2048)
        self.backbone = nn.Sequential(*list(base_model.children())[:-1])
        self.backbone.to(self.device)
        self.backbone.eval()

        # Standard ImageNet preprocessing transforms
        self.transform = transforms.Compose([
            transforms.ToPILImage(),
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(
                mean=[0.485, 0.456, 0.406],
                std=[0.229, 0.224, 0.225]
            )
        ])

    def preprocess_image(self, image_input):
        """
        Loads and prepares an image for ResNet-50.
        
        Args:
            image_input (str or np.ndarray): Filepath or OpenCV image array.
            
        Returns:
            torch.Tensor: Normalized tensor of shape (1, 3, 224, 224).
        """
        if isinstance(image_input, str):
            if not os.path.exists(image_input):
                raise FileNotFoundError(f"Image not found at: {image_input}")
            # Load image (handle grayscale or color)
            img = cv2.imread(image_input, cv2.IMREAD_COLOR)
            if img is None:
                raise ValueError(f"Failed to read image at: {image_input}")
            # Convert BGR to RGB
            img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        elif isinstance(image_input, np.ndarray):
            if len(image_input.shape) == 2:
                # Grayscale to 3-channel RGB
                img_rgb = cv2.cvtColor(image_input, cv2.COLOR_GRAY2RGB)
            elif len(image_input.shape) == 3 and image_input.shape[2] == 3:
                img_rgb = image_input
            else:
                raise ValueError(f"Unsupported image array shape: {image_input.shape}")
        else:
            raise TypeError("Expected image_input to be filepath (str) or numpy array")

        tensor = self.transform(img_rgb).unsqueeze(0).to(self.device)
        return tensor

    def extract_feature(self, image_input):
        """
        Extracts 2048-dimensional continuous feature vector from ResNet-50 GAP layer.
        
        Args:
            image_input (str or np.ndarray): Image path or array.
            
        Returns:
            np.ndarray: 1D float32 array of shape (2048,).
        """
        tensor = self.preprocess_image(image_input)
        with torch.no_grad():
            raw_features = self.backbone(tensor) # Shape: (1, 2048, 1, 1)
            flattened = torch.flatten(raw_features, 1) # Shape: (1, 2048)
            feature_vec = flattened.cpu().numpy().squeeze() # Shape: (2048,)
        return feature_vec

    @staticmethod
    def binarize_feature(feature_vec, method="median"):
        """
        Quantizes 2048-dimensional continuous vector into 2048-bit binary vector (0s and 1s).
        
        Args:
            feature_vec (np.ndarray): Continuous float vector of length 2048.
            method (str): 'median' (balanced 50% 1s, maximum entropy) or 'mean' or 'zero'.
            
        Returns:
            np.ndarray: Binary array of length 2048 (dtype np.uint8, values in {0, 1}).
        """
        feature_vec = np.asarray(feature_vec, dtype=np.float32)
        if method == "median":
            thresh = np.median(feature_vec)
        elif method == "mean":
            thresh = np.mean(feature_vec)
        elif method == "zero":
            thresh = 0.0
        else:
            raise ValueError(f"Unknown binarization method: {method}")

        binary_vec = (feature_vec >= thresh).astype(np.uint8)
        return binary_vec
