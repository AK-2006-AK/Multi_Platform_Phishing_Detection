import cv2
import os

def decode_qr_from_path(image_path: str) -> str:
    if not image_path or not os.path.exists(image_path):
        return ""
    img = cv2.imread(image_path)
    if img is None:
        return ""
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return data.strip() if data else ""