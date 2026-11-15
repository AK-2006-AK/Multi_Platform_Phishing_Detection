import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from detection_engine import analyze

assert analyze("https://github.com")["verdict"] == "Safe"
assert analyze("Urgent! Your SBI KYC is suspended. Update at http://sbi-kyc-update.net")["verdict"] == "Malicious"
print("All module tests passed successfully!")