# Copyright (c) 2025 Your Name
# Licensed under the Educational Use License (EUL) OR Commercial License Agreement (CLA)
# See the root LICENSE (EUL) and COMMERCIAL_LICENSE files for full terms.
# If you obtained a commercial license, use constitutes acceptance of the CLA.
# Unauthorized commercial use is prohibited.

#!/usr/bin/env python3
import json
import base64
import time
from datetime import datetime

def decode_jwt(token):
    """Decode a JWT without verification."""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None
    
    # Pad the base64 strings properly
    header = parts[0]
    payload = parts[1]
    signature = parts[2]
    
    # Fix padding for base64url decoding
    def fix_padding(data):
        data += '=' * (4 - len(data) % 4) if len(data) % 4 != 0 else ''
        return data.replace('-', '+').replace('_', '/')
    
    try:
        header_json = json.loads(base64.b64decode(fix_padding(header)).decode('utf-8'))
        payload_json = json.loads(base64.b64decode(fix_padding(payload)).decode('utf-8'))
        return header_json, payload_json, signature
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None, None, None

def analyze_security(header, payload):
    """Analyze JWT header and payload for security issues."""
    issues = []
    warnings = []
    
    # Current time for expiration checks
    current_time = int(time.time())
    
    # Check algorithm
    alg = header.get('alg', '')
    if alg in ['none', 'None', 'NONE']:
        issues.append("Critical: Algorithm 'none' is used which bypasses signature verification")
    if alg == 'HS256':
        warnings.append("Warning: HS256 algorithm used - verify appropriate key length and security")
    
    # Check for missing critical security claims
    if 'exp' not in payload:
        warnings.append("Warning: No expiration claim (exp) found - token never expires")
    
    # Check for expired token
    if 'exp' in payload and payload['exp'] < current_time:
        issues.append(f"Issue: Token has expired at {datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check for token not yet valid
    if 'nbf' in payload and payload['nbf'] > current_time:
        issues.append(f"Issue: Token not yet valid until {datetime.fromtimestamp(payload['nbf']).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check for very long validity period
    if 'exp' in payload and 'iat' in payload:
        validity_period = payload['exp'] - payload['iat']
        # More than 24 hours
        if validity_period > 86400:
            days = validity_period // 86400
            warnings.append(f"Warning: Long validity period ({days} days) - consider shorter token lifetime")
    
    # Check for extremely high auth level (potential tampering)
    if 'authLevel' in payload:
        try:
            auth_level = int(payload['authLevel'])
            if auth_level > 100:  # Arbitrary threshold, adjust based on your system
                warnings.append(f"Warning: Unusually high authLevel ({auth_level}) - verify this is appropriate")
        except (ValueError, TypeError):
            pass
    
    # Check for future issuance date
    if 'iat' in payload and payload['iat'] > current_time + 300:  # Allow 5 min for clock skew
        issues.append(f"Issue: Token issued in the future ({datetime.fromtimestamp(payload['iat']).strftime('%Y-%m-%d %H:%M:%S')})")
    
    # Check for JWT ID
    if 'jti' not in payload:
        warnings.append("Warning: No JWT ID (jti) claim - consider adding for revocation capability")
    
    # Check key management claims
    if 'kid' not in header:
        warnings.append("Warning: No Key ID (kid) in header - may cause issues with key rotation")
    
    return issues, warnings

def main():
    token = "eyJhbGciOiJFUzI1NiJ9.eyJ1bmlxdWUiOiJjYWJlYWUyOS0wMzI3LTQzMjgtOTMwNC02OWUyYjVhYmU1YjQiLCJ1c2VyVHlwZSI6IlJJTHBlcnNvbiIsImF1dGhMZXZlbCI6IjIwIiwiZGV2aWNlSWQiOiIxYTMxZTg1NTIyOTVhOWNmZTRlZWIwYWI5ZWM4MTkzMzEzNTQwZmE3MWViOTEwZTFjN2IzNTcyOGYxYjU3ZTJjNTc0YjQxM2I4YjJlZTVmYWI5M2YwMTE0N2M4YWMwOGQ5ZTAzYmVhZmRkNTlmYWIyMWIzNzJiMWZjNmI4Yzc5MSIsInJlYWxtIjoibm9uLWppbyIsImlhdCI6MTc1NjQ2NTAxMn0.P0ROYdJwWA2kfDX4Vj6URWPTQgaaVCNHoiY8GmnZS25gEKImUDh1ZtXrlSvN6045p2oPpK2LPwSjwtmJ3ish-w"
    
    print(f"\n{'=' * 50}")
    print("JWT Security Analysis")
    print(f"{'=' * 50}")
    
    header, payload, signature = decode_jwt(token)
    if not header or not payload:
        print("Failed to decode JWT")
        return
    
    print("\n[+] Token Header:")
    for key, value in header.items():
        print(f"  - {key}: {value}")
    
    print("\n[+] Token Payload:")
    for key, value in payload.items():
        if key == 'iat':
            time_str = datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  - {key}: {value} ({time_str})")
        else:
            print(f"  - {key}: {value}")
    
    issues, warnings = analyze_security(header, payload)
    
    print("\n[+] Security Analysis:")
    if not issues and not warnings:
        print("  No security issues found")
    else:
        if issues:
            print("\n  [!] Security Issues:")
            for issue in issues:
                print(f"  - {issue}")
        if warnings:
            print("\n  [!] Security Warnings:")
            for warning in warnings:
                print(f"  - {warning}")
    
    print(f"\n{'=' * 50}")

if __name__ == "__main__":
    main()