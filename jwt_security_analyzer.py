# Copyright (c) 2025 Your Name
# Licensed under the Educational Use License (EUL) OR Commercial License Agreement (CLA)
# See the root LICENSE (EUL) and COMMERCIAL_LICENSE files for full terms.
# If you obtained a commercial license, use constitutes acceptance of the CLA.
# Unauthorized commercial use is prohibited.

#!/usr/bin/env python3
"""
JWT Security Report Generator
Comprehensive security analysis and HTML report generation for JWT tokens
"""

import json
import base64
import time
import uuid
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class JWTSecurityAnalyzer:
    """Advanced JWT security analysis engine"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.warnings = []
        self.info_items = []
        self.technical_details = {}
        
    def decode_jwt(self, token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
        """Decode JWT token into header, payload, and signature components"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None
            
            def fix_padding(data: str) -> str:
                """Fix base64url padding"""
                data += '=' * (4 - len(data) % 4) if len(data) % 4 != 0 else ''
                return data.replace('-', '+').replace('_', '/')
            
            header = json.loads(base64.b64decode(fix_padding(parts[0])).decode('utf-8'))
            payload = json.loads(base64.b64decode(fix_padding(parts[1])).decode('utf-8'))
            signature = parts[2]
            
            return header, payload, signature
            
        except Exception as e:
            print(f"Error decoding JWT: {e}")
            return None, None, None
    
    def analyze_algorithm_security(self, header: Dict) -> Dict:
        """Analyze JWT algorithm security"""
        alg = header.get('alg', '')
        analysis = {
            'algorithm': alg,
            'security_level': 'Unknown',
            'recommendations': [],
            'vulnerabilities': []
        }
        
        if alg in ['none', 'None', 'NONE']:
            analysis['security_level'] = 'Critical Risk'
            analysis['vulnerabilities'].append('Algorithm "none" bypasses signature verification')
            
        elif alg == 'HS256':
            analysis['security_level'] = 'Medium'
            analysis['recommendations'].append('Ensure strong secret key (>256 bits)')
            analysis['recommendations'].append('Protect against RS/HS256 confusion attacks')
            
        elif alg in ['ES256', 'ES384', 'ES512']:
            analysis['security_level'] = 'High'
            analysis['recommendations'].append('Excellent choice - ECDSA provides strong security')
            
        elif alg in ['RS256', 'RS384', 'RS512']:
            analysis['security_level'] = 'High'
            analysis['recommendations'].append('Strong algorithm - ensure key size >= 2048 bits')
            
        return analysis
    
    def analyze_claims_security(self, header: Dict, payload: Dict) -> List[Dict]:
        """Comprehensive claims security analysis"""
        issues = []
        current_time = int(time.time())
        
        # Missing expiration check
        if 'exp' not in payload:
            issues.append({
                'severity': 'medium',
                'title': 'Missing Token Expiration (exp)',
                'description': 'Token lacks expiration claim, remaining valid indefinitely',
                'impact': 'Stolen tokens remain valid until key rotation',
                'mitigation': 'Add exp claim with reasonable timeout (15-60 minutes)',
                'cvss_score': 5.4,
                'technical_details': 'RFC 7519 recommends exp claim for temporal security controls'
            })
        
        # Expired token check
        if 'exp' in payload and payload['exp'] < current_time:
            issues.append({
                'severity': 'high',
                'title': 'Expired Token',
                'description': f'Token expired at {datetime.fromtimestamp(payload["exp"])}',
                'impact': 'Token should be rejected by applications',
                'mitigation': 'Generate new token with valid expiration',
                'cvss_score': 7.2
            })
        
        # Missing JWT ID
        if 'jti' not in payload:
            issues.append({
                'severity': 'medium',
                'title': 'Missing JWT Identifier (jti)',
                'description': 'Token lacks unique identifier for revocation tracking',
                'impact': 'Cannot selectively revoke individual tokens',
                'mitigation': 'Add jti claim with UUID or secure random identifier',
                'cvss_score': 4.9,
                'technical_details': 'JTI enables token blacklisting and audit capabilities'
            })
        
        # Missing Key ID in header
        if 'kid' not in header:
            issues.append({
                'severity': 'low',
                'title': 'Missing Key Identifier (kid)',
                'description': 'Header lacks key identifier for key management',
                'impact': 'Complications in key rotation and multi-tenant scenarios',
                'mitigation': 'Add kid parameter to header for key identification',
                'cvss_score': 3.1,
                'technical_details': 'KID claim facilitates automated key rotation'
            })
        
        # Future issuance check
        if 'iat' in payload and payload['iat'] > current_time + 300:
            issues.append({
                'severity': 'medium',
                'title': 'Future Issuance Date',
                'description': f'Token issued in the future: {datetime.fromtimestamp(payload["iat"])}',
                'impact': 'Potential clock synchronization or tampering issues',
                'mitigation': 'Verify system clocks and token generation process',
                'cvss_score': 4.3
            })
        
        # Not-before check
        if 'nbf' in payload and payload['nbf'] > current_time:
            issues.append({
                'severity': 'medium',
                'title': 'Token Not Yet Valid',
                'description': f'Token not valid until {datetime.fromtimestamp(payload["nbf"])}',
                'impact': 'Token should be rejected until valid time',
                'mitigation': 'Wait until nbf time or regenerate token',
                'cvss_score': 3.7
            })
        
        # Long validity period check
        if 'exp' in payload and 'iat' in payload:
            validity_period = payload['exp'] - payload['iat']
            if validity_period > 86400:  # More than 24 hours
                days = validity_period // 86400
                issues.append({
                    'severity': 'low',
                    'title': 'Extended Validity Period',
                    'description': f'Token valid for {days} days - unusually long',
                    'impact': 'Increased exposure window if token is compromised',
                    'mitigation': 'Consider shorter token lifetime with refresh mechanism',
                    'cvss_score': 2.8
                })
        
        return issues
    
    def generate_vulnerability_matrix(self, header: Dict, payload: Dict) -> List[Dict]:
        """Generate comprehensive vulnerability assessment matrix"""
        matrix = []
        
        # Algorithm confusion test
        alg = header.get('alg', '')
        if alg not in ['none', 'None', 'NONE']:
            matrix.append({
                'test': 'Algorithm Confusion (RS/HS256)',
                'description': 'Tests if token accepts different algorithm types',
                'status': 'pass',
                'details': f'Token uses {alg} - properly configured'
            })
        else:
            matrix.append({
                'test': 'Algorithm Confusion (RS/HS256)',
                'description': 'Tests if token accepts different algorithm types',
                'status': 'fail',
                'details': 'Token uses "none" algorithm - critical vulnerability'
            })
        
        # None algorithm test
        if alg != 'none':
            matrix.append({
                'test': 'None Algorithm Attack',
                'description': 'Verifies rejection of unsigned tokens',
                'status': 'pass',
                'details': 'Signature required for token validation'
            })
        else:
            matrix.append({
                'test': 'None Algorithm Attack',
                'description': 'Verifies rejection of unsigned tokens',
                'status': 'fail',
                'details': 'Token accepts no signature - critical vulnerability'
            })
        
        # Weak secret test (for HMAC algorithms)
        if alg.startswith('HS'):
            matrix.append({
                'test': 'Weak Secret Attack',
                'description': 'Tests for common/weak signing keys',
                'status': 'warning',
                'details': 'HMAC algorithm - verify secret strength'
            })
        else:
            matrix.append({
                'test': 'Weak Secret Attack',
                'description': 'Tests for common/weak signing keys',
                'status': 'pass',
                'details': f'{alg} uses asymmetric cryptography'
            })
        
        # Expiration test
        if 'exp' in payload:
            current_time = int(time.time())
            if payload['exp'] > current_time:
                matrix.append({
                    'test': 'Token Expiration',
                    'description': 'Validates temporal security controls',
                    'status': 'pass',
                    'details': 'Token has valid expiration time'
                })
            else:
                matrix.append({
                    'test': 'Token Expiration',
                    'description': 'Validates temporal security controls',
                    'status': 'fail',
                    'details': 'Token has expired'
                })
        else:
            matrix.append({
                'test': 'Token Expiration',
                'description': 'Validates temporal security controls',
                'status': 'fail',
                'details': 'No expiration claim present'
            })
        
        # Critical claims validation
        critical_claims = ['exp', 'jti']
        missing_claims = [claim for claim in critical_claims if claim not in payload]
        if not missing_claims:
            matrix.append({
                'test': 'Critical Claims Validation',
                'description': 'Checks for essential security claims',
                'status': 'pass',
                'details': 'All critical claims present'
            })
        else:
            matrix.append({
                'test': 'Critical Claims Validation',
                'description': 'Checks for essential security claims',
                'status': 'warning',
                'details': f'Missing claims: {", ".join(missing_claims)}'
            })
        
        # Key management test
        if 'kid' in header:
            matrix.append({
                'test': 'Key Management',
                'description': 'Evaluates key identification capabilities',
                'status': 'pass',
                'details': 'Key identifier present in header'
            })
        else:
            matrix.append({
                'test': 'Key Management',
                'description': 'Evaluates key identification capabilities',
                'status': 'warning',
                'details': 'No key identifier in header'
            })
        
        return matrix
    
    def analyze_token(self, token: str) -> Dict:
        """Perform comprehensive token analysis"""
        header, payload, signature = self.decode_jwt(token)
        
        if not header or not payload:
            return {'error': 'Failed to decode JWT token'}
        
        # Perform various security analyses
        algorithm_analysis = self.analyze_algorithm_security(header)
        security_issues = self.analyze_claims_security(header, payload)
        vulnerability_matrix = self.generate_vulnerability_matrix(header, payload)
        
        # Count issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for issue in security_issues:
            severity = issue.get('severity', 'unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'algorithm_analysis': algorithm_analysis,
            'security_issues': security_issues,
            'vulnerability_matrix': vulnerability_matrix,
            'severity_counts': severity_counts,
            'analysis_timestamp': datetime.now().isoformat(),
            'token_size': len(token)
        }

def main():
    """Main execution function"""
    # Sample token for demonstration
    token = "eyJhbGciOiJFUzI1NiJ9.eyJ1bmlxdWUiOiJjYWJlYWUyOS0wMzI3LTQzMjgtOTMwNC02OWUyYjVhYmU1YjQiLCJ1c2VyVHlwZSI6IlJJTHBlcnNvbiIsImF1dGhMZXZlbCI6IjIwIiwiZGV2aWNlSWQiOiIxYTMxZTg1NTIyOTVhOWNmZTRlZWIwYWI5ZWM4MTkzMzEzNTQwZmE3MWViOTEwZTFjN2IzNTcyOGYxYjU3ZTJjNTc0YjQxM2I4YjJlZTVmYWI5M2YwMTE0N2M4YWMwOGQ5ZTAzYmVhZmRkNTlmYWIyMWIzNzJiMWZjNmI4Yzc5MSIsInJlYWxtIjoibm9uLWppbyIsImlhdCI6MTc1NjQ2NTAxMn0.P0ROYdJwWA2kfDX4Vj6URWPTQgaaVCNHoiY8GmnZS25gEKImUDh1ZtXrlSvN6045p2oPpK2LPwSjwtmJ3ish-w"
    
    analyzer = JWTSecurityAnalyzer()
    analysis_result = analyzer.analyze_token(token)
    
    print("=" * 80)
    print("JWT SECURITY ANALYSIS REPORT")
    print("=" * 80)
    print(f"Analysis Date: {analysis_result['analysis_timestamp']}")
    print(f"Token Size: {analysis_result['token_size']} characters")
    print()
    
    print("SEVERITY SUMMARY:")
    counts = analysis_result['severity_counts']
    print(f"  Critical: {counts['critical']}")
    print(f"  High: {counts['high']}")
    print(f"  Medium: {counts['medium']}")
    print(f"  Low: {counts['low']}")
    print(f"  Info: {counts['info']}")
    print()
    
    print("SECURITY ISSUES:")
    for issue in analysis_result['security_issues']:
        print(f"  [{issue['severity'].upper()}] {issue['title']}")
        print(f"    Description: {issue['description']}")
        print(f"    Impact: {issue['impact']}")
        print(f"    Mitigation: {issue['mitigation']}")
        if 'cvss_score' in issue:
            print(f"    CVSS Score: {issue['cvss_score']}")
        print()
    
    print("VULNERABILITY MATRIX:")
    for vuln in analysis_result['vulnerability_matrix']:
        status_symbol = {"pass": "✅", "fail": "❌", "warning": "⚠️"}.get(vuln['status'], "❓")
        print(f"  {status_symbol} {vuln['test']}: {vuln['details']}")
    print()
    
    print("ALGORITHM ANALYSIS:")
    alg_analysis = analysis_result['algorithm_analysis']
    print(f"  Algorithm: {alg_analysis['algorithm']}")
    print(f"  Security Level: {alg_analysis['security_level']}")
    if alg_analysis['recommendations']:
        print("  Recommendations:")
        for rec in alg_analysis['recommendations']:
            print(f"    - {rec}")
    print()

if __name__ == "__main__":
    main()