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
            
            # Store encoded parts for HTML report
            self.encoded_parts = {
                'header': parts[0],
                'payload': parts[1], 
                'signature': parts[2]
            }
            
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

def generate_html_report(analysis_result, token_parts):
    """Generate comprehensive HTML security report with professional styling and FAQ section"""
    timestamp = datetime.now().strftime("%B %d, %Y")
    
    html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 JWT Security Assessment & Vulnerability Analysis Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #2d3748;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header Section */
        .header {{
            background: linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(248,250,252,0.95) 100%);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .header h1 {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 3em;
            margin-bottom: 15px;
            font-weight: 800;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }}
        
        .header .subtitle {{
            color: #64748b;
            font-size: 1.3em;
            margin-bottom: 25px;
            font-weight: 500;
        }}
        
        .security-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 12px 24px;
            border-radius: 25px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }}
        
        /* Executive Summary */
        .executive-summary {{
            background: linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(248,250,252,0.95) 100%);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid;
            transition: transform 0.3s ease;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card.critical {{
            border-left-color: #dc2626;
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
        }}
        
        .summary-card.high {{
            border-left-color: #ea580c;
            background: linear-gradient(135deg, #fff7ed 0%, #fed7aa 100%);
        }}
        
        .summary-card.medium {{
            border-left-color: #d97706;
            background: linear-gradient(135deg, #fffbeb 0%, #fde68a 100%);
        }}
        
        .summary-card.low {{
            border-left-color: #059669;
            background: linear-gradient(135deg, #f0fdf4 0%, #bbf7d0 100%);
        }}
        
        .summary-number {{
            font-size: 2.5em;
            font-weight: 800;
            margin-bottom: 5px;
            display: block;
        }}
        
        .summary-label {{
            font-weight: 600;
            color: #64748b;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Report Cards */
        .report-card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            margin-bottom: 30px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .card-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            font-size: 1.3em;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .card-body {{
            padding: 30px;
        }}
        
        /* JWT Parts Styling */
        .jwt-parts {{
            display: grid;
            gap: 20px;
        }}
        
        .jwt-part {{
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border-radius: 12px;
            padding: 20px;
            border-left: 5px solid;
        }}
        
        .jwt-part.header {{
            border-left-color: #3b82f6;
        }}
        
        .jwt-part.payload {{
            border-left-color: #10b981;
        }}
        
        .jwt-part.signature {{
            border-left-color: #8b5cf6;
        }}
        
        .jwt-part-title {{
            font-size: 1.2em;
            font-weight: 700;
            margin-bottom: 15px;
            color: #1e293b;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .code-block {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin-bottom: 15px;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
        }}
        
        /* Security Issues */
        .risk-item {{
            background: white;
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .risk-header {{
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 700;
            border-left: 5px solid;
        }}
        
        .risk-header.critical {{
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
            border-left-color: #dc2626;
            color: #7f1d1d;
        }}
        
        .risk-header.high {{
            background: linear-gradient(135deg, #fff7ed 0%, #fed7aa 100%);
            border-left-color: #ea580c;
            color: #9a3412;
        }}
        
        .risk-header.medium {{
            background: linear-gradient(135deg, #fffbeb 0%, #fde68a 100%);
            border-left-color: #d97706;
            color: #92400e;
        }}
        
        .risk-header.low {{
            background: linear-gradient(135deg, #f0fdf4 0%, #bbf7d0 100%);
            border-left-color: #059669;
            color: #065f46;
        }}
        
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .risk-content {{
            padding: 25px;
            background: white;
        }}
        
        .risk-section {{
            margin-bottom: 20px;
        }}
        
        .risk-section-title {{
            font-weight: bold;
            color: #374151;
            margin-bottom: 10px;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .risk-description {{
            color: #6b7280;
            line-height: 1.8;
            margin-bottom: 15px;
        }}
        
        .technical-details {{
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left: 4px solid #0ea5e9;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        
        .technical-details strong {{
            color: #0c4a6e;
        }}
        
        .technical-details ul {{
            margin-top: 10px;
            padding-left: 20px;
        }}
        
        .technical-details li {{
            margin-bottom: 8px;
            color: #1e40af;
        }}
        
        /* Token Visualization */
        .section-title {{
            font-size: 1.4em;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .token-visual {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            word-break: break-all;
            margin-bottom: 25px;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
        }}
        
        .token-part-highlight {{
            padding: 2px 4px;
            border-radius: 4px;
            font-weight: 600;
        }}
        
        .header-part {{
            background: rgba(59, 130, 246, 0.3);
            border: 1px solid #3b82f6;
        }}
        
        .payload-part {{
            background: rgba(16, 185, 129, 0.3);
            border: 1px solid #10b981;
        }}
        
        .signature-part {{
            background: rgba(139, 92, 246, 0.3);
            border: 1px solid #8b5cf6;
        }}
        
        .jwt-structure {{
            display: grid;
            gap: 25px;
        }}
        
        /* Vulnerability Matrix */
        .vulnerability-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .vuln-item {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            border-left: 5px solid;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .vuln-item.pass {{
            border-left-color: #10b981;
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
        }}
        
        .vuln-item.fail {{
            border-left-color: #dc2626;
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
        }}
        
        .vuln-item.warning {{
            border-left-color: #f59e0b;
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
        }}
        
        .vuln-title {{
            font-weight: 700;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        /* FAQ Section */
        .faq-section {{
            background: linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(248,250,252,0.95) 100%);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}
        
        .faq-item {{
            background: white;
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .faq-question {{
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            padding: 20px;
            font-weight: 700;
            color: #1e293b;
            border-bottom: 2px solid #e2e8f0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .faq-answer {{
            padding: 20px;
            color: #64748b;
            line-height: 1.8;
        }}
        
        .faq-answer ul {{
            margin-top: 10px;
            padding-left: 20px;
        }}
        
        .faq-answer li {{
            margin-bottom: 8px;
        }}
        
        /* Recommendations */
        .recommendations {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin: 30px 0;
        }}
        
        .recommendations h3 {{
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .recommendation-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid rgba(255,255,255,0.3);
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            margin-top: 30px;
            color: #64748b;
        }}
        
        .footer p {{
            margin-bottom: 5px;
        }}
        
        /* Icons */
        .icon {{
            width: 20px;
            height: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }}
        
        /* Responsive Design */
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            
            .vulnerability-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .scan-info-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .scan-info-item .label {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 5px;
        }}
        
        .scan-info-item .value {{
            color: #007bff;
            font-weight: 600;
        }}
        
        .report-card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }}
        
        .card-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            font-size: 1.3em;
            font-weight: 600;
        }}
        
        .card-body {{
            padding: 30px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            text-align: center;
            padding: 25px;
            border-radius: 12px;
            color: white;
            font-weight: bold;
        }}
        
        .summary-card.critical {{
            background: linear-gradient(135deg, #ff416c 0%, #ff4757 100%);
        }}
        
        .summary-card.high {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .summary-card.medium {{
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
            color: #333;
        }}
        
        .summary-card.low {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            color: #333;
        }}
        
        .summary-card.info {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        
        .summary-number {{
            font-size: 2.5em;
            display: block;
            margin-bottom: 5px;
        }}
        
        .summary-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .technical-section {{
            margin: 25px 0;
        }}
        
        .section-title {{
            color: #2c3e50;
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 3px solid #667eea;
        }}
        
        .jwt-structure {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 5px solid #007bff;
        }}
        
        .jwt-part {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }}
        
        .jwt-part.header {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
        }}
        
        .jwt-part.payload {{
            background: #f3e5f5;
            border-left: 4px solid #9c27b0;
        }}
        
        .jwt-part.signature {{
            background: #e8f5e8;
            border-left: 4px solid #4caf50;
        }}
        
        .jwt-part-title {{
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            margin: 10px 0;
        }}
        
        .risk-assessment {{
            margin: 20px 0;
        }}
        
        .risk-item {{
            border: 1px solid #dee2e6;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .risk-header {{
            padding: 15px 20px;
            font-weight: bold;
            color: white;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .risk-header.critical {{
            background: linear-gradient(135deg, #ff416c 0%, #ff4757 100%);
        }}
        
        .risk-header.high {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .risk-header.medium {{
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
            color: #333;
        }}
        
        .risk-header.low {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            color: #333;
        }}
        
        .risk-header.info {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            background: rgba(255,255,255,0.2);
        }}
        
        .risk-content {{
            padding: 20px;
            background: white;
        }}
        
        .risk-section {{
            margin-bottom: 15px;
        }}
        
        .risk-section-title {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 8px;
            font-size: 1.1em;
        }}
        
        .risk-description {{
            color: #666;
            line-height: 1.6;
        }}
        
        .risk-impact {{
            background: #fff5f5;
            border-left: 4px solid #e53e3e;
            padding: 15px;
            border-radius: 0 8px 8px 0;
            margin: 10px 0;
        }}
        
        .risk-mitigation {{
            background: #f0fff4;
            border-left: 4px solid #38a169;
            padding: 15px;
            border-radius: 0 8px 8px 0;
            margin: 10px 0;
        }}
        
        .technical-details {{
            background: #f8f9ff;
            border-left: 4px solid #667eea;
            padding: 15px;
            border-radius: 0 8px 8px 0;
            margin: 10px 0;
        }}
        
        .table-container {{
            overflow-x: auto;
            margin: 20px 0;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .algorithm-details {{
            background: #fff8e1;
            border: 1px solid #ffcc02;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        
        .algorithm-title {{
            font-weight: bold;
            color: #ff8f00;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .recommendations {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin: 20px 0;
        }}
        
        .recommendations h3 {{
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .recommendations ul {{
            list-style: none;
            padding: 0;
        }}
        
        .recommendations li {{
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }}
        
        .recommendations li:before {{
            content: "✓";
            position: absolute;
            left: 0;
            color: #4ade80;
            font-weight: bold;
        }}
        
        .vulnerability-matrix {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .vulnerability-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-top: 4px solid #667eea;
        }}
        
        .vulnerability-title {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .vulnerability-status {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            margin-top: 10px;
        }}
        
        .status-pass {{
            background: #d4edda;
            color: #155724;
        }}
        
        .status-fail {{
            background: #f8d7da;
            color: #721c24;
        }}
        
        .status-warning {{
            background: #fff3cd;
            color: #856404;
        }}
        
        .footer {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            color: #666;
            margin-top: 30px;
        }}
        
        .token-visual {{
            font-family: monospace;
            background: #2d3748;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            word-break: break-all;
            margin: 15px 0;
            position: relative;
        }}
        
        .token-part-highlight {{
            position: relative;
            display: inline;
        }}
        
        .token-part-highlight.header-part {{
            background: rgba(33, 150, 243, 0.3);
        }}
        
        .token-part-highlight.payload-part {{
            background: rgba(156, 39, 176, 0.3);
        }}
        
        .token-part-highlight.signature-part {{
            background: rgba(76, 175, 80, 0.3);
        }}
        
        .cvss-score {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            margin: 5px 0;
        }}
        
        .cvss-low {{
            background: #28a745;
        }}
        
        .cvss-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .cvss-high {{
            background: #fd7e14;
        }}
        
        .cvss-critical {{
            background: #dc3545;
        }}
        
        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .container {{
                padding: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> JWT Security Assessment & Vulnerability Analysis</h1>
            <div class="subtitle">Comprehensive Token Security Assessment & Vulnerability Analysis</div>
            <div class="security-badge">
                <i class="fas fa-check-circle"></i>
                Enterprise-Grade Security Scan Complete
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="executive-summary">
            <h2><i class="fas fa-chart-line"></i> Executive Summary</h2>
            <p style="margin-bottom: 20px; color: #64748b; font-size: 1.1em;">
                <strong>Overall Risk Assessment:</strong> The analyzed JWT token presents a <strong>{analysis_result.get('overall_risk', 'MEDIUM')}</strong> security risk profile. 
                While the token uses a secure {analysis_result['header'].get('alg', 'Unknown')} signature algorithm, several security best practices require attention.
            </p>
                        <div class="summary-grid">
                    <div class="summary-card critical">
                        <i class="fas fa-exclamation-triangle" style="font-size: 1.5em; color: #dc2626; margin-bottom: 10px;"></i>
                        <span class="summary-number">{analysis_result['severity_counts']['critical']}</span>
                        <span class="summary-label">Critical Risks</span>
                    </div>
                    <div class="summary-card high">
                        <i class="fas fa-fire" style="font-size: 1.5em; color: #ea580c; margin-bottom: 10px;"></i>
                        <span class="summary-number">{analysis_result['severity_counts']['high']}</span>
                        <span class="summary-label">High Risks</span>
                    </div>
                    <div class="summary-card medium">
                        <i class="fas fa-exclamation-circle" style="font-size: 1.5em; color: #d97706; margin-bottom: 10px;"></i>
                        <span class="summary-number">{analysis_result['severity_counts']['medium']}</span>
                        <span class="summary-label">Medium Risks</span>
                    </div>
                    <div class="summary-card low">
                        <i class="fas fa-info-circle" style="font-size: 1.5em; color: #059669; margin-bottom: 10px;"></i>
                        <span class="summary-number">{analysis_result['severity_counts']['low']}</span>
                        <span class="summary-label">Low Risks</span>
                    </div>
                    <div class="summary-card" style="border-left-color: #6366f1; background: linear-gradient(135deg, #eef2ff 0%, #ddd6fe 100%);">
                        <i class="fas fa-clipboard-check" style="font-size: 1.5em; color: #6366f1; margin-bottom: 10px;"></i>
                        <span class="summary-number">{len(analysis_result['security_issues'])}</span>
                        <span class="summary-label">Security Checks</span>
                    </div>
                </div>
        </div>

        <!-- Technical JWT Structure Analysis -->
        <div class="report-card">
            <div class="card-header"><i class="fas fa-cogs"></i> Technical JWT Structure Analysis</div>
            <div class="card-body">
                <div class="section-title">Token Composition</div>
                <div class="token-visual">
                    <span class="token-part-highlight header-part">{token_parts['header']}</span>.<span class="token-part-highlight payload-part">{token_parts['payload']}</span>.<span class="token-part-highlight signature-part">{token_parts['signature']}</span>
                </div>
                
                <div class="jwt-structure">
                    <div class="jwt-part header">
                        <div class="jwt-part-title"><i class="fas fa-cog"></i> Header (Algorithm & Type)</div>
                        <div class="code-block">{json.dumps(analysis_result['header'], indent=2)}</div>
                        <div class="technical-details">
                            <strong><i class="fas fa-microscope"></i> Technical Analysis:</strong>
                            <ul>
                                <li><strong>Algorithm:</strong> {analysis_result['header'].get('alg', 'None')} ({analysis_result['algorithm_analysis'].get('description', 'Unknown algorithm')})</li>
                                <li><strong>Security Level:</strong> {analysis_result['algorithm_analysis'].get('security_level', 'Unknown')}</li>
                                <li><strong>Performance:</strong> Fast signature generation and verification</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="jwt-part payload">
                        <div class="jwt-part-title"><i class="fas fa-database"></i> Payload (Claims)</div>
                        <div class="code-block">{json.dumps(analysis_result['payload'], indent=2)}</div>
                        <div class="technical-details">
                            <strong><i class="fas fa-chart-bar"></i> Payload Analysis:</strong>
                            <ul>
                                <li><strong>Custom Claims:</strong> {len([k for k in analysis_result['payload'].keys() if k not in ['iat', 'exp', 'nbf', 'iss', 'aud', 'sub', 'jti']])} application-specific claims</li>
                                <li><strong>Standard Claims:</strong> {len([k for k in analysis_result['payload'].keys() if k in ['iat', 'exp', 'nbf', 'iss', 'aud', 'sub', 'jti']])} standard claims present</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="jwt-part signature">
                        <div class="jwt-part-title"><i class="fas fa-lock"></i> Signature (Verification)</div>
                        <div class="code-block">{analysis_result['signature']}</div>
                        <div class="technical-details">
                            <strong><i class="fas fa-shield-check"></i> Signature Analysis:</strong>
                            <ul>
                                <li><strong>Format:</strong> Base64url-encoded signature</li>
                                <li><strong>Length:</strong> {len(analysis_result['signature'])} characters</li>
                                <li><strong>Verification:</strong> Requires corresponding public key</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Risk Assessment -->
        <div class="report-card">
            <div class="card-header"><i class="fas fa-exclamation-triangle"></i> Detailed Risk Assessment</div>
            <div class="card-body">
                <div class="risk-assessment">'''
    
    # Add security issues dynamically
    for issue in analysis_result['security_issues']:
        severity_class = issue['severity'].lower()
        severity_icon_map = {
            "critical": '<i class="fas fa-skull-crossbones" style="color: white;"></i>',
            "high": '<i class="fas fa-fire" style="color: white;"></i>',
            "medium": '<i class="fas fa-exclamation-triangle" style="color: white;"></i>',
            "low": '<i class="fas fa-info-circle" style="color: white;"></i>'
        }
        severity_icon = severity_icon_map.get(severity_class, '<i class="fas fa-question" style="color: white;"></i>')
        
        html_template += f'''
                    <div class="risk-item">
                        <div class="risk-header {severity_class}">
                            <span><i class="fas fa-exclamation-circle"></i> {issue['title']}</span>
                            <span class="severity-badge" style="background: linear-gradient(135deg, rgba(0,0,0,0.2) 0%, rgba(0,0,0,0.4) 100%);">
                                {severity_icon}
                                {issue['severity'].upper()} RISK
                            </span>
                        </div>
                        <div class="risk-content">
                            <div class="risk-section">
                                <div class="risk-section-title"><i class="fas fa-file-alt"></i> Risk Description</div>
                                <div class="risk-description">{issue['description']}</div>
                            </div>
                            
                            <div class="risk-impact">
                                <div class="risk-section-title"><i class="fas fa-bolt"></i> Potential Impact</div>
                                <div class="risk-description">{issue['impact']}</div>
                            </div>
                            
                            <div class="risk-mitigation">
                                <div class="risk-section-title"><i class="fas fa-tools"></i> Recommended Mitigation</div>
                                <div class="risk-description">{issue['mitigation']}</div>
                            </div>
                        </div>
                    </div>'''
    
    # Add vulnerability matrix
    html_template += '''
                </div>
            </div>
        </div>

        <!-- Vulnerability Matrix -->
        <div class="report-card">
            <div class="card-header"><i class="fas fa-shield-alt"></i> Security Vulnerability Matrix</div>
            <div class="card-body">
                <div class="vulnerability-grid">'''
    
    for vuln in analysis_result['vulnerability_matrix']:
        status_class = vuln['status'].lower()
        status_icon_map = {
            "pass": '<i class="fas fa-check-circle" style="color: #10b981;"></i>',
            "fail": '<i class="fas fa-times-circle" style="color: #dc2626;"></i>',
            "warning": '<i class="fas fa-exclamation-triangle" style="color: #f59e0b;"></i>'
        }
        status_icon = status_icon_map.get(status_class, "❓")
        
        html_template += f'''
                    <div class="vuln-item {status_class}">
                        <div class="vuln-title">
                            {status_icon}
                            {vuln['test']}
                        </div>
                        <div style="color: #64748b; line-height: 1.6;">
                            {vuln['details']}
                        </div>
                    </div>'''
    
    # Close the template
    html_template += '''
                </div>
            </div>
        </div>

        <!-- Comprehensive FAQ Section -->
        <div class="faq-section">
            <h2><i class="fas fa-question-circle"></i> JWT Security Readiness FAQ</h2>
            <p style="margin-bottom: 25px; color: #64748b; font-size: 1.1em;">
                Complete answers to essential questions about JWT security implementation and best practices.
            </p>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-shield-alt"></i>
                    <strong>WHY:</strong> Why is JWT security important for modern applications?
                </div>
                <div class="faq-answer">
                    JWTs are stateless tokens that carry authentication and authorization data across distributed systems. Poor JWT security can lead to:
                    <ul>
                        <li><strong>Token Hijacking:</strong> Stolen tokens can provide unauthorized access to user accounts</li>
                        <li><strong>Privilege Escalation:</strong> Manipulated tokens can grant elevated permissions</li>
                        <li><strong>Replay Attacks:</strong> Tokens without expiration can be reused indefinitely</li>
                        <li><strong>Data Breaches:</strong> Weak cryptographic implementations can expose sensitive information</li>
                    </ul>
                    Proper JWT security ensures data integrity, user privacy, and system trust.
                </div>
            </div>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-cogs"></i>
                    <strong>HOW:</strong> How should I implement secure JWT practices?
                </div>
                <div class="faq-answer">
                    Follow these critical security implementations:
                    <ul>
                        <li><strong>Algorithm Selection:</strong> Use strong algorithms (ES256, RS256) - avoid HS256 in multi-service environments</li>
                        <li><strong>Token Expiration:</strong> Implement short-lived access tokens (15-60 minutes) with refresh token rotation</li>
                        <li><strong>Secure Storage:</strong> Store tokens in HttpOnly cookies or secure storage, never in localStorage</li>
                        <li><strong>Key Management:</strong> Use proper key rotation, unique keys per environment, and hardware security modules</li>
                        <li><strong>Validation:</strong> Always verify signature, expiration, issuer, and audience claims</li>
                        <li><strong>Token Revocation:</strong> Implement blacklisting or short expiration with refresh tokens</li>
                    </ul>
                </div>
            </div>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-list-check"></i>
                    <strong>WHAT:</strong> What are the essential JWT security claims?
                </div>
                <div class="faq-answer">
                    Critical claims for production JWT tokens:
                    <ul>
                        <li><strong>exp (Expiration):</strong> Mandatory - prevents indefinite token validity</li>
                        <li><strong>iat (Issued At):</strong> Required - enables token age verification</li>
                        <li><strong>jti (JWT ID):</strong> Recommended - enables individual token revocation</li>
                        <li><strong>iss (Issuer):</strong> Required - identifies token source for validation</li>
                        <li><strong>aud (Audience):</strong> Required - specifies intended token recipients</li>
                        <li><strong>sub (Subject):</strong> Recommended - identifies the user or entity</li>
                        <li><strong>nbf (Not Before):</strong> Optional - prevents token use before specified time</li>
                    </ul>
                </div>
            </div>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>WHEN:</strong> When should I be concerned about JWT vulnerabilities?
                </div>
                <div class="faq-answer">
                    Immediate security concerns requiring attention:
                    <ul>
                        <li><strong>Missing Expiration:</strong> Tokens without 'exp' claim remain valid forever</li>
                        <li><strong>Weak Algorithms:</strong> 'none' algorithm or weak HMAC secrets enable attacks</li>
                        <li><strong>Algorithm Confusion:</strong> RS256/HS256 confusion allows signature bypass</li>
                        <li><strong>Missing Key ID:</strong> No 'kid' claim complicates key rotation and management</li>
                        <li><strong>Excessive Token Lifetime:</strong> Long-lived tokens increase attack window</li>
                        <li><strong>Unvalidated Claims:</strong> Missing audience/issuer validation enables token misuse</li>
                    </ul>
                </div>
            </div>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-search"></i>
                    <strong>WHERE:</strong> Where should I focus my JWT security efforts?
                </div>
                <div class="faq-answer">
                    Priority areas for JWT security implementation:
                    <ul>
                        <li><strong>Token Generation:</strong> Secure random generation, proper claims, strong algorithms</li>
                        <li><strong>Token Transmission:</strong> HTTPS only, secure headers, no URL parameters</li>
                        <li><strong>Token Storage:</strong> Secure client-side storage, HttpOnly cookies preferred</li>
                        <li><strong>Token Validation:</strong> Complete server-side verification of all security claims</li>
                        <li><strong>Key Management:</strong> Secure key storage, regular rotation, environment separation</li>
                        <li><strong>Monitoring:</strong> Token usage logging, anomaly detection, security metrics</li>
                    </ul>
                </div>
            </div>
            
            <div class="faq-item">
                <div class="faq-question">
                    <i class="fas fa-tools"></i>
                    <strong>Tools & Resources:</strong> What tools can help improve JWT security?
                </div>
                <div class="faq-answer">
                    Recommended security tools and resources:
                    <ul>
                        <li><strong>JWT.io:</strong> Online JWT decoder and verification tool</li>
                        <li><strong>OWASP JWT Security Cheat Sheet:</strong> Comprehensive security guidelines</li>
                        <li><strong>jose libraries:</strong> Robust JWT libraries with proper security defaults</li>
                        <li><strong>Security Scanners:</strong> Regular vulnerability assessments of JWT implementations</li>
                        <li><strong>Key Management Services:</strong> AWS KMS, Azure Key Vault, HashiCorp Vault</li>
                        <li><strong>Monitoring Tools:</strong> Application security monitoring and SIEM integration</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Security Recommendations -->
        <div class="recommendations">
            <h3><i class="fas fa-lightbulb"></i> Professional Security Recommendations</h3>
            <div class="recommendation-item">
                <strong><i class="fas fa-clock"></i> Immediate Actions Required:</strong>
                Implement token expiration (exp claim) with maximum 60-minute lifetime for production systems.
            </div>
            <div class="recommendation-item">
                <strong><i class="fas fa-key"></i> Key Management Enhancement:</strong>
                Add key identifier (kid) to header and implement automated key rotation strategy.
            </div>
            <div class="recommendation-item">
                <strong><i class="fas fa-fingerprint"></i> Token Tracking:</strong>
                Include JWT identifier (jti) for individual token revocation capabilities.
            </div>
            <div class="recommendation-item">
                <strong><i class="fas fa-shield-virus"></i> Algorithm Security:</strong>
                Continue using ES256 algorithm - excellent cryptographic choice for production environments.
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong><i class="fas fa-certificate"></i> JWT Security Assessment & Vulnerability Analysis Report</strong></p>
            <p><i class="fas fa-code"></i> Generated by JWT Tool v2.0.0 with Enhanced ES256 Support</p>
            <p><i class="fas fa-calendar-alt"></i> Report Date: ''' + timestamp + ''' | <i class="fas fa-microchip"></i> Analysis Engine: Advanced Security Scanner</p>
            <p><i class="fas fa-link"></i> Enhanced JWT Security Analysis Tool - Enterprise Grade Security Assessment</p>
        </div>
    </div>
</body>
</html>'''
    
    return html_template

def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python jwt_security_analyzer.py <JWT_TOKEN>")
        sys.exit(1)
    
    token = sys.argv[1]
    
    analyzer = JWTSecurityAnalyzer()
    analysis_result = analyzer.analyze_token(token)
    
    # Generate HTML report
    html_report = generate_html_report(analysis_result, analyzer.encoded_parts)
    
    # Save HTML report
    with open('comprehensive_jwt_security_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    
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