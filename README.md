# JWT Tool: Advanced JWT Security Testing Suite

**Version 2.0.0 (01 August 2025)**

A comprehensive, streamlined JWT (JSON Web Token) security testing toolkit with bot## 👨‍💻 Author

**Lalit Naphade**
- Website: https://yourwebsite.com
- GitHub: https://github.com/yourusername/jwt_tool
- Twitter: @lalit_1985
- Email: lnaphade@gmail.comand GUI interfaces. This tool provides complete JWT analysis, manipulation, and vulnerability testing capabilities in a clean, efficient codebase.

## 🚀 Quick Start

### Prerequisites
- Python 3### Additional Resources

### Documentation
- [Complete User Guide](https://github.com/yourusername/jwt_tool/wiki/Using-jwt_tool)
- [JWT Attack Playbook](https://github.com/yourusername/jwt_tool/wiki)
- [Vulnerability Testing Guide](https://github.com/yourusername/jwt_tool/wiki/Testing-for-JWT-Vulnerabilities)pip package manager

### Installation
```bash
git clone https://github.com/yourusername/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt
```

### Usage Options

#### Option 1: GUI Interface (Recommended)
```bash
python3 jwt_tool_standalone.py
```
The GUI provides an intuitive interface with tabs for all JWT operations.

#### Option 2: CLI Interface (Advanced Users)
```bash
python3 jwt_tool.py [options] <JWT>
```
Full-featured command-line interface for automation and advanced users.

## 📁 Clean Project Structure

```
jwt_tool/
├── jwt_tool.py              # Full-featured CLI tool (main file)
├── jwt_tool_standalone.py   # Complete GUI + core functionality
├── jwt_security_analyzer.py # Advanced security analysis engine
├── comprehensive_jwt_security_report.html # Detailed HTML security report
├── requirements.txt         # Python dependencies
├── common-headers.txt       # Common HTTP headers for testing
├── common-payloads.txt      # Payload templates
├── jwt-common.txt          # Common JWT secrets for cracking
├── jwks-common.txt         # JWKS test data
└── README.md               # This file
```

## 🔧 Features

### GUI Mode (jwt_tool_standalone.py)
- **Decode/Inspect**: Visual JWT decoder with detailed analysis
- **Verify**: Signature verification with comprehensive results
- **Sign**: Create new JWTs with multiple algorithms
- **Tamper/Edit**: Modify existing tokens interactively
- **Crack**: Dictionary-based signature cracking with progress tracking
- **Exploits**: Generate common JWT attack vectors
- **Scan**: Comprehensive security vulnerability assessment

### CLI Mode (jwt_tool.py)
- Advanced token manipulation and automation
- High-speed dictionary attacks
- Automated vulnerability scanning
- Timestamp tampering and claim manipulation
- Key generation and JWKS handling
- Rate-limited testing for production environments

### Security Analysis Tools
- **JWT Security Analyzer** (`jwt_security_analyzer.py`): Advanced security analysis engine
- **HTML Report Generator**: Comprehensive security reports with risk assessment
- **Vulnerability Matrix**: Complete security testing framework
- **CVSS Scoring**: Industry-standard risk scoring for identified issues

## 🛡️ Security Testing Capabilities

### Supported Vulnerabilities
- **Algorithm Confusion** (RS/HS256 attacks)
- **Signature Bypass** (`alg=none` attacks)
- **Key Injection** (JWK/JKU header manipulation)
- **Blank Password** vulnerabilities
- **Null Signature** bypass attempts
- **ECDSA Vulnerabilities** (Psychic signatures)
- **Timestamp Manipulation**
- **Claims Tampering**

### Signing Algorithms
- **HMAC**: HS256, HS384, HS512
- **RSA**: RS256, RS384, RS512 (requires cryptographic libraries)
- **ECDSA**: ES256, ES384, ES512 (requires pycryptodomex for ECC/DSS)
- **RSA-PSS**: PS256, PS384, PS512 (requires cryptographic libraries)

## 💻 Usage Examples

### GUI Mode
Launch the GUI and use the intuitive tabbed interface:
```bash
python3 jwt_tool_standalone.py
```

### CLI Mode Examples
```bash
# Decode a JWT
python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Crack a JWT signature
python3 jwt_tool.py -C -d jwt-common.txt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Sign a new JWT
python3 jwt_tool.py -S hs256 -p "secret" eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Run vulnerability scan
python3 jwt_tool.py -M pb eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Advanced security analysis
python3 jwt_security_analyzer.py

# Generate comprehensive HTML security report
# Open comprehensive_jwt_security_report.html in browser
```

## 🔒 Responsible Usage

This tool is designed for:
- **Security Testing**: Authorized penetration testing
- **Development**: JWT implementation validation
- **Education**: Learning about JWT security
- **Research**: Security vulnerability analysis

**⚠️ Important**: Only use this tool on systems you own or have explicit permission to test. Unauthorized testing is illegal and unethical.

## 📚 Dependencies

### Required (GUI Mode)
- PyQt5 >= 5.15.0
- pycryptodomex >= 3.18.0 (for advanced cryptography and ES256/ES384/ES512 signatures)
- requests >= 2.28.0 (for network operations)
- certifi >= 2022.12.7 (for certificate validation)

### CLI Mode Additional
- termcolor (for colored output)
- ratelimit (for rate limiting)

## 🚀 Quick Test

Test with this sample JWT:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po
```

## 🐛 Troubleshooting

### Common Issues
1. **PyQt5 Import Error**: Install PyQt5 with `pip install PyQt5`
2. **Cryptography Issues**: Install with `pip install pycryptodomex`
3. **ES256 Support**: ECDSA algorithms (ES256/ES384/ES512) require pycryptodomex to be installed
4. **Permission Denied**: Make scripts executable with `chmod +x`

### GUI Not Starting
If the GUI doesn't launch, check:
- PyQt5 is properly installed
- Display is available (for headless systems)
- Python version compatibility

## ‍💻 Author

**Your Name**
- Website: https://yourwebsite.com
- GitHub: https://github.com/yourusername/jwt_tool
- Email: your.email@example.com

## 🙏 Acknowledgments

Special thanks to the security research community for identifying JWT vulnerabilities and the developers of supporting libraries.

---

**Remember**: Use responsibly and only on systems you're authorized to test!
# JWT Tool: Advanced JWT Security Testing Suite

![jwt_tool version](https://img.shields.io/badge/version-v2.0.0-blue) ![python version](https://img.shields.io/badge/python-v3.8+-green) ![GUI Support](https://img.shields.io/badge/GUI-enabled-brightgreen)

**Timeline Reset:**
All version and date fields reset. New timeline starts: 1 August 2025.

JWT Tool is a comprehensive security testing suite for JSON Web Tokens (JWTs), available in both GUI and CLI versions. Perfect for security professionals, penetration testers, and developers who need to analyze, test, or manipulate JWTs.

![logo](https://user-images.githubusercontent.com/19988419/100555535-18598280-3294-11eb-80ed-ca5a0c3455d6.png)

## Key Features

### GUI Mode
- 🔍 Visual JWT decoder and encoder
- 🔐 Interactive signature verification
- ✏️ Token header and payload editor
- 🛠️ Built-in vulnerability testing
- 📊 Comprehensive security scanning
- 🔨 Common exploit testing
- 🔑 Dictionary-based cracking

### CLI Mode (jwt_tool.py)
- Advanced token manipulation
- Automated vulnerability scanning
- High-speed dictionary attacks
- Timestamp tampering
- Key generation and management
- JWKS handling
- Rate-limited testing

---

## Supported Vulnerabilities

JWT Tool can detect and test for numerous vulnerabilities, including:

- 🔓 **Signature Bypass** (CVE-2015-2951): alg=none attack
- 🔄 **Algorithm Confusion** (CVE-2016-10555): RS/HS256 confusion
- 💉 **Key Injection** (CVE-2018-0114)
- 🚫 **Blank Password** (CVE-2019-20933/CVE-2020-28637)
- ⚠️ **Null Signature** (CVE-2020-28042)
- 🎭 **ECDSA Vulnerability** (CVE-2022-21449): Psychic Signature

## Installation

### Requirements
- Python 3.8 or higher
- PyQt5 for GUI version
- Required Python packages (cryptography, requests, etc.)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/jwt_tool
cd jwt_tool
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running the Tool

#### GUI Version
Launch the graphical interface:
```bash
python jwt_tool_gui.py
```

#### CLI Version
Run the command-line interface:
```bash
python jwt_tool.py [options] [JWT]
```

## Using JWT Tool

### GUI Mode

The GUI version provides an intuitive interface with multiple tabs for different operations:

#### 1. Decode/Inspect
- Paste your JWT
- Click "Decode" to see header and payload details
- View detailed token analysis

#### 2. Verify
- Input your JWT and public key/JWKS
- Verify signature validity
- Get detailed verification results

#### 3. Sign
- Create new JWTs
- Choose from multiple signing algorithms
- Customize header and payload

#### 4. Tamper/Edit
- Modify existing tokens
- Edit header and payload JSON
- Generate unsigned tokens

#### 5. Crack
- Perform dictionary attacks
- Monitor cracking progress
- View detailed results

#### 6. Exploits
- Test common vulnerabilities
- Choose from multiple exploit types
- Get modified tokens

#### 7. Scan
- Run security assessments
- Check for vulnerabilities
- View detailed scan reports

### CLI Mode

The command-line interface provides powerful options for automation and scripting:

#### Basic Usage
```bash
python jwt_tool.py <JWT>
```

#### Common Operations
1. **Decode a Token**
   ```bash
   python jwt_tool.py <JWT>
   ```

2. **Verify Signature**
   ```bash
   python jwt_tool.py <JWT> -V -pk public.pem
   ```

3. **Run Security Scan**
   ```bash
   python jwt_tool.py -t https://example.com -rc "jwt=<JWT>" -M pb
   ```

4. **Test for Vulnerabilities**
   ```bash
   python jwt_tool.py <JWT> -X a  # Test alg:none attack
   ```

5. **Tamper with Claims**
   ```bash
   python jwt_tool.py <JWT> -T -pc name -pv admin
   ```

#### Advanced Features
- Web Application Testing
- Automated Scanning
- Vulnerability Assessment
- Custom Attack Vectors

## Configuration

### GUI Settings
- Look for `config.ini` in the application directory
- Customize appearance and behavior
- Set default paths and options

### CLI Settings
- Configure `jwtconf.ini` for CLI operations
- Set JWKS location for scanning
- Configure external service interactions

### Windows Users
For proper color display in Windows terminals:
```python
# In jwt_tool.py, uncomment:
# import colorama
# colorama.init()
```

## Additional Resources

### Documentation
- [Complete User Guide](https://github.com/lalit/jwt_tool/wiki/Using-jwt_tool)
- [JWT Attack Playbook](https://github.com/lalit/jwt_tool/wiki)
- [Vulnerability Testing Guide](https://github.com/lalit/jwt_tool/wiki/Testing-for-JWT-Vulnerabilities)

### Useful Tools
- [jwt.io](https://jwt.io) - JWT debugging
- [Burp Suite](https://portswigger.net/burp) - Web security testing
- [Postman](https://www.postman.com) - API testing

### Further Reading
- [JWT Security Best Practices](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP JWT Security Guide](https://owasp.org/www-project-jwt-security-best-practices/)
- [PentesterLab JWT Exercises](https://pentesterlab.com)
