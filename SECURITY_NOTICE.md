# Security Notice

This project provides tools for analyzing, generating, and inspecting JSON Web Tokens (JWTs). Use responsibly and only against tokens and systems you are authorized to test.

## Responsible Usage
- Do not use the tooling to attack, exploit, or exfiltrate data from systems you do not own or have explicit permission to assess.
- Always obtain written authorization for any security assessment of third-party infrastructure.
- Store sensitive keys (private keys, shared secrets) securely and never commit them to source control.

## Threat Model Considerations
The analyzer highlights common JWT weaknesses:
- Missing or weak claims (exp, nbf, iat, jti, aud, iss, sub)
- Algorithm downgrade or confusion risks
- Lack of key identifiers (kid) inhibiting rotation
- Use of symmetric algorithms (HS*) where asymmetric would reduce key sharing risk
- Long-lived tokens without rotation

## Best Practices
1. Always include an expiration (exp) and keep lifetimes short.
2. Include a unique identifier (jti) to enable revocation lists.
3. Use asymmetric algorithms (RS256 / ES256 / PS256) for better key control.
4. Enforce an allowlist of acceptable alg values; reject "none" or unexpected algorithms.
5. Validate all registered claims (iss, aud, sub) according to your trust boundaries.
6. Rotate keys regularly; use `kid` headers and publish a JWKS endpoint.
7. Log token identifier (jti) and subject for audit correlation (never log full tokens in plaintext).

## Vulnerability Reporting
If you discover a vulnerability in this tool (e.g., incorrect cryptographic validation logic or a bypass), please report it privately via email: security-contact@example.com
Include:
- Description
- Steps to reproduce
- Impact assessment
- Suggested remediation (if available)

A fix will be prioritized and released; acknowledgement will be provided upon request.

## Disclaimer
This tool is provided "as is" without warranty of any kind. The authors are not responsible for misuse or damage arising from its operation.
