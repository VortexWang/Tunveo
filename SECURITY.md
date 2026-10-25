# Tunveo security policy

Tunveo is in baseline development. No stable release or completed security audit is claimed. Do not interpret the absence of published advisories as evidence of security.

Report vulnerabilities through a private security advisory in this repository if the maintainer has enabled that feature. If it is unavailable, contact the repository owner through an independently verified private channel before sending sensitive details. A dedicated Tunveo security contact has not yet been configured; upstream contact details do not represent this project. No response-time commitment is made at this stage.

Include the commit/version, platform, configuration with secrets removed, reproduction steps and observed impact. Avoid publishing credentials, private keys or unpatched exploit details in public issues.

Inherited TLS mode 0 is plaintext. Mode 1 does not verify peer certificates. Mode 2 provides certificate validation; transport-specific behavior must be checked against the actual configuration. Restrict management API exposure and protect authentication credentials.

Initial work covers provenance, branding and internalization. Dependency scanning, source auditing, concurrency testing and confirmed fixes are tracked separately. Original upstream licenses remain in effect.
