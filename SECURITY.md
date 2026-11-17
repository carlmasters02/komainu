# Security policy

Komainu is a security tool, so bypasses are the bugs we care about most.

**Please report vulnerabilities privately** through GitHub's "Report a vulnerability" (Security tab). Don't open a public issue. Include a minimal reproduction: the untrusted content, the action that got through, and the mode/options used.

In scope: sandbox escapes via our configuration, policy bypasses that allow a critical action silently, secret leaks past redaction, audit-log forgery that verification doesn't catch.

New prompt-injection *attack cases* that Komainu already handles correctly are not vulnerabilities. Please PR them into `bench/injection/cases.json`.
