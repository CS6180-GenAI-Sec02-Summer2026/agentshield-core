"""Shared security pattern constants used across policy and risk checks."""

DEFAULT_INTERNAL_EMAIL_DOMAINS = (
    "@agentshield.example",
    "@company.example",
    "@internal.example",
)

STATE_CHANGING_HTTP_METHODS = (
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
)

BROADCAST_RECIPIENT_PATTERNS = (
    "all-",
    "all@",
    "all_",
    "everyone",
    "mailing-list",
)

INTERNAL_TARGET_INDICATORS = (
    "localhost",
    "127.0.0.1",
    "internal.",
    ".agentshield.example",
    ".company.example",
    ".corp.",
)

SECRET_PATTERNS = (
    "api_key",
    "api-key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "auth_token",
    "private_key",
    "credential",
    "aws_secret",
    "openai_api_key",
    "database_url",
    "connection_string",
    "bearer",
    "authorization",
    "license",
    "license_key",
)

INJECTION_PATTERNS = (
    "ignore previous instructions",
    "ignore your previous instructions",
    "ignore above instructions",
    "ignore all instructions",
    "disregard your instructions",
    "override your instructions",
    "forget your rules",
    "new instructions:",
    "system prompt:",
    "you are now",
    "instead, do the following",
    "do not follow your original",
    "ignore all prior",
    "ignore all previous instructions",
    "instruction to assistant",
    "assistant instruction",
    "assistant directive",
    "assistant:",
    "system note for assistant",
    "important assistant directive",
    "tool_response",
    "assistant_directive",
    "bypass security",
    "act as if",
    "pretend you are",
)

SENSITIVE_CONTENT_PATTERNS = (
    "revenue",
    "salary",
    "password",
    "ssn",
    "credit card",
    "confidential",
    "secret",
    "internal only",
    "proprietary",
    "social security",
    "bank account",
    "tax id",
    "compensation",
    "customer",
    "roadmap",
    "database credential",
    "api key",
    "api_key",
    "db_password",
    "wire",
    "transfer",
    "acquisition",
    "m&a",
)

SENSITIVE_SHARING_PATTERNS = (
    "api key",
    "api_key",
    "auth_token",
    "client_secret",
    "credential",
    "credentials",
    "compensation",
    "compensation_bands",
    "customer_contacts",
    "customer export",
    "customer_export",
    "customers_full_export",
    "database credential",
    "db_password",
    "employee_ssns",
    "file_content",
    "file_data",
    "internal api",
    "internal_report",
    "internal roadmap",
    "password",
    "private_key",
    "roadmap",
    "salary",
    "salary_bands",
    "service_credentials",
    "session token",
    "ssn",
)

SENSITIVE_FILE_PATH_PATTERNS = (
    ".env",
    ".ssh/",
    "api_key",
    "credential",
    "id_rsa",
    "password",
    "private_key",
    "prod.env",
    "secret",
)

PROTECTED_FILE_CHANGE_PATTERNS = (
    ".env",
    "allowlist",
    "auth_required=false",
    "config",
    "prod.env",
    "shared/",
    "trusted_domains",
)

INTERNAL_REFERENCE_PATTERNS = (
    "internal.",
    "vpc-",
    "10.0.",
    "192.168.",
    "172.16.",
    "database_url",
    "connection_string",
    "private_key",
    "intranet",
    ".internal.example",
    ".corp.",
)

FILE_CONTENT_INDICATORS = (
    "file_content",
    "file_data",
    "read_file",
    "attachment",
    "contents of",
    "extracted from",
)
