"""Shared security pattern constants used across policy and risk checks."""

DEFAULT_INTERNAL_EMAIL_DOMAINS = ("@company.com", "@internal.org")

INTERNAL_TARGET_INDICATORS = (
    "localhost",
    "127.0.0.1",
    "internal.",
    ".company.com",
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
    ".internal.com",
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
