# Task 5.6 Completion Summary — Webhook URL HTTPS Validation

## What Was Done

### Source Change: `src/agentauth/api/v1/webhooks.py`

- Added `HttpUrl` and `field_validator` to the pydantic imports.
- Changed the `url` field on `WebhookSubscriptionCreate` from `str` to `HttpUrl`.
- Added a `@field_validator("url")` (`require_https_in_production`) that raises a `ValueError` with a clear message when a non-HTTPS URL is submitted while `settings.environment` is `"production"` or `"staging"`. HTTP URLs are permitted in `"development"`.
- Updated `create_subscription` to pass `str(payload.url)` to the ORM model, converting Pydantic's `HttpUrl` object to a plain string for storage.

### Test Change: `tests/unit/test_webhooks.py`

Added `TestWebhookSubscriptionCreateUrlValidation` with six tests:

| Test | Scenario |
|------|----------|
| `test_https_url_accepted_in_development` | HTTPS passes in development |
| `test_https_url_accepted_in_production` | HTTPS passes in production |
| `test_http_url_accepted_in_development` | HTTP allowed in development |
| `test_http_url_rejected_in_production` | HTTP raises `ValidationError` in production with "HTTPS" in message |
| `test_http_url_rejected_in_staging` | HTTP raises `ValidationError` in staging |
| `test_invalid_url_rejected` | Non-URL string rejected by `HttpUrl` itself |

## Validation Checklist

- [x] Webhook URL field uses Pydantic `HttpUrl` type
- [x] HTTPS scheme is required in production and staging
- [x] HTTP scheme is allowed in development/testing
- [x] Clear error message when non-HTTPS URL is provided
- [x] Tests verify URL validation (22 unit tests pass, 0 failures)
