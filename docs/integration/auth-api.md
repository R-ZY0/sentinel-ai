# Authentication API

## Local setup

Copy .env.example to .env only if .env does not already exist.

Generate a signing key in PowerShell:

    $jwtBytes = New-Object byte[] 32
    $jwtRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $jwtRng.GetBytes($jwtBytes)
    [Convert]::ToBase64String($jwtBytes)
    $jwtRng.Dispose()

Save the generated value as JWT_SECRET_KEY in .env.
Keep .env private and out of Git.

Build and start the services:

    docker compose up -d --build

Changing JWT_SECRET_KEY invalidates existing tokens after the API is recreated.

## Register: POST /auth/register

Send JSON containing:
- email: a valid email address.
- password: 12–128 characters.

Example input:
{"email": "demo@example.com", "password": "LocalDemoPassword2026!"}

Use this example password only for a disposable local test account.

Success: 201 with id, email, is_active, and created_at.
Passwords are stored as Argon2 hashes and excluded from responses.
Emails are normalized to lowercase.

Errors:
- 409: email already registered.
- 422: invalid registration input.

## Login: POST /auth/login

Send form data, not JSON:
- username: the registered email address.
- password: the account password.

Success: 200 with access_token and token_type set to bearer.
Tokens expire after 30 minutes.

Wrong passwords, unknown accounts, and inactive accounts return 401.

## Current user: GET /auth/me

Send the access token in the Authorization header:

    Authorization: Bearer YOUR_ACCESS_TOKEN

Success: 200 with the account's public details.
Missing, invalid, expired, or inactive-user tokens return 401.

## Swagger UI

Open http://localhost:8000/docs.
Click Authorize and enter the account email in the username field.
Enter the password, then click Authorize and Close.

Swagger sends the token with protected requests.

## Protected routes

All /targets and /scans endpoints require authentication.
/health, /auth/register, and /auth/login remain public.

## Current limitations

Authenticated users share targets and scans; ownership checks are not implemented.
Logout in Swagger removes its token locally; it does not revoke the token.
Refresh tokens, password reset, email verification, and login rate limiting are not implemented.
This is a local development setup.