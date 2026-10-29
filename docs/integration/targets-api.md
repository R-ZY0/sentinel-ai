# Target API

Base URL: http://localhost:8000
Interactive documentation: http://localhost:8000/docs

## Endpoints

| Method | Path | Success | Purpose |
|---|---|---|---|
| POST | /targets | 201 | Create a target |
| GET | /targets | 200 | List targets |
| GET | /targets/{id} | 200 | Retrieve one target |
| PUT | /targets/{id} | 200 | Replace its name and endpoint |
| DELETE | /targets/{id} | 204 | Delete a target without scan history |

## Create and update input

Both POST and PUT require:
- name: a nonempty string, maximum 100 characters.
- endpoint: a valid HTTP or HTTPS URL.

Leading and trailing whitespace is removed from names.
Unknown request fields are rejected.

Example input:
{"name": "Local Ollama", "endpoint": "http://ollama:11434/"}

## Output

POST, GET by ID, and PUT return:
- id: UUID.
- name: target name.
- endpoint: normalized URL.
- created_at: creation timestamp.

GET /targets returns a list of these objects.
PUT preserves the original ID and creation timestamp.
Successful DELETE returns an empty response body.

## Errors

- 404: target does not exist.
- 409: target has scan history and cannot be deleted.
- 422: invalid UUID, missing fields, or invalid input.
- 503: database operation unavailable.
- 500: unexpected application failure.
- 401: missing, invalid, expired, or inactive-user login credentials.

## Current limitations

All target endpoints require a Bearer access token obtained through POST /auth/login.
Authenticated users currently share targets and scans. Per-user ownership is not implemented yet.

URL validation checks syntax; it does not verify reachability or authorization.
The scan pipeline currently supports the integrated local Ollama workflow.
Changing a target does not rewrite its existing scan records.