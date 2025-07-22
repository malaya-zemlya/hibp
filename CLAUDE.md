# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

This is a Python library and CLI tool for the Have I Been Pwned (HIBP) API with three core layers:

1. **REST Client Layer** (`hibp/rest_client.py`): Low-level HTTP wrapper around `requests` with HIBP-specific authentication headers and error handling. Handles both JSON and plain text responses (for Pwned Passwords).

2. **API Client Layer** (`hibp/api_client.py`): High-level wrapper that provides typed methods for all HIBP endpoints. Uses two REST clients - one for main HIBP API and one for Pwned Passwords. Returns Pydantic models instead of raw dictionaries.

3. **CLI Tool** (`main.py`): Command-line interface that processes email files using regex extraction and batch-checks emails against the API.

## Key Design Patterns

- **Pydantic Models First**: All API responses are parsed into type-safe Pydantic models in `hibp/models.py`. Field aliases map PascalCase JSON to snake_case Python.
- **Dual Client Architecture**: `ApiClient` uses separate `RestClient` instances for main API (JSON) vs Pwned Passwords API (plain text).
- **Error Boundary Pattern**: API client methods catch exceptions and let callers handle them, while CLI tool wraps everything in try/catch for user-friendly error messages.

## Development Commands

### Setup and Dependencies
```bash
pip install -e .                 # Install in editable mode
```

### Testing
```bash
python -m unittest discover -v   # Run all tests with unittest framework  
python test_models.py            # Run tests directly
python -m unittest test_models.TestBreachModel -v  # Run specific test class
```

### Running the CLI
```bash
python main.py --file emails.txt # Check emails from file
```

## Environment Setup

Requires `HIBP_API_KEY` environment variable (use `.env` file with python-dotenv).

## Code Style Preferences

- Use builtin types (`list[str]`, `dict[str, any]`) instead of typing imports
- Prefer Pydantic dataclasses over raw dictionaries for structured data
- API client methods return `None` for 404 responses, raise exceptions for other errors
- Output format for CLI is parseable: `email:status:data` where status is `ok` or `error`

## Important Implementation Details

- Email regex extraction in `main.py` uses comprehensive pattern to find emails in mixed text
- CLI output format avoids ambiguity: `email:ok:` (empty) means no breaches, `email:ok:Breach1 Breach2` means breaches found
- REST client automatically detects JSON vs plain text responses and handles both
- Pydantic models use `populate_by_name = True` to accept both Python field names and API field aliases