# HIBP Email Breach Checker

A Python client library and command-line tool for checking email addresses against the [Have I Been Pwned](https://haveibeenpwned.com/) API.

## Features

- **Complete API Coverage**: Supports all HIBP API endpoints including breaches, pastes, stealer logs, and Pwned Passwords
- **Type-Safe**: Uses Pydantic models for automatic validation and type safety
- **Batch Processing**: Check multiple emails from a file with intelligent parsing
- **Error Handling**: Robust error handling for API limits, network issues, and malformed data
- **Flexible Input**: Extract emails from mixed text files using regex patterns

## Installation

1. Clone the repository:
```bash
git clone https://github.com/malaya-zemlya/hibp.git
cd hibp
```

2. Install dependencies:
```bash
pip install -e .
```

3. Set up your API key:
```bash
# Create a .env file
echo "HIBP_API_KEY=your_api_key_here" > .env
```

Get your API key from [https://haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

## Usage

### Command Line Tool

Check emails from a file:

```bash
python main.py --file emails.txt
```

**Input file format**: The tool can extract emails from any text file. Each line can contain:
- Pure email addresses: `user@example.com`
- Mixed text: `Contact John at john@company.com for details`
- Multiple emails per line: `admin@site1.com, support@site2.org`

**Output format**:
- `email@domain.com:ok:Breach1 Breach2 Breach3` (breaches found)
- `email@domain.com:ok:` (no breaches found)  
- `email@domain.com:error:rate limit exceeded` (error occurred)

### Python Library

```python
from hibp.api_client import ApiClient

# Initialize client
client = ApiClient(api_key="your_key", user_agent="your_app")

# Check breaches for an email
breaches = client.get_breaches_for_account("test@example.com")
if breaches:
    for breach in breaches:
        print(f"Found in: {breach.name}")

# Get all breaches in system
all_breaches = client.get_all_breaches()

# Check pastes
pastes = client.get_pastes_for_account("test@example.com") 

# Search Pwned Passwords
result = client.search_passwords_by_range("21BD1")
```

## API Client Methods

### Breach Endpoints
- `get_breaches_for_account(email)` - Get breaches for an email address
- `get_breached_domain(domain)` - Get breached emails for a verified domain
- `get_all_breaches()` - Get all breaches in the system
- `get_single_breach(name)` - Get details of a specific breach
- `get_latest_breach()` - Get the most recently added breach
- `get_data_classes()` - Get all data class types

### Stealer Logs (Requires Pwned 5+ subscription)
- `get_stealer_logs_by_email(email)` - Get domains from stealer logs
- `get_stealer_logs_by_website_domain(domain)` - Get emails for a website
- `get_stealer_logs_by_email_domain(domain)` - Get stealer logs for email domain

### Other Endpoints
- `get_pastes_for_account(email)` - Get pastes containing an email
- `get_subscription_status()` - Get API subscription status
- `search_passwords_by_range(hash_prefix)` - Search Pwned Passwords

## Data Models

The library uses Pydantic models for type safety and validation:

- `Breach` - Complete breach information
- `BreachName` - Truncated breach (name only)
- `Paste` - Paste information
- `SubscribedDomain` - Domain subscription details

## Example Output

```
Checking emails from: emails.txt
Using API key: ****************abc12345
------------------------------------------------------------
Checking: test@example.com
  Result: test@example.com:ok:Adobe LinkedIn
Checking: clean@domain.org  
  Result: clean@domain.org:ok:
Checking: invalid-email
  Result: invalid-email:error:400 Bad Request
------------------------------------------------------------
SUMMARY:
Total emails processed: 3
Successful checks: 2
Errors: 1
Emails with breaches: 1
Clean emails: 1

FINAL RESULTS:
test@example.com:ok:Adobe LinkedIn
clean@domain.org:ok:
invalid-email:error:400 Bad Request
```

## Testing

Run the model validation tests:

```bash
# Run all tests using unittest discovery
python -m unittest discover -v

# Run tests directly
python test_models.py

# Run specific test class
python -m unittest test_models.TestBreachModel -v

# Run specific test method
python -m unittest test_models.TestEmailCheckResult.test_result_with_breaches -v
```

This validates that all Pydantic models correctly parse real HIBP API responses using Python's unittest framework.

## Development

The project structure:

```
hibp/
├── hibp/
│   ├── __init__.py
│   ├── api_client.py      # Main API client
│   ├── rest_client.py     # HTTP client wrapper  
│   └── models.py          # Pydantic data models
├── main.py                # CLI tool
├── test_models.py         # Model validation tests
├── pyproject.toml         # Dependencies
└── README.md
```

## Rate Limiting

The HIBP API has rate limits. The client will raise exceptions on rate limit errors. Consider adding delays between requests for batch processing.

## License

This project is for educational and security research purposes. Please respect the HIBP API terms of service and rate limits.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## API Documentation

For complete API documentation, visit: [https://haveibeenpwned.com/API/v3](https://haveibeenpwned.com/API/v3)