import requests
from typing import Optional


class RestClient:
    """A simple REST client wrapper around requests library for Have I Been Pwned API."""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None, user_agent: str = "hibp-client"):
        """
        Initialize the REST client.
        
        Args:
            base_url: The base URL for the API (e.g., 'https://haveibeenpwned.com/api/v3')
            api_key: Optional API key for authentication
            user_agent: User agent string for the client
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.user_agent = user_agent
    
    def get(self, endpoint: str) -> dict | list | str | None:
        """
        Perform a GET request to the specified endpoint.
        
        Args:
            endpoint: The API endpoint (e.g., '/breachedaccount/test@example.com')
        
        Returns:
            Parsed JSON data, plain text, or None if 404 status code
        
        Raises:
            requests.HTTPError: For non-200/404 status codes
        """
        url = f"{self.base_url}{endpoint}"
        
        headers = {
            'user-agent': self.user_agent
        }
        
        if self.api_key:
            headers['hibp-api-key'] = self.api_key
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            return None
        
        response.raise_for_status()
        
        # Try to parse as JSON, fall back to plain text
        try:
            return response.json()
        except ValueError:
            return response.text