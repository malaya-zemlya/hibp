from typing import Optional
from urllib.parse import quote
from .rest_client import RestClient
from .models import Breach, BreachName, Paste, SubscribedDomain


class ApiClient:
    """Have I Been Pwned API client wrapper."""
    
    def __init__(self, api_key: Optional[str] = None, user_agent: str = "hibp-client"):
        """
        Initialize the API client.
        
        Args:
            api_key: Optional API key for authenticated endpoints
            user_agent: User agent string for requests
        """
        self.client = RestClient(
            base_url="https://haveibeenpwned.com/api/v3",
            api_key=api_key,
            user_agent=user_agent
        )
        self.pwned_passwords_client = RestClient(
            base_url="https://api.pwnedpasswords.com",
            user_agent=user_agent
        )
    
    # Breach Endpoints
    
    def get_breaches_for_account(
        self,
        account: str,
        truncate_response: bool = True,
        domain: Optional[str] = None,
        include_unverified: bool = True
    ) -> list[BreachName | Breach] | None:
        """Get breaches for an account."""
        endpoint = f"/breachedaccount/{quote(account)}"
        params = []
        
        if not truncate_response:
            params.append("truncateResponse=false")
        if domain:
            params.append(f"domain={domain}")
        if not include_unverified:
            params.append("includeUnverified=false")
        
        if params:
            endpoint += "?" + "&".join(params)
        
        result = self.client.get(endpoint)
        if result is None:
            return None
        
        if truncate_response:
            return [BreachName.model_validate(item) for item in result]
        else:
            return [Breach.model_validate(item) for item in result]
    
    def get_breached_domain(self, domain: str) -> dict[str, list[str]] | None:
        """Get breached accounts for a domain."""
        result = self.client.get(f"/breacheddomain/{domain}")
        return result  # Returns dict with email aliases as keys, breach names as values
    
    def get_subscribed_domains(self) -> list[SubscribedDomain] | None:
        """Get subscribed domains."""
        result = self.client.get("/subscribeddomains")
        if result is None:
            return None
        return [SubscribedDomain.model_validate(item) for item in result]
    
    def get_all_breaches(
        self,
        domain: Optional[str] = None,
        is_spam_list: Optional[bool] = None
    ) -> list[Breach] | None:
        """Get all breaches."""
        endpoint = "/breaches"
        params = []
        
        if domain:
            params.append(f"Domain={domain}")
        if is_spam_list is not None:
            params.append(f"IsSpamList={'true' if is_spam_list else 'false'}")
        
        if params:
            endpoint += "?" + "&".join(params)
        
        result = self.client.get(endpoint)
        if result is None:
            return None
        return [Breach.model_validate(item) for item in result]
    
    def get_single_breach(self, name: str) -> Breach | None:
        """Get a single breach by name."""
        result = self.client.get(f"/breach/{name}")
        if result is None:
            return None
        return Breach.model_validate(result)
    
    def get_latest_breach(self) -> Breach | None:
        """Get the latest breach."""
        result = self.client.get("/latestbreach")
        if result is None:
            return None
        return Breach.model_validate(result)
    
    def get_data_classes(self) -> list[str] | None:
        """Get all data classes."""
        return self.client.get("/dataclasses")
    
    # Stealer Logs Endpoints (Requires Pwned 5+ subscription)
    
    def get_stealer_logs_by_email(self, email: str) -> list[str] | None:
        """Get stealer log domains by email."""
        return self.client.get(f"/stealerlogsbyemail/{quote(email)}")
    
    def get_stealer_logs_by_website_domain(self, domain: str) -> list[str] | None:
        """Get stealer log emails by website domain."""
        return self.client.get(f"/stealerlogsbywebsitedomain/{domain}")
    
    def get_stealer_logs_by_email_domain(self, domain: str) -> dict[str, list[str]] | None:
        """Get stealer logs by email domain."""
        result = self.client.get(f"/stealerlogsbyemaildomain/{domain}")
        return result  # Returns dict with email aliases as keys, website domains as values
    
    # Paste Endpoints
    
    def get_pastes_for_account(self, account: str) -> list[Paste] | None:
        """Get pastes for an account."""
        result = self.client.get(f"/pasteaccount/{quote(account)}")
        if result is None:
            return None
        return [Paste.model_validate(item) for item in result]
    
    # Subscription Endpoints
    
    def get_subscription_status(self) -> dict | None:
        """Get subscription status."""
        return self.client.get("/subscription/status")
    
    # Pwned Passwords Endpoints
    
    def search_passwords_by_range(self, hash_prefix: str) -> str | None:
        """Search passwords by hash range (first 5 characters of SHA-1 or NTLM hash)."""
        result = self.pwned_passwords_client.get(f"/range/{hash_prefix}")
        # Pwned Passwords API returns plain text, not JSON
        if isinstance(result, str):
            return result
        return None