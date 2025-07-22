from datetime import datetime, date
from typing import Optional
from pydantic import BaseModel, Field


class Breach(BaseModel):
    """Model for breach data from Have I Been Pwned API."""
    
    name: str = Field(..., alias="Name", description="Pascal-cased name representing the breach")
    title: str = Field(..., alias="Title", description="Descriptive title for the breach")
    domain: str = Field(..., alias="Domain", description="Domain of the primary website")
    breach_date: date = Field(..., alias="BreachDate", description="Date the breach occurred")
    added_date: datetime = Field(..., alias="AddedDate", description="Date breach was added to system")
    modified_date: datetime = Field(..., alias="ModifiedDate", description="Date breach was last modified")
    pwn_count: int = Field(..., alias="PwnCount", description="Total number of accounts in breach")
    description: str = Field(..., alias="Description", description="HTML description of the breach")
    logo_path: str = Field(..., alias="LogoPath", description="Path to the breach logo")
    data_classes: list[str] = Field(..., alias="DataClasses", description="Types of data compromised")
    is_verified: bool = Field(..., alias="IsVerified", description="Whether the breach is verified")
    is_fabricated: bool = Field(..., alias="IsFabricated", description="Whether the breach is fabricated")
    is_sensitive: bool = Field(..., alias="IsSensitive", description="Whether the breach is sensitive")
    is_retired: bool = Field(..., alias="IsRetired", description="Whether the breach is retired")
    is_spam_list: bool = Field(..., alias="IsSpamList", description="Whether the breach is a spam list")
    is_malware: bool = Field(..., alias="IsMalware", description="Whether the breach contains malware")
    is_stealer_log: bool = Field(False, alias="IsStealerLog", description="Whether the breach is from stealer logs")
    is_subscription_free: bool = Field(..., alias="IsSubscriptionFree", description="Whether the breach is subscription free")

    class Config:
        populate_by_name = True


class BreachName(BaseModel):
    """Model for truncated breach response containing only the name."""
    
    name: str = Field(..., alias="Name", description="Name of the breach")

    class Config:
        populate_by_name = True


class Paste(BaseModel):
    """Model for paste data from Have I Been Pwned API."""
    
    source: str = Field(..., alias="Source", description="The paste service (Pastebin, Pastie, etc.)")
    id: str = Field(..., alias="Id", description="ID of the paste at the source service")
    title: Optional[str] = Field(None, alias="Title", description="Title of the paste")
    date: Optional[datetime] = Field(None, alias="Date", description="Date the paste was posted")
    email_count: int = Field(..., alias="EmailCount", description="Number of emails found in the paste")

    class Config:
        populate_by_name = True


class BreachedDomain(BaseModel):
    """Model for breached domain response containing email aliases and breach names."""
    
    # This is a dynamic model as the keys are email aliases
    # We'll handle this as a dict of str -> list[str] in the API client
    pass


class StealerLogsByEmailDomain(BaseModel):
    """Model for stealer logs by email domain response."""
    
    # This is a dynamic model as the keys are email aliases  
    # We'll handle this as a dict of str -> list[str] in the API client
    pass


class SubscriptionStatus(BaseModel):
    """Model for subscription status response."""
    
    # Based on the documentation, this appears to return subscription details
    # The exact structure isn't fully documented, so we'll keep it flexible
    pass


class SubscribedDomain(BaseModel):
    """Model for subscribed domain data."""
    
    domain_name: str = Field(..., alias="DomainName", description="The verified domain name")
    pwn_count: Optional[int] = Field(None, alias="PwnCount", description="Total breached email addresses on domain")
    pwn_count_excluding_spam_lists: Optional[int] = Field(
        None, 
        alias="PwnCountExcludingSpamLists", 
        description="Breached emails excluding spam lists"
    )
    pwn_count_excluding_spam_lists_at_last_renewal: Optional[int] = Field(
        None,
        alias="PwnCountExcludingSpamListsAtLastSubscriptionRenewal",
        description="Breached emails at last subscription renewal"
    )
    next_subscription_renewal: Optional[datetime] = Field(
        None,
        alias="NextSubscriptionRenewal", 
        description="Date subscription ends"
    )

    class Config:
        populate_by_name = True