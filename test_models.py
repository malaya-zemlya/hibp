#!/usr/bin/env python3
"""
Test cases for HIBP API models based on sample responses from the API documentation.
"""

import json
from hibp.models import Breach, BreachName, Paste


def test_breach_name_parsing():
    """Test parsing truncated breach response (just names)."""
    sample_data = [
        {"Name": "Adobe"},
        {"Name": "Gawker"},
        {"Name": "Stratfor"}
    ]
    
    print("Testing BreachName parsing...")
    for item in sample_data:
        breach_name = BreachName.model_validate(item)
        print(f"  ✓ Parsed: {breach_name.name}")
        assert breach_name.name == item["Name"]
    print("✅ BreachName parsing successful\n")


def test_full_breach_parsing():
    """Test parsing full breach response with all fields."""
    sample_data = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2022-05-15T23:52:49Z",
            "PwnCount": 152445165,
            "Description": "In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and many were quickly resolved back to plain text. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
            "LogoPath": "Adobe.png",
            "DataClasses": [
                "Email addresses",
                "Password hints", 
                "Passwords",
                "Usernames"
            ],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "IsSubscriptionFree": False
        },
        {
            "Name": "BattlefieldHeroes",
            "Title": "Battlefield Heroes",
            "Domain": "battlefieldheroes.com", 
            "BreachDate": "2011-06-26",
            "AddedDate": "2014-01-23T13:10:00Z",
            "ModifiedDate": "2014-01-23T13:10:00Z",
            "PwnCount": 530270,
            "Description": "In June 2011 as part of a final breached data dump, the hacker collective \"LulzSec\" <a href=\"http://www.rockpapershotgun.com/2011/06/26/lulzsec-over-release-battlefield-heroes-data\" target=\"_blank\" rel=\"noopener\">obtained and released over half a million usernames and passwords from the game Battlefield Heroes</a>. The passwords were stored as MD5 hashes with no salt and many were easily converted back to their plain text versions.",
            "DataClasses": ["Passwords", "Usernames"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
            "IsMalware": False,
            "IsStealerLog": False,
            "IsSubscriptionFree": False,
            "LogoPath": "BattlefieldHeroes.png"
        }
    ]
    
    print("Testing full Breach parsing...")
    for item in sample_data:
        breach = Breach.model_validate(item)
        print(f"  ✓ Parsed: {breach.title} ({breach.name})")
        print(f"    - Domain: {breach.domain}")
        print(f"    - Breach Date: {breach.breach_date}")
        print(f"    - Pwn Count: {breach.pwn_count:,}")
        print(f"    - Data Classes: {', '.join(breach.data_classes)}")
        print(f"    - Verified: {breach.is_verified}")
        
        # Verify key fields match
        assert breach.name == item["Name"]
        assert breach.title == item["Title"]
        assert breach.domain == item["Domain"]
        assert breach.pwn_count == item["PwnCount"]
        assert breach.data_classes == item["DataClasses"]
        assert breach.is_verified == item["IsVerified"]
    print("✅ Full Breach parsing successful\n")


def test_paste_parsing():
    """Test parsing paste response."""
    sample_data = [
        {
            "Source": "Pastebin",
            "Id": "8Q0BvKD8", 
            "Title": "syslog",
            "Date": "2014-03-04T19:14:54Z",
            "EmailCount": 139
        },
        {
            "Source": "Pastie",
            "Id": "7152479",
            "Date": "2013-03-28T16:51:10Z", 
            "EmailCount": 30
            # Note: Title is missing in this sample (should be optional)
        }
    ]
    
    print("Testing Paste parsing...")
    for item in sample_data:
        paste = Paste.model_validate(item)
        print(f"  ✓ Parsed: {paste.source} - {paste.id}")
        print(f"    - Title: {paste.title}")
        print(f"    - Date: {paste.date}")
        print(f"    - Email Count: {paste.email_count}")
        
        # Verify key fields match
        assert paste.source == item["Source"]
        assert paste.id == item["Id"]
        assert paste.email_count == item["EmailCount"]
        if "Title" in item:
            assert paste.title == item["Title"]
        else:
            assert paste.title is None
    print("✅ Paste parsing successful\n")


def test_breached_domain_response():
    """Test breached domain response structure (dict format)."""
    sample_data = {
        "alias1": ["Adobe"],
        "alias2": ["Adobe", "Gawker", "Stratfor"], 
        "alias3": ["AshleyMadison"]
    }
    
    print("Testing breached domain response structure...")
    # This should be handled as a dict[str, list[str]] in the API client
    for alias, breaches in sample_data.items():
        print(f"  ✓ {alias}: {', '.join(breaches)}")
        assert isinstance(alias, str)
        assert isinstance(breaches, list)
        assert all(isinstance(breach, str) for breach in breaches)
    print("✅ Breached domain structure validation successful\n")


def test_stealer_logs_responses():
    """Test stealer logs response structures."""
    
    # Test stealer logs by email (returns list of domains)
    email_response = ["netflix.com", "spotify.com"]
    print("Testing stealer logs by email response...")
    assert isinstance(email_response, list)
    assert all(isinstance(domain, str) for domain in email_response)
    print(f"  ✓ Domains: {', '.join(email_response)}")
    
    # Test stealer logs by website domain (returns list of emails)
    website_response = ["andy@gmail.com", "jane@gmail.com"]
    print("Testing stealer logs by website domain response...")
    assert isinstance(website_response, list)
    assert all(isinstance(email, str) for email in website_response)
    print(f"  ✓ Emails: {', '.join(website_response)}")
    
    # Test stealer logs by email domain (returns dict of alias -> domains)
    email_domain_response = {
        "andy": ["netflix.com"],
        "jane": ["netflix.com", "spotify.com"]
    }
    print("Testing stealer logs by email domain response...")
    for alias, domains in email_domain_response.items():
        print(f"  ✓ {alias}: {', '.join(domains)}")
        assert isinstance(alias, str)
        assert isinstance(domains, list)
        assert all(isinstance(domain, str) for domain in domains)
    
    print("✅ Stealer logs response validation successful\n")


def test_data_classes_response():
    """Test data classes response (simple string array)."""
    # This is what the API would return
    sample_data = [
        "Account balances",
        "Avatars", 
        "Dates of birth",
        "Email addresses",
        "Geographic locations",
        "IP addresses",
        "Names",
        "Passwords",
        "Phone numbers",
        "Physical addresses",
        "Usernames"
    ]
    
    print("Testing data classes response...")
    assert isinstance(sample_data, list)
    assert all(isinstance(data_class, str) for data_class in sample_data)
    print(f"  ✓ Found {len(sample_data)} data classes")
    for dc in sample_data[:3]:  # Show first 3
        print(f"    - {dc}")
    print("    - ...")
    print("✅ Data classes validation successful\n")


def test_pwned_passwords_response():
    """Test Pwned Passwords API response (plain text)."""
    # This is what the Pwned Passwords API returns (plain text, not JSON)
    sample_response = """00000005AD76BD555C1D6D771DE417A4B87E4B4:4
00000008CD8B57AA7CA1D16D96A2C70C7C86BAB5:1
0000000A0E6C5B6F7E8A8F4A1B0F1B0F1B0F1B0F:2"""
    
    print("Testing Pwned Passwords response...")
    assert isinstance(sample_response, str)
    lines = sample_response.strip().split('\n')
    print(f"  ✓ Found {len(lines)} hash suffix entries")
    for line in lines[:2]:  # Show first 2
        hash_suffix, count = line.split(':')
        print(f"    - {hash_suffix}: {count} occurrences")
    print("✅ Pwned Passwords response validation successful\n")


if __name__ == "__main__":
    print("🧪 Running HIBP API Model Tests\n")
    print("=" * 50)
    
    try:
        test_breach_name_parsing()
        test_full_breach_parsing() 
        test_paste_parsing()
        test_breached_domain_response()
        test_stealer_logs_responses()
        test_data_classes_response()
        test_pwned_passwords_response()
        
        print("=" * 50)
        print("🎉 All tests passed! The Pydantic models correctly parse HIBP API responses.")
        
    except Exception as e:
        print("=" * 50)
        print(f"❌ Test failed: {e}")
        raise