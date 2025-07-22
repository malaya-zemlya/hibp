#!/usr/bin/env python3
"""
Test cases for HIBP API models based on sample responses from the API documentation.
"""

import unittest
from hibp.models import Breach, BreachName, Paste, EmailCheckResult


class TestBreachNameModel(unittest.TestCase):
    """Test cases for BreachName model parsing."""
    
    def test_breach_name_parsing(self):
        """Test parsing truncated breach response (just names)."""
        sample_data = [
            {"Name": "Adobe"},
            {"Name": "Gawker"},
            {"Name": "Stratfor"}
        ]
        
        for item in sample_data:
            with self.subTest(breach_name=item["Name"]):
                breach_name = BreachName.model_validate(item)
                self.assertEqual(breach_name.name, item["Name"])


class TestBreachModel(unittest.TestCase):
    """Test cases for Breach model parsing."""
    
    def setUp(self):
        """Set up test data."""
        self.sample_data = [
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
    
    def test_full_breach_parsing(self):
        """Test parsing full breach response with all fields."""
        for item in self.sample_data:
            with self.subTest(breach=item["Name"]):
                breach = Breach.model_validate(item)
                
                # Verify key fields match
                self.assertEqual(breach.name, item["Name"])
                self.assertEqual(breach.title, item["Title"])
                self.assertEqual(breach.domain, item["Domain"])
                self.assertEqual(breach.pwn_count, item["PwnCount"])
                self.assertEqual(breach.data_classes, item["DataClasses"])
                self.assertEqual(breach.is_verified, item["IsVerified"])
                
                # Verify types
                self.assertIsInstance(breach.pwn_count, int)
                self.assertIsInstance(breach.data_classes, list)
                self.assertIsInstance(breach.is_verified, bool)


class TestPasteModel(unittest.TestCase):
    """Test cases for Paste model parsing."""
    
    def setUp(self):
        """Set up test data."""
        self.sample_data = [
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
    
    def test_paste_parsing(self):
        """Test parsing paste response."""
        for item in self.sample_data:
            with self.subTest(paste=item["Id"]):
                paste = Paste.model_validate(item)
                
                # Verify key fields match
                self.assertEqual(paste.source, item["Source"])
                self.assertEqual(paste.id, item["Id"])
                self.assertEqual(paste.email_count, item["EmailCount"])
                
                if "Title" in item:
                    self.assertEqual(paste.title, item["Title"])
                else:
                    self.assertIsNone(paste.title)
                
                # Verify types
                self.assertIsInstance(paste.email_count, int)
                self.assertIsInstance(paste.source, str)


class TestAPIResponseFormats(unittest.TestCase):
    """Test cases for various API response formats that aren't full Pydantic models."""
    
    def test_breached_domain_response(self):
        """Test breached domain response structure (dict format)."""
        sample_data = {
            "alias1": ["Adobe"],
            "alias2": ["Adobe", "Gawker", "Stratfor"], 
            "alias3": ["AshleyMadison"]
        }
        
        # This should be handled as a dict[str, list[str]] in the API client
        for alias, breaches in sample_data.items():
            with self.subTest(alias=alias):
                self.assertIsInstance(alias, str)
                self.assertIsInstance(breaches, list)
                self.assertTrue(all(isinstance(breach, str) for breach in breaches))


    def test_stealer_logs_responses(self):
        """Test stealer logs response structures."""
        
        # Test stealer logs by email (returns list of domains)
        email_response = ["netflix.com", "spotify.com"]
        self.assertIsInstance(email_response, list)
        self.assertTrue(all(isinstance(domain, str) for domain in email_response))
        
        # Test stealer logs by website domain (returns list of emails)
        website_response = ["andy@gmail.com", "jane@gmail.com"]
        self.assertIsInstance(website_response, list)
        self.assertTrue(all(isinstance(email, str) for email in website_response))
        
        # Test stealer logs by email domain (returns dict of alias -> domains)
        email_domain_response = {
            "andy": ["netflix.com"],
            "jane": ["netflix.com", "spotify.com"]
        }
        for alias, domains in email_domain_response.items():
            with self.subTest(alias=alias):
                self.assertIsInstance(alias, str)
                self.assertIsInstance(domains, list)
                self.assertTrue(all(isinstance(domain, str) for domain in domains))


    def test_data_classes_response(self):
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
        
        self.assertIsInstance(sample_data, list)
        self.assertTrue(all(isinstance(data_class, str) for data_class in sample_data))
        self.assertEqual(len(sample_data), 11)


    def test_pwned_passwords_response(self):
        """Test Pwned Passwords API response (plain text)."""
        # This is what the Pwned Passwords API returns (plain text, not JSON)
        sample_response = """00000005AD76BD555C1D6D771DE417A4B87E4B4:4
00000008CD8B57AA7CA1D16D96A2C70C7C86BAB5:1
0000000A0E6C5B6F7E8A8F4A1B0F1B0F1B0F1B0F:2"""
        
        self.assertIsInstance(sample_response, str)
        lines = sample_response.strip().split('\n')
        self.assertEqual(len(lines), 3)
        
        # Verify format of each line
        for line in lines:
            with self.subTest(line=line):
                parts = line.split(':')
                self.assertEqual(len(parts), 2)
                hash_suffix, count = parts
                self.assertTrue(len(hash_suffix) > 0)
                self.assertTrue(count.isdigit())


class TestEmailCheckResult(unittest.TestCase):
    """Test cases for EmailCheckResult model."""
    
    def test_result_with_breaches(self):
        """Test successful result with breaches."""
        result = EmailCheckResult(
            email="test@example.com",
            status="ok", 
            breaches=["Adobe", "LinkedIn"]
        )
        
        self.assertEqual(result.email, "test@example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.breaches, ["Adobe", "LinkedIn"])
        self.assertIsNone(result.error)
    
    def test_result_clean_email(self):
        """Test successful result with no breaches."""
        result = EmailCheckResult(
            email="clean@example.com",
            status="ok"
        )
        
        self.assertEqual(result.email, "clean@example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.breaches, [])  # Default empty list
        self.assertIsNone(result.error)
    
    def test_result_with_error(self):
        """Test error result."""
        result = EmailCheckResult(
            email="invalid@example.com",
            status="error",
            error="Rate limit exceeded"
        )
        
        self.assertEqual(result.email, "invalid@example.com")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.breaches, [])  # Default empty list even on error
        self.assertEqual(result.error, "Rate limit exceeded")


if __name__ == "__main__":
    unittest.main(verbosity=2)