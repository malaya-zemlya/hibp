#!/usr/bin/env python3
"""
Have I Been Pwned (HIBP) email breach checker.

This script reads emails from a file and checks them against the HIBP API
to find which breaches they appear in.
"""

import argparse
import os
import re
import sys
from typing import List
from dotenv import load_dotenv

from hibp.api_client import ApiClient
from hibp.models import BreachName, EmailCheckResult

load_dotenv()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Check emails against Have I Been Pwned database"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="File containing emails to check (one per line or mixed with other text)"
    )
    return parser.parse_args()


def extract_emails_from_line(line: str) -> List[str]:
    """
    Extract email addresses from a line of text using regex.
    
    Args:
        line: Line of text that may contain email addresses
        
    Returns:
        List of email addresses found in the line
    """
    # Comprehensive email regex pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, line)


def check_email_breaches(api_client: ApiClient, email: str) -> EmailCheckResult:
    """
    Check if an email appears in any breaches.
    
    Args:
        api_client: HIBP API client instance
        email: Email address to check
        
    Returns:
        EmailCheckResult with status, email, and either breaches or error
    """
    try:
        # Get breaches for the account (truncated response for just names)
        breaches = api_client.get_breaches_for_account(email, truncate_response=True)
        
        if breaches is None:
            return EmailCheckResult(
                email=email,
                status='ok',
                breaches=[]
            )
        
        breach_names = [breach.name for breach in breaches]
        return EmailCheckResult(
            email=email,
            status='ok',
            breaches=breach_names
        )
        
    except Exception as e:
        return EmailCheckResult(
            email=email,
            status='error',
            error=str(e)
        )


def format_result(result: EmailCheckResult) -> str:
    """
    Format a result into the required output format.
    
    Args:
        result: EmailCheckResult from check_email_breaches
        
    Returns:
        Formatted string: "email:ok:breach1 breach2 ..." or "email:error:description"
    """
    if result.status == 'ok':
        if result.breaches:
            breaches_str = ' '.join(result.breaches)
            return f"{result.email}:ok:{breaches_str}"
        else:
            return f"{result.email}:ok:"
    else:
        return f"{result.email}:error:{result.error}"


def main():
    """Main function."""
    args = parse_args()
    
    # Get API key from environment
    api_key = os.getenv('HIBP_API_KEY')
    if not api_key:
        print("Error: HIBP_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    # Initialize API client
    api_client = ApiClient(api_key=api_key, user_agent="hibp-email-checker")
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Checking emails from: {args.file}")
    print(f"Using API key: {'*' * (len(api_key) - 8) + api_key[-8:]}")
    print("-" * 60)
    
    results = []
    total_emails = 0
    
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Extract emails from this line
                emails = extract_emails_from_line(line)
                
                if not emails:
                    # Line contains no emails, skip silently
                    continue
                
                # Check each email found in this line
                for email in emails:
                    total_emails += 1
                    print(f"Checking: {email}")
                    result = check_email_breaches(api_client, email)
                    results.append(result)
                    
                    # Print immediate result
                    print(f"  Result: {format_result(result)}")
    
    except FileNotFoundError:
        print(f"Error: Could not read file '{args.file}'", file=sys.stderr)
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(f"Error: Could not decode file '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Print summary
    print("-" * 60)
    print("SUMMARY:")
    print(f"Total emails processed: {total_emails}")
    
    # Count results by status
    ok_results = [r for r in results if r.status == 'ok']
    error_results = [r for r in results if r.status == 'error']
    breached_results = [r for r in ok_results if r.breaches]
    
    print(f"Successful checks: {len(ok_results)}")
    print(f"Errors: {len(error_results)}")
    print(f"Emails with breaches: {len(breached_results)}")
    print(f"Clean emails: {len(ok_results) - len(breached_results)}")
    
    # Final output in requested format
    print("\nFINAL RESULTS:")
    for result in results:
        print(format_result(result))


if __name__ == "__main__":
    main()