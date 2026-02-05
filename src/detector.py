from collections import defaultdict
import re

def detect_brute_force(entries, threshold=5):
    """Detect brute force attacks (multiple failed login attempts)"""
    
    failed_attempts = defaultdict(int)
    
    # Count failed login attempts per IP
    for entry in entries:
        # 401 = Unauthorized, 403 = Forbidden
        if entry['status'] in [401, 403]:
            failed_attempts[entry['ip']] += 1
    
    # Find IPs exceeding threshold
    brute_force_ips = {}
    for ip, count in failed_attempts.items():
        if count >= threshold:
            brute_force_ips[ip] = count
    
    return brute_force_ips

