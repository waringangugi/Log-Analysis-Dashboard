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

def detect_sql_injection(entries):
    """Detect SQL injection attempts in URLs"""
    
    sql_patterns = [
        r"'.*OR.*'",
        r"'.*--",
        r"UNION.*SELECT",
        r"DROP.*TABLE",
        r"';.*--",
        r"1=1"
    ]
    
    sql_injection_attempts = []
    
    for entry in entries:
        path = entry['path']
        
        for pattern in sql_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                sql_injection_attempts.append({
                    'ip': entry['ip'],
                    'path': path,
                    'timestamp': entry['timestamp']
                })
                break  # Only count once per entry
    
    return sql_injection_attempts

def detect_path_traversal(entries):
    """Detect path traversal attacks"""
    
    path_traversal_attempts = []
    
    for entry in entries:
        # Look for ../ or ..\ patterns
        if '../' in entry['path'] or '..\\'in entry['path']:
            path_traversal_attempts.append({
                'ip': entry['ip'],
                'path': entry['path'],
                'timestamp': entry['timestamp']
            })
    
    return path_traversal_attempts

