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

def detect_scanning(entries, threshold=5):
    """Detect scanning/reconnaissance (many 404s from same IP)"""
    
    not_found_per_ip = defaultdict(int)
    
    for entry in entries:
        if entry['status'] == 404:
            not_found_per_ip[entry['ip']] += 1
    
    scanning_ips = {}
    for ip, count in not_found_per_ip.items():
        if count >= threshold:
            scanning_ips[ip] = count
    
    return scanning_ips

def analyze_logs(entries):
    """Run all detection functions and return summary"""
    
    brute_force = detect_brute_force(entries)
    sql_injection = detect_sql_injection(entries)
    path_traversal = detect_path_traversal(entries)
    scanning = detect_scanning(entries)
    
    total_attacks = (
        len(brute_force) + 
        len(sql_injection) + 
        len(path_traversal) + 
        len(scanning)
    )
    
    return {
        'total_requests': len(entries),
        'total_attacks': total_attacks,
        'brute_force': brute_force,
        'sql_injection': sql_injection,
        'path_traversal': path_traversal,
        'scanning': scanning
    }

# Test the detector
if __name__ == "__main__":
    from parser import parse_log_file
    
    entries = parse_log_file('static/sample_logs.txt')
    results = analyze_logs(entries)
    
    print("=== Log Analysis Results ===\n")
    print(f"Total Requests: {results['total_requests']}")
    print(f"Total Attacks Detected: {results['total_attacks']}\n")
    
    print(f"Brute Force Attacks: {len(results['brute_force'])}")
    for ip, count in results['brute_force'].items():
        print(f"  - {ip}: {count} failed login attempts")
    
    print(f"\nSQL Injection Attempts: {len(results['sql_injection'])}")
    for attempt in results['sql_injection']:
        print(f"  - {attempt['ip']}: {attempt['path']}")
    
    print(f"\nPath Traversal Attempts: {len(results['path_traversal'])}")
    for attempt in results['path_traversal']:
        print(f"  - {attempt['ip']}: {attempt['path']}")
    
    print(f"\nScanning Activity: {len(results['scanning'])}")
    for ip, count in results['scanning'].items():
        print(f"  - {ip}: {count} pages scanned")