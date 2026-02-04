import re
from datetime import datetime

def parse_log_line(line):
    """Parse a single log line and extract key information"""
    
    # Regex pattern for common log format
    # IP - - [timestamp] "METHOD /path HTTP/1.1" status size
    pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\]\s+"(\w+)\s+(.*?)\s+HTTP.*?"\s+(\d+)\s+(\d+)'
    
    match = re.match(pattern, line)
    
    if match:
        ip = match.group(1)
        timestamp = match.group(2)
        method = match.group(3)
        path = match.group(4)
        status = int(match.group(5))
        size = int(match.group(6))
        
        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'status': status,
            'size': size
        }
    
    return None

def parse_log_file(filepath):
    """Parse entire log file and return list of parsed entries"""
    
    entries = []
    
    try:
        with open(filepath, 'r') as file:
            for line in file:
                parsed = parse_log_line(line.strip())
                if parsed:
                    entries.append(parsed)
        
        return entries
    
    except FileNotFoundError:
        print(f"Error: File {filepath} not found")
        return []
    except Exception as e:
        print(f"Error parsing log file: {e}")
        return []

