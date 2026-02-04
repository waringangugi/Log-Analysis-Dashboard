"""Unit tests for log parser and detector"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.parser import parse_log_line, parse_log_file
from src.detector import detect_brute_force, detect_sql_injection, detect_path_traversal, detect_scanning

def test_parse_log_line():
    """Test parsing a single log line"""
    line = '192.168.1.100 - - [03/Feb/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234'
    result = parse_log_line(line)
    
    assert result is not None
    assert result['ip'] == '192.168.1.100'
    assert result['method'] == 'GET'
    assert result['path'] == '/index.html'
    assert result['status'] == 200
    print("✓ test_parse_log_line passed")

def test_brute_force_detection():
    """Test brute force attack detection"""
    entries = [
        {'ip': '192.168.1.50', 'status': 401, 'path': '/login', 'method': 'POST'},
        {'ip': '192.168.1.50', 'status': 401, 'path': '/login', 'method': 'POST'},
        {'ip': '192.168.1.50', 'status': 401, 'path': '/login', 'method': 'POST'},
        {'ip': '192.168.1.50', 'status': 401, 'path': '/login', 'method': 'POST'},
        {'ip': '192.168.1.50', 'status': 401, 'path': '/login', 'method': 'POST'},
    ]
    
    result = detect_brute_force(entries, threshold=5)
    assert '192.168.1.50' in result
    assert result['192.168.1.50'] == 5
    print("✓ test_brute_force_detection passed")

def test_sql_injection_detection():
    """Test SQL injection detection"""
    entries = [
        {'ip': '192.168.1.75', 'path': "/search?q=' OR '1'='1", 'timestamp': 'test'},
        {'ip': '192.168.1.76', 'path': '/normal-page', 'timestamp': 'test'}
    ]
    
    result = detect_sql_injection(entries)
    assert len(result) == 1
    assert result[0]['ip'] == '192.168.1.75'
    print("✓ test_sql_injection_detection passed")

def test_path_traversal_detection():
    """Test path traversal detection"""
    entries = [
        {'ip': '192.168.1.99', 'path': '/files/../../etc/passwd', 'timestamp': 'test'},
        {'ip': '192.168.1.100', 'path': '/normal-file.txt', 'timestamp': 'test'}
    ]
    
    result = detect_path_traversal(entries)
    assert len(result) == 1
    assert result[0]['ip'] == '192.168.1.99'
    print("✓ test_path_traversal_detection passed")

def test_scanning_detection():
    """Test scanning/reconnaissance detection"""
    entries = [
        {'ip': '192.168.1.120', 'status': 404, 'path': '/admin'},
        {'ip': '192.168.1.120', 'status': 404, 'path': '/backup'},
        {'ip': '192.168.1.120', 'status': 404, 'path': '/config'},
        {'ip': '192.168.1.120', 'status': 404, 'path': '/test'},
        {'ip': '192.168.1.120', 'status': 404, 'path': '/phpMyAdmin'},
    ]
    
    result = detect_scanning(entries, threshold=5)
    assert '192.168.1.120' in result
    assert result['192.168.1.120'] == 5
    print("✓ test_scanning_detection passed")

if __name__ == "__main__":
    print("Running tests...\n")
    test_parse_log_line()
    test_brute_force_detection()
    test_sql_injection_detection()
    test_path_traversal_detection()
    test_scanning_detection()
    print("\n✓ All tests passed!")