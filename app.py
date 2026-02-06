from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from src.parser import parse_log_file, parse_log_line
from src.detector import analyze_logs
import os
import tempfile

app = Flask(__name__)
CORS(app)

# Use system temp directory (works on all platforms including Render)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

@app.route('/')
def index():
    """Serve the dashboard"""
    return render_template('dashboard.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the default sample logs"""
    
    # Parse the sample log file
    entries = parse_log_file('static/sample_logs.txt')
    
    if not entries:
        return jsonify({'error': 'Failed to parse log file'}), 500
    
    # Analyze for attacks
    results = analyze_logs(entries)
    
    # Get unique IPs
    unique_ips = len(set(entry['ip'] for entry in entries))
    
    return jsonify({
        'total_requests': results['total_requests'],
        'total_attacks': results['total_attacks'],
        'unique_ips': unique_ips,
        'brute_force': results['brute_force'],
        'sql_injection': results['sql_injection'],
        'path_traversal': results['path_traversal'],
        'scanning': results['scanning']
    })

@app.route('/analyze-upload', methods=['POST', 'OPTIONS'])
def analyze_upload():
    """Analyze uploaded log file"""
    
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        print("=== Upload request received ===")
        
        if 'logfile' not in request.files:
            print("ERROR: No file in request")
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['logfile']
        print(f"File received: {file.filename}")
        
        if file.filename == '':
            print("ERROR: Empty filename")
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content directly into memory (no disk save)
        try:
            file_content = file.read().decode('utf-8')
            print(f"File content length: {len(file_content)} bytes")
        except UnicodeDecodeError:
            return jsonify({'error': 'File must be a text file (UTF-8 encoded)'}), 400
        
        # Parse log entries from content string
        entries = []
        for line in file_content.splitlines():
            line = line.strip()
            if line:  # Skip empty lines
                entry = parse_log_line(line)
                if entry:
                    entries.append(entry)
        
        print(f"Parsed {len(entries)} entries")
        
        if not entries:
            print("ERROR: No entries parsed")
            return jsonify({'error': 'Failed to parse log file. Make sure it\'s in standard Apache/Nginx format.'}), 400
        
        # Analyze for attacks
        print("Analyzing logs...")
        results = analyze_logs(entries)
        print(f"Analysis complete. Found {results['total_attacks']} attacks")
        
        # Get unique IPs
        unique_ips = len(set(entry['ip'] for entry in entries))
        
        return jsonify({
            'total_requests': results['total_requests'],
            'total_attacks': results['total_attacks'],
            'unique_ips': unique_ips,
            'brute_force': results['brute_force'],
            'sql_injection': results['sql_injection'],
            'path_traversal': results['path_traversal'],
            'scanning': results['scanning']
        })
    
    except Exception as e:
        print(f"EXCEPTION CAUGHT: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500
    
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')