from flask import Flask, render_template, request, jsonify
from src.parser import parse_log_file
from src.detector import analyze_logs

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')