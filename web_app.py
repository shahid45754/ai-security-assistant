"""
Web Interface for Security Incident Assistant
Run this from the project root: python web_app.py
"""

import sys
import os
import asyncio
import json
import traceback
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_cors import CORS

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from app.cli.pipeline import run_analysis

app = Flask(__name__,
    template_folder=str(project_root / 'app' / 'web' / 'templates'),
    static_folder=str(project_root / 'app' / 'static')
)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
CORS(app)

# Configuration
UPLOAD_FOLDER = project_root / 'uploads'
REPORTS_FOLDER = project_root / 'app' / 'reports'
ALLOWED_EXTENSIONS = {'log', 'txt', 'json', 'csv', 'pcap', 'pcapng'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

# Create folders if they don't exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)

# Store analysis results in memory
analysis_history = []


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def run_analysis_async(file_path):
    """Run analysis asynchronously with error handling."""
    try:
        print(f"🔍 Starting run_analysis_async for: {file_path}")
        print(f"📁 File exists: {os.path.exists(file_path)}")
        
        # Create event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Import and run
        from app.cli.pipeline import run_analysis
        print("✅ Imported run_analysis successfully")
        
        result = loop.run_until_complete(run_analysis(file_path))
        loop.close()
        
        print(f"✅ Analysis result status: {result.get('status', 'unknown')}")
        return result
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        traceback.print_exc()
        return {
            "status": "error",
            "error": f"Import error: {str(e)}",
            "traceback": traceback.format_exc()
        }
    except Exception as e:
        print(f"❌ Analysis error: {e}")
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }


@app.route('/')
def index():
    return render_template('index.html', reports=analysis_history[-10:])


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload - supports both GET and POST."""
    if request.method == 'GET':
        flash('Please use the upload form on the home page')
        return redirect(url_for('index'))
    
    # POST method - handle file upload
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if not allowed_file(file.filename):
        flash(f'File type not allowed. Please upload: {", ".join(ALLOWED_EXTENSIONS)}')
        return redirect(request.url)
    
    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_filename = f"{timestamp}_{filename}"
        file_path = UPLOAD_FOLDER / saved_filename
        
        # Save the file
        file.save(file_path)
        print(f"✅ File saved: {file_path}")
        print(f"📄 File size: {file_path.stat().st_size} bytes")
        
        # Read first few lines to debug
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)
                print(f"📄 First 500 chars:\n{content}")
        except Exception as e:
            print(f"⚠️ Could not read file: {e}")
        
        flash(f'File {filename} uploaded successfully! Analyzing...')
        
        # Run analysis
        result = run_analysis_async(file_path)
        
        # Print result for debugging
        print(f"📊 Result: {result}")
        
        if not result:
            flash('Analysis returned no result')
            print("❌ Result is None or empty")
            return redirect(request.url)
        
        if result.get('status') == 'ok':
            # Store result with metadata
            analysis_record = {
                'id': len(analysis_history) + 1,
                'filename': filename,
                'timestamp': datetime.now().isoformat(),
                'file_path': str(file_path),
                'result': result,
                'status': 'completed'
            }
            analysis_history.append(analysis_record)
            incident_count = len(result.get("incidents", []))
            flash(f'✅ Analysis complete! Found {incident_count} incidents.')
            return redirect(url_for('report', report_id=analysis_record['id']))
        else:
            # Get detailed error
            error_msg = result.get('error', 'Unknown error')
            traceback_info = result.get('traceback', '')
            print(f"❌ Analysis failed: {error_msg}")
            if traceback_info:
                print(f"📋 Traceback:\n{traceback_info}")
            flash(f'Analysis failed: {error_msg}')
            return redirect(request.url)
            
    except Exception as e:
        error_msg = f"Upload error: {str(e)}\n{traceback.format_exc()}"
        print(f"❌ {error_msg}")
        flash(f'Error processing upload: {str(e)}')
        return redirect(request.url)


@app.route('/reports')
def reports():
    return render_template('reports.html', reports=analysis_history[::-1])


@app.route('/report/<int:report_id>')
def report(report_id):
    report_data = None
    for r in analysis_history:
        if r.get('id') == report_id:
            report_data = r
            break
    
    if not report_data:
        flash('Report not found')
        return redirect(url_for('reports'))
    
    result = report_data.get('result', {})
    
    # Prepare data for template
    context = {
        'report': report_data,
        'incidents': result.get('incidents', []),
        'campaigns': result.get('campaigns', []),
        'stats': result.get('stats', {}),
        'summary': result.get('summary', {}),
        'soc_verdict': result.get('soc_verdict', {}),
        'timeline': result.get('timeline', []),
        'exports': result.get('exports', {}),
        'has_reports': len(result.get('reports', [])) > 0
    }
    
    return render_template('report.html', **context)


@app.route('/api/report/<int:report_id>/json')
def api_report_json(report_id):
    report_data = None
    for r in analysis_history:
        if r.get('id') == report_id:
            report_data = r
            break
    
    if not report_data:
        return jsonify({'error': 'Report not found'}), 404
    
    result = report_data.get('result', {})
    
    api_result = {
        'report_id': report_id,
        'filename': report_data.get('filename'),
        'timestamp': report_data.get('timestamp'),
        'status': report_data.get('status'),
        'campaigns': [
            {
                'attack_type': c.attack_type if hasattr(c, 'attack_type') else c.get('attack_type', 'Unknown'),
                'source_ip': c.source_ip if hasattr(c, 'source_ip') else c.get('source_ip', 'Unknown'),
                'risk': c.risk if hasattr(c, 'risk') else c.get('risk', 'Unknown'),
                'confidence': c.confidence if hasattr(c, 'confidence') else c.get('confidence', 0)
            }
            for c in result.get('campaigns', [])
        ],
        'stats': result.get('stats', {}),
        'summary': result.get('summary', {})
    }
    
    return jsonify(api_result)


@app.route('/download/<int:report_id>/<format>')
def download_report(report_id, format):
    report_data = None
    for r in analysis_history:
        if r.get('id') == report_id:
            report_data = r
            break
    
    if not report_data:
        flash('Report not found')
        return redirect(url_for('reports'))
    
    result = report_data.get('result', {})
    exports = result.get('exports', {})
    
    format_map = {
        'json': ('json', 'application/json'),
        'html': ('html', 'text/html'),
        'pdf': ('pdf', 'application/pdf'),
        'md': ('markdown', 'text/markdown')
    }
    
    if format not in format_map:
        flash('Invalid format')
        return redirect(url_for('report', report_id=report_id))
    
    file_key, mime_type = format_map[format]
    file_path = exports.get(file_key)
    
    if not file_path or not os.path.exists(file_path):
        flash(f'{format.upper()} report not found')
        return redirect(url_for('report', report_id=report_id))
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=f"report_{report_id}.{format}",
        mimetype=mime_type
    )


@app.route('/delete/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    global analysis_history
    
    for i, r in enumerate(analysis_history):
        if r.get('id') == report_id:
            analysis_history.pop(i)
            break
    
    flash('Report deleted successfully')
    return redirect(url_for('reports'))


@app.route('/clear_reports', methods=['POST'])
def clear_reports():
    global analysis_history
    analysis_history = []
    
    for file in UPLOAD_FOLDER.glob('*'):
        try:
            file.unlink()
        except:
            pass
    
    flash('All reports cleared')
    return redirect(url_for('reports'))


@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'running',
        'reports_count': len(analysis_history),
        'upload_folder': str(UPLOAD_FOLDER),
        'reports_folder': str(REPORTS_FOLDER)
    })


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Page not found'), 404


@app.errorhandler(405)
def method_not_allowed(error):
    flash('Method not allowed. Please use the correct form.')
    return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 50MB.')
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    import traceback
    traceback.print_exc()
    return render_template('error.html', error='Internal server error'), 500


if __name__ == '__main__':
    print("=" * 60)
    print("Security Incident Assistant - Web Interface")
    print("=" * 60)
    print(f"Upload folder: {UPLOAD_FOLDER}")
    print(f"Reports folder: {REPORTS_FOLDER}")
    print("\nStarting web server...")
    print("Access the application at: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
