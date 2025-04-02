from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
from datetime import datetime
import hashlib
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import jwt
from dotenv import load_dotenv
import mimetypes
from PIL import Image
import io

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3002", "https://chatter-nachuthenappan.vercel.app", "https://cool32-s39e-cf82734oe-nachuts-projects.vercel.app"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

# Ensure uploads directory exists
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.chmod(UPLOAD_FOLDER, 0o755)  # Set directory permissions to 755

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_DATA_SIZE = 400 * 1024 * 1024  # 400MB in bytes
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key')
MAX_IMAGE_DIMENSION = 1920  # Maximum dimension for images
JPEG_QUALITY = 85  # JPEG compression quality (0-100)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_data_size():
    """Calculate total size of data directory in bytes"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(UPLOAD_FOLDER):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size

def clear_data():
    """Clear all messages and uploaded files while preserving user accounts"""
    try:
        # Get all uploads
        uploads_response = supabase.table('uploads').select('filename').execute()
        if uploads_response.data:
            # Delete files from disk
            for upload in uploads_response.data:
                file_path = os.path.join(UPLOAD_FOLDER, upload['filename'])
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f'Error deleting {file_path}: {e}')
            
            # Clear uploads from database with a WHERE clause
            supabase.table('uploads').delete().neq('id', 0).execute()
        
        # Clear messages from database with a WHERE clause
        supabase.table('messages').delete().neq('id', 0).execute()
                
        return True
    except Exception as e:
        print(f'Error clearing data: {e}')
        return False

def check_and_clear_data():
    """Check data size and clear if exceeds limit"""
    current_size = get_data_size()
    if current_size > MAX_DATA_SIZE:
        print(f'Data size ({current_size} bytes) exceeds limit ({MAX_DATA_SIZE} bytes). Clearing data...')
        if clear_data():
            print('Data cleared successfully')
        else:
            print('Failed to clear data')

def verify_token(token):
    try:
        print(f"Verifying token: {token[:10]}...")  # Log first 10 chars for security
        # Check if token starts with "Bearer " and remove it
        if token.startswith('Bearer '):
            token = token[7:]
            print("Bearer prefix removed")
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        print(f"Token verified successfully for user: {payload['username']}")
        return payload['username']
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error verifying token: {str(e)}")
        return None

def process_image(image_file):
    """Process and compress the image"""
    try:
        # Open the image
        img = Image.open(image_file)
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Get original dimensions
        original_width, original_height = img.size
        
        # Calculate new dimensions while maintaining aspect ratio
        if original_width > MAX_IMAGE_DIMENSION or original_height > MAX_IMAGE_DIMENSION:
            ratio = min(MAX_IMAGE_DIMENSION / original_width, MAX_IMAGE_DIMENSION / original_height)
            new_width = int(original_width * ratio)
            new_height = int(original_height * ratio)
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Save compressed image to bytes buffer
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=JPEG_QUALITY, optimize=True)
        buffer.seek(0)
        
        # Get compressed size
        compressed_size = buffer.getbuffer().nbytes
        
        return {
            'buffer': buffer,
            'original_width': original_width,
            'original_height': original_height,
            'compressed_size': compressed_size,
            'format': 'JPEG'
        }
    except Exception as e:
        print(f'Error processing image: {e}')
        raise

def get_file_metadata(file, image_data=None):
    """Get metadata about the uploaded file"""
    filename = secure_filename(file.filename)
    extension = 'jpg'  # Always use jpg for compressed images
    mime_type = 'image/jpeg'
    
    metadata = {
        'original_name': file.filename,
        'extension': extension,
        'mime_type': mime_type,
        'size': 0,  # Will be updated after saving
        'format': 'JPEG'
    }
    
    if image_data:
        metadata.update({
            'original_width': image_data['original_width'],
            'original_height': image_data['original_height'],
            'compressed_size': image_data['compressed_size']
        })
    
    return metadata

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Check if username already exists
        response = supabase.table('users').select('username').eq('username', username).execute()
        if response.data:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Add new user
        supabase.table('users').insert({
            'username': username,
            'password_hash': hash_password(password)
        }).execute()
        
        # Generate JWT token
        token = jwt.encode({'username': username}, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'status': 'success', 
            'message': 'User registered successfully',
            'username': username,
            'token': token
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Check user credentials
        response = supabase.table('users').select('username').eq('username', username).eq('password_hash', hash_password(password)).execute()
        if not response.data:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Generate JWT token
        token = jwt.encode({'username': username}, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'status': 'success',
            'username': username,
            'token': token
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
            
        username = verify_token(token)
        if not username:
            return jsonify({'error': 'Invalid token'}), 401
            
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if file and allowed_file(file.filename):
            try:
                # Ensure upload directory exists
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                # Check and clear data if needed
                check_and_clear_data()
                
                # Process and compress the image
                image_data = process_image(file)
                
                # Generate unique filename
                timestamp = datetime.now().timestamp()
                filename = secure_filename(f"{timestamp}.jpg")
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                
                # Save compressed image
                try:
                    with open(filepath, 'wb') as f:
                        f.write(image_data['buffer'].getvalue())
                    os.chmod(filepath, 0o644)  # Set file permissions to 644
                except Exception as e:
                    print(f'Error saving file: {e}')
                    return jsonify({'error': 'Failed to save image file'}), 500
                
                # Get file metadata
                metadata = get_file_metadata(file, image_data)
                metadata['size'] = image_data['compressed_size']
                
                # Add image metadata to uploads table
                upload_data = {
                    'filename': filename,
                    'original_name': metadata['original_name'],
                    'extension': metadata['extension'],
                    'mime_type': metadata['mime_type'],
                    'size': metadata['size'],
                    'original_width': metadata['original_width'],
                    'original_height': metadata['original_height'],
                    'compressed_size': metadata['compressed_size'],
                    'format': metadata['format'],
                    'uploaded_by': username,
                    'uploaded_at': datetime.now().isoformat()
                }
                
                try:
                    upload_response = supabase.table('uploads').insert(upload_data).execute()
                    
                    if not upload_response.data:
                        # If upload metadata fails, delete the file
                        if os.path.exists(filepath):
                            os.remove(filepath)
                        return jsonify({'error': 'Failed to save image metadata'}), 500
                    
                    # Add image message to messages table
                    message_data = {
                        'timestamp': datetime.now().isoformat(),
                        'username': username,
                        'message': filename,
                        'type': 'image',
                        'upload_id': upload_response.data[0]['id']
                    }
                    
                    supabase.table('messages').insert(message_data).execute()
                    
                    return jsonify({
                        'status': 'success',
                        'filename': filename,
                        'metadata': metadata
                    })
                    
                except Exception as e:
                    print(f'Database error: {str(e)}')
                    # Clean up the file if database operation fails
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    return jsonify({'error': 'Database operation failed'}), 500
                    
            except Exception as e:
                print(f'File operation error: {str(e)}')
                return jsonify({'error': 'File operation failed'}), 500
            
        return jsonify({'error': 'File type not allowed'}), 400
    except Exception as e:
        print(f'Error uploading image: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/<filename>', methods=['GET'])
def get_image(filename):
    try:
        # Get image metadata from uploads table
        response = supabase.table('uploads').select('*').eq('filename', filename).execute()
        if not response.data:
            return jsonify({'error': 'Image not found'}), 404
            
        upload_data = response.data[0]
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'Image file not found'}), 404
            
        return send_file(
            file_path,
            mimetype=upload_data['mime_type'],
            as_attachment=False,
            download_name=upload_data['original_name']
        )
    except Exception as e:
        print(f'Error serving image: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        response = supabase.table('messages').select('*').order('timestamp').execute()
        messages = response.data
        return jsonify(messages)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear', methods=['POST'])
def clear_all_data():
    """Endpoint to manually clear all data"""
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
            
        username = verify_token(token)
        if not username:
            return jsonify({'error': 'Invalid token'}), 401

        if clear_data():
            return jsonify({'status': 'success', 'message': 'All data cleared successfully'})
        else:
            return jsonify({'error': 'Failed to clear data'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        token = request.headers.get('Authorization')
        print(f"Received Authorization header: {token[:10] if token else 'None'}...")
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
            
        username = verify_token(token)
        if not username:
            return jsonify({'error': 'Invalid token'}), 401
        
        message = data.get('message')
        message_type = data.get('type', 'text')
        
        print(f"Processing message from user {username}: {message[:20]}...")
        
        # Add message to database
        response = supabase.table('messages').insert({
            'username': username,
            'message': message,
            'type': message_type,
            'timestamp': datetime.now().isoformat()
        }).execute()
        
        return jsonify({'status': 'success', 'message': 'Message sent successfully'})
    except Exception as e:
        print(f"Error in send_message: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 
