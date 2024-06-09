from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for
import os
from werkzeug.utils import secure_filename
from utils import derive_key, encrypt_file, decrypt_file
from cryptography.fernet import Fernet
import hashlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
PASSKEY = 'your_secret_passkey'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            fernet = Fernet(derive_key(PASSKEY))
            encrypted_data, file_hash = encrypt_file(filepath, fernet)

            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            flash('File uploaded and encrypted successfully!')
            return render_template('success.html', filename=filename, file_hash=file_hash)
    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    fernet = Fernet(derive_key(PASSKEY))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    decrypted_data = decrypt_file(filepath, fernet)

    # Verify hash
    file_hash = hashlib.sha256(decrypted_data).hexdigest()
    if file_hash != request.args.get('hash'):
        flash('File integrity compromised!')
        return redirect(url_for('index'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
