from flask import Flask, flash, request, render_template, send_file , redirect, session
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import mysql.connector
import io
from io import BytesIO
import struct  # for packing length

app = Flask(__name__)
app.secret_key = "123456789"

# ---------- MySQL Config ----------
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'dual_layer2'
}

#-------------creating tables----------
def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
      id INT NOT NULL AUTO_INCREMENT,
      filename VARCHAR(255) DEFAULT NULL,
      stego_image LONGBLOB,
      aes_key VARBINARY(32) DEFAULT NULL,
      data_len INT DEFAULT NULL,
      owner_email VARCHAR(255) DEFAULT NULL,
      PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS owner (
      id INT NOT NULL AUTO_INCREMENT,
      name VARCHAR(100) DEFAULT NULL,
      email VARCHAR(100) DEFAULT NULL,
      password VARCHAR(100) DEFAULT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS requests (
      id INT NOT NULL AUTO_INCREMENT,
      file_id INT DEFAULT NULL,
      user_email VARCHAR(100) DEFAULT NULL,
      owner_email VARCHAR(100) DEFAULT NULL,
      status ENUM('pending','accepted','rejected') DEFAULT 'pending',
      request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY file_id (file_id),
      CONSTRAINT requests_ibfk_1 FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user (
      id INT NOT NULL AUTO_INCREMENT,
      name VARCHAR(100) DEFAULT NULL,
      email VARCHAR(100) DEFAULT NULL,
      password VARCHAR(100) DEFAULT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
    """)

    conn.commit()
    cursor.close()
    conn.close()

# ---------- AES Encryption ----------
def encrypt_aes(data):
    key = os.urandom(16)  # AES-128 key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding to multiple of 16
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, key, iv

# ---------- AES Decryption ----------
def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]
    return plaintext

# ---------- LSB Steganography ----------
def embed_data_in_image(cover_image_filelike, data_bytes):
    img = Image.open(cover_image_filelike)
    width, height = img.size
    max_capacity = width * height * 3 // 8  # bytes
    if len(data_bytes) + 4 > max_capacity:
        raise ValueError(f"Data too large! Max capacity: {max_capacity} bytes, Data size: {len(data_bytes)} bytes")
    # Prepend 4-byte length for extraction
    length_prefix = struct.pack('>I', len(data_bytes))
    data_to_hide = length_prefix + data_bytes

    binary_data = ''.join(format(byte, '08b') for byte in data_to_hide)
    data_index = 0
    pixels = list(img.getdata())
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel[:3]
        if data_index < len(binary_data):
            r = (r & 0xFE) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            g = (g & 0xFE) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = (b & 0xFE) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))
    img.putdata(new_pixels)
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    return img_byte_arr.getvalue()

# ---------- LSB Extraction ----------
def extract_data_from_image(stego_bytes):
    img = Image.open(io.BytesIO(stego_bytes))
    pixels = list(img.getdata())
    binary_data = ""
    for pixel in pixels:
        for color in pixel[:3]:
            binary_data += str(color & 1)

    # First 32 bits = length of data
    length_bytes = bytearray()
    for i in range(0, 32, 8):
        byte = binary_data[i:i+8]
        length_bytes.append(int(byte, 2))
    data_len = struct.unpack('>I', length_bytes)[0]

    # Extract exact data length
    data_bytes = bytearray()
    for i in range(32, 32 + data_len*8, 8):
        byte = binary_data[i:i+8]
        data_bytes.append(int(byte, 2))
    return data_bytes

# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/owner')
def owner_index():
    return render_template('owner_index.html')

@app.route('/user')
def user_index():
    return render_template('user_index.html')

@app.route('/owner_register', methods=['GET', 'POST'])
def owner_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']  # plain text password

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("INSERT INTO owner (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, password))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect('/owner_login')
        except mysql.connector.IntegrityError:
            flash("Email already exists.", "danger")
            return redirect('/owner_register')
        finally:
            cursor.close()
            conn.close()

    return render_template('owner_register.html')


@app.route('/owner_login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM owner WHERE email=%s AND password=%s", (email, password))
        owner = cursor.fetchone()
        cursor.close()
        conn.close()

        if owner:
            # Store the whole owner record in session
            session['owner'] = owner
            return redirect('/owner_dashboard')
        else:
            flash("Invalid Email or Password", "danger")
            return redirect('/owner_login')

    return render_template('owner_login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/owner_dashboard')
def owner_dashboard():
    if 'owner' not in session:
        return redirect('/owner_login')

    owner_email = session['owner']['email']
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, filename FROM files WHERE owner_email=%s", (owner_email,))
    files = cursor.fetchall()

    cursor.execute("""
    SELECT r.id, r.file_id, r.user_email, r.status, f.filename 
    FROM requests r 
    LEFT JOIN files f ON r.file_id = f.id 
    WHERE r.owner_email=%s
    """, (owner_email,))

    requests = cursor.fetchall()    

    cursor.close()
    conn.close()

    return render_template('owner.html', files=files, owner=session['owner'] , requests=requests)

@app.route('/upload', methods=['POST'])
def upload():
    if 'owner' not in session:
        return redirect('/owner_login')

    try:
        file = request.files['file']
        cover_image = request.files['cover']
        data = file.read()
        owner_email = session['owner']['email']

        # Encrypt
        ciphertext, key, iv = encrypt_aes(data)
        combined_data = iv + ciphertext
        data_len = len(combined_data)

        # Embed in image (steganography)
        cover_image_bytes = BytesIO(cover_image.read())
        stego_bytes = embed_data_in_image(cover_image_bytes, combined_data)

        # Save to DB
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (filename, stego_image, aes_key, data_len, owner_email) VALUES (%s, %s, %s, %s, %s)",
            (file.filename, stego_bytes, key, data_len, owner_email)
        )
        conn.commit()
        cursor.close()
        conn.close()

        # Convert ciphertext and key to hex to display
        cipher_hex = ciphertext.hex()
        key_hex = key.hex()
        iv_hex = iv.hex()

        # Prepare stego image preview as base64
        import base64
        stego_base64 = base64.b64encode(stego_bytes).decode('utf-8')

        flash("✅ File uploaded successfully!", "success")
        return render_template(
            'owner.html',
            owner=session['owner'],
            show_process=True,
            original_filename=file.filename,
            key_hex=key_hex,
            iv_hex=iv_hex,
            cipher_hex=cipher_hex,
            stego_base64=stego_base64
        )

    except ValueError as e:
        flash(f"⚠️ {str(e)}", "danger")
        return redirect('/owner_dashboard')

@app.route('/uploaded_files')
def uploaded_files():
    if 'owner' not in session:
        return redirect('/owner_login')

    owner_email = session['owner']['email']
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
        
    cursor.execute("""
        SELECT id, filename, upload_date 
        FROM files 
        WHERE owner_email = %s 
        ORDER BY upload_date DESC
    """, (owner_email,))
    files = cursor.fetchall()

    cursor.execute("""
        SELECT id, filename, upload_date
        FROM files
        WHERE owner_email = %s
        ORDER BY upload_date DESC
        LIMIT 2
    """, (owner_email,))
    recent_files = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('uploaded_files.html', owner=session['owner'], files=files ,recent_files=recent_files )       

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'owner' not in session:
        return redirect('/login')

    owner_email = session['owner']['email']
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id=%s AND owner_email=%s", (file_id, owner_email))
    row = cursor.fetchone()
    conn.close()

    if row:
        filename = row['filename']
        stego_bytes = row['stego_image']
        key = row['aes_key']
        data_len = row['data_len']

        # Extract exact data
        extracted_bytes = extract_data_from_image(stego_bytes)

        # Split IV + ciphertext
        iv = extracted_bytes[:16]
        ciphertext = extracted_bytes[16:]

        # Decrypt
        plaintext = decrypt_aes(ciphertext, key, iv)
        return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=filename)
    else:
        return "File not found!"

@app.route('/delete_file/<int:file_id>')
def delete_file(file_id):
    if 'owner' not in session:
        flash("Please login first", "warning")
        return redirect('/owner_login')

    owner_email = session['owner']['email']

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Ensure only the owner who uploaded the file can delete it
    cursor.execute("SELECT * FROM files WHERE id=%s AND owner_email=%s", (file_id, owner_email))
    file = cursor.fetchone()

    if file:
        cursor.execute("DELETE FROM files WHERE id=%s", (file_id,))
        conn.commit()
        flash("File deleted successfully! All related requests are also deleted.", "success")
    else:
        flash("File not found or you don't have permission to delete it.", "danger")

    cursor.close()
    conn.close()

    return redirect('/uploaded_files')

@app.route('/view_requests')
def view_requests():
    if 'owner' not in session:
        return redirect('/owner_login')

    owner_email = session['owner']['email']
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch all requests for this owner
    cursor.execute("""
        SELECT r.id, r.user_email, r.status, r.request_date, f.filename
        FROM requests r
        LEFT JOIN files f ON r.file_id = f.id
        WHERE r.owner_email = %s
        ORDER BY r.request_date DESC
    """, (owner_email,))
    all_requests = cursor.fetchall()
    cursor.close()
    conn.close()

    # Separate requests by status
    pending_requests = [r for r in all_requests if r['status'] == 'pending']
    accepted_requests = [r for r in all_requests if r['status'] == 'accepted']
    rejected_requests = [r for r in all_requests if r['status'] == 'rejected']

    return render_template(
        'view_requests.html',
        owner=session['owner'],
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        rejected_requests=rejected_requests
    )


@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    if 'owner' not in session:
        flash("Please login first", "warning")
        return redirect('/owner_login')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("UPDATE requests SET status='accepted' WHERE id=%s", (request_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/view_requests')


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if 'owner' not in session:
        flash("Please login first", "warning")
        return redirect('/owner_login')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("UPDATE requests SET status='rejected' WHERE id=%s", (request_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/view_requests')

@app.route('/user_register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']  # plain text password

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("INSERT INTO user (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, password))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect('/user_login')
        except mysql.connector.IntegrityError:
            flash("Email already exists.", "danger")
            return redirect('/user_register')
        finally:
            cursor.close()
            conn.close()

    return render_template('user_register.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()

        if user:
            # Store the whole owner record in session
            session['user'] = user

            return redirect('/user_dashboard')
        else:
            cursor.close()
            conn.close()
            flash("Invalid Email or Password", "danger")
            return redirect('/user_login')

    return render_template('user_login.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user' not in session:
        flash("Please login first", "warning")
        return redirect('/user_login')

    user_email = session['user']['email']

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all files
        cursor.execute("SELECT id, filename, owner_email FROM files")
        all_files = cursor.fetchall()

        # Fetch all requests made by this user
        cursor.execute("SELECT file_id FROM requests WHERE user_email=%s", (user_email,))
        user_requests = cursor.fetchall()  # ensure this runs before using the variable

    finally:
        cursor.close()
        conn.close()

    # Extract the file_ids the user has already requested
    requested_file_ids = {r['file_id'] for r in user_requests}

    # Filter files to only include those that have not been requested yet
    available_files = [f for f in all_files if f['id'] not in requested_file_ids]

    return render_template('user_dashboard.html', user=session['user'], files=available_files)


@app.route('/view_responses')
def view_responses():
    if 'user' not in session:
        flash("Please login first", "warning")
        return redirect('/user_login')

    user_email = session['user']['email']

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT r.id, r.file_id, f.filename, r.status, r.request_date, r.owner_email
        FROM requests r
        JOIN files f ON r.file_id = f.id
        WHERE r.user_email = %s
        ORDER BY r.request_date DESC
    """, (user_email,))
    all_requests = cursor.fetchall()
    cursor.close()
    conn.close()

    # Separate based on status
    pending = [r for r in all_requests if r['status'] == 'pending']
    accepted = [r for r in all_requests if r['status'] == 'accepted']
    rejected = [r for r in all_requests if r['status'] == 'rejected']

    return render_template(
        'view_responses.html',
        user=session['user'],
        pending=pending,
        accepted=accepted,
        rejected=rejected
    )


@app.route('/request_again/<int:request_id>')
def request_again(request_id):
    if 'user' not in session:
        flash("Please login first", "warning")
        return redirect('/user_login')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("UPDATE requests SET status='pending' WHERE id=%s", (request_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Request sent again to owner!", "success")
    return redirect('/view_responses')

@app.route('/request_file/<int:file_id>')
def request_file(file_id):
    if 'user' not in session:
        flash("Please login first", "warning")
        return redirect('/user_login')

    user_email = session['user']['email']

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Check if request already exists
    cursor.execute("SELECT * FROM requests WHERE file_id=%s AND user_email=%s", (file_id, user_email))
    existing = cursor.fetchone()
    if not existing:
        # Get owner email
        cursor.execute("SELECT owner_email FROM files WHERE id=%s", (file_id,))
        owner_email = cursor.fetchone()[0]
        cursor.execute("INSERT INTO requests (file_id, user_email, owner_email) VALUES (%s, %s, %s)",
                       (file_id, user_email, owner_email))
        conn.commit()

    cursor.close()
    conn.close()
    flash("Request sent to owner!", "success")
    return redirect('/user_dashboard')


@app.route('/download_user/<int:file_id>')
def download_user(file_id):
    if 'user' not in session:
        flash("Please login first", "warning")
        return redirect('/user_login')

    user_email = session['user']['email']

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Check if request is accepted
    cursor.execute("SELECT * FROM requests WHERE file_id=%s AND user_email=%s AND status='accepted'",
                   (file_id, user_email))
    req = cursor.fetchone()
    if not req:
        cursor.close()
        conn.close()
        flash("Your request is not accepted yet!", "danger")
        return redirect('/user_dashboard')

    # Fetch file
    cursor.execute("SELECT * FROM files WHERE id=%s", (file_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row:
        filename = row['filename']
        stego_bytes = row['stego_image']
        key = row['aes_key']
        data_len = row['data_len']

        # Extract data from image
        extracted_bytes = extract_data_from_image(stego_bytes)
        iv = extracted_bytes[:16]
        ciphertext = extracted_bytes[16:]
        plaintext = decrypt_aes(ciphertext, key, iv)

        return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=filename)
    else:
        return "File not found!"

@app.route('/cloud', methods=['GET', 'POST'])
def cloud_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'cloud' and password == 'cloud':
            session['cloud'] = username
            return redirect('/cloudhome')
        else:
            flash("Invalid credentials!", "danger")
            return redirect('/cloud')

    return render_template('cloud_login.html')


# CLOUD HOME - SHOW ALL FILES
@app.route('/cloudhome')
def cloud_home():
    if 'cloud' not in session:
        flash("Please login first", "warning")
        return redirect('/cloud')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Fetch all users
    cursor.execute("SELECT id, name, email FROM user")
    users = cursor.fetchall()

    # Fetch all owners
    cursor.execute("SELECT id, name, email FROM owner")
    owners = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('cloud_home.html', users=users, owners=owners)

@app.route('/files')
def cloud_files():
    if 'cloud' not in session:
        flash("Please login first", "warning")
        return redirect('/cloud')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, filename, owner_email, data_len FROM files")
    files = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('cloud_files.html', files=files)

# Cloud Requests - List all requests
@app.route('/req')
def cloud_requests():
    if 'cloud' not in session:
        flash("Please login first", "warning")
        return redirect('/cloud')

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT r.id, r.file_id, f.filename, r.user_email, r.owner_email, r.status, r.request_date
        FROM requests r
        JOIN files f ON r.file_id = f.id
        ORDER BY r.request_date DESC
    """)
    requests = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('cloud_requests.html', requests=requests)

# CLOUD LOGOUT
@app.route('/cloud_logout')
def cloud_logout():
    session.pop('cloud', None)
    flash("Logged out successfully!", "success")
    return redirect('/cloud')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)


