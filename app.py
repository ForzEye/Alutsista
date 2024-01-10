from flask import Flask, render_template, request, redirect, url_for, jsonify
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from bson import ObjectId
from functools import wraps
import hashlib
from datetime import datetime, timedelta
import jwt
import os
from os.path import join, dirname
from dotenv import load_dotenv


dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]

app = Flask(__name__)
app.config['UPLOAD_FOLDER']='./static/img_senjata'

SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_KEY = os.environ.get("ADMIN_KEY")

TOKEN_KEY = 'mytoken'


articles_per_page = 3

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token_receive = request.cookies.get('mytoken')
        if token_receive is not None:
            try:
                payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
                if payload["role"] == "admin":
                    return f(*args, **kwargs)
                else:
                    return redirect(url_for('admin', msg='Only admin can access this page'))
            except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
                return redirect(url_for('login', msg='Your token is invalid or has expired'))
        else:
            return redirect(url_for('login', msg='Please login to view this page'))
    return decorated_function

@app.route('/')
def index():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        page = int(request.args.get('page', 1))
        start_index = (page - 1) * articles_per_page
        end_index = start_index + articles_per_page
    
        articles = list(db.articles.find().sort('tanggal_upload', -1).skip(start_index).limit(articles_per_page))

        total_articles = db.articles.count_documents({})
        total_pages = (total_articles + articles_per_page - 1) // articles_per_page
        

        # Pastikan tanggal_upload adalah objek datetime saat dikirim ke template
        for article in articles:
            if 'tanggal_upload' in article and isinstance(article['tanggal_upload'], str):
                article['tanggal_upload'] = datetime.strptime(article['tanggal_upload'], '%Y-%m-%d %H:%M:%S')
        return render_template('index.html', articles=articles, total_pages=total_pages, current_page=page, payload=payload)
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login',msg = msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was a problem logging you in'
        return redirect(url_for('login',msg = msg))

@app.route("/login")
def login():
    token_receive = request.cookies.get("mytoken")
    try:
        if token_receive:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.anggota.find_one({'username': payload['id']})
            if user_info:
                # Redirect to the admin page if the user is an admin
                if user_info['role'] == 'admin':
                    return redirect(url_for('admin'))
                else:
                    return redirect(url_for('index'))

        return render_template("login.html")

    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return render_template("login.html")

@app.route("/admin_reg")
def admin_register():
    token_receive = request.cookies.get("mytoken")
    try:
        if token_receive:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.anggota.find_one({'username': payload['id']})
            if user_info:
                # Jika pengguna sudah login, arahkan ke halaman lain
                return redirect(url_for('admin'))
        
        # Jika pengguna belum login, tampilkan halaman registrasi admin
        return render_template("admin_register.html")
    
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return render_template("admin_register.html")


@app.route("/admin_signup", methods=["POST"])
def admin_signup():
    username_receive = request.form["username"]
    nama_receive = request.form["nama_lengkap"]
    pw_receive = request.form["password"]
    adminkey_receive = request.form["admin_key"]
    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

    user_exists = bool(db.anggota.find_one({"username": username_receive}))
    if user_exists:
        return jsonify({"result": "error_uname", "msg": f"An account with username {username_receive} is already exists. Please Login!"})
    elif adminkey_receive != ADMIN_KEY:
        return jsonify({"result": "error_akey", "msg": f"Admin key yang anda masukkan salah!"})
    else:
        doc = {
        "username": username_receive,                              
        "name": nama_receive,
        "password": pw_hash,                                      
        "profile_pic_real": "profile_pics/profile_placeholder.png", 
        "profile_info": "",
        "role": "admin"                                          
        }
        db.anggota.insert_one(doc)
        return jsonify({"result": "success"})
    

@app.route("/user_signup", methods=["POST"])
def user_signup():
    username_receive = request.form["username"]
    nama_receive = request.form["nama_lengkap"]
    pw_receive = request.form["password"]
    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

    user_exists = bool(db.anggota.find_one({"username": username_receive}))
    if user_exists:
        return jsonify({"result": "error_uname", "msg": f"An account with username {username_receive} is already exists. Please Login!"})
    else:
        doc = {
        "username": username_receive,                              
        "name": nama_receive,
        "password": pw_hash,                                      
        "profile_pic_real": "profile_pics/profile_placeholder.png", 
        "profile_info": "",
        "role": "member"                                          
        }
        db.anggota.insert_one(doc)
        return jsonify({"result": "success"})
    

@app.route("/sign_in", methods=["POST"])
def sign_in():
    # Sign in
    username_receive = request.form["username_give"]
    password_receive = request.form["password_give"]
    result = db.anggota.find_one(
        {
            "username": username_receive,
            "password": hashlib.sha256(password_receive.encode("utf-8")).hexdigest(),
        }
    )

    if result:
        payload = {
            "id": username_receive,
            "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
            "role": result["role"],
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        if result["role"] == "admin":
            return jsonify(
                {
                    "result": "success",
                    "token": token,
                    "redirect_url": "/admin",
                }
            )
        else:
            return jsonify(
                {
                    "result": "success",
                    "token": token,
                    "redirect_url": "/",
                }
            )
    else:
        return jsonify(
            {
                "result": "fail",
                "msg": "Kami tidak dapat menemukan pengguna dengan kombinasi username/password tersebut.",
            }
        )


# Route untuk halaman tambah_senjata
@app.route('/tambah', methods=['GET'])
@admin_required
def tambah():
    senjata_list = db.senjata.find()
    return render_template('tambah.html', senjata_list=senjata_list)

@app.route('/tambah_senjata', methods=['POST'])
@admin_required
def tambah_senjata():
    # Mengambil data dari form
    nama_receive = request.form.get('nama_give')
    jumlah_receive = request.form.get('jumlah_give')
    deskripsi_receive = request.form.get('deskripsi_give')
    tahun_pembuatan_receive = request.form.get('tahun_pembuatan_give')
    type_receive = request.form.get('type')  # Get the selected type
    
    if 'file_give' in request.files:
        file = request.files.get('file_give')
        file_name = secure_filename(file.filename)
        picture_name = f"{file_name.split('.')[0]}[{nama_receive}].{file_name.split('.')[1]}"
        file_path = f'./static/img_senjata/{picture_name}'
        file.save(file_path)
    else:
        picture_name = 'default.jpg'
    
    doc = {
        'nama': nama_receive,
        'jumlah': jumlah_receive,
        'deskripsi': deskripsi_receive,
        'tahun_pembuatan': tahun_pembuatan_receive,
        'type': type_receive,  # Add the new type field
        'picture': picture_name
    }
    db.senjata.insert_one(doc)
    
    return redirect(url_for('tambah'))

@app.route('/pinjam_senjata', methods=['POST'])
def pinjam_senjata():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        senjata_id = request.form.get('senjata_id')
        borrower_name = request.form.get('borrower_name')
        borrow_duration = int(request.form.get('borrow_duration'))
        borrow_quantity = int(request.form.get('borrow_quantity'))

        senjata = db.senjata.find_one({'_id': ObjectId(senjata_id)})

        if senjata:
            available_quantity = int(senjata['jumlah'])

            if available_quantity >= borrow_quantity > 0:
                db.peminjam.insert_one({
                    'nama_peminjam': borrower_name,
                    'nama_senjata': senjata['nama'],
                    'senjata_id': senjata_id,
                    'borrow_duration': borrow_duration,
                    'borrow_quantity': borrow_quantity,
                    'tanggal_pinjaman': datetime.now(),
                    'tanggal_pengembalian': datetime.now() + timedelta(days=borrow_duration),
                    'approval_status': 'Menunggu Persetujuan'
                })

                new_quantity = available_quantity - borrow_quantity
                db.senjata.update_one(
                    {'_id': ObjectId(senjata_id)},
                    {'$set': {'jumlah': new_quantity}}
                )

                return redirect(url_for('senjata_dipinjam'))
            else:
                error_message = "Jumlah senjata tidak mencukupi untuk dipinjam."
                senjata_list = db.senjata.find()
                return render_template('pinjam_senjata.html', senjata_list=senjata_list, error_message=error_message)
        else:
            return "Senjata tidak ditemukan."
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    
@app.route('/pinjam_senjata/<senjata_id>', methods=['GET'])
def pinjam_senjata_form(senjata_id):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        senjata = db.senjata.find_one({'_id': ObjectId(senjata_id)})
        return render_template('pinjam_senjata.html', senjata=senjata)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))


def replace_characters(text):
    text = text.replace('\n', '\\n')
    
    text = text.replace('\r', '\\r')

    text = text.replace('\t', '\\t')

    return text

@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    total_senjata = db.senjata.count_documents({})
    total_peminjam = db.peminjam.count_documents({})
    total_pengembalian = db.pengembalian.count_documents({})
    total_artikel = db.articles.count_documents({})
    total_perawatan = db.perawatan.count_documents({})

    return render_template('admin.html', total_senjata=total_senjata, total_peminjam=total_peminjam, total_pengembalian=total_pengembalian, total_artikel=total_artikel, total_perawatan=total_perawatan)

@app.route('/data_peminjam', methods=['GET', 'POST'])
@admin_required
def data_peminjam():
    if request.method == 'POST':
        senjata_id = request.form.get('senjata_id')
        approval_status = request.form.get('approval_status')

        db.peminjam.update_one(
            {'senjata_id': senjata_id},
            {'$set': {'approval_status': approval_status}}
        )

    borrowed_data = list(db.peminjam.find({'nama_senjata': {'$exists': True}}))
    return render_template('data_peminjam.html', borrowed_data=borrowed_data)


@app.route('/pinjam', methods=['GET'])
def pinjam():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        page = int(request.args.get('page', 1))
        items_per_page = 6
        start_index = (page - 1) * items_per_page
        end_index = start_index + items_per_page

        senjata_list = db.senjata.find().skip(start_index).limit(items_per_page)

        total_senjata = db.senjata.count_documents({})
        total_pages = (total_senjata + items_per_page - 1) // items_per_page

        return render_template('pinjam_senjata.html', senjata_list=senjata_list, total_pages=total_pages, current_page=page)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))


# Tambahkan route untuk halaman edit_senjata
@app.route('/edit_senjata/<senjata_id>', methods=['GET'])
@admin_required
def edit_senjata(senjata_id):
    senjata = db.senjata.find_one({'_id': ObjectId(senjata_id)})
    return render_template('edit_senjata.html', senjata=senjata)

# Handle request update_senjata
@app.route('/update_senjata/<senjata_id>', methods=['POST'])
@admin_required
def update_senjata(senjata_id):
    # Mengambil data dari form edit
    nama_receive = request.form.get('nama_give')
    jumlah_receive = request.form.get('jumlah_give')
    deskripsi_receive = request.form.get('deskripsi_give')
    tahun_pembuatan_receive = request.form.get('tahun_pembuatan_give')

    db.senjata.update_one(
        {'_id': ObjectId(senjata_id)},
        {
            '$set': {
                'nama': nama_receive,
                'jumlah': jumlah_receive,
                'deskripsi': deskripsi_receive,
                'tahun_pembuatan': tahun_pembuatan_receive,
            }
        }
    )
    return redirect(url_for('tambah'))

# Handle request delete_senjata
@app.route('/delete_senjata/<senjata_id>', methods=['GET'])
@admin_required
def delete_senjata(senjata_id):
    db.senjata.delete_one({'_id': ObjectId(senjata_id)})
    return redirect(url_for('tambah'))

returned_weapons_collection = db.pengembalian

@app.route('/pengembalian', methods=['GET', 'POST'])
def pengembalian():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        if request.method == 'POST':
            # Handle approval form submission
            senjata_id = request.form.get('senjata_id')
            approval_status = request.form.get('approval_status')

            # Update the approval status in the peminjam collection
            db.peminjam.update_one(
                {'senjata_id': senjata_id},
                {'$set': {'approval_status': approval_status}}
            )

        # Retrieve borrowed data with approval_status
        borrowed_data = list(db.peminjam.find({'nama_senjata': {'$exists': True}}))
        return render_template('pengembalian_senjata.html', borrowed_data=borrowed_data)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    

@app.route('/kembalikan_senjata/<senjata_id>', methods=['POST'])
def kembalikan_senjata(senjata_id):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        # Retrieve the borrowed weapon from the database
        borrowed_weapon = db.peminjam.find_one({'senjata_id': senjata_id})

        if borrowed_weapon:
            # Update the senjata collection with the returned quantity
            returned_quantity = borrowed_weapon['borrow_quantity']
            db.senjata.update_one(
                {'_id': ObjectId(senjata_id)},
                {'$inc': {'jumlah': returned_quantity}}
            )

            # Move the returned weapon information to the new pengembalian collection
            returned_weapon_info = {
                'nama_peminjam': borrowed_weapon['nama_peminjam'],
                'nama_senjata': borrowed_weapon['nama_senjata'],
                'senjata_id': senjata_id,
                'borrow_quantity': returned_quantity,
                'tanggal_pinjaman': borrowed_weapon['tanggal_pinjaman'],
                'tanggal_pengembalian': datetime.now(),
                'approval_status': borrowed_weapon.get('approval_status', 'Belum Disetujui')
            }
            db.pengembalian.insert_one(returned_weapon_info)

            # Remove the record from the peminjam collection
            db.peminjam.delete_one({'senjata_id': senjata_id})

            return redirect(url_for('pengembalian'))
        else:
            return "Senjata tidak ditemukan atau sudah dikembalikan."
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    
@app.route('/data_pengembalian', methods=['GET'])
@admin_required
def data_pengembalian():
    # Retrieve the returned weapons data from the pengembalian collection
    returned_weapons = list(db.pengembalian.find({'nama_senjata': {'$exists': True}}))

    return render_template('data_pengembalian.html', returned_weapons=returned_weapons)

@app.route('/senjata_dipinjam', methods=['GET', 'POST'])
def senjata_dipinjam():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        if request.method == 'POST':
            senjata_id = request.form.get('senjata_id')
            approval_status = request.form.get('approval_status')

            # Update the approval status in the peminjam collection
            db.peminjam.update_one(
                {'senjata_id': senjata_id},
                {'$set': {'approval_status': approval_status}}
            )

        # Retrieve borrowed data with approval_status
        borrowed_data = list(db.peminjam.find({'nama_senjata': {'$exists': True}}))

        return render_template('senjata_dipinjam.html', borrowed_data=borrowed_data)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    
    

@app.route('/batalkan_peminjaman/<senjata_id>', methods=['POST'])
def batalkan_peminjaman(senjata_id):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        # Mendapatkan informasi peminjaman
        borrowed_item = db.peminjam.find_one({'senjata_id': senjata_id})

        if borrowed_item:
            # Mengembalikan jumlah senjata yang dipinjam
            returned_quantity = borrowed_item['borrow_quantity']
            db.senjata.update_one(
                {'_id': ObjectId(senjata_id)},
                {'$inc': {'jumlah': returned_quantity}}
            )

            # Menghapus record dari peminjam collection
            db.peminjam.delete_one({'senjata_id': senjata_id})

            return redirect(url_for('senjata_dipinjam'))
        else:
            return "Peminjaman tidak ditemukan atau sudah selesai."
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    
@app.route('/tambah_perawatan', methods=['POST'])
def tambah_perawatan_post():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        nama_senjata = request.form.get('nama_senjata')
        tanggal_perawatan = request.form.get('tanggal_perawatan')
        nama_petugas = request.form.get('nama_petugas')
        keterangan = request.form.get('keterangan')

        doc = {
            'nama_senjata': nama_senjata,
            'tanggal_perawatan': tanggal_perawatan,
            'nama_petugas': nama_petugas,
            'keterangan': keterangan
        }

        db.perawatan.insert_one(doc)

        return redirect(url_for('tambah_perawatan'))
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))

@app.route('/data_perawatan', methods=['GET'])
@admin_required
def data_perawatan():
    maintenance_data = list(db.perawatan.find())
    return render_template('data_perawatan.html', maintenance_data=maintenance_data)
    
@app.route('/tambah_perawatan', methods=['GET'])
def tambah_perawatan():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        senjata_list = db.senjata.find()
        return render_template('perawatan_senjata.html', senjata_list=senjata_list)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))

@app.route('/tambah_artikel', methods=['POST'])
@admin_required
def tambah_artikel():
    nama_receive = request.form.get('nama_give')
    keterangan_gambar_receive = request.form.get('keterangan_gambar')
    keterangan_artikel_receive = request.form.get('keterangan_artikel')

    # Get the current date and time
    current_date = datetime.now()

    if 'gambar_artikel' in request.files:
        file = request.files.get('gambar_artikel')
        file_name = secure_filename(file.filename)
        picture_name = f"{file_name.split('.')[0]}[{nama_receive}].{file_name.split('.')[1]}"
        file_path = f'./static/img_artikel/{picture_name}'
        file.save(file_path)
    else:
        picture_name = 'default.jpg'

    doc = {
        'nama_artikel': nama_receive,
        'keterangan_gambar': keterangan_gambar_receive,
        'keterangan_artikel': keterangan_artikel_receive,
        'gambar_artikel': picture_name,
        'tanggal_upload': current_date
    }
    db.articles.insert_one(doc)

    return redirect(url_for('artikel'))


# Route for displaying articles
@app.route('/artikel')
@admin_required
def artikel():
    articles = list(db.articles.find().sort('_id', -1))
    return render_template('artikel.html', articles=articles)

# Route for updating an article
@app.route('/update_artikel/<article_id>', methods=['POST'])
@admin_required
def update_artikel(article_id):
    # Retrieve the existing article
    article = db.articles.find_one({'_id': ObjectId(article_id)})

    if article:
        # Get the updated data from the form
        nama_receive = request.form.get('nama_give')
        keterangan_gambar_receive = request.form.get('keterangan_gambar')
        keterangan_artikel_receive = request.form.get('keterangan_artikel')

        if 'gambar_artikel' in request.files:
            file = request.files.get('gambar_artikel')
            file_name = secure_filename(file.filename)
            picture_name = f"{file_name.split('.')[0]}[{nama_receive}].{file_name.split('.')[1]}"
            file_path = f'./static/img_artikel/{picture_name}'
            file.save(file_path)
        else:
            picture_name = article['gambar_artikel']

        # Update the article in the database
        db.articles.update_one(
            {'_id': ObjectId(article_id)},
            {
                '$set': {
                    'nama_artikel': nama_receive,
                    'keterangan_gambar': keterangan_gambar_receive,
                    'keterangan_artikel': keterangan_artikel_receive,
                    'gambar_artikel': picture_name
                }
            }
        )

        return redirect(url_for('artikel'))
    else:
        return "Artikel tidak ditemukan."

# Route for deleting an article
@app.route('/hapus_artikel/<article_id>', methods=['GET'])
@admin_required
def hapus_artikel(article_id):
    # Retrieve the article
    article = db.articles.find_one({'_id': ObjectId(article_id)})

    if article:
        # Delete the article from the database
        db.articles.delete_one({'_id': ObjectId(article_id)})

        # Remove the associated image file (optional)
        image_path = f"./static/img_artikel/{article['gambar_artikel']}"
        if os.path.exists(image_path):
            os.remove(image_path)

        return redirect(url_for('artikel'))
    else:
        return "Artikel tidak ditemukan."
    
@app.route('/artikel/<article_id>')
def artikel_detail(article_id):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        # Retrieve the specific article based on the provided article_id
        article = db.articles.find_one({'_id': ObjectId(article_id)})

        if article:
            return render_template('detail_artikel.html', article=article)
        else:
            return "Artikel tidak ditemukan."
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('index'))
    

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
