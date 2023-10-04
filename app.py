from flask import (Flask, request, jsonify, Response, render_template,
                   send_file, send_from_directory, redirect, flash, url_for)
import os, zipfile
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from os.path import getsize
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite DB location
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config["SECRET_KEY"] = "fksdly48thergl9#8%3@45t%u9834tu95$hgui$rfg49$t67"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)


# ---------------------- Database tables ---------------------- #

class Agents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(80))
    hostname = db.Column(db.String(80))
    username = db.Column(db.String(80))
    fqdn = db.Column(db.String(80))
    domain = db.Column(db.String(80))
    local_ip = db.Column(db.String(80))
    local_groups = db.Column(db.String(80))
    ad_groups = db.Column(db.String(80))
    file_path = db.Column(db.String(500))
    agent_creation = db.Column(db.DateTime)
    file_addition = db.Column(db.DateTime)


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

@app.route('/add_agent', methods=['POST'])
def add_agent():
    data = request.json
    new_agent = Agents(
        uid=data.get('uid', None),
        hostname=data.get('hostname', None),
        username=data.get('username', None),
        fqdn=data.get('fqdn', None),
        domain=data.get('domain', None),
        local_ip=data.get('local_ip', None),
        local_groups=data.get('local_groups', None),
        ad_groups=data.get('ad_groups', None),
        agent_creation=datetime.now().astimezone()
    )

    db.session.add(new_agent)
    db.session.commit()

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

    if mode == 'ab':
        return Response(status=206)  # Partial Content
    else:
        return jsonify({"message": "File uploaded successfully"}), 200


@app.route('/speedtest', methods=['POST'])
def speedtest():
    _ = request.data
    return "Speed test done"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('command'))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = True if request.form.get("remember_me") else False

        user = Administrator.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for('command'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template("login.html")


@login_manager.user_loader
def load_user(user_id):
    return Administrator.query.get(int(user_id))

# ---------------------- Protected Routes ---------------------- #

@app.route('/')
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


@app.route('/view_files/<uid>', defaults={'subpath': None}, methods=['GET'])
@app.route('/view_files/<uid>/<path:subpath>', methods=['GET'])
@login_required
def view_files(uid, subpath=None):
    agent = Agents.query.filter_by(uid=uid).first()
    if not agent:
        return "Agent not found", 404

    # Handle the subpath
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
    num_files = 0  # reset this variable
    for dirpath, dirnames, filenames in os.walk(base_path):
        num_files += len(filenames)

    total_files = sum([len(files) for _, _, files in os.walk(base_path)])

    return render_template("explorer.html", directories=directories, files=files, agent=agent, subpath=subpath,
                           breadcrumbs=breadcrumbs, total_size=total_size, num_files=num_files, total_files=total_files,
                           base_size=base_size)


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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

