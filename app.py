from flask import Flask, request, jsonify, Response, render_template
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite DB location
db = SQLAlchemy(app)


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
    agent_creation = db.Column(db.DateTime)
    file_addition = db.Column(db.DateTime)


with app.app_context():
    db.create_all()


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

    if uid:
        app.logger.info(f"Received UID: {uid}")
    else:
        app.logger.error("No UID provided in the request")
        return jsonify({"error": "No UID provided in the request"}), 400

    if not file:
        app.logger.error("No file part in the request")
        return jsonify({"error": "No file part in the request"}), 400

    # Use UID to keep a consistent filename
    unique_filename = f"{uid}.zip"

    # Check for Content-Range header
    range_header = request.headers.get('Content-Range', '').strip()
    beginning_bytes = 0
    if range_header.startswith('bytes '):
        beginning_bytes, _ = range_header[len('bytes '):].split('-')
        beginning_bytes = int(beginning_bytes.strip())

    filepath = os.path.join(os.getcwd(), unique_filename)

    # Handle resumable upload (append to file)
    mode = 'ab' if beginning_bytes else 'wb'
    with open(filepath, mode) as f:
        if mode == 'ab':
            f.seek(beginning_bytes)
        f.write(file.read())

    app.logger.info(f"File saved to {filepath}")

    if mode == 'ab':
        return Response(status=206)  # Partial Content
    else:
        return jsonify({"message": "File uploaded successfully"}), 200


@app.route('/speedtest', methods=['POST'])
def speedtest():
    _ = request.data
    return "Speed test done"


# ---------------------- Protected Routes ---------------------- #
@app.route('/')
def command():
    agents = Agents.query.all()
    return render_template('command.html', active='command', agents=agents)


@app.route('/logout')
def logout():
    return 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

