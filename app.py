from flask import Flask, request, jsonify, Response
import os

app = Flask(__name__)


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


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

