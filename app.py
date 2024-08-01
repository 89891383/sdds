import base64
import datetime as dt
import hashlib
import hmac
import json
import requests
from urllib.parse import urlparse, quote
from flask import Flask, request, jsonify
from os import path

app = Flask(__name__)

# Constants and configuration
PLATFORM = "CDA"
VIDEO_SEARCH_URL = "https://api.cda.pl/video/search"
VIDEO_URL = "https://www.cda.pl/video/"
BASE_URL = "https://www.cda.pl"
LOGIN = "{{login}}"
PASSWORD = "{{password}}"
REQUEST_HEADERS = {
    'Accept': 'application/vnd.cda.public+json',
    'User-Agent': 'Mozilla/5.0'
}
BASE_AUTH = 'Basic NzdjMGYzYzUtMzZhMC00YzNkLWIwZDQtMGM0ZGZiZmQ1NmQ1Ok5wbU1MQldSZ3RFWDh2cDNLZjNkMHRhc0JwRnQwdHVHc3dMOWhSMHF0N2JRZGF4dXZER29jekZHZXFkNjhOajI'

# Load accounts from konta.txt file
account_file = "konta.txt"
accounts = []
with open(account_file, "r") as file:
    for line in file:
        parts = line.strip().split(":")
        if len(parts) == 2:
            accounts.append({"username": parts[0], "password": parts[1]})

# Define global variables for account management
cda_username = None
cda_password = None
current_account_index = 0

# Update credentials
def update_credentials():
    global cda_username, cda_password, current_account_index
    if current_account_index < len(accounts):
        account = accounts[current_account_index]
        cda_username = account["username"]
        cda_password = account["password"]
        current_account_index += 1
    else:
        print("All accounts from konta.txt have been used.")
        cda_username = None
        cda_password = None

# Initialize the credentials
update_credentials()

# Cache file for tokens
cache_file = "oauth.json"

# Function to get the bearer token
def get_bearer_token(username, password):
    if path.exists(cache_file):
        with open(cache_file, "r") as infile:
            file_data = json.load(infile)
            if username in file_data:
                access_token = file_data[username]
                if int(dt.datetime.now().timestamp()) < access_token['expiration_date']:
                    return access_token
    else:
        file_data = {}

    headers = REQUEST_HEADERS.copy()
    headers['Authorization'] = BASE_AUTH

    res = requests.post(
        f'https://api.cda.pl/oauth/token?grant_type=password&login={quote(username)}&password={password}',
        headers=headers)

    data = res.json()

    # Debug log the response data to understand its structure
    print(f"Response data: {data}")

    if 'expires_in' not in data:
        raise ValueError('Missing "expires_in" in response')

    now = dt.datetime.now()
    expires_in = dt.timedelta(seconds=data['expires_in'])
    expiration_time = now + expires_in

    data['expiration_date'] = int(expiration_time.timestamp())
    file_data[username] = data

    with open(cache_file, "w") as outfile:
        json.dump(file_data, outfile)
    return data

# Function to get video URLs for all qualities
def get_video_urls_all_qualities(video_url, bearer_token):
    headers = REQUEST_HEADERS.copy()
    headers['Authorization'] = 'Bearer ' + bearer_token['access_token']

    video_id = video_url.split('/')[-1]
    res = requests.get(f'https://api.cda.pl/video/{video_id}', headers=headers)
    video_json = res.json()['video']

    title = video_json['title']
    img = video_json.get('thumb_premium') or video_json.get('thumb')
    urls = [{'name': q['name'], 'url': q['file']} for q in video_json['qualities']]

    return title, img, urls

# Function to validate URI
def uri_validator(x):
    try:
        result = urlparse(x)
        if ("cda.pl" in result.netloc or "cda.pl" in result.path) and "/video/" in result.path:
            return True, result.netloc + result.path
    except:
        pass
    return False, None

# Function to get URLs
def get_urls(url):
    result, valid_url = uri_validator(url)
    if not result:
        print("Not correct URL to video on cda")
        return
    bearer_token = get_bearer_token(cda_username, cda_password)
    title, img, urls = get_video_urls_all_qualities(valid_url, bearer_token)
    print('\nTitle: ' + title)
    print('Img URL: ' + img)
    for x in urls:
        print('\t[' + x['name'] + ']' + x['url'])

# Define a list of allowed passwords
ALLOWED_PASSWORDS = ["8hT!kL#9pWz2sYd1"]

# Define the log file path
LOG_FILE = "request_logs.txt"

# Function to log the request with timestamp, IP address, and password
def log_request(password, ip_address):
    current_time = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{current_time}: IP Address - {ip_address}, Password Used - {password}\n"
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

@app.route('/cda', methods=['POST'])
def generate_link():
    try:
        if 'X-Api-Password' not in request.headers:
            return jsonify({'error': 'Authentication required'}), 401

        provided_password = request.headers['X-Api-Password']
        if provided_password not in ALLOWED_PASSWORDS:
            return jsonify({'error': 'Authentication failed'}), 401

        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL not provided'}), 400

        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

        if cda_username is None or cda_password is None:
            return jsonify({'error': 'No accounts available'}), 503

        bearer_token = get_bearer_token(cda_username, cda_password)
        title, img, urls = get_video_urls_all_qualities(url, bearer_token)

        response_data = {
            'title': title,
            'img_url': img,
            'urls': [{'name': x['name'], 'url': x['url']} for x in urls]
        }

        log_request(provided_password, client_ip)
        return jsonify(response_data)

    except Exception as e:
        update_credentials()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=80)
