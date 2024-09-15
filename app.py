from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import openai
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

# Load environment variables from .env
load_dotenv()

# Set up OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

# Initialize Flask app
app = Flask(__name__)

# MongoDB Setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database('myDatabase')  # Example of accessing the database

# Flask Session Setup
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.getenv("SESSION_SECRET")
Session(app)

# Function to get AI response using OpenAI API
def get_ai_response(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are an AI assistant."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=100,
    )
    return response.choices[0].message['content'].strip()

# Route to serve the landing page with the login button
@app.route('/')
def landing_page():
    return render_template('login.html')  # This will render the login page with the Google login button

# Route to serve the AI page after login
@app.route('/ai_page')
def ai_page():
    # Check if the user is authenticated
    if 'credentials' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# Route to handle user input and return the AI's response
@app.route('/get_response', methods=['POST'])
def get_response():
    user_input = request.json['message']
    response = get_ai_response(user_input)
    return jsonify({"response": response})

# Route to handle Google OAuth login
@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/userinfo.profile'],
        redirect_uri=url_for('callback', _external=True, _scheme='https')  # Ensure HTTPS
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

# Route to handle Google OAuth callback
@app.route('/callback')
def callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/userinfo.profile'],
        state=state,
        redirect_uri=url_for('callback', _external=True, _scheme='https')  # Ensure HTTPS
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('ai_page'))

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Route to test MongoDB connection
@app.route('/test_mongo')
def test_mongo():
    try:
        collection = db['capsules']
        document = collection.find_one()

        if document:
            if '_id' in document:
                document['_id'] = str(document['_id'])
            return jsonify({"status": "success", "data": document}), 200
        else:
            return jsonify({"status": "success", "message": "No documents found"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(port=int(os.getenv("PORT")), debug=True)
