from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import openai
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from werkzeug.security import generate_password_hash, check_password_hash
import googleapiclient.discovery


# Load environment variables from .env
load_dotenv()

# Set up OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    print("Error: OPENAI_API_KEY not found in environment variables")

# Initialize Flask app
app = Flask(__name__)

# MongoDB Setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database('myDatabase')  # Example of accessing the database
users_collection = db['users']  # Collection for storing user details

# Flask Session Setup
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.getenv("SESSION_SECRET")
Session(app)

# Function to get AI response using OpenAI API
def get_ai_response(prompt):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an AI assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=100,
        )
        # Accessing the response content might need adjustment based on the library version
        return response.choices[0].message['content'].strip()
    except Exception as e:
        print(f"Error fetching AI response: {e}")
        return "Error communicating with AI."


# Route to serve the landing page with the login button
@app.route('/')
def landing_page():
    return render_template('login.html')  # This will render the login page with the Google login button

# Route to serve the AI page after login
@app.route('/ai_page')
def ai_page():
    if 'credentials' not in session:
        return redirect(url_for('login'))

    # Fetch the user's name from the session
    user_name = session.get('name', 'User')
    
    return render_template('index.html', user_name=user_name)



# Route to handle user input and return the AI's response
@app.route('/get_response', methods=['POST'])
def get_response():
    try:
        # Check if the request has JSON data
        if not request.is_json:
            return jsonify({"response": "Invalid request format. JSON required."}), 400
        
        user_input = request.json.get('message', None)
        
        # Check if 'message' key is present in the JSON data
        if not user_input:
            return jsonify({"response": "Missing 'message' in request data."}), 400

        # Log the input to see if it's received
        print(f"Received message: {user_input}")

        # Get the AI response
        response = get_ai_response(user_input)

        # Log the response to ensure it's working
        print(f"AI response: {response}")

        return jsonify({"response": response})

    except Exception as e:
        # Log any exceptions for debugging
        print(f"Error: {str(e)}")
        return jsonify({"response": "Error communicating with AI."}), 500


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
# Route to handle Google OAuth callback
@app.route('/callback')
def callback():
    state = session.get('state')
    if not state:
        return redirect(url_for('login'))

    # Set up the OAuth2 flow
    flow = Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/userinfo.profile'],
        state=state,
        redirect_uri=url_for('callback', _external=True, _scheme='https')
    )
    
    # Fetch the OAuth2 token
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    try:
        # Access Google API to get the user's profile information
        userinfo_service = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
        user_info = userinfo_service.userinfo().get().execute()
        
        # Store the user's name and email in the session
        session['name'] = user_info.get('name', 'User')
        session['email'] = user_info.get('email', '')
        
        # Store user details in MongoDB or update if necessary
        email = user_info.get('email')
        if email:
            users_collection.update_one(
                {'email': email},
                {'$set': {'name': user_info.get('name', 'User')}},
                upsert=True
            )
    except Exception as e:
        print(f"Error fetching user info: {e}")
        return redirect(url_for('login'))  # Redirect to login if there is an error
    
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

# Route to handle user signup with email and password
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        # Store the user in MongoDB
        users_collection.insert_one({'email': email, 'password': hashed_password})
        session['email'] = email
        return redirect(url_for('ai_page'))

    return render_template('signup.html')

# Route to handle user login with email and password
@app.route('/login_email', methods=['GET', 'POST'])
def login_email():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the user exists in MongoDB
        user = users_collection.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session['email'] = email
            return redirect(url_for('ai_page'))
        else:
            return "Invalid credentials, try again."

    return render_template('login_email.html')

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
    app.run(
        port=int(os.getenv("PORT")),
        debug=True,
        ssl_context=(
            'C:/Users/Saptarshi/Desktop/Riddhika/PEM/cert.pem',
            'C:/Users/Saptarshi/Desktop/Riddhika/PEM/privkey.pem'
        )
    )
