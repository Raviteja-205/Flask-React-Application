from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
from datetime import timedelta
from auth_decorator import login_required

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="296182337755-d178m2emeaimc8l6k8o4g64eo8fot8kj.apps.googleusercontent.com",
    client_secret="sL_L673Kh7Ki_HpIXxT4__3G",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)


@app.route('/')
@login_required
def hello_world():
    email = dict(session)['profile']['email']
    return f'Hello, you are logge in as {email}!'


@app.route('/login')
def login():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    user = oauth.google.userinfo()  
    session['profile'] = user_info
    session.permanent = True
    return redirect('/')


@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')