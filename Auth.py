import os
import pathlib
from urllib.parse import quote_plus
import requests
from flask import Blueprint, render_template, flash, url_for, session, abort, redirect, request,Flask
from Model import User
from werkzeug.security import generate_password_hash, check_password_hash
from init import db   
from flask_login import login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import random
import string
from pip._vendor import cachecontrol
from flask_migrate import Migrate





app = Flask("__name__")


route = Blueprint('route', __name__)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
migrate = Migrate(app, db)


client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret_456919260803-h9q8ulaac3tdd84snip522kd0t695akt.apps.googleusercontent.com.json")

GOOGLE_CLIENT_ID = "456919260803-h9q8ulaac3tdd84snip522kd0t695akt.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)




@route.route('/login-by-google')
def login_bygoogle():

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@route.route('/callback')
def callback():



    flow.fetch_token(authorization_response=request.url)



    if not session["state"] == request.args["state"]:
        abort(500)  



    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
        
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        plain_password = ''.join(random.choice(string.ascii_letters) for i in range(10))
        hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')



        new_user = User(
            email=session["email"],
            first_name=session["name"],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    flash('Logged in successfully!', category='success')
    login_user(user, remember=True)
    return redirect(url_for('show.home'))  



@route.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('login.html')


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()



    return wrapper

@route.route('/telegram')
@login_required
def telegram():
    message = f" Name: {current_user.first_name}\nEmail: {current_user.email}\n messages: {current_user.id} here is your messages: \n Your ID in web site is : {current_user.id}"
    encoded_message = quote_plus(message)

    url_to_share = url_for('show.home', _external=True)

    telegram_url = f"https://t.me/share/url?url={quote_plus(url_to_share)}&text={encoded_message}"

    return redirect(telegram_url)
