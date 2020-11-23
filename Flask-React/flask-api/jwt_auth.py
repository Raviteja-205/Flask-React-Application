from flask import Flask, jsonify, request, make_response, render_template
from functools import wraps
import jwt
import datetime
from flask import session
import configparser


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisthesecretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('profile', None)
        # You would add a check here and usethe user id or something to fetch
        # the other data for that user/check if they exist
        if user:
            return f(*args, **kwargs)
        return 'You aint logged in, no page for u!'
    return decorated_function

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message' : 'This is only available for people with valid tokens.'})


@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('signin.html')
    else:
        return 'Currently logged in'

@app.route('/login', methods=['POST'])
def login():
    # auth = request.authorization
    if request.form['username'] and request.form['password'] == 'secret':
        token = jwt.encode({'user' : request.form['username'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=60)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    else:
        return "Could not verify - Wrong Password"

if __name__ == '__main__':
    app.run(debug=True)