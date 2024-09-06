from flask import Flask, request, jsonify, session, render_template, redirect, url_for, make_response
from flask_session import Session
from flask_socketio import SocketIO, emit
from datetime import timedelta, datetime, timezone
import logging
import redis
import psutil
import os

# Flask app setup
app = Flask(__name__)
app.secret_key = 'edf33b76ceb7f476e54370031b3180865268a3b679dfb614'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session/'
app.config['SESSION_PERMANENT'] = False
app.config['DEBUG'] = True  # Enable debug mode for development

# Initialize session and socket
Session(app)
socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Redis client
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Rate limit settings
RATE_LIMIT_REQUESTS = 5  # Maximum requests allowed within the window
RATE_LIMIT_WINDOW = timedelta(minutes=1)  # 1-minute window for rate limiting

# Unique identifier key for tracking the initial session
INITIAL_SESSION_KEY = "initial_chatbot_session"

def get_or_create_device_id():
    """Retrieve or create a unique device identifier."""
    device_id = request.cookies.get('device_id')
    if not device_id:
        # Generate a unique device ID if it doesn't exist
        device_id = f"device-{os.urandom(8).hex()}"
    return device_id

@app.before_request
def before_request():
    """Attach device ID before handling requests."""
    device_id = get_or_create_device_id()
    session['device_id'] = device_id

def track_user_requests(user_id):
    """Track and limit the number of requests per user using Redis."""
    current_time = datetime.now(timezone.utc)
    current_timestamp = int(current_time.timestamp())
    window_start_timestamp = current_timestamp - int(RATE_LIMIT_WINDOW.total_seconds())
    
    # Define Redis key
    redis_key = f"rate_limit:{user_id}"

    # Get existing request timestamps from Redis
    request_timestamps = redis_client.lrange(redis_key, 0, -1)
    
    # Convert timestamps to integers and remove old timestamps
    request_timestamps = [int(ts) for ts in request_timestamps if int(ts) > window_start_timestamp]
    
    # Add the current request timestamp
    request_timestamps.append(current_timestamp)

    # Check if the request limit is exceeded
    if len(request_timestamps) > RATE_LIMIT_REQUESTS:
        # Calculate remaining time for rate limit
        rate_limit_expiry = redis_client.get(f"{redis_key}:expiry")

        if rate_limit_expiry is None:
            # Set expiry if not already set
            rate_limit_expiry = current_timestamp + int(RATE_LIMIT_WINDOW.total_seconds())
            redis_client.set(f"{redis_key}:expiry", rate_limit_expiry, ex=int(RATE_LIMIT_WINDOW.total_seconds()))
        else:
            rate_limit_expiry = int(rate_limit_expiry)

        time_remaining = rate_limit_expiry - current_timestamp
        redis_client.ltrim(redis_key, 0, RATE_LIMIT_REQUESTS - 1)  # Keep only recent requests
        return True, time_remaining

    # Update the request timestamps in Redis
    redis_client.delete(redis_key)  # Clear previous values
    redis_client.rpush(redis_key, *request_timestamps)
    redis_client.expire(redis_key, int(RATE_LIMIT_WINDOW.total_seconds()))  # Set TTL
    
    # Remove any existing expiry key if the user is not rate limited
    redis_client.delete(f"{redis_key}:expiry")

    # User has not exceeded the request limit
    return False, None

def is_first_session():
    """Check if the current session is the first session to open the chatbot."""
    device_id = session.get('device_id')
    session_key = f"{INITIAL_SESSION_KEY}:{device_id}"
    initial_session = redis_client.get(session_key)

    if initial_session:
        if initial_session == session.get('initial_session'):
            return True
        else:
            return False
    else:
        # No session recorded, set this session as the initial one
        session['initial_session'] = session.sid
        redis_client.set(session_key, session.sid, ex=60*10)  # Store the session ID with an expiry of 10 minutes
        return True

@app.route('/')
def index():
    """Render the main chat interface or handle rate limiting."""
    user_id = request.remote_addr  # Using IP as user_id (you can change this to session ID or another identifier)
    is_rate_limited, time_remaining = track_user_requests(user_id)

    if is_rate_limited:
        return redirect(url_for('rate_limit_exceeded', time_remaining=int(time_remaining)))
    
    # Check if the initial session key matches the current session ID
    if is_first_session():
        return render_template('try.html')
    else:
        return redirect(url_for('already_open'))

@app.route('/already_open')
def already_open():
    """Render the page indicating the chatbot is already open in another session."""
    return render_template('already_open.html')

@app.route('/set_location', methods=['POST'])
def set_location():
    """Set user location in the session."""
    user_location = request.json
    logging.debug(f"Setting user location: {user_location}")
    session['user_location'] = user_location

    # Update timestamp for last activity
    session['last_update'] = datetime.now(timezone.utc).isoformat()

    return jsonify({'status': 'location set'})

@app.route('/clear_session', methods=['POST'])
def clear_session():
    """Clear the session data selectively."""
    user_location = session.get('user_location')

    # Clear the session data
    session.clear()

    # Clear the initial session key from Redis if the session ID matches
    if redis_client.get(INITIAL_SESSION_KEY) == session.sid:
        redis_client.delete(INITIAL_SESSION_KEY)

    # Restore the user location in the session
    if user_location:
        session['user_location'] = user_location

    return jsonify({'status': 'session cleared'})

@app.route('/rate_limit_exceeded')
def rate_limit_exceeded():
    """Render the rate limit exceeded page."""
    user_id = request.remote_addr
    redis_key = f"rate_limit:{user_id}:expiry"

    # Get the exact remaining time from Redis
    rate_limit_expiry = redis_client.get(redis_key)
    if rate_limit_expiry is None:
        time_remaining = 60
    else:
        current_time = datetime.now(timezone.utc)
        current_timestamp = int(current_time.timestamp())
        time_remaining = int(rate_limit_expiry) - current_timestamp

    return render_template('rate_limit_exceeded.html', time_remaining=max(time_remaining, 0))

@app.route('/track_tab', methods=['POST'])
def track_tab():
    """Track and validate the tab identifier."""
    tab_id = request.json.get('tabId')
    device_id = session.get('device_id')
    redis_key = f"{session.sid}:{device_id}:tab_id"

    redis_tab_id = redis_client.get(redis_key)

    if redis_tab_id is None:
        redis_client.set(redis_key, tab_id, ex=60*10)
        return jsonify({'status': 'allowed'})

    if redis_tab_id != tab_id:
        return jsonify({'redirect': True, 'redirect_url': url_for('already_open')})

    return jsonify({'status': 'allowed'})

@app.after_request
def after_request(response):
    """Set device ID in cookies after each request."""
    device_id = session.get('device_id')
    if device_id:
        response.set_cookie('device_id', device_id, max_age=60*60*24*30)  # Cookie expires in 30 days
    return response

if __name__ == '__main__':
    logging.info("Starting Flask app on http://127.0.0.1:4180")
    socketio.run(app, host='0.0.0.0', port=4180, debug=True)


