from flask import Flask, request, redirect, render_template, make_response
from flask_socketio import SocketIO, emit
import redis
import uuid
import logging
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='gevent')
r = redis.Redis(host='localhost', port=6379, db=0)

logging.basicConfig(level=logging.DEBUG)

def get_unique_id():
    return str(uuid.uuid4())

def get_redis_key(device_id):
    return f'session_{device_id}'

@app.route('/')
def index():
    device_id = request.cookies.get('device_id')
    user_ip = request.remote_addr

    if not device_id:
        # Generate a new unique device_id if it doesn't exist
        device_id = get_unique_id()
        response = make_response(render_template('index.html'))
        response.set_cookie('device_id', device_id)
        session_data = {
            'chatbot_status': 'open',
            'device_ids': [device_id]
        }
        r.set(get_redis_key(device_id), json.dumps(session_data))
        logging.debug(f"New session created with Device ID: {device_id}")
        return response
    else:
        session_key = get_redis_key(device_id)
        session_data = r.get(session_key)
        if session_data:
            session_data = json.loads(session_data)
            if session_data['chatbot_status'] == 'open':
                logging.debug("Chatbot already open, redirecting to already_open")
                return redirect('/already_open')
            else:
                # Update session data
                session_data['chatbot_status'] = 'open'
                r.set(session_key, json.dumps(session_data))
                response = make_response(render_template('index.html'))
                response.set_cookie('device_id', device_id)
                logging.debug(f"Session continued with Device ID: {device_id}")
                return response
        else:
            # If session data does not exist, create it
            session_data = {
                'chatbot_status': 'open',
                'device_ids': [device_id]
            }
            r.set(session_key, json.dumps(session_data))
            response = make_response(render_template('index.html'))
            response.set_cookie('device_id', device_id)
            logging.debug(f"New session created with Device ID: {device_id}")
            return response

@app.route('/already_open')
def already_open():
    return "Chatbot is already open in another tab or window."

@socketio.on('connect')
def handle_connect():
    device_id = request.cookies.get('device_id')
    if device_id:
        session_key = get_redis_key(device_id)
        session_data = r.get(session_key)
        if session_data:
            session_data = json.loads(session_data)
            connection_count = session_data.get('connection_count', 0) + 1
            session_data['connection_count'] = connection_count
            r.set(session_key, json.dumps(session_data))
            logging.debug(f"Device connected: {device_id}")
            logging.debug(f"Current connection count: {connection_count}")
            emit('connected', {'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    device_id = request.cookies.get('device_id')
    if device_id:
        session_key = get_redis_key(device_id)
        session_data = r.get(session_key)
        if session_data:
            session_data = json.loads(session_data)
            connection_count = session_data.get('connection_count', 0) - 1
            if connection_count <= 0:
                # Clear session data when no active connections remain
                r.delete(session_key)
                logging.debug(f"Session cleared for Device ID: {device_id}")
            else:
                session_data['connection_count'] = connection_count
                r.set(session_key, json.dumps(session_data))
            logging.debug(f"Device disconnected: {device_id}")
            logging.debug(f"Current connection count: {connection_count}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=4180, debug=True)
