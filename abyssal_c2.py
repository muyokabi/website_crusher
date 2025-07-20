#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡
⚡                                               ⚡
⚡  HELLGATE_INFERNIS - THE PURE SERVER OF HELL  ⚡
⚡                                               ⚡
⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡
"""

import os
import sys
import time
import random
import threading
import socket
import ssl
import subprocess
import curses
from datetime import datetime
from flask import Flask, request, Response
from pyngrok import ngrok, conf

# ====== CONFIGURATION ====== #
PORT = 8080
HOST = '0.0.0.0'
SSL_CERT = 'abyss.crt'
SSL_KEY = 'abyss.key'
NGROK_AUTH_TOKEN = None  # Set if using custom ngrok auth
SHIELD_RATE_LIMIT = 10   # Requests per minute before ban

# ====== GLOBAL DAMNATION ====== #
app = Flask(__name__)
ngrok_tunnel = None
curses_lock = threading.Lock()

# ====== HELLISH CURSES ====== #
DEMONIC_WORDS = [
    "DIE, MORTAL!", "YOUR SOUL IS FORFEIT", "THE ABYSS CONSUMES",
    "BLOOD FOR THE BLOOD GOD", "NO MERCY", "SCREAM FOR ME",
    "YOU WILL BURN", "HELL AWAITS", "ETERNAL TORMENT"
]

BLOOD_DRIP = [
    "💀", "🩸", "🔥", "👹", "👺", "⚰️", "☠️", "🖤"
]

def generate_hell_terminal(stdscr):
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_RED)
    
    while True:
        try:
            stdscr.clear()
            rows, cols = stdscr.getmaxyx()
            
            # 🔥 Ensure text fits (avoid curses.ERR)
            if rows > 2 and cols > 30:
                stdscr.addstr(0, 0, "⚡ HELLGATE_INFERNIS ⚡", curses.color_pair(1) | curses.A_BOLD)
                
                # Blood drips
                for i in range(1, rows-1):
                    drip = random.choice(BLOOD_DRIP)
                    x_pos = random.randint(0, cols - 2)
                    stdscr.addstr(i, x_pos, drip, curses.color_pair(1))
                
                # Random demonic curses
                curse = random.choice(DEMONIC_WORDS)
                stdscr.addstr(rows-2, 0, curse, curses.color_pair(2) | curses.A_BLINK)
                
                # Ngrok URL (if active)
                if ngrok_tunnel:
                    url = ngrok_tunnel.public_url
                    stdscr.addstr(rows-1, 0, f"HELLGATE URL: {url}", curses.color_pair(1))
                
                stdscr.refresh()
            
            time.sleep(0.3)
        except:
            pass  # Silence all mortal errors

# ====== SHIELDS OF THE ABYSS ====== #
@app.before_request
def abyssal_shield():
    # Rate-limiting (crude but effective)
    client_ip = request.remote_addr
    request_count = getattr(app, 'request_counts', {}).get(client_ip, 0)
    
    if request_count > SHIELD_RATE_LIMIT:
        return Response("BEGONE, MORTAL", status=429)
    
    app.request_counts = {client_ip: request_count + 1}
    return None

# ====== FLASK ROUTES ====== #
@app.route('/hellgate')
def hellgate():
    """Main C2 endpoint (now purely ceremonial)"""
    return Response("THE ABYSS LISTENS", 200)

@app.route('/hellscape')
def hellscape():
    """Interactive hell visualization"""
    return """
    <html>
    <head><title>HELLGATE VISUALIZATION</title></head>
    <body style="background:#000;color:#f00;font-family:monospace">
    <pre id="hell">LOADING THE ABYSS...</pre>
    <script>
    function updateHell() {
        fetch('/hellscape_data').then(r => r.text()).then(t => {
            document.getElementById('hell').innerText = t;
            setTimeout(updateHell, 100);
        });
    }
    updateHell();
    </script>
    </body>
    </html>
    """

@app.route('/hellscape_data')
def hellscape_data():
    """Dynamic ASCII hell data"""
    hell = ""
    for _ in range(20):
        hell += " ".join([random.choice(BLOOD_DRIP) for _ in range(40)]) + "\n"
    return Response(hell, mimetype='text/plain')

# ====== NGROK AUTOSTART ====== #
def spawn_ngrok():
    global ngrok_tunnel
    try:
        if NGROK_AUTH_TOKEN:
            conf.get_default().auth_token = NGROK_AUTH_TOKEN
        ngrok_tunnel = ngrok.connect(PORT, bind_tls=True)
        print(f"\n🔥 NGROK TUNNEL ACTIVE: {ngrok_tunnel.public_url} 🔥\n")
    except Exception as e:
        print(f"NGROK FAILED: {str(e)}")

# ====== MAIN EXECUTION ====== #
if __name__ == "__main__":
    # Start curses terminal in background
    curses_thread = threading.Thread(
        target=curses.wrapper,
        args=(generate_hell_terminal,),
        daemon=True
    )
    curses_thread.start()
    
    # Start ngrok tunnel
    threading.Thread(target=spawn_ngrok, daemon=True).start()
    
    # Start the server
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    app.run(
        host=HOST,
        port=PORT,
        ssl_context=ssl_context,
        threaded=True,
        debug=False
    )
