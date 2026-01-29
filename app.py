#!/usr/bin/env python3
import asyncio, os, re, json, time, logging
from aiohttp import web
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, SessionExpiredError
from telethon.sessions import StringSession
import threading

# ================= CONFIG =================
BYPASS_BOT = "Nick_Bypass_Bot"   # without @
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))  # Render default port

# Regex patterns
ORIGINAL_RE = re.compile(r"Original Link.*?(https?://\S+)", re.S)
BYPASSED_RE = re.compile(r"Bypassed Link.*?(https?://\S+)", re.S)

# ================= GLOBAL =================
client = None
HISTORY = []
API_PENDING = {}
SESSION_STRING = None  # Store session as string for Render
LOGGED_IN = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================= HTML =================
def page(body):
    return web.Response(
        text=f"""
<html>
<head>
<title>KAALIX Bypasser</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {{ 
    background: linear-gradient(135deg, #0f0f0f 0%, #1a1a2e 100%);
    color: #fff;
    font-family: 'Segoe UI', Arial, sans-serif;
    margin: 0;
    padding: 20px;
    min-height: 100vh;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}}
.header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 15px;
    border-bottom: 2px solid #00ffcc;
}}
h1 {{ color: #00ffcc; margin: 0; }}
h2 {{ color: #fff; }}
button, input {{
    padding: 12px 20px;
    margin: 8px 0;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    transition: all 0.3s;
}}
input {{
    background: rgba(255,255,255,0.1);
    color: white;
    border: 1px solid #333;
    width: 100%;
    box-sizing: border-box;
}}
button {{
    background: #00cc66;
    color: white;
    cursor: pointer;
    font-weight: bold;
}}
button:hover {{ background: #00b359; transform: translateY(-2px); }}
button.logout {{ background: #ff4444; }}
button.logout:hover {{ background: #cc0000; }}
.api-box {{
    background: rgba(0,0,0,0.3);
    border: 1px solid #333;
    border-radius: 10px;
    padding: 25px;
    margin: 25px 0;
    box-shadow: 0 4px 15px rgba(0,0,0,0.5);
}}
pre {{
    background: rgba(0,0,0,0.5);
    padding: 15px;
    border-radius: 8px;
    overflow-x: auto;
    color: #00ffcc;
    border: 1px solid #333;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    background: rgba(0,0,0,0.2);
    border-radius: 8px;
    overflow: hidden;
}}
th {{
    background: rgba(0,255,204,0.1);
    padding: 15px;
    text-align: left;
    font-weight: bold;
    color: #00ffcc;
}}
td {{
    padding: 15px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
    word-break: break-all;
}}
tr:hover td {{ background: rgba(255,255,255,0.05); }}
a {{ color: #00ffcc; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.login-container {{
    max-width: 500px;
    margin: 50px auto;
    padding: 40px;
    background: rgba(0,0,0,0.4);
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
}}
.alert {{
    padding: 15px;
    border-radius: 8px;
    margin: 20px 0;
    background: rgba(255,68,68,0.2);
    border-left: 4px solid #ff4444;
    color: #ff9999;
}}
.success {{
    background: rgba(0,204,102,0.2);
    border-left: 4px solid #00cc66;
    color: #99ffcc;
}}
.info-box {{
    background: rgba(0,255,204,0.1);
    padding: 15px;
    border-radius: 8px;
    margin: 15px 0;
}}
.status-badge {{
    display: inline-block;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 14px;
    font-weight: bold;
    margin-left: 10px;
}}
.status-online {{ background: #00cc66; }}
.status-offline {{ background: #ff4444; }}
</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>
""",
        content_type="text/html"
    )

# ================= SESSION MANAGEMENT =================
def save_session_to_env():
    """Save session string to environment variable (for Render)"""
    if SESSION_STRING:
        # In Render, you can't permanently save to env, but we can log it
        logger.info("SESSION_STRING (copy this for next deployment):")
        logger.info(SESSION_STRING)
        # Save to a temporary file (ephemeral storage)
        with open("/tmp/telethon_session.txt", "w") as f:
            f.write(SESSION_STRING)

def load_session_from_env():
    """Load session from environment or file"""
    global SESSION_STRING, LOGGED_IN
    
    # Try from environment variable first
    SESSION_STRING = os.environ.get("TELEGRAM_SESSION_STRING", "")
    
    # Try from file
    if not SESSION_STRING and os.path.exists("/tmp/telethon_session.txt"):
        with open("/tmp/telethon_session.txt", "r") as f:
            SESSION_STRING = f.read().strip()
    
    if SESSION_STRING:
        LOGGED_IN = True
        return True
    return False

# ================= ROUTES =================
async def home(request):
    global LOGGED_IN, client
    
    if not LOGGED_IN:
        return web.HTTPFound('/loginkaalix')
    
    # Check if client is connected
    status = "🟢 Online" if client and client.is_connected() else "🔴 Offline"
    
    rows = ""
    for h in reversed(HISTORY[-20:]):
        rows += f"""
        <tr>
            <td><a href="{h['original']}" target="_blank">{h['original'][:80]}...</a></td>
            <td><a href="{h['bypassed']}" target="_blank">{h['bypassed'][:80]}...</a></td>
        </tr>
        """
    
    if not rows:
        rows = """
        <tr>
            <td colspan="2" style="text-align:center; color:#888; padding:40px;">
                📭 No bypass history yet. Use the API to get started!
            </td>
        </tr>
        """
    
    return page(f"""
    <div class="header">
        <h1>🔓 KAALIX LINK BYPASSER <span class="status-badge status-online">{status}</span></h1>
        <form method="post" action="/logout">
            <button type="submit" class="logout">🚪 Logout</button>
        </form>
    </div>
    
    <div class="api-box">
        <h2>📡 API ENDPOINT</h2>
        <div class="info-box">
            <p><strong>URL:</strong> <code>GET {request.scheme}://{request.host}/bypass</code></p>
            <p><strong>Parameter:</strong> <code>?link=YOUR_URL_HERE</code></p>
            <p><strong>Example:</strong> <code>{request.scheme}://{request.host}/bypass?link=https://example.com/restricted-link</code></p>
        </div>
        
        <h3>📝 Example Response:</h3>
        <pre>
{{
  "success": true,
  "original": "https://example.com/restricted-link",
  "bypassed": "https://direct-link.com/file",
  "timestamp": "2024-01-15T12:00:00"
}}</pre>
        
        <h3>🔧 cURL Example:</h3>
        <pre>
curl "{request.scheme}://{request.host}/bypass?link=https://your-link-here.com"</pre>
    </div>
    
    <h2>📜 RECENT HISTORY ({len(HISTORY)})</h2>
    <table>
        <thead>
            <tr>
                <th width="50%">Original Link</th>
                <th width="50%">Bypassed Link</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    
    <div style="margin-top: 30px; text-align: center; color: #888; font-size: 14px;">
        🔄 Server Time: {time.strftime('%Y-%m-%d %H:%M:%S')} | 
        📊 Total Requests: {len(HISTORY)} |
        ⚡ Powered by Telethon
    </div>
    """)

async def login(request):
    global LOGGED_IN
    
    # If already logged in with valid session
    if LOGGED_IN:
        return web.HTTPFound('/')
    
    if request.method == "GET":
        # Try to load existing session
        if load_session_from_env():
            return web.HTTPFound('/')
        
        return page("""
        <div class="login-container">
            <h1 style="text-align: center;">🔐 LOGIN TO TELEGRAM</h1>
            <p style="text-align: center; color: #aaa; margin-bottom: 30px;">
                Get your API credentials from <a href="https://my.telegram.org" target="_blank">my.telegram.org</a>
            </p>
            
            <form method="post">
                <label for="api_id">📱 API ID:</label>
                <input type="number" id="api_id" name="api_id" required placeholder="123456">
                
                <label for="api_hash" style="margin-top: 20px;">🔑 API HASH:</label>
                <input type="text" id="api_hash" name="api_hash" required placeholder="a1b2c3d4e5f6...">
                
                <label for="phone" style="margin-top: 20px;">📞 PHONE NUMBER:</label>
                <input type="text" id="phone" name="phone" required placeholder="+919876543210">
                
                <button type="submit" style="width: 100%; margin-top: 25px; padding: 15px;">
                    📲 SEND OTP
                </button>
            </form>
            
            <div class="info-box" style="margin-top: 25px;">
                <strong>💡 Note:</strong> This will create a Telegram session that will be stored temporarily. 
                For persistent login, save the session string shown after successful login.
            </div>
        </div>
        """)
    
    else:  # POST request
        try:
            data = await request.post()
            api_id = int(data.get("api_id", 0))
            api_hash = data.get("api_hash", "").strip()
            phone = data.get("phone", "").strip()
            
            if not all([api_id, api_hash, phone]):
                return page("""
                <div class="login-container">
                    <div class="alert">❌ All fields are required!</div>
                    <a href="/loginkaalix"><button style="width:100%">← Back</button></a>
                </div>
                """)
            
            # Store in session for next steps
            request.app['login_data'] = {
                'api_id': api_id,
                'api_hash': api_hash,
                'phone': phone
            }
            
            return web.HTTPFound('/otp')
            
        except Exception as e:
            return page(f"""
            <div class="login-container">
                <div class="alert">❌ Error: {str(e)}</div>
                <a href="/loginkaalix"><button style="width:100%">← Try Again</button></a>
            </div>
            """)

async def otp(request):
    global client
    
    login_data = request.app.get('login_data')
    if not login_data:
        return web.HTTPFound('/loginkaalix')
    
    if request.method == "GET":
        return page(f"""
        <div class="login-container">
            <h1 style="text-align: center;">📱 ENTER OTP</h1>
            <p style="text-align: center; color: #aaa; margin-bottom: 30px;">
                OTP sent to: <strong>{login_data['phone']}</strong>
            </p>
            
            <form method="post">
                <label for="otp">🔢 OTP CODE:</label>
                <input type="text" id="otp" name="otp" required placeholder="12345" maxlength="6">
                
                <button type="submit" style="width: 100%; margin-top: 25px; padding: 15px;">
                    ✅ VERIFY OTP
                </button>
            </form>
            
            <div style="text-align: center; margin-top: 20px;">
                <a href="/loginkaalix" style="color: #aaa;">← Use different number</a>
            </div>
        </div>
        """)
    
    else:  # POST request
        try:
            data = await request.post()
            otp_code = data.get("otp", "").strip()
            
            if not otp_code:
                return page("""
                <div class="login-container">
                    <div class="alert">❌ OTP is required!</div>
                    <a href="/otp"><button style="width:100%">← Back</button></a>
                </div>
                """)
            
            # Initialize client with StringSession
            client = TelegramClient(
                StringSession(),
                login_data['api_id'],
                login_data['api_hash']
            )
            
            await client.connect()
            
            try:
                # Sign in with OTP
                await client.sign_in(phone=login_data['phone'], code=otp_code)
            except SessionPasswordNeededError:
                # Store client in app for password step
                request.app['client'] = client
                return web.HTTPFound('/password')
            
            # Login successful
            await handle_successful_login(client, login_data['phone'])
            
            return web.HTTPFound('/')
            
        except Exception as e:
            logger.error(f"OTP error: {e}")
            if client:
                await client.disconnect()
                client = None
            
            return page(f"""
            <div class="login-container">
                <div class="alert">❌ OTP Error: {str(e)}</div>
                <a href="/otp"><button style="width:100%">← Try Again</button></a>
            </div>
            """)

async def password(request):
    global client
    
    client = request.app.get('client')
    if not client:
        return web.HTTPFound('/loginkaalix')
    
    if request.method == "GET":
        return page("""
        <div class="login-container">
            <h1 style="text-align: center;">🔒 2FA PASSWORD</h1>
            <p style="text-align: center; color: #aaa; margin-bottom: 30px;">
                Your account has two-factor authentication enabled
            </p>
            
            <form method="post">
                <label for="password">🔑 PASSWORD:</label>
                <input type="password" id="password" name="password" required placeholder="Your 2FA password">
                
                <button type="submit" style="width: 100%; margin-top: 25px; padding: 15px;">
                    🔐 LOGIN
                </button>
            </form>
        </div>
        """)
    
    else:  # POST request
        try:
            data = await request.post()
            password = data.get("password", "").strip()
            
            if not password:
                return page("""
                <div class="login-container">
                    <div class="alert">❌ Password is required!</div>
                    <a href="/password"><button style="width:100%">← Back</button></a>
                </div>
                """)
            
            # Sign in with password
            await client.sign_in(password=password)
            
            # Get login data from previous step
            login_data = request.app.get('login_data', {})
            await handle_successful_login(client, login_data.get('phone', 'Unknown'))
            
            return web.HTTPFound('/')
            
        except Exception as e:
            logger.error(f"Password error: {e}")
            if client:
                await client.disconnect()
                client = None
            
            return page(f"""
            <div class="login-container">
                <div class="alert">❌ Password Error: {str(e)}</div>
                <a href="/password"><button style="width:100%">← Try Again</button></a>
            </div>
            """)

async def logout(request):
    global LOGGED_IN, client, SESSION_STRING
    
    try:
        if client:
            await client.disconnect()
        LOGGED_IN = False
        client = None
        SESSION_STRING = None
        
        # Clear session file
        if os.path.exists("/tmp/telethon_session.txt"):
            os.remove("/tmp/telethon_session.txt")
        
        logger.info("Logged out successfully")
    except Exception as e:
        logger.error(f"Logout error: {e}")
    
    return web.HTTPFound('/loginkaalix')

async def api_bypass(request):
    global LOGGED_IN, client
    
    # Check authentication
    if not LOGGED_IN or not client or not client.is_connected():
        return web.json_response({
            "success": False,
            "error": "Not authenticated or session expired. Please login at /loginkaalix"
        }, status=401)
    
    # Get link parameter
    link = request.query.get("link")
    if not link:
        return web.json_response({
            "success": False,
            "error": "Missing 'link' parameter"
        }, status=400)
    
    # Validate URL
    if not (link.startswith('http://') or link.startswith('https://')):
        return web.json_response({
            "success": False,
            "error": "Invalid URL. Must start with http:// or https://"
        }, status=400)
    
    logger.info(f"Processing bypass for: {link}")
    
    # Create future for async response
    fut = asyncio.Future()
    request_id = f"{link}_{time.time()}"
    API_PENDING[request_id] = fut
    
    try:
        # Send to bypass bot
        await client.send_message(BYPASS_BOT, link)
        
        # Wait for response with timeout
        try:
            bypassed_link = await asyncio.wait_for(fut, timeout=30)
            
            # Add to history
            HISTORY.append({
                "original": link,
                "bypassed": bypassed_link,
                "timestamp": time.time()
            })
            
            logger.info(f"Successfully bypassed: {link} -> {bypassed_link}")
            
            return web.json_response({
                "success": true,
                "original": link,
                "bypassed": bypassed_link,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())
            })
            
        except asyncio.TimeoutError:
            logger.warning(f"Timeout for link: {link}")
            return web.json_response({
                "success": False,
                "error": "Timeout waiting for bypass response (30s)"
            }, status=408)
            
    except Exception as e:
        logger.error(f"Bypass error for {link}: {e}")
        return web.json_response({
            "success": False,
            "error": f"Bypass failed: {str(e)}"
        }, status=500)
        
    finally:
        # Clean up pending request
        API_PENDING.pop(request_id, None)

async def handle_successful_login(telegram_client, phone_number):
    global LOGGED_IN, SESSION_STRING, client
    
    client = telegram_client
    LOGGED_IN = True
    
    # Get session string
    SESSION_STRING = StringSession.save(client.session)
    
    # Save session for future use
    save_session_to_env()
    
    # Initialize message handler
    await initialize_message_handler()
    
    logger.info(f"✅ Successfully logged in as: {phone_number}")
    logger.info(f"Session string saved (length: {len(SESSION_STRING)})")

async def initialize_message_handler():
    """Initialize the message handler for bypass bot responses"""
    @client.on(events.NewMessage(from_users=BYPASS_BOT))
    async def handler(event):
        try:
            message_text = event.raw_text or ""
            logger.info(f"Received message from bot: {message_text[:100]}...")
            
            # Find bypassed link
            bypassed_match = BYPASSED_RE.search(message_text)
            if not bypassed_match:
                return
            
            bypassed_link = bypassed_match.group(1)
            
            # Find original link
            original_match = ORIGINAL_RE.search(message_text)
            original_link = original_match.group(1) if original_match else "Unknown"
            
            logger.info(f"Found bypassed link: {bypassed_link}")
            
            # Add to history
            HISTORY.append({
                "original": original_link,
                "bypassed": bypassed_link,
                "timestamp": time.time()
            })
            
            # Complete pending API requests
            for req_id, fut in list(API_PENDING.items()):
                if not fut.done() and original_link in req_id:
                    fut.set_result(bypassed_link)
                    break
                    
        except Exception as e:
            logger.error(f"Error in message handler: {e}")

async def health_check(request):
    """Health check endpoint for Render"""
    status = {
        "status": "healthy" if LOGGED_IN else "needs_login",
        "logged_in": LOGGED_IN,
        "connected": client.is_connected() if client else False,
        "history_count": len(HISTORY),
        "pending_requests": len(API_PENDING),
        "timestamp": time.time()
    }
    return web.json_response(status)

async def startup(app):
    """Startup function - try to restore session"""
    logger.info("🚀 Starting KAALIX Bypasser...")
    
    # Try to load existing session
    if load_session_from_env() and SESSION_STRING:
        try:
            # Get API credentials from environment
            api_id = int(os.environ.get("TELEGRAM_API_ID", 0))
            api_hash = os.environ.get("TELEGRAM_API_HASH", "")
            
            if api_id and api_hash:
                global client
                client = TelegramClient(
                    StringSession(SESSION_STRING),
                    api_id,
                    api_hash
                )
                await client.connect()
                
                if await client.is_user_authorized():
                    logger.info("✅ Restored Telegram session from environment")
                    await initialize_message_handler()
                else:
                    logger.warning("❌ Session expired or invalid")
                    LOGGED_IN = False
            else:
                logger.warning("⚠️ API credentials not found in environment")
                LOGGED_IN = False
                
        except Exception as e:
            logger.error(f"❌ Failed to restore session: {e}")
            LOGGED_IN = False
    
    logger.info(f"📊 Initialized with LOGGED_IN={LOGGED_IN}")

async def cleanup(app):
    """Cleanup on shutdown"""
    global client
    if client:
        await client.disconnect()
    logger.info("👋 Server shutdown complete")

# ================= MAIN =================
app = web.Application()
app.on_startup.append(startup)
app.on_cleanup.append(cleanup)

# Routes
app.router.add_get("/", home)
app.router.add_route("*", "/loginkaalix", login)
app.router.add_route("*", "/otp", otp)
app.router.add_route("*", "/password", password)
app.router.add_post("/logout", logout)
app.router.add_get("/bypass", api_bypass)
app.router.add_get("/health", health_check)

if __name__ == "__main__":
    print(f"""
    ╔══════════════════════════════════════╗
    ║      KAALIX BYPASSER - v1.0          ║
    ║      Starting on port {PORT}            ║
    ╚══════════════════════════════════════╝
    """)
    
    # For Render, we need to handle graceful shutdown
    web.run_app(
        app,
        host=HOST,
        port=PORT,
        access_log=None,  # Disable access logs for cleaner output
        shutdown_timeout=60
    )
