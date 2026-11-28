from flask import Flask, request, jsonify
import sqlite3
from aws_lambda_wsgi import make_lambda_handler

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect("/tmp/vulnerable.db")  # Use /tmp for Lambda compatibility
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Helper function for database queries
def query_db(query, args=(), one=False):
    conn = sqlite3.connect("/tmp/vulnerable.db")
    cursor = conn.cursor()
    cursor.execute(query, args)
    rv = cursor.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    query_db("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    return jsonify({"message": f"User {username} registered!"})

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = query_db("SELECT * FROM users WHERE username = ? AND password = ?", (username, password), one=True)
    if user:
        return jsonify({"message": "Login successful", "user_id": user[0]})
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        author_id = request.form.get("author_id")
        query_db(f"INSERT INTO posts (title, content, author_id) VALUES ('{title}', '{content}', {author_id})")
        return jsonify({"message": "Post created!"})
    elif request.method == "GET":
        posts = query_db("SELECT * FROM posts")
        return jsonify([{"id": p[0], "title": p[1], "content": p[2]} for p in posts])

@app.route("/delete_post/<int:post_id>", methods=["DELETE"])
def delete_post(post_id):
    query_db(f"DELETE FROM posts WHERE id = {post_id}")
    return jsonify({"message": "Post deleted!"})

# Create Lambda handler
init_db()
lambda_handler = make_lambda_handler(app)


# --- Demo landing page (added for the Demo Center; the API flaws above are unchanged) ---
@app.route("/")
def _demo_index():
    return """<!doctype html><html><head><meta charset=utf-8><title>Vulnerable API</title>
<style>body{font-family:Inter,system-ui,sans-serif;background:#04060b;color:#e2e8f0;margin:0;padding:40px;line-height:1.6}
code{font-family:'JetBrains Mono',monospace;background:#0f1420;padding:2px 6px;border-radius:6px;color:#67e8f9}
h1{font-size:22px}a{color:#67e8f9}.w{max-width:760px}.tag{display:inline-block;font-size:12px;padding:3px 8px;border-radius:999px;border:1px solid #d7192166;color:#fca5a5;background:#d7192114}</style></head>
<body><div class=w><span class=tag>Deliberately vulnerable &middot; lab only</span>
<h1>Vulnerable API</h1>
<p>A demo REST API with SQL injection, weak authentication and XSS, for showing how Cloud Security, Container Security and a WAF catch common API flaws.</p>
<h3>Endpoints</h3>
<ul>
<li><code>POST /register</code> &mdash; {username, password}</li>
<li><code>POST /login</code> &mdash; {username, password} (injectable)</li>
<li><code>GET|POST /posts</code> &mdash; list or create posts</li>
<li><code>DELETE /delete_post/&lt;id&gt;</code></li>
</ul>
<h3>Try an injection</h3>
<p><code>curl -s -X POST .../login -H 'Content-Type: application/json' -d '{"username":"admin","password":"\\\" OR \\\"1\\\"=\\\"1"}'</code></p>
<p style="color:#94a3b8;font-size:13px">All data is synthetic. This service is bound to the lab network only.</p>
</div></body></html>"""
