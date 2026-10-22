from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import os, sqlite3, hashlib
from datetime import datetime
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cybershield.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'cybershield-demo-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED = {'pdf','png','jpg','jpeg','txt','doc','docx'}


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_no TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        priority TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',
        description TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL
    );
    ''')
    con.commit()
    con.close()


def log(action, details=''):
    con = db()
    con.execute('INSERT INTO activity(action, details, created_at) VALUES (?,?,?)',
                (action, details, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    con.commit(); con.close()


def logged_in():
    return session.get('user') == 'admin'


def allowed_file(name):
    return '.' in name and name.rsplit('.',1)[1].lower() in ALLOWED


@app.route('/')
def home():
    if not logged_in():
        return redirect(url_for('login'))
    con = db()
    stats = {
        'cases': con.execute('SELECT COUNT(*) FROM cases').fetchone()[0],
        'open': con.execute("SELECT COUNT(*) FROM cases WHERE status='Open'").fetchone()[0],
        'evidence': con.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],
        'activity': con.execute('SELECT COUNT(*) FROM activity').fetchone()[0],
    }
    recent = con.execute('SELECT * FROM cases ORDER BY id DESC LIMIT 5').fetchall()
    con.close()
    return render_template('dashboard.html', stats=stats, recent=recent)


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if username == 'admin' and password == 'admin123':
            session['user'] = 'admin'
            log('Login', 'Administrator logged in')
            return redirect(url_for('home'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    if logged_in(): log('Logout', 'Administrator logged out')
    session.clear()
    return redirect(url_for('login'))


@app.route('/cases')
def cases():
    if not logged_in(): return redirect(url_for('login'))
    con = db(); rows = con.execute('SELECT * FROM cases ORDER BY id DESC').fetchall(); con.close()
    return render_template('cases.html', cases=rows)


@app.route('/cases/new', methods=['GET','POST'])
def new_case():
    if not logged_in(): return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        category = request.form.get('category','').strip()
        priority = request.form.get('priority','Medium')
        description = request.form.get('description','').strip()
        if not title or not category:
            flash('Title and category are required.', 'error')
            return render_template('new_case.html')
        stamp = datetime.now().strftime('%Y%m%d%H%M%S')
        case_no = 'CS-' + stamp
        con = db()
        con.execute('INSERT INTO cases(case_no,title,category,priority,status,description,created_at) VALUES (?,?,?,?,?,?,?)',
                    (case_no,title,category,priority,'Open',description,datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        con.commit(); con.close()
        log('Case Created', f'{case_no} - {title}')
        flash(f'Case {case_no} created successfully.', 'success')
        return redirect(url_for('cases'))
    return render_template('new_case.html')


@app.route('/cases/<int:case_id>')
def case_detail(case_id):
    if not logged_in(): return redirect(url_for('login'))
    con = db(); case = con.execute('SELECT * FROM cases WHERE id=?',(case_id,)).fetchone(); evidence = con.execute('SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC',(case_id,)).fetchall(); con.close()
    if not case: return 'Case not found', 404
    return render_template('case_detail.html', case=case, evidence=evidence)


@app.route('/cases/<int:case_id>/evidence', methods=['POST'])
def upload_evidence(case_id):
    if not logged_in(): return redirect(url_for('login'))
    file = request.files.get('evidence')
    con = db(); case = con.execute('SELECT * FROM cases WHERE id=?',(case_id,)).fetchone(); con.close()
    if not case: return 'Case not found', 404
    if not file or not file.filename:
        flash('Please select a file.', 'error'); return redirect(url_for('case_detail', case_id=case_id))
    if not allowed_file(file.filename):
        flash('File type not allowed.', 'error'); return redirect(url_for('case_detail', case_id=case_id))
    original = secure_filename(file.filename)
    data = file.read()
    sha = hashlib.sha256(data).hexdigest()
    stored = f'{datetime.now().strftime("%Y%m%d%H%M%S%f")}_{original}'
    with open(os.path.join(UPLOAD_DIR, stored), 'wb') as out: out.write(data)
    con = db(); con.execute('INSERT INTO evidence(case_id,filename,stored_name,sha256,uploaded_at) VALUES (?,?,?,?,?)',
                            (case_id,original,stored,sha,datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); con.commit(); con.close()
    log('Evidence Uploaded', f'{case["case_no"]} - {original} - SHA256 {sha[:16]}...')
    flash('Evidence uploaded and SHA-256 hash generated.', 'success')
    return redirect(url_for('case_detail', case_id=case_id))


@app.route('/evidence/<path:name>')
def evidence_file(name):
    if not logged_in(): return redirect(url_for('login'))
    return send_from_directory(UPLOAD_DIR, name, as_attachment=True)


@app.route('/evidence')
def evidence_management():
    if not logged_in(): return redirect(url_for('login'))
    con = db()
    rows = con.execute('''SELECT e.*, c.case_no, c.title, c.category
                          FROM evidence e JOIN cases c ON c.id=e.case_id
                          ORDER BY e.id DESC''').fetchall()
    con.close()
    return render_template('evidence.html', evidence=rows)


@app.route('/activity')
def activity():
    if not logged_in(): return redirect(url_for('login'))
    con=db(); rows=con.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 100').fetchall(); con.close()
    return render_template('activity.html', rows=rows)


@app.route('/about')
def about():
    if not logged_in(): return redirect(url_for('login'))
    return render_template('about.html')


@app.errorhandler(413)
def too_large(_):
    return render_template('error.html', message='File is too large. Maximum size is 16 MB.'), 413


init_db()

if __name__ == '__main__':
    print('=' * 58)
    print('CYBERSHIELD - DIGITAL CRIME & EVIDENCE MANAGEMENT SYSTEM')
    print('Login: admin / admin123')
    print('Open: http://127.0.0.1:5055')
    print('=' * 58)
    app.run(host='127.0.0.1', port=5055, debug=False, use_reloader=False)
