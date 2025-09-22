from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import datetime
import json  # Para guardar respuestas de auditoría como JSON

# ------------------ Configuración ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'demo-secret-key'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'sgc.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------ Extensiones ------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------ Decoradores ------------------
def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if current_user.role not in roles:
                flash('No tienes permisos para acceder a esta sección', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated
    return wrapper

# ------------------ Modelos ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)
    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    razon_social = db.Column(db.String(150))
    numero_empresa = db.Column(db.String(50))
    nit = db.Column(db.String(50))
    email = db.Column(db.String(120))
    representante_legal = db.Column(db.String(120))
    pagina_web = db.Column(db.String(120))
    sector_economico = db.Column(db.String(120))
    tipo_empresa = db.Column(db.String(120))
    direccion = db.Column(db.String(200))
    redes_sociales = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class AuditChecklistTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    questions = db.Column(db.Text, nullable=False)

class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('audit_checklist_template.id'))
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    answers = db.Column(db.Text)  # Guardaremos JSON como string

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_uploaded = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ------------------ Login Loader ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ Rutas ------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html', AuditChecklistTemplate=AuditChecklistTemplate)

# --- Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and u.check_password(request.form['password']):
            login_user(u)
            return redirect(url_for('index'))
        flash('Credenciales inválidas', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role', 'user')
        u = User(username=request.form['username'], email=request.form['email'], role=role)
        u.set_password(request.form['password'])
        db.session.add(u)
        db.session.commit()
        flash(f'Usuario creado con rol {role}', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Empresas ---
@app.route('/company', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'empresa')
def company():
    if request.method == 'POST':
        c = Company(
            razon_social=request.form['razon_social'],
            numero_empresa=request.form['numero_empresa'],
            nit=request.form['nit'],
            email=request.form['email'],
            representante_legal=request.form['representante_legal'],
            pagina_web=request.form['pagina_web'],
            sector_economico=request.form['sector_economico'],
            tipo_empresa=request.form['tipo_empresa'],
            direccion=request.form['direccion'],
            redes_sociales=request.form['redes_sociales'],
            user_id=current_user.id
        )
        db.session.add(c)
        db.session.commit()
        flash('Empresa registrada', 'success')
    companies = Company.query.all()
    return render_template('company.html', companies=companies)

# --- Plantillas de Auditoría ---
@app.route('/audit/template', methods=['GET','POST'])
@login_required
@role_required('admin', 'auditor')
def audit_template():
    if request.method == 'POST':
        a = AuditChecklistTemplate(
            title=request.form['title'],
            questions=request.form['questions']
        )
        db.session.add(a)
        db.session.commit()
        flash('Checklist creado', 'success')
    templates = AuditChecklistTemplate.query.all()
    return render_template('audit_template.html', templates=templates)

# --- Realizar Auditoría ---
@app.route('/audit/run/<int:tid>', methods=['GET','POST'])
@login_required
@role_required('admin', 'auditor')
def audit_run(tid):
    t = AuditChecklistTemplate.query.get_or_404(tid)
    companies = Company.query.all()
    if request.method == 'POST':
        answers = {k: v for k, v in request.form.items() if k != 'company_id'}
        rec = AuditRecord(
            template_id=tid,
            company_id=request.form['company_id'],
            user_id=current_user.id,
            answers=json.dumps(answers)  # <- Guardar dict como JSON
        )
        db.session.add(rec)
        db.session.commit()
        flash('Auditoría registrada', 'success')
        return redirect(url_for('audit_template'))
    return render_template('audit_run.html', template=t, companies=companies)

# --- Auditorías realizadas ---
@app.route('/audit/records')
@login_required
def audit_records():
    if current_user.role == 'empresa':
        records = AuditRecord.query.join(Company).filter(Company.user_id == current_user.id).all()
    elif current_user.role in ['admin', 'auditor']:
        records = AuditRecord.query.all()
    else:
        records = []

    for rec in records:
        rec.template = AuditChecklistTemplate.query.get(rec.template_id)
        rec.company = Company.query.get(rec.company_id)
        rec.user = User.query.get(rec.user_id)
        # Convertir de JSON a dict para usar en template
        if rec.answers:
            try:
                rec.answers_dict = json.loads(rec.answers)
            except:
                rec.answers_dict = {}
        else:
            rec.answers_dict = {}

    return render_template('audit_records.html', records=records)

# --- Documentos ---
@app.route('/documents', methods=['GET','POST'])
@login_required
def documents():
    if request.method == 'POST' and 'file' in request.files:
        f = request.files['file']
        if f.filename != '':
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            d = Document(filename=filename, uploaded_by=current_user.id)
            db.session.add(d)
            db.session.commit()
            flash('Documento subido', 'success')
            return redirect(url_for('documents'))
    docs = db.session.query(Document, User).join(User, Document.uploaded_by == User.id).all()
    drive_links = [
        {'name': 'Documentos Drive 1', 'url': 'https://drive.google.com/drive/folders/1d2AXA8215YzyH4iQBLb0qJ6HUuMe447v'},
        {'name': 'Documentos Drive 2', 'url': 'https://drive.google.com/drive/folders/1oZ4-NeVQSxsYVd3Mko-0r9OOE2Yip1vL'}
    ]
    return render_template('documents.html', documents=docs, drive_links=drive_links)

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    d = Document.query.get_or_404(doc_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], d.filename, as_attachment=True)

@app.route('/documents/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    d = Document.query.get_or_404(doc_id)
    if d.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('No tienes permiso para eliminar este documento', 'danger')
        return redirect(url_for('documents'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], d.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(d)
    db.session.commit()
    flash('Documento eliminado', 'success')
    return redirect(url_for('documents'))

# ------------------ Paneles por rol ------------------
@app.route('/admin-panel')
@login_required
@role_required('admin')
def admin_panel():
    return "Bienvenido al panel de administración"

@app.route('/auditor-panel')
@login_required
@role_required('auditor')
def auditor_panel():
    return "Bienvenido al panel de auditor"

@app.route('/empresa-panel')
@login_required
@role_required('empresa')
def empresa_panel():
    return "Bienvenido al panel de empresa"

# ------------------ Ejecutar ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
