from app import db, User

# Crear usuarios de prueba
users = [
    {'username': 'admin', 'email': 'admin@test.com', 'password': 'admin123', 'role': 'admin'},
    {'username': 'auditor', 'email': 'auditor@test.com', 'password': 'auditor123', 'role': 'auditor'},
    {'username': 'empresa', 'email': 'empresa@test.com', 'password': 'empresa123', 'role': 'empresa'},
    {'username': 'user', 'email': 'user@test.com', 'password': 'user123', 'role': 'user'},
]

for u in users:
    if not User.query.filter_by(username=u['username']).first():
        user = User(username=u['username'], email=u['email'], role=u['role'])
        user.set_password(u['password'])
        db.session.add(user)

db.session.commit()
print("Usuarios de prueba creados correctamente.")
