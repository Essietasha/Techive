from app import app, db
from app.models import User

with app.app_context():
    admin_user = User.query.filter_by(username='essietasha').first()
    if not admin_user:
        admin_user = User(username='essietasha', is_admin=True)
        admin_user.set_password('Essie@012')
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")