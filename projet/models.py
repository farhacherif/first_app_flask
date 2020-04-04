from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from projet import db, login_manager, app
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#agent
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    comptes = db.relationship('Compte', backref='createur', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"
#user
class Compte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(20), unique=True, nullable=False)
    prenom = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    sexe = db.Column(db.String(20), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    date_naissance = db.Column(db.String, nullable=False, default=datetime.utcnow)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    solde = db.Column(db.Integer, nullable=False, default=0)
    type_compte = db.Column(db.String(20), nullable=False, default='courant')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Compte('{self.id}','{self.email}', '{self.date_posted}', '{self.solde}')"
    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def get_id(self):
        return self.id
