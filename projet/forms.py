from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from projet.models import User, Compte
from wtforms.fields.html5 import DateField


class RegistrationForm(FlaskForm):
    username = StringField('Nom',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmer mot de passe',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('S\'inscrire')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ce nom est déjà pris. Veuillez en choisir un autre.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Cet e-mail est pris. Veuillez en choisir un autre.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    remember = BooleanField('Se souvenir')
    submit = SubmitField('Se connecter')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Demander la réinitialisation du mot de passe')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Il n\'y a pas de compte avec cet e-mail. Vous devez d\'abord vous inscrire.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmer le mot de passe',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Réinitialiser le mot de passe')



class UpdateAccountForm(FlaskForm):
    username = StringField('Nom',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Mettre à jour l\'image de profil', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Modifier')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Ce nom est déjà pris. Veuillez en choisir un autre.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Cet e-mail est pris. Veuillez en choisir un autre.')

class CompteForm(FlaskForm):
    nom = StringField('Nom', validators=[DataRequired()])
    prenom = StringField('Prenom', validators=[DataRequired()])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmer mot de passe',
                                     validators=[DataRequired(), EqualTo('password')])
    date_naissance = DateField('Date de naissance', format='%d-%m-%y')
    sexe = RadioField('Sexe', choices=[('Homme','Homme'),('Femme','Femme')])
    submit = SubmitField('Créer un compte')

    def validate_email(self, email):
        compte = Compte.query.filter_by(email=email.data).first()
        if compte:
            raise ValidationError('Cet e-mail est pris. Veuillez en choisir un autre.')

class UpdateCompteForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Mettre à jour l\'image de profil', validators=[FileAllowed(['jpg', 'png'])])

    submit = SubmitField('Modifier un compte')


    def validate_email(self, email):
        compte = Compte.query.filter_by(email=email.data).first()
        if compte:
            raise ValidationError('Cet e-mail est pris. Veuillez en choisir un autre.')


class DeposerForm(FlaskForm):
    solde = IntegerField('Saisir le montant à déposer', validators=[DataRequired()])
    submit = SubmitField('Déposer argent')

class RetirerForm(FlaskForm):
    solde = IntegerField('Saisir le montant à retirer', validators=[DataRequired()])
    submit = SubmitField('Retirer argent')

class AjouterAgentForm(FlaskForm):
    nom = StringField('Nom', validators=[DataRequired()])
    prenom = StringField('Prenom', validators=[DataRequired()])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmer mot de passe',
                                     validators=[DataRequired(), EqualTo('password')])
    sexe = RadioField('Sexe', choices=[('Homme','Homme'),('Femme','Femme')])
    type_compte = RadioField('Type du compte', choices=[('Epargne','Epargne'),('Courant','Courant')])
    submit = SubmitField('Ajouter')

class VirerForm(FlaskForm):
    sender_id = IntegerField('Compte qui va verser', validators=[DataRequired()])
    receiver_id = IntegerField('Compte bénéficier', validators=[DataRequired()])
    sum_money = IntegerField('La somme d\'argent à verser', validators=[DataRequired()])
    submit = SubmitField('Verser')

