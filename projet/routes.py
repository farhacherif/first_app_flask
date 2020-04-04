import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from projet import app, db, bcrypt, mail
from projet.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, UpdateAccountForm, CompteForm, DeposerForm, RetirerForm, UpdateCompteForm, AjouterAgentForm, VirerForm
from projet.models import User, Compte
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message


@app.route("/")
@app.route("/about")
def about():
    return render_template('accueil.html')


@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    comptes = Compte.query.order_by(Compte.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', comptes=comptes)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Votre compte a été créé! Vous pouvez maintenant vous connecter', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        compte = Compte.query.filter_by(email=form.email.data).first()
        if compte and bcrypt.check_password_hash(compte.password, form.password.data):
            login_user(compte, remember=form.remember.data)
        #form.email.data == 'admin@gmail.com'and form.password.data == '123':
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('test'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/test")
@login_required
def test():
    comptes= Compte.query.all()
    return render_template('test.html', comptes=comptes)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/create/account", methods=['GET', 'POST'])
@login_required
def create_account():
    form = AjouterAgentForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        compte = Compte(nom=form.nom.data, prenom=form.prenom.data, email=form.email.data,password=hashed_password,sexe=form.sexe.data, createur=current_user)
        db.session.add(compte)
        db.session.commit()
        flash('Le compte a été crée', 'success')
        return redirect(url_for('home'))
    return render_template('create_account.html', title='Nouveau Compte',
                        form=form, legend='Nouveau Compte')

@app.route("/creer/compte", methods=['GET', 'POST'])
@login_required
def creer_compte():
    form = CompteForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        dt = form.date_naissance.data.strftime('%d-%m-%y')
        compte = Compte(nom=form.nom.data, prenom=form.prenom.data, email=form.email.data,
        password=hashed_password, date_naissance=dt, sexe=form.sexe.data, createur=current_user)
        db.session.add(compte)
        db.session.commit()
        flash('Le compte a été crée', 'success')
        return redirect(url_for('home'))
    return render_template('create_compte.html', title='Nouveau compte',
                        form=form, legend='Nouveau compte')

@app.route("/compte/<int:compte_id>/update", methods=['GET', 'POST'])
@login_required
def update_compte(compte_id):
    compte = Compte.query.get_or_404(compte_id)
    if compte.createur != current_user:
        abort(403)
    form = UpdateCompteForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            compte.image_file = picture_file
        compte.email = form.email.data
        db.session.commit()
        flash('Votre compte a été mis à jour!', 'success')
        return redirect(url_for('compte', compte_id=compte.id))
    elif request.method == 'GET':
        form.email.data = compte.email
        image_file = url_for('static', filename='profile_pics/' + compte.image_file)
    return render_template('update_compte.html', title='Modifier compte', image_file=image_file,
                           form=form, legend='Modifier compte', compte=compte)

@app.route("/compte/<int:compte_id>")
def compte(compte_id):
    compte = Compte.query.get_or_404(compte_id)
    return render_template('compte.html', title=compte.prenom, compte=compte)

@app.route("/user/<string:username>")
def user_comptes(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    comptes = Compte.query.filter_by(createur=user)\
        .order_by(Compte.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_comptes.html', comptes=comptes, user=user)


@app.route("/virer", methods=['GET', 'POST'])
@login_required
def virer_argent():
    form = VirerForm()
    comptes= Compte.query.all()
    if form.validate_on_submit():
        sender = form.sender_id.data
        receiver = form.receiver_id.data
        money = form.sum_money.data
        accout_receiver = Compte.query.get_or_404(receiver)
        accout_sender = Compte.query.get_or_404(sender)
        if money < accout_sender.solde:
            accout_receiver.solde = accout_receiver.solde + money
            accout_sender.solde = accout_sender.solde - money
            db.session.commit()
            flash('La somme a été versée!', 'success')
            return render_template('about.html')
        else:
            flash('vous n\'avez pas assez d\'argent, veuillez vérifier à nouveau la somme!', 'danger')
            return redirect(url_for('virer_argent'))
    return render_template('verser_account.html', title='Verser argent',
                           form=form, legend='Verser argent', comptes=comptes)






@app.route("/compte/<int:compte_id>/deposer", methods=['GET', 'POST'])
@login_required
def deposer_argent(compte_id):
    compte = Compte.query.get_or_404(compte_id)
    if compte.createur != current_user:
        abort(403)
    form = DeposerForm()
    if form.validate_on_submit():
        compte.solde = compte.solde + form.solde.data
        db.session.commit()
        flash('La somme a été déposée!', 'success')
        return redirect(url_for('compte', compte_id=compte.id))
    elif request.method == 'GET':
        form.solde.data = compte.solde
    return render_template('deposer_argent.html', title='Deposer argent',
                           form=form, legend='Deposer argent')

@app.route("/compte/<int:compte_id>/retirer", methods=['GET', 'POST'])
@login_required
def retirer_argent(compte_id):
    compte = Compte.query.get_or_404(compte_id)
    if compte.createur != current_user:
        abort(403)
    form = RetirerForm()
    if form.validate_on_submit() and form.solde.data<compte.solde:
        compte.solde = compte.solde - form.solde.data
        db.session.commit()
        flash('La somme a été retirée!', 'success')
        return redirect(url_for('compte', compte_id=compte.id))
    elif request.method == 'GET':
        form.solde.data = compte.solde
    elif form.solde.data>compte.solde:
        flash('impossible d\'effectuer la transaction!', 'warning')
    return render_template('retirer_argent.html', title='Retirer argent',
                           form=form, legend='Retirer argent')

@app.route("/compte/<int:compte_id>/delete", methods=['Post'])
@login_required
def delete_compte(compte_id):
    compte = Compte.query.get_or_404(compte_id)
    if compte.createur != current_user:
        abort(403)
    db.session.delete(compte)
    db.session.commit()
    flash('Your compte has been deleted!', 'success')
    return redirect(url_for('home'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Demande de réinitialisation du mot de passe',
                  sender='farahcherif',
                  recipients=[user.email])
    msg.body = f'''Pour réinitialiser votre mot de passe, visitez le lien suivant:
{url_for('reset_token', token=token, _external=True)}
Si vous n'avez pas fait cette demande, ignorez simplement cet e-mail et aucune modification ne sera apportée.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Un e-mail a été envoyé avec des instructions pour réinitialiser votre mot de passe.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('C\'est un jeton invalide ou expiré', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Votre mot de passe a été mis à jour! Vous pouvez maintenant vous connecter', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)