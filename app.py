from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from wtforms import form, fields, validators
from datetime import datetime
import flask_admin as admin
import flask_login as login
from flask_admin.contrib import sqla
from flask_admin import helpers, expose
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_admin.menu import MenuLink
from flask_security import current_user
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.contrib.sqla import ModelView
from flask_admin.babel import lazy_gettext
import re
import telepot
from telepot.loop import MessageLoop


app = Flask(__name__)
app.config['SECRET_KEY'] = 'MuratSelcuk'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bot = telepot.Bot('API TOKEN')
db = SQLAlchemy(app)


# Create user model.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    login = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(64))

    # Flask-Login integration
    # NOTE: is_authenticated, is_active, and is_anonymous
    # are methods in Flask-Login < 0.3.0
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer)
    name = db.Column(db.String(64))
    classroom = db.Column(db.String(10))
    telegram = db.Column(db.String(50))
    lates = db.relationship('Late_Table', backref='Student', lazy='dynamic')

    def __repr__(self):
        return '{}'.format(self.name)

class Late_Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #number = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    #student_number = db.Column(db.Integer, db.ForeignKey('student.number'))
    student_id = db.Column(db.Integer, db.ForeignKey('student.number'))

    def __repr__(self):
        return '<Lates {}>'.format(self.timestamp)

# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    login = fields.StringField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Invalid user')

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        return db.session.query(User).filter_by(login=self.login.data).first()


class RegistrationForm(form.Form):
    login = fields.StringField(validators=[validators.required()])
    email = fields.StringField()
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(login=self.login.data).count() > 0:
            raise validators.ValidationError('Duplicate username')


# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)

class FilterPhrase(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        stmt = "%{phrase}%".format(phrase=value)
        return query.filter(self.get_column(alias).ilike(stmt))

    def operation(self):
        return lazy_gettext('phrase')


class PostAdmin(sqla.ModelView):

    column_searchable_list = ['timestamp', 'student_id', 'Student.name']
    column_labels = dict(timestamp='Tarih', Student='Öğrenci',)

    column_filters = (
        FilterPhrase(Late_Table.timestamp, "timestamp"),
        FilterPhrase(Late_Table.student_id, "student_id"),
    )
    def is_accessible(self):
        return login.current_user.is_authenticated
    def _apply_search(self, query, count_query, joins, count_joins, search):
        
        phrases = re.findall(r'"([^"]*)"', search)

        if len(phrases) == 0:
            return super(PostAdmin, self)._apply_search(query, count_query, joins, count_joins, search)

        stmt = "%{phrase}%".format(phrase=phrases[0])

        # The code below is taken directly from the base _apply_search
        filter_stmt = []
        count_filter_stmt = []

        for field, path in self._search_fields:
            query, joins, alias = self._apply_path_joins(query, joins, path, inner_join=False)

            count_alias = None

            if count_query is not None:
                count_query, count_joins, count_alias = self._apply_path_joins(count_query,
                                                                               count_joins,
                                                                               path,
                                                                               inner_join=False)

            column = field if alias is None else getattr(alias, field.key)
            filter_stmt.append(column.ilike(stmt))

            if count_filter_stmt is not None:
                column = field if count_alias is None else getattr(count_alias, field.key)
                count_filter_stmt.append(column.ilike(stmt))

        query = query.filter(or_(*filter_stmt))

        if count_query is not None:
            count_query = count_query.filter(or_(*count_filter_stmt))

        return query, count_query, joins, count_joins

# Create customized model view class
class MyModelView(sqla.ModelView):

    def is_accessible(self):
        return login.current_user.is_authenticated
    
    column_labels = dict(name='Adı Soyadı', classroom='Sınıf', number='Numarası', first_name = 'Adı', last_name = 'Soyadı', login = 'Kullanıcı Adı', email = 'E-posta Adresi', password = 'Şifre')

	
# Create customized index view class that handles login & registration
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated:
            return redirect(url_for('.index'))
        link = '<p>Don\'t have an account? <a href="' + url_for('.register_view') + '">Click here to register.</a></p>'
        self._template_args['form'] = form
        #self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = User()

            form.populate_obj(user)
            # we hash the users password to avoid saving it as plaintext in the db,
            # remove to use plain text:
            user.password = generate_password_hash(form.password.data)

            db.session.add(user)
            db.session.commit()

            login.login_user(user)
            return redirect(url_for('.index'))
        link = '<p>Already have an account? <a href="' + url_for('.login_view') + '">Click here to log in.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        login.logout_user()
        return redirect(url_for('.index'))

# Initialize flask-login
init_login()

# Create admin
admin = admin.Admin(app, 'Yönetici Sistemi', index_view=MyAdminIndexView(), base_template='my_master.html')

# Add view
admin.add_view(MyModelView(User, db.session, 'Yöneticiler'))


@app.route("/")
def index():
    user = {'username': 'Hazırlayan: Murat SELCUK'}
    return render_template('index.html', title='Anasayfa', user=user)

@app.route('/late', methods=['GET'])
def lates():
    processed_text = request.args.get('number', default=0)
    student = Student.query.filter_by(number=processed_text).first_or_404(description='HATA: {} numarali ogrenci kayitli degil.'.format(processed_text))
    testgec = Late_Table(student_id=processed_text)
    db.session.add(testgec)
    db.session.commit()
    try:
        bot.sendMessage(student.telegram, 'Ogrenciniz okula gec kalmistir')
    except:
        print('telegram mesaj gonderilemedi')
    saat=datetime.now()
    return render_template('print.html', ad=student.name, saat=saat.strftime("%H:%M:%S"), tarih=saat.strftime("%d/%m/%Y"), sinif=student.classroom, no=processed_text)

@app.route('/db')
def db_create():
    db.create_all()
    test_user = User(login="test", password=generate_password_hash("test"))
    db.session.add(test_user)
    db.session.commit()
    return "DB olusturuldu"
    
class LoginMenuLink(MenuLink):

    def is_accessible(self):
        return not current_user.is_authenticated 


class LogoutMenuLink(MenuLink):

    def is_accessible(self):
        return current_user.is_authenticated 

if __name__ == "__main__":
    #admin = admin(app, name='Ogrenci Gec Kalma Takip Sistemi')
    admin.add_view(MyModelView(Student, db.session, 'Öğrenciler'))
    admin.add_view(PostAdmin(Late_Table, db.session, 'Geç Kalanlar'))
    
    admin.add_link(LogoutMenuLink(name='Cikis', category='', url="/admin/logout"))
    admin.add_link(MenuLink(name='Ana Sayfa', url='/', category=''))
    app.run()
