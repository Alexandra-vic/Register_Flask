from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_restx import Api, Resource, fields


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'mysecretkey'


db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


api = Api(app, doc='/swagger/', title='Authentication API', description='API for user authentication')


user_model = api.model('User', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})


@api.route('/register')
class UserRegistration(Resource):
    @api.doc(responses={201: 'User registered successfully', 400: 'Invalid payload', 409: 'User already exists'})
    @api.expect(user_model)
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username and password:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return {'message': 'User already exists'}, 409

            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()

            return {'message': 'User registered successfully'}, 201
        else:
            return {'message': 'Invalid payload'}, 400


@api.route('/login')
class UserLogin(Resource):
    @api.doc(responses={200: 'Login successful', 400: 'Invalid payload', 401: 'Invalid username or password'})
    @api.expect(user_model)
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = User.query.filter_by(username=username).first()
            if user and user.password == password:
                access_token = create_access_token(identity=user.id)
                return {'access_token': access_token}, 200
            else:
                return {'message': 'Invalid username or password'}, 401
        else:
            return {'message': 'Invalid payload'}, 400


@api.route('/users')
class Users(Resource):
    def get(self):
        users = User.query.all()
        user_list = [{'username': user.username, 'password': user.password} for user in users]
        return {'users': user_list}, 200


@app.before_request
def create_tables():
    db.create_all()


if __name__ == '__main__':
    app.run()
