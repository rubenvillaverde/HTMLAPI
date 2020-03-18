#nota importantisima. para utilizar las variables conseguidas a través de input,
#tengo que hacerlas enviar a una url...si esa url no demanda dicha variable en su titulo
#ed (/login) puedo definir directamente las variables (con request.form) debajo de la clase 
#de python, sin pasar por vestíbulo previos.
#PEEEro, si ncesito que la variable esté en la url ya que así está configurada en python 
#,ed (item/<string:name>) tengo que hacerla pasar por una url intermedia, programar en dicha 
#url una ecuacion de python para coger la variable deseada (con request.form) y devolver un template 
#html de otro form para que este lo envíe finalmente a item/nombre de la variable segun input 

#Es decir, puedo usar un una variable en html para mostrar o para poner en la url
#si previamente la he recogido con un input y la he definido posteriormente con python..
#ed, una variable en html para poder usarla no basta con cogerla en html si no que tengo que redefinirla 
#en python. Si la variable no hace falta quew esté en la URL (ED no necesito que vuelva a html) no tengo
#que crear otro formulario para enviarla,,,si necesito que esté en la url sí que tengo que crearlo. 

from flask import Flask
from flask import json, jsonify, render_template, request, session
from flask_restful import Api
from flask_jwt_extended import JWTManager
from resources.user import UserRegister, User, UserLogin, UserLogout, TokenRefresh
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from models.user import UserModel
from blacklist import BLACKLIST
#from db import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
#app.config['JWT_TOKEN_LOCATION'] = ['cookies']
#app.config['JWT_ACCESS_COOKIE_PATH']='/login'
#app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.secret_key = 'jose'

api = Api(app)

#db.init_app(app)


@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)  

@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:
         
        return {'is_admin': True}
    return {'is_admin': False}



@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST
    #ahora ponemos que busque el jti (id del propio token) y no el id del usuario
    


@jwt.expired_token_loader 
def expired_token_callback():
    
    return jsonify({
        'description':'token has expired',
        'error':'token_expired'
    }), 401

@jwt.invalid_token_loader 
def invalid_token_callback(error):
    return jsonify({
        'description':'invalid token given',
        'error':'invalid_token'
    })
@jwt.unauthorized_loader  
def missing_token_callback(error):
    return jsonify({
        'description':'el request no contiene ningun token',
        'error':'authorization_requiered'
    })

@jwt.needs_fresh_token_loader 
def token_not_fresh_callback():
    return jsonify({
        'description':'token is not fresh',
        'error':'fresh_token_requiered'
    })

@jwt.revoked_token_loader 
def revoke_token_callback():
    return jsonify({
        'description':'The token has been revoked',
        'error':'token_revoked'
    })


@app.route('/login')
def login():
    return render_template("login.html")
    
@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/')
def home():
    return render_template("home.html")

@app.route('/posthome')
def posthome():
    return render_template("posthome.html")
#@app.route('/item', methods=['POST'])
#def itemgetname():
    #name=request.form['name']    
    #return render_template('itembynameAPI.html', name=request.form['name'])

@app.route('/loginhtml', methods=['POST'])
def login_user():
    password=request.form['password']
    username=request.form['username']    
    user=UserModel.find_by_username(username)

    if password==user.password:
        return render_template('profile.html', username=request.form['username'])
        #al devolver la render template tenemos que definir que variable queremos reutilizar
        #pàra que salga tambn con el template
    else:
        return render_template('profile.html', username='usuario o contraseña incorrectos')




api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(Item, '/item/<string:name>')
#api.add_resource(Item, '/item')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register2')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login2')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')


if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
