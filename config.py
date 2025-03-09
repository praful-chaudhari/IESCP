from app import app
import secrets
from flask_login import LoginManager

def generate_secret_key():
  return secrets.token_hex(32)

app.config["SECRET_KEY"] = generate_secret_key()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite3"

login_manager = LoginManager()

login_manager.init_app(app)
login_manager.login_view = "user_login"
login_manager.request_loader = "load_user"
