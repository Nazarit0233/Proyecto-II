from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Panel de administración</h1><a href='/login'>Login</a>"

@app.route('/login')
def login():
    return "Formulario de login (puerto 5000 expuesto, sin HTTPS ni autenticación robusta)"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)