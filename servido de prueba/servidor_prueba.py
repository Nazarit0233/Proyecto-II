from flask import Flask, request
from datetime import datetime
import sqlite3
import os

app = Flask(__name__)

@app.route('/')
def home():
    ip_cliente = request.remote_addr
    print(f"[{datetime.now()}] Conexión entrante a '/' desde: {ip_cliente}")
    return "<h1>Panel de administración</h1><a href='/login'>Login</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_cliente = request.remote_addr
    print(f"[{datetime.now()}] Conexión entrante a '/login' desde: {ip_cliente}")

    if request.method == 'GET':
        # Formulario simple de login
        return """
        <h2>Login</h2>
        <form method="POST">
            Usuario: <input type="text" name="username"><br>
            Contraseña: <input type="password" name="password"><br>
            <input type="submit" value="Entrar">
        </form>
        """

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # ============================================================
    # VULNERABILIDAD INTENCIONAL (solo para fines educativos):
    # La consulta se arma concatenando texto directamente, sin
    # parámetros seguros. Esto permite inyectar código SQL propio
    # dentro de los campos username/password.
    # ============================================================
    conexion = sqlite3.connect(os.path.join("bd", "usuarios.db"))
    cursor = conexion.cursor()
    consulta = f"SELECT * FROM usuarios WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG] Consulta ejecutada: {consulta}")  # para que veas en consola qué se ejecuta realmente

    try:
        cursor.execute(consulta)
        resultado = cursor.fetchone()
    except sqlite3.Error as e:
        conexion.close()
        return f"Error en la consulta: {e}"

    conexion.close()

    if resultado:
        return f"<h2>Acceso concedido</h2>Bienvenido, {resultado[1]}."
    else:
        return "<h2>Acceso denegado</h2>Usuario o contraseña incorrectos."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)