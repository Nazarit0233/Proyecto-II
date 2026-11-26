import sqlite3
import os

# La base de datos se guarda dentro de la carpeta "bd"
carpeta_bd = "bd"
os.makedirs(carpeta_bd, exist_ok=True)  # crea la carpeta si no existe
ruta_bd = os.path.join(carpeta_bd, "usuarios.db")

conexion = sqlite3.connect(ruta_bd)
cursor = conexion.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
)
""")

cursor.execute("DELETE FROM usuarios")
cursor.executemany(
    "INSERT INTO usuarios (username, password) VALUES (?, ?)",
    [("admin", "admin123"), ("santiago", "1234")]
)

conexion.commit()
conexion.close()
print(f"Base de datos creada en '{ruta_bd}' con usuarios de prueba.")