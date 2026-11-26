import socket
import threading
import ssl
import requests
import os
from datetime import datetime
from queue import Queue

# ======================================================================
# CONFIGURACIÓN BASE
# Diccionario de puertos comunes con su servicio y riesgo asociado.
# Esto es parte del núcleo del escáner: define qué se reconoce y cómo
# se explica cada puerto en el reporte final.
# ======================================================================

PUERTOS_COMUNES = {
    21: ("FTP", "Transferencia de archivos sin cifrado; credenciales viajan en texto plano."),
    22: ("SSH", "Acceso remoto; vulnerable a fuerza bruta si no hay límite de intentos."),
    23: ("Telnet", "Protocolo obsoleto, sin cifrado; alto riesgo si está expuesto."),
    25: ("SMTP", "Servicio de correo saliente; vulnerable a spam y ataques de phishing."),
    53: ("DNS", "Servicio de resolución de nombres; vulnerable a ataques de denegación de servicio."),
    80: ("HTTP", "Tráfico web sin cifrar; vulnerable a interceptación (sniffing)."),
    110: ("POP3", "Servicio de correo entrante; vulnerable a acceso no autorizado."),
    143: ("IMAP", "Servicio de correo entrante; vulnerable a acceso no autorizado."),
    443: ("HTTPS", "Tráfico cifrado, pero vulnerable si el servidor usa versiones TLS obsoletas."),
    3306: ("MySQL", "Base de datos expuesta; riesgo crítico si no tiene autenticación fuerte."),
    3389: ("RDP", "Escritorio remoto; objetivo común de ataques de fuerza bruta y ransomware."),
    5000: ("Flask (desarrollo)", "Servicio web de prueba sin HTTPS ni autenticación; expone panel de login directamente."),
    8080: ("HTTP alternativo", "Suele usarse para servicios de desarrollo/pruebas, a veces sin protección."),
}

PUERTOS_WEB = {80, 443, 5000, 8080}  # puertos donde tiene sentido pedir cabeceras HTTP

puertos_abiertos = []
lock = threading.Lock()  # evita que varios hilos escriban a la vez en la lista compartida


def obtener_info(puerto):
    """Núcleo del escáner: devuelve (servicio, riesgo) conocido, o valores genéricos si no."""
    if puerto in PUERTOS_COMUNES:
        return PUERTOS_COMUNES[puerto]
    return ("Desconocido", "Servicio no identificado; revisar manualmente qué está corriendo ahí.")


# ======================================================================
# MÓDULO EXTRA 1: BANNER GRABBING
# ¿Qué es?: al conectarse a un puerto, muchos servicios envían un
# mensaje de bienvenida ("banner") que revela el software y versión
# exacta que corre ahí.
# ¿Para qué sirve?: identificar vulnerabilidades conocidas asociadas
# a esa versión específica del servicio (ej. una versión vieja de SSH).
# ======================================================================

def obtener_banner(host, puerto):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, puerto))
        sock.send(b'\r\n')
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner if banner else None
    except:
        return None


# ======================================================================
# MÓDULO EXTRA 2: CABECERAS HTTP
# ¿Qué es?: para puertos que sirven contenido web, se hace una
# petición HTTP simple y se leen las cabeceras de la respuesta.
# ¿Para qué sirve?: la cabecera "Server" suele revelar el software
# y versión del servidor web (ej. "Werkzeug/3.1.9 Python/3.15.2"),
# útil para el mismo análisis de identificación de versión/riesgo.
# ======================================================================

def obtener_cabeceras_http(host, puerto):
    try:
        esquema = "https" if puerto == 443 else "http"
        resp = requests.get(f"{esquema}://{host}:{puerto}", timeout=1, verify=False)
        return dict(resp.headers)
    except:
        return None


# ======================================================================
# MÓDULO EXTRA 3: INFORMACIÓN DE CERTIFICADO SSL/TLS
# ¿Qué es?: para el puerto 443 (HTTPS), se establece una conexión TLS
# y se extrae el certificado del servidor: quién lo emitió, a quién,
# fechas de validez, versión de TLS y algoritmo de cifrado usado.
# ¿Para qué sirve?: un certificado vencido, autofirmado o con TLS
# obsoleto (1.0/1.1) es una vulnerabilidad real y verificable, y es
# justo el tipo de hallazgo que se espera en un análisis de este tipo.
# ======================================================================

def obtener_info_certificado(host, puerto=443):
    try:
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE  # permite inspeccionar incluso certificados no confiables

        with socket.create_connection((host, puerto), timeout=3) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version_tls = ssock.version()
                cipher = ssock.cipher()

                vencido = False
                if cert and cert.get("notAfter"):
                    try:
                        fecha_exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        vencido = fecha_exp < datetime.now()
                    except:
                        pass

                return {
                    "emisor": dict(x[0] for x in cert.get("issuer", [])) if cert else "No disponible",
                    "sujeto": dict(x[0] for x in cert.get("subject", [])) if cert else "No disponible",
                    "valido_desde": cert.get("notBefore") if cert else "No disponible",
                    "valido_hasta": cert.get("notAfter") if cert else "No disponible",
                    "vencido": vencido,
                    "version_tls": version_tls,
                    "cipher_suite": cipher[0] if cipher else "No disponible",
                }
    except Exception as e:
        return {"error": str(e)}


# ======================================================================
# NÚCLEO DEL ESCÁNER
# Esta es la lógica principal: probar conexión a un puerto, y si está
# abierto, llamar a los módulos extra para enriquecer la información.
# ======================================================================

def escanear_puerto(host, puerto):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((host, puerto))
        sock.close()

        if resultado == 0:
            servicio, riesgo = obtener_info(puerto)

            # Llamadas a los módulos extra (solo cuando aplica al tipo de puerto)
            banner = obtener_banner(host, puerto)
            cabeceras = obtener_cabeceras_http(host, puerto) if puerto in PUERTOS_WEB else None
            certificado = obtener_info_certificado(host, puerto) if puerto == 443 else None

            with lock:
                puertos_abiertos.append((puerto, servicio, riesgo, banner, cabeceras, certificado))

            print(f"[ABIERTO] Puerto {puerto} - {servicio}")
            if banner:
                print(f"           Banner: {banner}")
            if cabeceras:
                print(f"           Servidor HTTP: {cabeceras.get('Server', 'No especificado')}")
            if certificado and "error" not in certificado:
                print(f"           Certificado emitido por: {certificado['emisor']}")
                print(f"           Vencido: {'Sí' if certificado['vencido'] else 'No'}")
    except socket.error:
        pass


def trabajador(cola, host):
    """Núcleo del escáner: cada hilo toma puertos de la cola hasta que se vacía (multithreading)."""
    while not cola.empty():
        puerto = cola.get()
        escanear_puerto(host, puerto)
        cola.task_done()


# ======================================================================
# PROGRAMA PRINCIPAL
# Pide datos al usuario, reparte el trabajo entre hilos, y al final
# genera el resumen en consola y el reporte en archivo .txt.
# ======================================================================

def main():
    print("=== Escáner de Puertos Educativo (con multithreading, banners, cabeceras HTTP y certificados) ===")
    host = input("Ingrese la IP o dominio a escanear (ej. 127.0.0.1): ")

    try:
        host_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print("No se pudo resolver el host.")
        return

    try:
        puerto_inicio = int(input("Puerto inicial (ej. 1): "))
        puerto_fin = int(input("Puerto final (ej. 1024): "))
    except ValueError:
        print("Debes ingresar números válidos para el rango de puertos.")
        return

    # Validación de entrada: evita rangos imposibles o fuera del límite real de puertos (1-65535)
    if puerto_inicio < 1 or puerto_fin > 65535 or puerto_inicio > puerto_fin:
        print("Rango de puertos inválido. Debe estar entre 1 y 65535.")
        return

    print(f"\nEscaneando {host} ({host_ip})")
    print(f"Rango: {puerto_inicio}-{puerto_fin}")
    print(f"Hora de inicio: {datetime.now()}\n")

    cola = Queue()
    for puerto in range(puerto_inicio, puerto_fin + 1):
        cola.put(puerto)

    hilos = []
    num_hilos = 50  # cantidad de hilos simultáneos escaneando (balance velocidad/estabilidad)
    for _ in range(num_hilos):
        hilo = threading.Thread(target=trabajador, args=(cola, host_ip))
        hilo.start()
        hilos.append(hilo)

    for hilo in hilos:
        hilo.join()

    puertos_abiertos.sort(key=lambda x: x[0])

    print(f"\nEscaneo finalizado: {datetime.now()}")
    print(f"Total de puertos abiertos encontrados: {len(puertos_abiertos)}")

    if puertos_abiertos:
        print("\n--- Puertos abiertos, riesgos e información adicional ---")
        for puerto, servicio, riesgo, banner, cabeceras, certificado in puertos_abiertos:
            print(f"- Puerto {puerto} ({servicio}): {riesgo}")
            if banner:
                print(f"    Banner: {banner}")
            if cabeceras:
                print(f"    Servidor HTTP: {cabeceras.get('Server', 'No especificado')}")
            if certificado and "error" not in certificado:
                print(f"    Certificado emitido por: {certificado['emisor']}")
                print(f"    Válido hasta: {certificado['valido_hasta']} (Vencido: {'Sí' if certificado['vencido'] else 'No'})")
                print(f"    TLS: {certificado['version_tls']} | Cipher: {certificado['cipher_suite']}")

        # Generación del reporte en archivo de texto, dentro de la carpeta "reporte"
        # Cada ejecución genera un archivo con fecha y hora distintas, para llevar un historial
        carpeta_reportes = "reporte"
        os.makedirs(carpeta_reportes, exist_ok=True)  # crea la carpeta si no existe, sin dar error si ya existe

        marca_tiempo = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        nombre_archivo = f"reporte_escaneo_{marca_tiempo}.txt"
        ruta_completa = os.path.join(carpeta_reportes, nombre_archivo)

        with open(ruta_completa, "w", encoding="utf-8") as f:
            f.write(f"Reporte de escaneo - {host} ({host_ip})\n")
            f.write(f"Rango escaneado: {puerto_inicio}-{puerto_fin}\n")
            f.write(f"Fecha: {datetime.now()}\n\n")
            f.write("Puertos abiertos, riesgos e información adicional:\n")
            for puerto, servicio, riesgo, banner, cabeceras, certificado in puertos_abiertos:
                f.write(f"\n- Puerto {puerto} ({servicio})\n")
                f.write(f"  Riesgo: {riesgo}\n")
                if banner:
                    f.write(f"  Banner: {banner}\n")
                if cabeceras:
                    f.write(f"  Servidor HTTP: {cabeceras.get('Server', 'No especificado')}\n")
                    f.write(f"  Cabeceras completas: {cabeceras}\n")
                if certificado and "error" not in certificado:
                    f.write(f"  Certificado emitido por: {certificado['emisor']}\n")
                    f.write(f"  Sujeto: {certificado['sujeto']}\n")
                    f.write(f"  Válido desde: {certificado['valido_desde']} hasta: {certificado['valido_hasta']}\n")
                    f.write(f"  Vencido: {'Sí' if certificado['vencido'] else 'No'}\n")
                    f.write(f"  Versión TLS: {certificado['version_tls']} | Cipher: {certificado['cipher_suite']}\n")
                elif certificado and "error" in certificado:
                    f.write(f"  Certificado: no se pudo obtener ({certificado['error']})\n")
        print(f"\nReporte guardado en '{ruta_completa}'")
    else:
        print("\nNo se encontraron puertos abiertos en el rango especificado.")


if __name__ == "__main__":
    main()
    input("\nPresione Enter para salir...")