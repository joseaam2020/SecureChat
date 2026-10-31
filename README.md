# SecureChat

Chat cifrado de consola entre dos procesos (Alice y Bob) en la misma computadora, usando criptografía híbrida: RSA-2048 con OAEP para establecer la sesión y AES-256-GCM para proteger cada mensaje.

## Requisitos
- Python 3.8 o superior y la biblioteca `cryptography` (`requirements.txt`), **o**
- Docker con `docker compose`

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

### Opción A: Python sobre localhost

Abrir dos terminales en la carpeta del proyecto:

```bash
# Terminal 1 - Bob (escucha)
python3 -m app.main --name Bob --listen --port 5000

# Terminal 2 - Alice (se conecta a Bob)
python3 -m app.main --name Alice --connect 127.0.0.1 --port 5000
```

### Opción B: Docker

```bash
docker compose build
docker compose run --rm bob      # Terminal 1
docker compose run --rm alice    # Terminal 2
```

En este caso los contenedores se comunican por una red interna de Docker en lugar de `localhost`.

### Comandos dentro del chat
| Comando | Acción |
|---|---|
| texto + Enter | Cifra y envía el mensaje |
| `/tamper` | El siguiente mensaje se envía con 1 byte del ciphertext alterado |
| `/quit` | Cierra la sesión |

## Demostración

1. Iniciar Bob y luego Alice. Ambos muestran `SESION SEGURA ESTABLECIDA` al terminar el handshake.
2. Enviar al menos tres mensajes desde cada lado. El emisor ve el plaintext local y el ciphertext enviado; el receptor ve el ciphertext recibido y el plaintext recuperado.
3. Escribir `/tamper` y luego un mensaje. El receptor muestra `RECHAZADO: autenticacion invalida` y no muestra ningún plaintext.
4. Escribir `/quit` para finalizar.

## Protocolo

### Algoritmos
| Uso | Algoritmo | Tamaño |
|---|---|---|
| Establecimiento de la sesión | RSA con OAEP (SHA-256, MGF1-SHA-256) | 2048 bits |
| Cifrado de mensajes | AES-GCM | Clave de 256 bits, nonce de 96 bits, tag de 128 bits |

### Handshake
1. Bob escucha y Alice se conecta por TCP.
2. Cada uno genera su propio par RSA-2048 en memoria. La clave privada nunca sale del proceso ni se imprime.
3. Ambos envían su nombre y su clave pública en formato PEM.
4. Alice genera una clave de sesión AES-256 aleatoria, la cifra con la clave pública de Bob (RSA-OAEP) y la envía.
5. Bob la descifra con su clave privada.
6. Ambos intercambian el mensaje `SESSION_OK` cifrado con AES-GCM para confirmar que tienen la misma clave.

### Formato de los mensajes
Cada mensaje en el socket se envía con un prefijo de longitud:

```
[ longitud: 4 bytes big-endian ][ payload ]
```

Después del handshake, el payload de cada mensaje de chat es:

```
[ nonce: 12 bytes ][ ciphertext: n bytes ][ tag: 16 bytes ]
```

El nonce es aleatorio (`os.urandom`) para cada mensaje. El receptor verifica el tag antes de descifrar y descarta el mensaje si la verificación falla.

### Limitaciones
- Las claves públicas no se autentican, por lo que el protocolo no protege contra un ataque de intermediario (MITM) activo.
- Si se compromete la clave privada de Bob, se puede descifrar la clave de sesión enviada en el handshake y, con ella, el tráfico grabado de esa sesión. Como los pares RSA se generan en cada ejecución, el daño se limita a esa sesión.

## Estructura
```
app/crypto.py   Primitivas criptográficas (RSA-OAEP, AES-GCM)
app/main.py     Sockets, handshake y chat
Preguntas de cierre/Preguntas_de_cierre.md   Respuestas del punto 8
```

## Preguntas de cierre
Las respuestas están en [Preguntas de cierre/Preguntas_de_cierre.md](Preguntas%20de%20cierre/Preguntas_de_cierre.md).
