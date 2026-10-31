# SecureChat

Chat de consola cifrado entre dos procesos en la misma máquina. RSA-2048 con OAEP establece la sesión y AES-256-GCM protege los mensajes.

## Requisitos
- Python 3.8+ y `cryptography`, o Docker con `docker compose`.

```bash
pip install -r requirements.txt
```

## Ejecución

### Python (localhost)
```bash
# Terminal 1 - Bob
python3 -m app.main --name Bob --listen --port 5000

# Terminal 2 - Alice
python3 -m app.main --name Alice --connect 127.0.0.1 --port 5000
```

### Docker
```bash
docker compose build
docker compose run --rm bob      # Terminal 1
docker compose run --rm alice    # Terminal 2
```
Con Docker la conexión va por una red interna de Docker, no por `localhost`.

## Comandos
- Texto + Enter: cifra y envía el mensaje.
- `/tamper`: altera 1 byte del ciphertext del siguiente mensaje.
- `/quit`: cierra la sesión.

## Demostración
1. Arrancar Bob y después Alice; ambos deben mostrar `SESION SEGURA ESTABLECIDA`.
2. Enviar al menos tres mensajes desde cada lado. El emisor ve el plaintext local y el ciphertext enviado; el receptor ve el ciphertext recibido y el plaintext recuperado.
3. Usar `/tamper` y enviar un mensaje; el receptor lo rechaza sin mostrar plaintext.
4. Cerrar con `/quit`.

## Protocolo

### Algoritmos
- **Asimétrico:** RSA-2048 con OAEP (SHA-256, MGF1-SHA-256), solo para la clave de sesión.
- **Simétrico:** AES-256-GCM, con nonce de 96 bits y tag de 128 bits.

### Handshake
1. Bob escucha y Alice se conecta por TCP.
2. Cada uno genera un par RSA-2048 en memoria. La clave privada nunca se envía ni se imprime.
3. Intercambian nombre y clave pública (PEM).
4. Alice genera una clave AES-256 aleatoria, la cifra con la pública de Bob y la envía.
5. Bob la descifra con su privada.
6. Ambos intercambian `SESSION_OK` cifrado con AES-GCM para confirmar que tienen la misma clave.

### Formato de los mensajes
Cada frame del socket:
```
[ longitud: 4 bytes big-endian ][ payload ]
```
Payload de cada mensaje de chat:
```
[ nonce: 12 bytes ][ ciphertext ][ tag: 16 bytes ]
```
El nonce sale de `os.urandom` en cada mensaje. El receptor verifica el tag antes de aceptar el plaintext y descarta el mensaje si falla.

## Limitaciones
- Las claves públicas no se autentican, así que no hay protección contra un MITM activo.
- Si se compromete la clave privada de Bob, se puede recuperar la clave de sesión y descifrar el tráfico grabado de esa sesión. Como los pares RSA se generan en cada ejecución, el daño se queda en esa sesión.

## Estructura
- `app/crypto.py`: primitivas criptográficas (RSA-OAEP, AES-GCM).
- `app/main.py`: sockets, handshake y chat.
- `Preguntas de cierre/Preguntas_de_cierre.md`: respuestas del punto 8.
