# SecureChat — Preguntas de cierre

### 1. ¿Qué problema resuelve la criptografía asimétrica durante el handshake?

Resuelve la distribución de la clave de sesión. Alice y Bob no comparten ningún secreto al inicio, así que Alice cifra la clave de sesión con la clave pública de Bob (RSA-OAEP) y solo Bob puede recuperarla con su clave privada. Así la clave simétrica nunca viaja en texto plano.

### 2. ¿Por qué la conversación utiliza criptografía simétrica después del handshake?

Porque AES es mucho más rápido que RSA, y RSA-OAEP solo puede cifrar unos pocos bytes por operación. Además, AES-GCM da confidencialidad e integridad al mismo tiempo, así que es lo adecuado para proteger muchos mensajes durante la sesión.

### 3. ¿Qué información puede observar un tercero que capture los paquetes de la conversación?

Solo metadatos y datos públicos: IPs, puertos, tiempos, cantidad y tamaño aproximado de los mensajes, las claves públicas, la clave de sesión cifrada con RSA, y el nonce, el ciphertext y el tag de cada mensaje. No puede ver el contenido de los mensajes, la clave de sesión ni las claves privadas.

### 4. ¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?

Puede viajar en claro porque no es secreto; la seguridad depende de la clave y el receptor necesita el nonce para descifrar. No debe repetirse con la misma clave porque GCM genera el keystream a partir del nonce: si se repite, el XOR de dos ciphertexts revela el XOR de sus plaintexts, y además un atacante puede recuperar la clave de autenticación y falsificar tags.

### 5. ¿Qué función cumple el authentication tag?

Garantiza la integridad y autenticidad del mensaje. El receptor recalcula el tag con la clave de sesión y, si no coincide, rechaza el mensaje sin descifrarlo. Así se detecta cualquier modificación del ciphertext, del nonce o del tag.

### 6. ¿Qué ocurriría si la clave de sesión se transmitiera sin protección?

Cualquiera que capture el tráfico obtendría la clave, podría descifrar todos los mensajes de la sesión y también crear o modificar mensajes con tags válidos, haciéndose pasar por cualquiera de los dos participantes. El cifrado simétrico dejaría de servir.

### 7. ¿Qué ocurriría si un atacante obtiene una de las claves privadas?

Podría descifrar la clave de sesión enviada a ese participante y, con ella, leer y modificar todos los mensajes de esa sesión, incluso si solo grabó el tráfico y lo descifra después. Como en nuestra implementación el par RSA se genera en memoria en cada ejecución y no se guarda, el daño se limita a esa sesión. Si el par de claves fuera persistente, el atacante también podría descifrar sesiones futuras y suplantar a ese participante en cada handshake.
