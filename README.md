# SecureChat

Chat cifrado entre dos instancias (Alice y Bob) con criptografía híbrida. Corre en Docker.

> Estado: versión preliminar. Solo está el chat TCP sin cifrar (Paso 1) y la infraestructura de contenedores.

## Requisitos
- Docker Desktop (incluye `docker compose`)

## Ejecución
Abrir dos terminales en la carpeta del proyecto:

```bash
# Terminal 1 - Bob (escucha)
docker compose run --rm bob

# Terminal 2 - Alice (se conecta a Bob)
docker compose run --rm alice
```

Para salir: `/quit`. Después del cambio de código: `docker compose build`.

## Pendiente
- [ ] Paso 2: pares de claves RSA-2048
- [ ] Paso 3: handshake (RSA-OAEP) y clave de sesión
- [ ] Paso 4-5: AES-256-GCM y chat bidireccional con evidencia visible
- [ ] Paso 6: comando `/tamper`
- [ ] README final: protocolo, limitaciones y respuestas de cierre
