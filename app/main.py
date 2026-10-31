import argparse
import os
import socket
import struct
import sys
import threading
import time

from cryptography.exceptions import InvalidTag

from app.crypto import (
    NONCE_SIZE,
    SESSION_KEY_SIZE,
    aes_decrypt,
    aes_encrypt,
    generate_keypair,
    generate_session_key,
    public_key_from_bytes,
    public_key_to_bytes,
    rsa_decrypt,
    rsa_encrypt,
)


def send_frame(sock, data: bytes):
    """Envia un mensaje con prefijo de longitud (4 bytes, big-endian)."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("conexion cerrada")
        buf += chunk
    return buf


def recv_frame(sock) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)


def listen(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[*] Esperando conexion en el puerto {port}...")
    conn, addr = srv.accept()
    print(f"[+] Conexion desde {addr[0]}:{addr[1]}")
    return conn


def connect(host: str, port: int) -> socket.socket:
    for _ in range(30):
        try:
            sock = socket.create_connection((host, port))
            print(f"[+] Conectado a {host}:{port}")
            return sock
        except OSError:
            time.sleep(1)
    sys.exit(f"[!] No se pudo conectar a {host}:{port}")


# Colores ANSI; se desactivan si la salida no es una terminal (o con NO_COLOR).
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
GREEN, YELLOW, CYAN, MAGENTA, RED = "32", "33", "36", "35", "1;31"


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


CONFIRMATION = b"SESSION_OK"
closing = threading.Event()  # se activa cuando este lado cierra la sesion


def handshake(sock, is_listener, private_key, peer_public_key) -> bytes:
    """Handshake hibrido. El que se conecta (Alice) genera la clave de sesion y
    la envia cifrada con RSA-OAEP con la publica del que escucha (Bob)."""
    if is_listener:
        encrypted_key = recv_frame(sock)
        print(f"[<] Clave de sesion cifrada recibida ({len(encrypted_key)} bytes)")
        session_key = rsa_decrypt(private_key, encrypted_key)
        if len(session_key) != SESSION_KEY_SIZE:
            raise ValueError("clave de sesion con tamano invalido")
        print("[+] Clave de sesion recuperada con mi clave privada")
        # Confirmacion: ambos demuestran tener la misma clave usando AES-GCM.
        send_frame(sock, aes_encrypt(session_key, CONFIRMATION))
        if aes_decrypt(session_key, recv_frame(sock)) != CONFIRMATION:
            raise ValueError("confirmacion de sesion invalida")
    else:
        session_key = generate_session_key()
        encrypted_key = rsa_encrypt(peer_public_key, session_key)
        send_frame(sock, encrypted_key)
        print(f"[>] Clave de sesion generada y enviada cifrada ({len(encrypted_key)} bytes)")
        if aes_decrypt(session_key, recv_frame(sock)) != CONFIRMATION:
            raise ValueError("confirmacion de sesion invalida")
        send_frame(sock, aes_encrypt(session_key, CONFIRMATION))
    return session_key


def receiver(sock, peer: str, session_key: bytes):
    try:
        while True:
            data = recv_frame(sock)
            print(color(f"\r[<] Ciphertext recibido: {data.hex()}", MAGENTA))
            try:
                # aes_decrypt verifica el tag antes de devolver el plaintext.
                msg = aes_decrypt(session_key, data).decode()
            except (InvalidTag, ValueError):
                print(color("[!] RECHAZADO: autenticacion invalida, mensaje descartado", RED))
                print("> ", end="", flush=True)
                continue
            print(color(f"[{peer}] Plaintext recuperado: {msg}", CYAN))
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        if not closing.is_set():
            print(f"\n[!] {peer} cerro la conexion. Sesion finalizada.", flush=True)
            # sys.exit() en un hilo no termina el proceso (el principal sigue en input()).
            os._exit(0)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--listen", action="store_true")
    mode.add_argument("--connect", metavar="HOST")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()

    sock = listen(args.port) if args.listen else connect(args.connect, args.port)

    # Paso 2: par de claves RSA propio. La privada nunca sale de este proceso
    # ni se imprime; solo se envia la publica.
    print("[*] Generando par de claves RSA-2048...")
    private_key = generate_keypair()
    public_key = private_key.public_key()

    send_frame(sock, args.name.encode())
    send_frame(sock, public_key_to_bytes(public_key))
    peer = recv_frame(sock).decode()
    peer_public_key = public_key_from_bytes(recv_frame(sock))
    print(f"[+] Clave publica de {peer} recibida (RSA-{peer_public_key.key_size})")

    try:
        session_key = handshake(sock, args.listen, private_key, peer_public_key)
    except (ValueError, InvalidTag, ConnectionError) as e:
        sys.exit(f"[!] Handshake fallido: {e}")
    print(color(f"[+] SESION SEGURA ESTABLECIDA con {peer} (AES-256-GCM)", GREEN))
    print("[+] Escribe mensajes ('/quit' para salir, '/tamper' para alterar el siguiente).")

    threading.Thread(target=receiver, args=(sock, peer, session_key), daemon=True).start()

    tamper_next = False
    try:
        while True:
            line = input("> ")
            if line == "/quit":
                break
            if line == "/tamper":
                tamper_next = True
                print(color("[TAMPER] El siguiente mensaje se enviara con 1 byte alterado.", RED))
                continue
            data = aes_encrypt(session_key, line.encode())
            print(color(f"[>] Plaintext local: {line}", GREEN))
            print(color(f"[>] Ciphertext enviado (nonce+ct+tag): {data.hex()}", YELLOW))
            if tamper_next:
                tamper_next = False
                # Invierte todos los bits del primer byte despues del nonce.
                altered = bytearray(data)
                altered[NONCE_SIZE] ^= 0xFF
                data = bytes(altered)
                print(color(f"[TAMPER] Ciphertext alterado (byte {NONCE_SIZE}): {data.hex()}", RED))
            send_frame(sock, data)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        closing.set()
        sock.close()
        print("[+] Sesion finalizada.", flush=True)


if __name__ == "__main__":
    main()
