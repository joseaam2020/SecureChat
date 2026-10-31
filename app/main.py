import argparse
import socket
import struct
import sys
import threading
import time

from app.crypto import (
    generate_keypair,
    public_key_from_bytes,
    public_key_to_bytes,
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


def receiver(sock, peer: str):
    try:
        while True:
            msg = recv_frame(sock)
            print(f"\r[{peer}] {msg.decode()}\n> ", end="", flush=True)
    except (ConnectionError, OSError):
        print("\n[!] Conexion finalizada.")
        sys.exit(0)


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

    # TODO Paso 3: handshake -- cifrar la clave de sesion con rsa_encrypt(peer_public_key, ...)
    # y recuperarla con rsa_decrypt(private_key, ...).
    print(f"[+] Conectado con {peer}. Escribe mensajes ('/quit' para salir).")

    threading.Thread(target=receiver, args=(sock, peer), daemon=True).start()

    try:
        while True:
            line = input("> ")
            if line == "/quit":
                break
            # TODO Paso 4: cifrar con AES-256-GCM antes de enviar.
            send_frame(sock, line.encode())
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
