import socket
import threading
from handleclient import *


def processNewConnection(conn, addr):
    print(40 * "-")
    print(f"-> client {addr} connected.")
    # create new handle to treate client
    client_handle = HandleClient(conn)
    while True:
        try:
            #------- receive request head and unpack it
            request = Request()
            req_buf = conn.recv(REQUEST_HEADER_SIZE)
            request.unpackRequestHeader(req_buf)

            #------- receive payload -----
            payload_buf = bytes()

            while True:
                if len(payload_buf) >= request.payload_size:
                    break
                else:
                    packet = conn.recv(request.payload_size - len(payload_buf))
                    if not packet:
                        break
                    payload_buf += packet

            # If there is no more request, break the process
            if not client_handle.receivePayload(request, payload_buf):
                break
        except Exception as e:
            print(f"[Exception] {e}")
            break
    conn.close()


# --------- check file storate ---------
is_exist = os.path.exists(FILE_STORAGE)
if not is_exist:
    # Create a new directory because it does not exist
    os.makedirs(FILE_STORAGE)

# ----------- set ip and port ------
tcp_ip = '127.0.0.1'
tcp_port = 1357  # default port
try:
    port_file = open(PORT_INFO, "r")
    port = port_file.read()
    tcp_port = int(port)
    port_file.close()
except Exception:
    tcp_port = 1357
    print("----> Cannot import port file. HandleClient will use default port 1357")
server_addr = (tcp_ip, tcp_port)

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(server_addr)
server_sock.listen()
print(f"----> Server is running on {tcp_ip}:{tcp_port}")

try:
    while True:
        # waiting for new client connection
        conn, server_addr = server_sock.accept()
        thread = threading.Thread(target=processNewConnection, args=(conn, server_addr))
        thread.start()

except Exception as e:
    print(e)
