import socket

HOST = "27.133.128.207"
PORT = 54321
MESSAGE = "mahi"

def main():
    data = MESSAGE.encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(data, (HOST, PORT))

if __name__ == "__main__":
    main()
