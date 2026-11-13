import socket

# Fill in the right target here
HOST = "netsec.net.in.tum.de"  # TODO
PORT = 20001  # TODO


def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((HOST, PORT))

        sf = s.makefile("rw")

        # Step 1: Read username prompt
        print(sf.readline().strip())

        # Step 2: Send username
        sf.write("admin\n")
        sf.flush()

        # Step 3: Read password prompt
        print(sf.readline().strip())

        # Step 4: Send password
        sf.write("password\n")
        sf.flush()

        # Step 5: Read authentication response
        print(sf.readline().strip())

        # Step 6: Read flag
        flag = sf.readline()
        print(flag.strip())

        sf.close()

    finally:
        s.close()


if __name__ == '__main__':
    get_flag()
