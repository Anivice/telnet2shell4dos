import socket
import sys
import threading
import textwrap
import ollama
from time import sleep

# Set up the server address and port
HOST = '0.0.0.0'
PORT = 2224

def end_of_dos_screen(message):
    off = 0
    msg_off = 0
    for c in message:
        if c == '\n':
            off = off + (80 - (off % 80))
        else:
            off = off + 1

        if off >= 1919:
            if 0x20 < ord(message[msg_off]) < 0x7F:  # printable
                while msg_off > 0 and (0x20 < ord(message[msg_off]) < 0x7F):  # decrease msg_off until non-printable or is space
                    msg_off -= 1

            return msg_off

        msg_off += 1

    return msg_off

class Server:
    def __init__(self, host, port):
        self.Host = host
        self.Port = port
        self.threads = { }
        self.main_loop_thread = None
        self.main_loop_thread_stop = False
        self.messages = [{"role": "assistant", "content": "You are here to answer all questions."}]

    def __main_loop(self):
        # Create a socket object
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the address and port
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(5)  # Allow up to 5 pending connections

        print(f"Telnet service started on {HOST}:{PORT}")
        while not self.main_loop_thread_stop:
            # Accept incoming connections
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection established with {client_address}")

                thread = threading.Thread(target=self.__handle_client, args=(client_socket,))
                self.threads[client_socket] = thread
                thread.start()
            except OSError:
                pass

        # stopped, waiting for client to quit
        for this_socket, thread in self.threads.items():
            this_socket.close()
            thread.join()

    def start(self):
        self.main_loop_thread = threading.Thread(target=self.__main_loop)
        self.main_loop_thread.start()

    def stop(self):
        self.server_socket.close()
        self.main_loop_thread_stop = True
        self.main_loop_thread.join()

    def __handle_client(self, client_socket):
        def send_literal_response(msg):
            try:
                client_socket.send(b'\r\n' + msg.encode())
            except OSError:
                pass

        try:
            send_literal_response("Welcome to Telnet DOS to Ollama Backend Wrapper!")
            send_literal_response("Ollama > ")
            current_response_before_break = ""
            pwd = ""

            while True:
                # Receive data from the client
                data = client_socket.recv(1024)
                if not data:
                    print("Client closed, abort")
                    break  # Client disconnected

                # first, append message
                data_str = data.decode('utf-8', 'ignore')
                data_str = data_str.replace('\x00', '')

                # filter out control characters
                # end of the DOS command input
                if data_str == '\r':  # Enter
                    if len(current_response_before_break) > 0:
                        print(f"<<< {current_response_before_break}")
                        send_literal_response("Please wait...")

                        if (current_response_before_break.lower() == "quit"
                                or current_response_before_break.lower() == "exit"):
                            print("Client requested quit")
                            send_literal_response('Goodbye!')
                            client_socket.close()
                            break

                        self.messages.append({"role": "user", "content": current_response_before_break})
                        response_from_ollama_json = ollama.chat(
                            model="huihui_ai/phi4-abliterated:latest",
                            messages=self.messages,
                            options={"keep_alive": -1}
                        )

                        response_str = response_from_ollama_json['message']['content']

                        print(f">>> {response_str}")
                        lines = response_str.splitlines()
                        wrapped_lines = []
                        for line in lines:
                            wrapped_text = textwrap.wrap(line, width=80)
                            for wrapped_line in wrapped_text:
                                wrapped_lines.append(wrapped_line)
                        current_response_before_break = ""
                        response_to_dos = ""
                        for line in wrapped_lines:
                            for i in range(0, len(line)):
                                char = line[i]
                                if ord(char) > 127: # non printable
                                    response_to_dos += '*'
                                elif char == '\n':
                                    response_to_dos += '\r\n'
                                else:
                                    response_to_dos += char
                            response_to_dos += "\r\n"

                        if len(response_to_dos) == 0 or (len(response_to_dos) > 0 and response_to_dos[0] != '\r'):
                            response_to_dos = '\r\n' + response_to_dos

                        if end_of_dos_screen(response_to_dos) < len(response_to_dos):
                            literals = []
                            while len(response_to_dos) > 0:
                                end = end_of_dos_screen(response_to_dos)
                                chunk = response_to_dos[0:end]
                                literals.append(chunk)
                                response_to_dos = response_to_dos[end:]

                            for literal in literals:
                                printable_characters = 0
                                skipped_chars = [' ']
                                for char in literal:
                                    if not char in skipped_chars:
                                        printable_characters += 1
                                if printable_characters == 0:
                                    continue
                                send_literal_response(literal + '\r\nPress Enter to continue...')
                                client_socket.recv(1024)
                        else:
                            client_socket.send(response_to_dos.encode('utf-8'))

                    else:
                        client_socket.send(b'\r\n')  # new line

                    send_literal_response("Ollama > ")
                elif data_str == '\x7f':  # Backspace
                    current_response_before_break = current_response_before_break[0:len(current_response_before_break) - 1]
                    client_socket.send(b'\rOllama > ' + current_response_before_break.encode('utf-8') + b' \x08')
                else:
                    if 0x20 <= ord(data_str[0]) <= 0x7E:
                        current_response_before_break += data_str
                        client_socket.send(data_str.encode('utf-8'))
                    else:
                        print(f"Unhandled control character {hex(ord(data_str[0]))}", end="")
                        if len(data_str) > 1:
                            print(data_str[1:len(data_str)])
                        else:
                            print()

            # Close the client connection
            client_socket.close()
        except OSError:
            pass

if __name__ == "__main__":
    if len(sys.argv) == 2:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    elif len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)

    telnet_service = Server(HOST, PORT)
    telnet_service.start()
    sleep(.5) # wait for the service to start
    print("Press Ctrl+C to exit")
    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            print("Stopping Telnet service...")
            telnet_service.stop()
            sys.exit(0)
