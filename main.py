import argparse
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict


@dataclass
class HttpRequest:
    method: bytes
    host: str
    port: int
    full_resource_path: bytes
    version: bytes
    headers: Dict


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class Server:
    def __init__(self, port, image_flag, attack_flag, proxy_logger):
        self.logger = proxy_logger

        self.is_sub_image = image_flag == 1
        self.sub_image_full_resource_url = b"http://ocna0.d2.comp.nus.edu.sg:50000/change.jpg"
        self.sub_image_url_host = "ocna0.d2.comp.nus.edu.sg"
        self.sub_image_url_port = 50000

        self.is_attack_webpage = attack_flag == 1

        self.telemetry = {}
        self._lock = threading.Lock()

        try:
            self.main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.main_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as e:
            proxy_logger.error(f"Unable to create/re-use the socket. Error: {e}")

        self.main_socket.bind(("localhost", port))
        max_client_connection = 10
        self.main_socket.listen(max_client_connection)
        proxy_logger.info(f"Proxy server is listening for clients at port {port}")

    def start(self):
        try:
            while True:
                client_connection_socket, client_address = self.main_socket.accept()
                ip_address = client_address[0]
                port = client_address[1]
                self.logger.info(f"Receiving connection from host: {ip_address} @Port: {port}")
                t = threading.Thread(target=self.proxy_handler, args=(client_connection_socket, ip_address, port,))
                t.start()
        except KeyboardInterrupt:
            self.logger.info("Closing down the main socket")
            self.main_socket.close()

    def proxy_handler(self, client_connection_socket, ip_address, port):
        buffer_size = 2048
        client_request = client_connection_socket.recv(buffer_size)
        http_version = b'HTTP/1.1' if b'HTTP/1.1' in client_request else b'HTTP/1.0'

        try:
            http_contents = self.parse_http(client_request)
            self.logger.info(f"Receiving HTTP Request: {http_contents}")

            if http_contents.method != b"GET":  # as per Piazza response, handling GET should be enough
                self.logger.warning(
                    f"Sending 405 to {ip_address}@{port} for method {http_contents.method.decode('utf-8')}"
                )
                client_connection_socket.sendall(http_version + b' 405 Method Not Allowed\r\n\r\n')
                client_connection_socket.close()
                return

            code, message, size = self.relay_request_to_server(http_contents, client_request)
            if code == 200:
                client_connection_socket.sendall(message)
                self.handle_telemetry(http_contents, size)
                client_connection_socket.close()
                return
            if code == 301:
                client_connection_socket.sendall(message)
                client_connection_socket.close()
                return
            else:
                self.logger.warning(
                    f"Sending {code} to {ip_address}@{port} for {http_contents.full_resource_path.decode('utf-8')}"
                )
                http_response = http_version + b' ' + str(code).encode('utf-8') + b' ' + message + b'\r\n\r\n'
                client_connection_socket.sendall(http_response)
                client_connection_socket.close()

        except ValueError as e:
            self.logger.warning(f"Sending 400 to {ip_address}@{port} for message: {client_request} because of {e}")
            client_connection_socket.sendall(http_version + b' 400 Bad Request\r\n\r\n')
            client_connection_socket.close()
            return

    def is_an_image_request(self, parsed_http_request):
        accept_headers = parsed_http_request.headers.get(b'Accept')
        is_accepting_image = False
        if b'image' in accept_headers or b'*/*' in accept_headers:
            is_accepting_image = True

        image_extensions = [b'.jpg', b'.png', b'.ico', b'.jpeg', b'.gif', b'.tiff']  # common image extensions
        for ext in image_extensions:
            if ext in parsed_http_request.full_resource_path.lower() and is_accepting_image:
                return True

        return False

    def build_sub_image_request(self, parsed_http_request):
        http_request = b'GET ' + self.sub_image_full_resource_url + b' ' + parsed_http_request.version + b'\r\n'
        http_request += b'Host: ' + f"{self.sub_image_url_host}:{self.sub_image_url_port}".encode('utf-8') + b'\r\n'
        for key, value in parsed_http_request.headers.items():
            if key == b'Host':
                continue
            http_request += key + b': ' + value + b'\r\n'
        http_request += b'\r\n'
        self.logger.info(http_request)
        return http_request

    def attack_html_request(self, parsed_http_request):
        html = b'<html><h1>You are being attacked</h1></html>'
        http_response = parsed_http_request.version + b' 200 OK\r\n\r\n'
        http_response += html
        return http_response, len(html)

    def relay_request_to_server(self, parsed_http_request, client_request):
        if self.is_attack_webpage:
            http_response, length = self.attack_html_request(parsed_http_request)
            return 200, http_response, length

        proxy_connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_connection_socket.settimeout(10)

        if self.is_an_image_request(parsed_http_request) and self.is_sub_image:
            parsed_http_request.full_resource_path = self.sub_image_full_resource_url
            parsed_http_request.port = self.sub_image_url_port
            parsed_http_request.host = self.sub_image_url_host
            client_request = self.build_sub_image_request(parsed_http_request)

        proxy_connection_socket.connect((parsed_http_request.host, parsed_http_request.port))
        proxy_connection_socket.sendall(client_request)

        header = b''
        while b'\r\n\r\n' not in header:
            server_response = proxy_connection_socket.recv(4096)
            header += server_response

        http_header, data = header.split(b'\r\n\r\n', 1)
        web_server_full_response = header

        content_length = -1
        # Find content length
        headers = http_header.split(b'\r\n')
        _, status, message = headers[0].split(b' ', 2)
        if int(status) not in [200, 301]:
            return int(status), message, 0

        for item in headers:
            if item.startswith(b'Content-Length'):
                header, data = item.split(b':', 1)
                content_length = int(data)
                break

        # if there is content-length header, read until content-length, otherwise read until timeout
        if content_length == -1:
            while True:
                try:
                    server_response = proxy_connection_socket.recv(4096)
                except TimeoutError:
                    _, data = header.split(b'\r\n\r\n', 1)
                    self.logger.info(
                        f"Timeout with no content-length, receive {len(web_server_full_response)}B "
                        f"({len(data)}B w/o headers) of data from {parsed_http_request.host}@{parsed_http_request.port}"
                    )
                    return int(status), web_server_full_response, len(data)

                if not server_response:
                    break
                else:
                    web_server_full_response += server_response

            proxy_connection_socket.close()
            _, data = header.split(b'\r\n\r\n', 1)
            self.logger.info(
                f"Successfully receive {len(web_server_full_response)}B ({len(data)}B w/o headers) "
                f"of data from {parsed_http_request.host}@{parsed_http_request.port}"
            )
            return int(status), web_server_full_response, len(data)
        else:
            while len(web_server_full_response) < content_length:
                try:
                    server_response = proxy_connection_socket.recv(4096)
                except TimeoutError:
                    return 408, b'', 0
                if not server_response:
                    break
                else:
                    web_server_full_response += server_response

            proxy_connection_socket.close()
            self.logger.info(
                f"Successfully receive {len(web_server_full_response)}B ({content_length}B w/o headers) "
                f"of data from {parsed_http_request.host}@{parsed_http_request.port}"
            )
            return int(status), web_server_full_response, content_length

    def parse_http(self, message: str):
        valid_http_messages = (b"GET", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"PATCH", b"TRACE", b"HEAD")
        is_valid_message = message.startswith(valid_http_messages)
        if not is_valid_message:
            raise ValueError("Invalid Method")

        is_valid_ending = message.endswith(b"\r\n\r\n")
        if not is_valid_ending:
            raise ValueError("Invalid Ending")

        try:
            messages = message[:-4].split(b"\r\n")
            method, full_path, http_version = messages[0].split(b" ")
            headers = {}
            for item in messages[1:]:
                field, value = item.split(b": ", 1)
                headers[field] = value

            host_port = headers.get(b'Host')
            if host_port is None:
                raise ValueError("Host not found in HTTP request")

            if b':' in host_port:
                host, port = host_port.split(b':')
            else:
                host = host_port
                port = 80  # Assume common HTTP port

            host = host.decode('utf-8')
            port = int(port)

            return HttpRequest(method, host, port, full_path, http_version, headers)
        except Exception as e:
            raise ValueError(f"Invalid Parsing: {e}")

    def check_telemetry(self, key, url):
        timeout = 7.5  # purely based on heuristics
        while time.time() < self.telemetry[key][0] + timeout:
            remainder_time = self.telemetry[key][0] + timeout - time.time()
            time.sleep(remainder_time)

        telemetry_result = f"{url.decode('utf-8')}, {self.telemetry[key][1]}"
        self.logger.info(f"Printing telemetry result: {telemetry_result}")
        print(telemetry_result)

        with self._lock:
            del self.telemetry[key]

    def handle_telemetry(self, http_parsed_content, message_size):
        key = (http_parsed_content.host, http_parsed_content.port)
        url = http_parsed_content.full_resource_path.replace(b'//', b'||').split(b'/')[0].replace(b'||', b'//')

        with self._lock:
            if self.telemetry.get(key) is None:
                self.telemetry[key] = (time.time(), message_size)

                t = threading.Thread(target=self.check_telemetry, args=(key, url,))
                t.start()
            else:
                self.telemetry[key] = (time.time(), self.telemetry[key][1] + message_size)


if __name__ == '__main__':
    # Create logger
    logger = logging.getLogger("Proxy")
    logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    # To disable logging, uncomment the following line
    # logger.disabled = True

    # Create parser
    parser = argparse.ArgumentParser(description="Python proxy server for CS3103 assignments")
    parser.add_argument('port', metavar='P', type=int,
                        help='The port the proxy is listening on, check your firefox:)')
    parser.add_argument('image_flag', metavar='I', type=int,
                        help='Image substitution flag, 0 for disabling it and 1 to activate it')
    parser.add_argument('attack_flag', metavar='A', type=int,
                        help='HTTP Attack flag, 0 for disabling it and 1 to activate it')
    args = parser.parse_args()
    assert 0 <= args.image_flag <= 1 and 0 <= args.attack_flag <= 1, "Invalid arguments"

    s = Server(args.port, args.image_flag, args.attack_flag, logger)
    s.start()
