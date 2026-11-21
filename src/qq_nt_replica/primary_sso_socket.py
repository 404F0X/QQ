import math
import select
import socket
import threading

from .errors import InputError


class SsoSocketError(OSError):
    def __init__(self, code, os_errno=None):
        self.code, self.os_errno = code, os_errno
        super().__init__(code)


def _timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise InputError('SSO_SOCKET_TIMEOUT')
    return float(value)


class SsoSocket:
    def __init__(self, connection, *, own_socket=False):
        if not isinstance(connection, socket.socket) or type(own_socket) is not bool:
            raise InputError('SSO_SOCKET_CONNECTION')
        if connection.gettimeout() is None or connection.gettimeout() <= 0:
            raise InputError('SSO_SOCKET_BOUNDED_TIMEOUT_REQUIRED')
        self._socket = connection
        self._own_socket = own_socket
        self._closed = False
        self._claim_lock = threading.Lock()
        self._transport_claimed = False

    def _claim_transport(self):
        with self._claim_lock:
            if self._closed or self._socket.fileno() < 0 or self._transport_claimed:
                raise InputError('SSO_SOCKET_TRANSPORT_ALREADY_USED_OR_CLOSED')
            self._transport_claimed = True

    @classmethod
    def connect(cls, host, port, *, timeout=10.0):
        if not isinstance(host, str) or type(port) is not int or not 0 < port < 65536:
            raise InputError('SSO_SOCKET_ENDPOINT')
        timeout = _timeout(timeout)
        if not timeout:
            raise InputError('SSO_SOCKET_CONNECT_TIMEOUT')
        try:
            connection = socket.create_connection((host, port), timeout=timeout)
        except OSError as error:
            raise SsoSocketError('SSO_SOCKET_CONNECT_FAILED', error.errno) from None
        return cls(connection, own_socket=True)

    @property
    def closed(self):
        return self._closed

    def send(self, frame):
        if self._closed or not isinstance(frame, bytes):
            raise InputError('SSO_SOCKET_SEND_STATE')
        try:
            self._socket.sendall(frame)
        except OSError as error:
            raise SsoSocketError('SSO_SOCKET_SEND_FAILED', error.errno) from None

    def receive(self, *, timeout=0.0):
        if self._closed:
            raise SsoSocketError('SSO_SOCKET_CLOSED')
        timeout = _timeout(timeout)
        try:
            readable, _, _ = select.select((self._socket,), (), (), timeout)
            if not readable:
                return None
            data = self._socket.recv(65536)
        except (OSError, ValueError) as error:
            raise SsoSocketError('SSO_SOCKET_RECEIVE_FAILED', getattr(error, 'errno', None)) from None
        if not data:
            raise SsoSocketError('SSO_SOCKET_EOF')
        return data

    def close(self):
        if self._closed:
            return
        self._closed = True
        if not self._own_socket:
            return
        try:
            self._socket.close()
        except OSError as error:
            raise SsoSocketError('SSO_SOCKET_CLOSE_FAILED', error.errno) from None

    def __enter__(self):
        if self._closed:
            raise InputError('SSO_SOCKET_CLOSED')
        return self

    def __exit__(self, *exception):
        self.close()
