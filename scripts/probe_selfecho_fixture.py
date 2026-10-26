"""Controlled loopback allocation fixture; no engine or echo listener is used."""
import socket


class ForcedSourceCollision:
    def __init__(self, udp):
        self.real_socket = socket.socket
        self.kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        with self.real_socket(type=self.kind) as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.target = reservation.getsockname()
        self.forced = False
        self.sockets = []

    def socket(self, *args, **kwargs):
        raw = self.real_socket(*args, **kwargs)
        owner = self

        class TrackedSocket:
            def __init__(self):
                self.sends = 0
                self.closed = False
                self.local = None
                self.peer = None

            def bind(self, address):
                if address == ('127.0.0.1', 0) and not owner.forced:
                    address = owner.target
                    owner.forced = True
                raw.bind(address)
                self.local = raw.getsockname()

            def connect(self, address):
                if raw.getsockname()[1] == 0 and not owner.forced:
                    # Model the kernel choosing the free destination port.
                    raw.bind(owner.target)
                    owner.forced = True
                self.local = raw.getsockname()
                raw.connect(address)
                self.local, self.peer = raw.getsockname(), raw.getpeername()

            def sendall(self, data):
                self.sends += 1
                return raw.sendall(data)

            def close(self):
                self.closed = True
                return raw.close()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def __getattr__(self, name):
                return getattr(raw, name)

        wrapped = TrackedSocket()
        self.sockets.append(wrapped)
        return wrapped
