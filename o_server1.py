# echo_server.py

import SocketServer
import logging


class MyTCPSocketHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        #self.data = self.request.recv(1024).strip()
        self.data = self.request.getpeername()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        # just send back the same data, but upper-cased
        #self.request.sendall(self.data.upper())
        self.request.sendall(self.data[0])


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    loglevel = 'INFO'
    logger = logging.getLogger('socket_server')
    level = logging.getLevelName(loglevel)
    logger.setLevel(level)
    # fmt = '%(asctime)s %(funcName)s:%(lineno)d %(message)s'
    # fmt = '%(asctime)s %(levelname)s: %(message)s'
    fmt = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'
    logging_format = logging.Formatter(fmt, date_fmt)
    handler = logging.StreamHandler()
    handler.setFormatter(logging_format)
    handler.setLevel(level)
    logger.addHandler(handler)

    # instantiate the server, and bind to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPSocketHandler)

    # activate the server
    # this will keep running until Ctrl-C
    logger.info('Starting Socket Server.')
    server.serve_forever()