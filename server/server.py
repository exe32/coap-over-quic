"""
QUIC Server which consumes UDP traffic (such as LwM2M/CoAP) over QUIC
Performs translation of LwM2M/QUIC and forwards further via UDP
"""

import argparse
import asyncio
import binascii
import logging
import queue
import ssl
import struct
from threading import Thread
from typing import Dict, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    ProtocolNegotiated,
    QuicEvent,
)
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket


class NotRegisterMessage(Exception):
    """
    Exception to be raised when non Register message is parsed as Register
    """


class CoapServerProtocol(QuicConnectionProtocol):
    """
    Main Class to handle LwM2M (CoAP) over QUIC
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.first_message = False
        self.cid = ""
        self.endpoint_name = ""

    def get_cid_str(self, cid: bytes):
        return binascii.hexlify(cid).decode("ascii")

    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Logic Executed upon Receiving QUIC event
        """

        if isinstance(event, DatagramFrameReceived):
            length = struct.unpack("!H", bytes(event.data[:2]))[0]
            query = event.data[2 : 2 + length]
            quic_event_logger.info("Received QUIC data:\n%s...", query[:15])
            if self.first_message:
                quic_event_logger.info(
                    "First message retrieved after establishing connection"
                )
                
                self.cid = self.get_cid_str(self._quic.original_destination_connection_id)
                quic_event_logger.info("CID retrieved: %s", self.cid)

                quic_event_logger.debug(
                    "Saving QUIC connection details for client %s", self.cid
                )
                quic_connections[self.cid] = self


                self.first_message = False

            quic_event_logger.info(
                "Adding data to the queue to be forwarded via UDP, identified by cid: %s",
                self.cid,
            )
            
            quic_to_udp_queue.put((self.cid, query))


        if isinstance(event, ProtocolNegotiated):
            logger.info("QUIC Connection established, protocol negotiated: %s", event.alpn_protocol)
            self.first_message = True                

        if isinstance(event, ConnectionTerminated):
            logger.info("QUIC Connection termination reason: %s", {event.reason_phrase})
            logger.info("Deleting the QUIC connection entry")
            try:
                del quic_connections[self.cid]
            except (KeyError, NameError):
                logger.error("Deleting failed")


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        "Function to add session ticket."
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        "Function to delete session ticket."
        return self.tickets.pop(label, None)


def get_quic_connection(cid: str) -> Optional[CoapServerProtocol]:
    """
    Return QUIC Connection for cid. If does not exist - return None
    """
    quic_forwarder_logger = logging.getLogger("[QUIC forwarder]")
    try:
        quic_connection: CoapServerProtocol = quic_connections[cid]
        return quic_connection
    except (KeyError, NameError):
        quic_forwarder_logger.error(
            "QUIC Connection for CID %s not found", cid
        )
        return None


class QuicToUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, cid):
        self.transport = None
        self.cid = cid

    def connection_made(self, transport):
        self.transport = transport
        udp_forwarder_logger.debug("UDP Connection for cid %s made, saving it globally", self.cid)
        udp_transports[self.cid] = transport

    def datagram_received(self, data: bytes, addr: tuple):
        udp_connections[self.cid] = addr
        udp_forwarder_logger.debug("Retrievied data %s from UDP", data)
        try:
            # try to parse the payload as str
            str_data = data.decode().strip()
            logger.debug("Looks like input data is string: %s", {str_data})
        except UnicodeDecodeError:
            logger.debug("Looks like input data are bytes already: %s", {data})
        data = struct.pack("!H", len(data)) + data
        logger.debug("Attempting to forward over existing QUIC connection: %s", {data})
        active_connection = get_quic_connection(self.cid)
        udp_to_quic_queue.put((active_connection, data))
        pass
    

async def establish_udp_connection(address, port, cid):
    ## TODO: where to call it?
    loop = asyncio.get_running_loop()
    udp_forwarder_logger.debug("Establishing UDP 'connection' towards %s:%s", address, port)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuicToUdpProtocol(cid),
        remote_addr=(address, port))



async def udp_forwarder(address: str, port: int) -> None:
    """
    Check if there are data waiting to be forwarded in 'quic_to_http_queue'.
    If yes - forward them via HTTP to UDP {{address}}
    """
    while True:
        try:
            cid, data = quic_to_udp_queue.get_nowait()
            if cid is None and data is None:
                break
            if cid not in udp_transports.keys():
                udp_forwarder_logger.error("cid %s not found in UDP connection")
                await establish_udp_connection(address = address, port = port, cid = cid)
            udp_forwarder_logger.debug("Attempting data (%s) to 'forward via UDP queue'", data)
            transport: asyncio.DatagramTransport = udp_transports[cid]
            transport.sendto(data=data)           
            quic_to_udp_queue.task_done()
        except queue.Empty:
            # sleeping inside a loop is required to "unblock" handling the events if received UDP datagrams
            await asyncio.sleep(0.1)

async def quic_forwarder() -> None:
    """
    Constantly read the "http_to_quic_queue" and if there are any data to be forwarded -
    sends them via appropriate QUIC connection
    """
    while True:
        active_connection: QuicConnectionProtocol
        data: bytes
        active_connection, data = udp_to_quic_queue.get()
        if active_connection is None and data is None:
            break
        quic_forwarder_logger.info("Attempting to forward data via QUIC")
        quic_forwarder_logger.debug("Full data to be forwarded via QUIC:\n%s", data)
        QuicConnection.send_datagram_frame(
            active_connection._quic, data  # pylint: disable=protected-access
        )
        QuicConnectionProtocol.transmit(active_connection)
        quic_forwarder_logger.info("Forwarding done")
        udp_to_quic_queue.task_done()


async def start_quic_server(
    host: str,
    port: int,
    config: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
) -> None:
    """
    Start the async QUIC and HTTP Servers.
    """
    # QUIC Server Start
    await serve(
        host,
        port,
        configuration=config,
        create_protocol=CoapServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )

    # Waiting infinitely
    await asyncio.Future()


def parse_args() -> argparse.Namespace:
    """
    Parse the startup arguments.
    """
    parser = argparse.ArgumentParser(description="CoAP over QUIC server")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="QUIC Server listens on the specified address (defaults to 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4784,
        help="QUIC Server listens on the specified port (defaults to 4784)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file (for the QUIC Endpoint)",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file (for the QUIC Endpoint)",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "--remoteUdpServerHost",
        type=str,
        default="127.0.0.1",
        help="LwM2M Server API address to which the data will be forwarded by HTTP",
    )
    parser.add_argument(
        "--remoteUdpServerPort",
        type=str,
        default="9999",
        help="LwM2M Server API address to which the data will be forwarded by HTTP",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    return parser.parse_args()


# Declaring Globals
logger = logging.getLogger("[Main]")
quic_forwarder_logger = logging.getLogger("[QUIC Forwarder]")
http_server_logger = logging.getLogger("[HTTP Server]")
quic_event_logger = logging.getLogger("[QUIC event]")
udp_forwarder_logger = logging.getLogger("[UDP Forwarder]")

udp_connections = {}
udp_transports = {}
quic_connections = {}

allowed_alpns = ["http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", 
"stun.turn", "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", 
"pop3", "managesieve", "coap", "xmpp-client", "xmpp-server", "acme-tls/1", 
"mqtt", "dot", "ntske/1", "sunrpc", "h3", "smb", "irc", "nntp", "nnsp", "doq", "sip/2", "tds/8.0"]

## populated by quic_event_received() and handled by http_forwarder()
quic_to_udp_queue = queue.Queue()

## populated by http_listener() and handled by quic_forwarder()
udp_to_quic_queue = queue.Queue()

if __name__ == "__main__":
    startArgs = parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if startArgs.verbose else logging.INFO,
    )

    # QUIC part
    # create QUIC logger
    if startArgs.quic_log:
        QUIC_LOGGER = QuicFileLogger(startArgs.quic_log)
    else:
        QUIC_LOGGER = None

    # Starting Quic forwarder
    quic_forwarder_thread = Thread(target=asyncio.run, args=(quic_forwarder(),))
    quic_forwarder_thread.start()

    # Starting UDP forwarder 
    # TODO: update the IP and the port from args
    udp_forwarder_thread = Thread(target=asyncio.run, args=(udp_forwarder(startArgs.remoteUdpServerHost, startArgs.remoteUdpServerPort),))
    udp_forwarder_thread.start()

    # preparing QUIC Server configuration
    configuration = QuicConfiguration(
        alpn_protocols=allowed_alpns,
        is_client=False,
        quic_logger=QUIC_LOGGER,
        max_datagram_frame_size=65535,
        idle_timeout=86400,
        verify_mode=ssl.CERT_REQUIRED,
    )

    configuration.load_cert_chain(startArgs.certificate, startArgs.private_key)

    # launching async QUIC and HTTP server
    try:
        logger.info("Starting QUIC and HTTP Server")
        asyncio.run(
            start_quic_server(
                host=startArgs.host,
                port=startArgs.port,
                config=configuration,
                session_ticket_store=SessionTicketStore(),
                retry=startArgs.retry,
            )
        )
    except KeyboardInterrupt:
        print("Graceful shutdown")

        # putting emtpy event to stop the quic_forwarder_thread
        udp_to_quic_queue.put((None, None))
        # putting emtpy event to stop the http_client_thread
        quic_to_udp_queue.put((None, None))

        quic_forwarder_thread.join()
        udp_forwarder_thread.join()

