"""
QUIC Server which consumes LwM2M (CoAP) over QUIC
Performs translation of LwM2M/QUIC and forwards it to proper
LwM2M Server via REST (LwM2M is base64 encoded).
Any LwM2M Server generated message are parsed and send back to QUIC client (LwM2M/QUIC)
"""

import argparse
import asyncio
import base64
import logging
import queue
import ssl
import struct
from threading import Thread
from typing import Dict, Optional

from aiocoap import Message
from aiohttp import BasicAuth, ClientSession, web

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
        self.endpoint_name = ""

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
                    "First message retrieved after establishing connection, \
                    assuming to be Register. Attempting to retrieve \
                    the LwM2M endpointName"
                )
                try:
                    endpoint_name = retrieve_endpointname(query)
                    quic_event_logger.info("EndpointName retrieved: %s", endpoint_name)
                except NotRegisterMessage:
                    quic_event_logger.error(
                        "Could not parse the endpointName. \
                        Perhaps it's not valid LwM2M register message? \
                        EndpointName 'andzej1' will be used as a stub."
                    )
                    endpoint_name = "andzej1"
                quic_event_logger.debug(
                    "Saving QUIC connection details for client %s", endpoint_name
                )
                quic_connections[endpoint_name] = self
                self.first_message = False
                self.endpoint_name = endpoint_name

            quic_event_logger.info(
                "Adding data to be forwarded via HTTP to the queue for endpoint name: %s",
                self.endpoint_name,
            )
            quic_to_http_queue.put((self.endpoint_name, query))

        if isinstance(event, ProtocolNegotiated):
            logger.info("QUIC Connection established")
            if str(event.alpn_protocol) == "coap":
                self.first_message = True

        if isinstance(event, ConnectionTerminated):
            logger.info("QUIC Connection termination reason: %s", {event.reason_phrase})
            logger.info("Deleting the QUIC connection entry")
            try:
                del quic_connections[self.endpoint_name]
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


# Configuration of HTTP Server Handlers

routes = web.RouteTableDef()


@routes.get("/")
async def get(request: web.Request):
    """
    Handle GET request
    """
    http_server_logger.debug("Received GET reques on %s", request.url)
    if len(quic_connections) == 0:
        return web.Response(
            text="CoAP/HTTP to CoAP/QUIC proxy active. There is *NO* active QUIC connection",
            status=404,
        )
    else:
        return web.Response(
            text=f"CoAP/HTTP to CoAP/QUIC proxy active.\
                Currently active connections: {len(quic_connections)}"
        )


@routes.post("/")
async def post(request: web.Request):
    """
    Handle POST request
    """
    try:
        body = await request.json()
        endpoint_name = body["endpointName"]
    except (KeyError, NameError):
        http_server_logger.error(
            "Received HTTP Payload does not look like valid JSON with\
            'endpointName' and 'data' fields:\n%s",
            await request.text(),
        )
        return web.Response(text="Incorrect JSON", status=400)
    active_connection = get_quic_connection(endpoint_name)
    if active_connection is None:
        return web.Response(
            text="Unfortunately there are no active QUIC clients,\
            LwM2M Client should perform full registration",
            status=404,
        )
    else:
        http_server_logger.info(
            "Received HTTP data for endpointName '%s', adding to queue to forward via QUIC",
            endpoint_name,
        )
        http_server_logger.debug("Full data received:\n%s", body)
        # parse http body: -> decode base64 -> encode -> put to the queue:
        data = base64.b64decode(body["data"])
        data = struct.pack("!H", len(data)) + data
        http_to_quic_queue.put((active_connection, data))
        return web.Response(text="OK")


def retrieve_endpointname(data) -> Optional[str]:
    """
    Parse bytes as CoAP message and retrieve the "ep" parameter from uri_query.
    If parameter missing - raise 'NotRegisterMessage' exception.
    """
    try:
        query_params: tuple = Message().decode(data).opt.uri_query
        for query in query_params:
            name, value = str.split(query, "=")
            if name == "ep":
                return value
        return None
    except:
        raise NotRegisterMessage(
            "EndpointName not found. Perhaps it's not register message?"
        ) from Exception


def get_quic_connection(endpoint_name: str) -> Optional[CoapServerProtocol]:
    """
    Return QUIC Connection for given endpoint_name. If does not exist - return None
    """
    quic_forwarder_logger = logging.getLogger("[QUIC forwarder]")
    try:
        quic_connection: CoapServerProtocol = quic_connections[endpoint_name]
        return quic_connection
    except (KeyError, NameError):
        quic_forwarder_logger.error(
            "QUIC Connection for EndpointName %s not found", endpoint_name
        )
        return None


async def http_forwarder(api_url: str, api_user: str, api_pass: str) -> None:
    """
    Check if there are data waiting to be forwarded in 'quic_to_http_queue'.
    If yes - forward them via HTTP to api_url endpoint, with api_user and api_pass used
    as HTTP Basic Auth.
    """
    http_forwarder_logger = logging.getLogger("[HTTP Forwarder]")
    async with ClientSession() as session:
        while True:
            endpoint_name, data = quic_to_http_queue.get()
            if endpoint_name is None and data is None:
                break
            ## Reimplement how the payload looks like if needed:
            json = {
                "endpointName": endpoint_name,
                "data": base64.b64encode(data).decode(),
            }
            http_forwarder_logger.debug(
                "Attempting to forward data (%s) via HTTP, as a json: {%s}", data, json
            )
            async with session.post(
                url=api_url, json=json, auth=BasicAuth(api_user, api_pass)
            ) as resp:
                resp.raise_for_status()
                payload = await resp.text()
                http_forwarder_logger.debug("Received HTTP response: %s", payload)
            quic_to_http_queue.task_done()


async def quic_forwarder() -> None:
    """
    Constantly read the "http_to_quic_queue" and if there are any data to be forwarded -
    sends them via appropriate QUIC connection
    """
    while True:
        active_connection: QuicConnectionProtocol
        data: bytes
        active_connection, data = http_to_quic_queue.get()
        if active_connection is None and data is None:
            break
        quick_forwarder_logger.info("Attempting to forward data via QUIC")
        quick_forwarder_logger.debug("Full data to be forwarded via QUIC:\n%s", data)
        QuicConnection.send_datagram_frame(
            active_connection._quic, data  # pylint: disable=protected-access
        )
        QuicConnectionProtocol.transmit(active_connection)
        quick_forwarder_logger.info("Forwarding done")
        http_to_quic_queue.task_done()


async def start_servers(
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

    # HTTP Server Start
    app = web.Application()
    app.add_routes(routes)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    asyncio.gather(site.start())
    http_server_logger.info("HTTP Server Started")

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
        "--lwm2mServerApiEndpoint",
        type=str,
        default="http://localhost:8080",
        help="LwM2M Server API address to which the data will be forwarded by HTTP",
    )
    parser.add_argument(
        "--lwm2mServerApiUser",
        type=str,
        default="avsystem",
        help="LwM2M Server API username for basic authentication",
    )
    parser.add_argument(
        "--lwm2mServerApiPass",
        type=str,
        default="avsystem",
        help="LwM2M Server API password for basic authentication",
    )
    parser.add_argument(
        "--httpServerPort",
        type=int,
        default=8080,
        help="Port to listen for incoming HTTP API calls with base64 encoded CoAP data",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    return parser.parse_args()


# Declaring Globals
logger = logging.getLogger("[Main]")
quick_forwarder_logger = logging.getLogger("[QUIC Forwarder]")
http_server_logger = logging.getLogger("[HTTP Server]")
quic_event_logger = logging.getLogger("[QUIC event]")


## populated by quic_event_received() and handled by http_forwarder()
quic_to_http_queue = queue.Queue()
## populated by http_listener() and handled by quic_forwarder()
http_to_quic_queue = queue.Queue()

quic_connections: dict = {}

if __name__ == "__main__":
    startArgs = parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if startArgs.verbose else logging.INFO,
    )

    # HTTP Part
    # Launching HTTP Server
    # http_server_thread = Thread(target=asyncio.run, args=(http_listener(),))
    # http_server_thread.start()

    # Starting HTTP Client
    http_client_thread = Thread(
        target=asyncio.run,
        args=(
            http_forwarder(
                api_url=startArgs.lwm2mServerApiEndpoint,
                api_user=startArgs.lwm2mServerApiUser,
                api_pass=startArgs.lwm2mServerApiPass,
            ),
        ),
    )
    http_client_thread.start()

    # QUIC part
    # create QUIC logger
    if startArgs.quic_log:
        QUIC_LOGGER = QuicFileLogger(startArgs.quic_log)
    else:
        QUIC_LOGGER = None

    # Starting Quic forwarder
    quic_forwarder_thread = Thread(target=asyncio.run, args=(quic_forwarder(),))
    quic_forwarder_thread.start()

    # preparing QUIC Server configuration
    configuration = QuicConfiguration(
        alpn_protocols=["coap"],
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
            start_servers(
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
        http_to_quic_queue.put((None, None))
        # putting emtpy event to stop the http_client_thread
        quic_to_http_queue.put((None, None))

        quic_forwarder_thread.join()
        http_client_thread.join()
