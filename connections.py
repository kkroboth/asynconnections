"""
Packet based connection classes used with asyncore dispatcher.

:Author Kyle Kroboth
"""
import Queue
import asyncore
import logging
from threading import Lock
import struct


class PacketConnection(asyncore.dispatcher):
    """
    Connection for reading and writing packets with a type, length as header and
    body payload.

    This connection must be run on the same thread a server dispatcher.

    The packet format is in the format:
    +--------------------+-------------------+
    |        Header      |      Body         |
    +====================+===================+
    | Type |    Length   |    Message...     |
    +--------------------+-------------------+

    Header byte sizes by default are 1 (type), and 4(length).
    Message or body max length in characters is 65535.
    These sizes and lengths can be set through settings() methods.

    Once PacketConnection() created, additional options are set in the
    settings() method. Before this dispatcher connection can run, start_dispatcher()
    must be called.

    Packet errors use an integer(byte) less than 0.
    First ten errors up to -10 are reserved with the exception of -1. -1 is a general default error.
    Custom packet errors must be less than -10.

    **NOTE**
    If start_dispatcher() isn't called and try to access dispatcher methods/attributes, a
    infinite recursion of getattr() from dispatcher.__getattr__() will happen. Any attributes
    that do not exist will also result in this recursion in getattr()
    """

    # These errors will close the connection
    ERROR_DEFAULT = -1
    ERROR_INVALIDPACKET = -2
    ERROR_TYPEINVALID = -3
    ERROR_LENGTHLZERO = -4
    ERROR_LENGTHTOOBIG = -5

    # In bytes
    DEFAULT_TYPE_SIZE = 1
    DEFAULT_LENGTH_SIZE = 4
    # In string length
    DEFAULT_MAX_BODY_LENGTH = 65535

    DEFAULT_BUFFER_READ_SIZE = 1024
    DEFAULT_BUFFER_SEND_SIZE = 1024

    def __init__(self, sock=None):
        """
        Sets up packet connection. Must call initialize to tell the dispatcher to listen on
        the socket. Must call start_dispatcher() for listening on socket.

        :param sock: Socket
        """
        self.dispatcher_sock = sock

        # Defaults
        self.type_size = PacketConnection.DEFAULT_TYPE_SIZE
        self.length_size = PacketConnection.DEFAULT_LENGTH_SIZE
        self.header_size = self.type_size + self.length_size
        self.max_body_length = PacketConnection.DEFAULT_MAX_BODY_LENGTH
        self.buffer_read_size = PacketConnection.DEFAULT_BUFFER_READ_SIZE
        self.buffer_send_size = PacketConnection.DEFAULT_BUFFER_SEND_SIZE
        self.valid_header_types = None
        self.write_sendall = True
        self.safely_handle_errors = True
        self.send_queue = Queue.Queue()

        self.send_ready = False  # Used by writable() for dispatcher
        self.send_ready_lock = Lock()

        self.sending_packet = None  # Current popped packet from send_queue

        # Read buffer
        self._read_buffer = bytearray(self.buffer_read_size)
        self.read_buffer = memoryview(self._read_buffer)
        self.read_size = 0
        self.read_offset = 0
        self.read_remaining = 0

        # Write buffer - only used if write_sendall is False
        self._write_buffer = None
        self.write_buffer = None
        self.write_offset = 0
        self.write_size = 0
        self.sending_packet_offset = 0

        self._handle_write = self._write_send

        self.log = logging.getLogger(__name__)

    def settings(self,
                 type_size=DEFAULT_TYPE_SIZE,
                 length_size=DEFAULT_LENGTH_SIZE,
                 max_body_length=DEFAULT_MAX_BODY_LENGTH,
                 buffer_read_size=DEFAULT_BUFFER_READ_SIZE,
                 buffer_send_size=DEFAULT_BUFFER_SEND_SIZE,
                 valid_header_types=None,
                 write_sendall=True,
                 safely_handle_errors=True):
        """
        Settings for connection before initializing dispatcher.

        :param type_size: Header type byte size: (default 1)
        :param length_size: Header length byte size: (default 4)
        :param max_body_length: Max body length: (default 65535)
        :param buffer_read_size: Read size for receiving bytes: (default 1024)
        :param buffer_send_size: Send size for writing bytes: (default 1024)
        :param valid_header_types: List of valid header type integers: (default any type)
        :param write_sendall: If true, will use socket.sendall() for writing packets: (default True)
                Otherwise, remaining bytes not sent will be written on next dispatcher select() call
        :param safely_handle_errors: If true, on send and receive errors the connection will be closed.
        """
        self.type_size = type_size
        self.length_size = length_size
        self.header_size = self.type_size + self.length_size
        self.max_body_length = max_body_length
        self.buffer_read_size = buffer_read_size
        self.buffer_send_size = buffer_send_size
        self.valid_header_types = valid_header_types
        self.write_sendall = write_sendall
        self.safely_handle_errors = safely_handle_errors

    def set_logger(self, name):
        """
        Sets pre-made logger.
        :param name: Name of predefined logger
        """
        self.log = logging.getLogger(name)

    def start_dispatcher(self):
        """
        Call this method to init asyncore dispatcher after all settings have been set.
        """
        if self.write_sendall:
            self._handle_write = self._write_sendall
            self.write_buffer = None
        else:
            self._write_buffer = bytearray(self.buffer_send_size)
            self.write_buffer = memoryview(self._write_buffer)

        asyncore.dispatcher.__init__(self, self.dispatcher_sock)

    def writable(self):
        """
        Called by dispatcher to check socket is ready to be written to.
        :return: send_ready attribute
        """
        with self.send_ready_lock:
            return self.send_ready

    def push_packet(self, packet, *args, **kwargs):
        """
        Puts packet into send queue and signals send_ready for dispatcher to write on socket.

        :param packet: Raw packet
        """
        self._put_push_packet(packet)
        with self.send_ready_lock:
            self.send_ready = True

    def send_packet(self, packet):
        """
        Use this method to send packet right away on socket. Will block.

        :param packet: Raw packet
        :return Number of bytes sent
        """
        return self.send(packet)

    def handle_write(self):
        self._handle_write()

    def handle_read(self):
        read = self.recv_into(self.read_buffer)
        if read == 0:
            self.handle_close()

        self.read_offset = 0
        self.read_size = read
        self.read_remaining = read

        while self.read_remaining > 0:
            result = self.check_packet(self.read_buffer, self.read_offset)
            if isinstance(result, int):
                self.read_remaining = 0
                self.handle_packet_error(result)
                self.handle_close()
            p_type, p_size = result
            if not self._is_multipacket(p_size):
                packet_size = p_size + self.header_size
                self.read_packet(p_type, p_size, self.read_buffer, self.read_offset, packet_size)
                self.read_size += packet_size
                self.read_remaining -= packet_size
                self.read_offset += packet_size
            else:
                # ---Multi-Packet---
                # Builds a new buffer from packet size and copies chunk from first read
                # Reads into buffer from chunks until fully read
                full_buffer = bytearray(p_size + self.header_size)
                full_view = memoryview(full_buffer)
                # Copies(pointer) current buffer starting at offset into full buffer(packet size)
                full_view[:self.read_remaining] = self.read_buffer[self.read_offset:]
                full_read_size = self.read_remaining
                full_read_offset = 0

                remaining = p_size + self.header_size - full_read_size
                while remaining > 0:
                    # Slice memory view full buffer for reading into from socket.
                    if remaining <= self.buffer_read_size:
                        # Only slice amount left
                        read_buffer = full_view[full_read_size:full_read_size + remaining]
                    else:
                        # Slice full buffer read size
                        read_buffer = full_view[full_read_size:full_read_size + self.buffer_read_size]
                    read = self.recv_into(read_buffer)
                    if read == 0:
                        self.handle_close()
                    full_read_size += read
                    remaining -= read
                # Can finally read packet
                self.read_packet(p_type, p_size, full_view, full_read_offset, full_read_size)
                self.read_size += full_read_size
                # Read only up to packet size. Read remaining is therefor set to zero.
                # Then waits for signal from async select()
                self.read_remaining = 0

    def check_packet(self, view, offset):
        """
        Pre-checks packet before processing for defects.

        ERRORS
        --------
        -2 - ERROR_INVALIDPACKET. Could not read header
        -3 - ERROR_TYPEINVALID. Packet type not in valid packet types
        -4 - ERROR_LENGTHLZERO. Body length less than zero
        -5 - ERROR_LENGTHTOOBIG. Body length bigger than set max length

        :return Tuple (type, size) of packet or error number.
        """
        # Must begin with packet heading
        header = self.read_packet_header(view[offset:])
        if not header:
            self.log.error('Invalid packet from connection %s' % self.addr)
            return PacketConnection.ERROR_INVALIDPACKET
        p_type, p_length = header
        # Check if type is in valid packet types - if set
        if self.valid_header_types and p_type not in self.valid_header_types:
            self.log.error('Packet type not valid: [%i] in connection %s' % (p_type, self.addr))
            return PacketConnection.ERROR_TYPEINVALID
        if p_length < 0:
            self.log.error('Packet length is less than zero in connection %s' % self.addr)
            return PacketConnection.ERROR_LENGTHLZERO
        if p_length > self.max_body_length:
            self.log.warn('Packet body length too big [%i] in connection %s' % (p_length, self.addr))

        return p_type, p_length

    def read_packet_header(self, read_buffer):
        """
        Reads packet type and length from buffer.

        Uses struct.unpack() with format '!bi' with default header sizes.
        If not using default header this method must be overridden.

        The return result must be in a list as such (packet_type, packet_length).
        If an error occurs during reading header, return None.

        :param read_buffer: Read buffer (memoryview)
        :return list (packet_type, packet_length) or None on error
        """
        fmt = '!bi'
        try:
            return struct.unpack(fmt, read_buffer[:self.header_size])
        except (struct.error, ValueError):
            self.log.exception("read_packet_header")
        return None

    def read_packet(self, packet_type, packet_length, read_buffer, offset, read_size):
        """
        Once a packet has been verified and fully read this method is called.

        The offset starts at the beginning of the packet, not the body. Read size is the
        total byte size of packet including header.

        :param packet_type: Type of packet
        :param packet_length: Body length
        :param read_buffer: Read buffer (memoryview)
        :param offset: Offset start packet in read_buffer
        :param read_size: Packet size in read_buffer
        """
        raise NotImplementedError

    def handle_packet_error(self, error_type):
        """
        Called if there was an error while trying to read packet. Connection will
        be closed after this method is called.

        Will create an error packet (-1) with message "Packet invalid"
        and send immediately.

        :param error_type: Error number
        """
        packet = self.build_packet(error_type, "Packet invalid")
        self.send_packet(packet)

    def build_packet(self, packet_type, packet_body):
        """
        Create complete raw packet.

        Uses struct.pack() with format `'!bi%ds' % len(packet_body)` with
        default packet header and body sizes. If not using default sizes, must
        override.

        Raises TypeError if packet_body length is bigger than max body length.

        :param packet_type: Type of packet
        :param packet_body: Payload body for packet
        :return Complete raw packet
        """
        body_len = len(packet_body)
        if body_len > self.max_body_length:
            raise TypeError("Packet body length [%i] bigger than set max length [%i]"
                            % (body_len, self.max_body_length))
        fmt = '!bi%ds' % body_len
        return struct.pack(fmt, packet_type, body_len, packet_body)

    def handle_close(self):
        """
        Calls dispatcher.close()
        """
        self.close()

    def handle_error(self):
        """
        Logs errors and closes connection.
        """
        self.log.exception("Socket error - closing connection")
        self.close()

    def _is_multipacket(self, length):
        # Helper to check if packet body length is bigger than buffer
        return length + self.header_size > self.buffer_read_size

    def _get_push_packet(self):
        try:
            packet = self.send_queue.get_nowait()
            self.send_queue.task_done()
            return packet
        except Queue.Empty:
            return None

    def _put_push_packet(self, packet):
        self.send_queue.put(packet)

    # Replacement methods for writing data
    def _write_sendall(self):
        # Just one call to socket.sendall()
        # On error will call handle_error_send and discard packet.
        if not self.sending_packet:
            packet = self._get_push_packet()
            if not packet:
                # No more packets to send
                with self.send_ready_lock:
                    self.send_ready = False
                return
            self.sending_packet = packet

        # Bypass send buffer - Leave it to the socket.sendall()
        try:
            self.sendall(self.sending_packet)
            self.sending_packet = None
        except IOError as err:
            self.handle_error_send(err, self.sending_packet, -1)
            if self.safely_handle_errors:
                self.handle_close()

    def _write_send(self):
        # For new packet, puts as much into send buffer.
        # Sends packet through dispatcher.send() if data is remaining
        # If all data was not writen, waits for dispatcher
        # to call handle_write again.
        if not self.sending_packet:
            packet = self._get_push_packet()
            if not packet:
                # No more packets to send
                with self.send_ready_lock:
                    self.send_ready = False
                return
            self.sending_packet = packet

        # Using send buffer
        length = len(self.sending_packet)
        max_length = min(length, self.buffer_send_size)
        if self.write_size <= 0:
            if self.sending_packet_offset == 0:
                # Buffer is empty - copy as much into it
                self.write_buffer[:max_length] = self.sending_packet[:max_length]
                self.write_size = max_length
                self.sending_packet_offset = max_length
            elif self.sending_packet_offset < length:
                # Write a chunk to buffer
                self.write_size = max_length - self.sending_packet_offset
                self.write_buffer[:self.write_size] = self.sending_packet[self.sending_packet_offset:self.write_size]
                self.sending_packet_offset += self.write_size
            else:
                # Packet was sent
                self.sending_packet = None
                self.sending_packet_offset = 0
                self.write_size = 0
                self.write_offset = 0
                return self._write_send()
        else:
            # Buffer was partially sent
            pass

        sent = self.send(self.write_buffer[self.write_offset:self.write_offset + self.write_size])
        if sent == 0:
            self.handle_error_send(None, self.sending_packet, 0)
            if self.safely_handle_errors:
                self.handle_close()

        self.write_offset += sent
        self.write_size -= sent


class PriorityPacketConnection(PacketConnection):
    """
    PacketConnection with a push priority Queue.PriorityQueue().

    Changes signature of push_packet to push_packet(priority, packet).
    """

    # Priorities for pushed packets. Lower values are sent first.
    # Feel free to use an value, these are here for convenience.
    LOW = 100
    NORMAL = 50
    HIGH = 1

    # Critical is a special zero value for sending packets right before the
    # connection is closed. In other words, all CRITICAL packets will be
    # sent(errors ignored) before the socket is closed.
    # CRITICAL packets should be short - less than 1024
    CRITICAL = 0

    def __init__(self, sock):
        PacketConnection.__init__(self, sock)
        self.send_queue = Queue.PriorityQueue()

    def read_packet(self, packet_type, packet_length, read_buffer, offset, read_size):
        raise NotImplementedError

    def _get_push_packet(self):
        try:
            packet = self.send_queue.get_nowait()[1]
            self.send_queue.task_done()
            return packet
        except Queue.Empty:
            return None

    def _put_push_packet(self, priority, packet):
        self.send_queue.put((priority, packet))

    def push_packet(self, priority, packet):
        """
        Puts packet into send queue and signals send_ready for dispatcher to write on socket.

        :param priority: Priority Number. Lower numbers are retrieved first
        :param packet: Raw packet
        """
        self._put_push_packet(priority, packet)
        with self.send_ready_lock:
            self.send_ready = True

    def handle_close(self):
        """
        Will send CRITICAL priority packets to connection before closing.
        """
        self.is_writable = False
        # Send CRITICAL priority packets only - if connection is still alive
        try:
            while True:
                priority, packet = self.send_queue.get_nowait()
                if not priority == self.CRITICAL:
                    break
                # Sending packet through socket because dispatcher will call
                # handle_close() again on error.
                # Not checking how much sent because not waiting to close a connection.
                self.socket.send(packet)
        except (IOError, Queue.Empty):
            pass
        finally:
            PacketConnection.handle_close(self)
