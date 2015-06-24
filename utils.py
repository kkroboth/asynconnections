import logging
import struct

def create_logger(name, logfile, level):
    """
    Sets up file logger.
    :param name: Logger name
    :param logfile: Location of log file
    :param level: logging level
    :return: Initiated logger
    """
    logger = logging.getLogger(name)
    handler = logging.FileHandler(logfile)
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def create_stream_logger(name, stream, level):
    """
    Sets up stream logger.
    :param name: Logger name
    :param stream: Stream to log out
    :param level: logging level
    :return: Initiated logger
    """
    logger = logging.getLogger(name)
    handler = logging.StreamHandler(stream=stream)
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)


def read_packet_header(packet, header_size):
    """
    Gets type and length of packet. On error, returns None tuple.

    :param packet: Full packet
    :return: Type and length of packet in bytes
    """
    try:
        return struct.unpack('!bi', packet[:header_size])
    except (struct.error, TypeError) as e:
        return None, None


def read_packet_body(packet, length, header_size):
    """
    Gets packet body. On error, returns None.

    :param packet: Full packet
    :param length: Length of body in bytes
    :return: Packet body as string
    """
    fmt = '!%ds' % length
    body = packet[header_size:header_size + length]
    try:
        return struct.unpack(fmt, body)[0]
    except (struct.error, TypeError) as e:
        return None


def read_body_array(packet_body):
    """
    Reads array formatted struct packet body. On error returns None.

    :param packet_body: Body of packet
    :return: Array of items
    """
    size_fmt = '!i'
    string_fmt = '!%ds'

    body_array = []
    body_len = len(packet_body)
    offset = 0
    if body_len <= 0:
        return None

    try:
        while offset < body_len:
            # Read size of item
            item_size = struct.unpack_from(size_fmt, packet_body, offset)[0]
            offset += 4
            # Read string
            item_string = struct.unpack_from(string_fmt % item_size, packet_body, offset)[0]
            body_array.append(item_string)
            offset += item_size

        return body_array
    except (struct.error, TypeError):
        return None


def write_body_array(*items):
    """
    Write a collection of items in struct format for packet body tuple.

    :param items: Collection of items
    :return: Struct formatted
    """
    fmt = 'i%ds'
    body_fmt = "!"
    body_array = []

    # Build format
    for item in items:
        item_fmt = fmt % len(item)
        body_fmt += item_fmt
        body_array.append(len(item))
        body_array.append(item)

    return struct.pack(body_fmt, *body_array)


def write_packet(packet_type, body):
    """
    Write full packet from type and body string.

    :param packet_type: Type of packet
    :param body: Body string
    :return: Packed packet
    """
    body_size = len(body)
    fmt = '!bi%ds' % body_size
    return struct.pack(fmt, packet_type, body_size, body)