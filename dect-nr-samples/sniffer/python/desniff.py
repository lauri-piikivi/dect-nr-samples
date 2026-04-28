import argparse
import ipaddress
import socket
import sys
import threading
import time

import serial

"""
Listens on serial line for DECT messages and forwards them to a multicast group for wireshark capturing
Format for serial line string is:
  H for PCC Header
  Type_1 (dect nr+ beacon header) 5 bytes + filled with  0x00 to make 10 byte header
  Type_2 (dect nr+ unicast) 10 byte header
  PCC error is H0000

Prepends strings with P == PDC header
  P for PDC payload, variable length
  PDC error is P0000
  op_complete in device prints plain P for cases where only header (ACK) is received (MCS 0, len == 0)

Script strips the H and P identifiers
Forwards to (multicast)IP, to be shown in Wireshark a UDP packet, can be saved in wireshark
UDP Packet payload [PCC 10B header, PDC] as raw bytes
UDP packet can be decoded in wireshark by port number
at start writes the parameters network_id and carrier to devicce

if DEBUG flag is given, will not send over socket, only print on terminal

Requires python 3.6 or f-strings
===========================================================================

"""
serial_port = None
ser = None
multicast_ip = None
udp_port = None
network_id = None
carrier = None
sock = None
sthread = None
stop_event = threading.Event()
debug = None
hdr_line = ""


def createSocket():
    # Create UDP socket
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Set the time-to-live for messages to control how far they propagate
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    print(f"Opened socket : {multicast_ip} {udp_port}")


def send_multicast(data: bytes):
    if sock is None:
        createSocket()
    try:  # Send data to multicast group
        sock.sendto(data, (str(multicast_ip), int(udp_port)))
        print(f"Sent \t {data}")
    except Exception as e:
        print(f"An error occurred while sending multicast: {str(e)}")
        exit()


# only used at start to write configuration to device
def write_serial():
    ser.write(network_id.to_bytes(4, byteorder="little"))
    ser.write(carrier.to_bytes(2, byteorder="little"))
    return


def parse(line: str):
    global hdr_line
    line = line.strip()
    if debug and len(line) > 1:
        print(line)

    if line.startswith("H"):
        line = line[1:]
        hdr_line = line
        # wait for PDC

    if line.startswith("P"):
        line = line[1:]
        packet = hdr_line + line
        if len(packet) > 0:
            send_multicast(bytes.fromhex(packet))
        hdr_line = ""
    return


def open_serial():
    global ser
    global serial_port

    try:
        ser = serial.Serial(serial_port, baudrate=115200)

    except Exception as e:
        print(f"An error occurred while opening serial port: {str(e)}")
        exit()


def read_serial():
    global ser
    global serial_port

    try:
        while True:
            line = ser.readline().decode("utf-8")
            # calls parse, which calls send
            parse(line)

    except Exception as e:
        print(f"An error occurred while reading from serial port: {str(e)}")
        exit()


def exit():
    print("Exiting...")
    if ser and ser.is_open:
        ser.close()
    if sock is not None:
        sock.close()
    stop_event.set()
    sys.exit(1)


def main():
    global serial_port
    global sthread

    createSocket()
    open_serial()
    print(f"Starting DECT sniffer on serial port {serial_port}")
    write_serial()
    print(f"Configured radio network {network_id} on carrier {carrier}")
    try:
        sthread = threading.Thread(target=read_serial)
        sthread.daemon = True
        sthread.start()

        while True:
            time.sleep(0.1)

    except KeyboardInterrupt:
        exit()

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Read data from a serial port and send in UDP for wireshark capturing"
    )
    parser.add_argument(
        "-s",
        "--serial_port",
        type=str,
        default="/dev/tty.usbmodem0010512266311",
        help="Serial port identifier (e.g., COM1, /dev/ttyUSB0), use nrfuitl device list to find, note the added 1 on the end",
    )
    parser.add_argument(
        "-m",
        "--multicast_ip",
        type=ipaddress.IPv4Address,
        default="224.0.31.41",
        help="multicast IPv4 to send captured DECT messages to",
    )
    parser.add_argument(
        "-u", "--udp_port", type=int, default=31414, help="UDP port to send to"
    )
    parser.add_argument(
        "-n", "--network_id", type=int, default=1193046, help="NETWORK_ID"
    )
    parser.add_argument(
        "-c", "--carrier", type=int, default=1659, help="CARRIER to listen on"
    )
    parser.add_argument(
        "-d", "--debug", type=bool, default=True, help="Print messages on terminal"
    )

    args = parser.parse_args()

    serial_port = args.serial_port
    multicast_ip = args.multicast_ip
    udp_port = args.udp_port
    network_id = args.network_id
    carrier = args.carrier
    debug = args.debug
    main()
