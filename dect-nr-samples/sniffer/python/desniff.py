import argparse
import serial
import sys
import time
import threading
import socket
import ipaddress

"""
Listens on serial line for DECT messages and forwards them to a multicast group for wireshark capturing
Format for serial line string is:
  W
  write configuration , NETWORK_ID CARRIER
  
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
===========================================================================
FUTURE: give network ID from serial to device

"""
serial_port = None
start_time = 0
ser = None
multicast_ip = None
udp_port = None
network_id = None
carrier = None
sock = None
sthread = None
stop_event = threading.Event()
debug= None
hdr_line=""

def createSocket():
    # Create UDP socket
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Set the time-to-live for messages to control how far they propagate
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    if(debug):print("created socket")

def send_multicast(data: bytes):
    if sock == None:
        createSocket()
    
    try:# Send data to multicast group
        sock.sendto(data, (str(multicast_ip), int(udp_port)))

    except Exception as e: 
        print(f"An error occurred while sending multicast: {str(e)}")
        exit()

# only used at start to write configuration to device
def write_serial():
    ser.write(network_id.to_bytes(4, byteorder='little'))
    ser.write(carrier.to_bytes(2, byteorder='little'))
    return

def parse(line: str):
    global hdr_line
    line=line.strip()
    if (debug and len(line)>1): print(line)

    #waits for configuration
    if(line.startswith("W")):
        write_serial()

    if line.startswith("H"):
        line=line.strip('H')
        hdr_line = line
        #wait for PDC

    if line.startswith("P"):
        line=line.strip('P')
        packet=hdr_line+line
        if(len(packet)>0):send_multicast(bytes.fromhex(packet))
        hdr_line=""
    return
    
def read_serial():
    global ser
    global serial_port

    try:
        ser = serial.Serial(serial_port, baudrate=115200)

        while True:
            line = ser.readline().decode('utf-8')
            #calls parse, which calls send
            parse(line)

    except Exception as e:
        print(f"An error occurred while reading from serial port: {str(e)}")
        exit()

def exit():
    global thread
    print('Exiting...')
    if ser and ser.is_open:
        ser.close()
    if sock != None:
        sock.close()
    stop_event.set()
    sys.exit(1)

def main():
    global serial_port
    global start_time
    global sthread

    createSocket()

    print(f"Starting DECT sniffer on serial port {serial_port}")
    try:
        start_time = str(int(time.time()))

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
    parser = argparse.ArgumentParser(description='Read data from a serial port and send in UDP for wireshark capturing')
    parser.add_argument('-s','--serial_port', type=str, default="/dev/tty.usbmodem0010512017591",help='Serial port identifier (e.g., COM1, /dev/ttyUSB0)')
    parser.add_argument('-m', '--multicast_ip', type=ipaddress.IPv4Address, default="224.0.31.41", help='multicast IPv4 to send captured DECT messages to')
    parser.add_argument('-u','--udp_port', type=int, default=31414, help='UDP port to send to')
    parser.add_argument('-n', '--network_id', type=int, default=0x12345678, help='NETWORK_ID HEX')
    parser.add_argument('-c', '--carrier', type=int, default=1663, help='CARRIER to listen on')
    parser.add_argument('-d', '--debug', type=bool, default=True, help='Print messages on terminal')

    args = parser.parse_args()

    serial_port = args.serial_port
    multicast_ip=args.multicast_ip
    udp_port=args.udp_port
    network_id=args.network_id
    carrier=args.carrier
    debug=args.debug
    main()
