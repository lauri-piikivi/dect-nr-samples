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
H + 1 byte length  in hex + PPC header hex
P + PDC payload hex bytes
The PCC hdr length  is needed as PPC header type 1 and type 2 both have format 000 as exact same header value

Forwards to (multicast)IP, to be shown, saved in Wireshark a UDP packet
UDP Packet payload [PCC header length, PCC, PDC] as raw bytes
UDP packet can be decoded in wireshark by port number
===========================================================================
FUTURE: give network ID from serial to device

"""
serial_port = None
start_time = 0
ser = None
multicast_ip = None
udp_port = None
sock = None
sthread = None
stop_event = threading.Event()
debug=True
hdr_line=None

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

def parse(line: str):
    global hdr_line
    line=line.strip()
    if line.startswith("H"):
        line=line.strip('H')
        hdr_line = line
        #wait for PDC for the header

    if line.startswith("P"):
        line=line.strip('P')
        packet=hdr_line+line
        send_multicast(bytes.fromhex(packet))
        if(debug):print(packet)
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
    parser.add_argument('-u','--udp_port', type=int, default=31414, help='UDP port to send ßto')
  
    args = parser.parse_args()

    serial_port = args.serial_port
    multicast_ip=args.multicast_ip
    udp_port=args.udp_port

    main()
