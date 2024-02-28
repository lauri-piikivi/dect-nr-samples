../******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple broadcast of DECT NR+ messages, for initial testing and sample

2 Development Kits for 9161 needed
   1st transmits a counter value, needs only power, prints progress information
   2nd receives the value, needs terminal for printout

PC SW: nRF Connect for Desktop 
For development Zephyr and IDE (VSCode and nRF Connect extension)

Device first listens on hard-coded channel for 10secs, if no transmission detected, 
starts sending for-ever. Another device can start, listens and stays in listen 
mode, simple statistics are provided at end, when button is pressed. Reset 
board to start again

RX accepts first received counter value, and after that detects if messages
lost between receptions, increases a counter for missed messages
- RX calculates CRC error callbacks
- RX printouts basic data for each message received the to show progress
- RX will end if nothing received in 10 secs or if any button on DK pressed
- When RX ends, simple statistics shown

TX Mode: leds blink
RX mode: leds on
*******************************************************************************
PRINTOUT RX. NOTE that logging must be on and level INF should be used. 
Logging is faster than printk, so the progress uses logging output

RECEIVED DATA, 1386, rssi_2, -50,  missed/crc errors,  19
RECEIVED DATA, 1387, rssi_2, -50,  missed/crc errors,  19
...
PCC CRC ERROR, rssi_2, -52, crc error count,  7
RECEIVED DATA, 1389, rssi_2, -50,  missed/crc errors,  20
...
Exit on timeout or button
*********************************************
Received messages 1409
Missed messages 13
CRC errors  7
RSSI_2 AVG (rounded) -53 for successful reception
*********************************************

****************************************************************************
TODO:
- floats, config issue
****************************************************************************/