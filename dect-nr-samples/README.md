# dect-nr-samples
simple sample applications for DECT NR+ on Nordic nrf91

Main contents
MAC_DEMO
  sample how to use the MAC API in Nordic NR+ release 2.0.0 firmware. This is without IP and network management APIs to show the lowest API operation
SNIFFER
  capture any NR+ traffick, a python script can give the parameters and maps the NR+ traffick in UDP packet. Wireshark can show it as decode_as for the UDP port
  
2026-04-28
- added the new mac_demo which is a blog entry hopefully available soon on Nordic DevZone
- note on the sniffer,  the MAC modem side implementation in rel2.0.0 is too fast. Either the ACK/NACK or original message is shown in capture. Modem side implementation sends the ACK too fast, the sniffer operation has ended and starting new one needs to be faster. I am trying to make it from 1st reception PCC callback, where there is length, and could calculate when the PDC for that ends and start new reception on PDC_end+N but somehow this is fighting me

2025-12-04
- wireshark 4.6 includes native dect nr dissector
  
2025-04-15
v0.9 improved sniffer, now fast enough to catch HARQ ack/nack
- sniffer zephyr app reads network_id and carrier to use from the serial line
- python script takes the network_id and carrier as parameters and writes to serial
- wireshark lua dissector correctly decodes the Nordic ping command from Nordic nRF Connect SDK samples dect_shell
  
2025-04-03
continued sniffer changes, improved lua dissector, tagged as 0.8 as semi stable. Works on small setups
- dissecotr identifies nordic ping command, but does not dissect
- sniffer runs single_shot rx mode, need to add workerque for printout to improve speed

2025-03-31 
nrf SDK now includes hello_dect and dect_shell sample applications, removed old samples from here
**sniffer remake**, writes PCC and PDC to serial as 'raw' hex, not logging hexdump. **Simple python app** forwards packets from serial to (multicast) UDP port.
REQUIRES Nordic DECT PHY firmware 1.1.0
- multicast allows to  record from multiple sites or multiple networks. 
- UDP payload has PCC header length (5 or 10 bytes), PCC and PDC. header length is needed because both type 1 and 2 of PCC have same format 000 identifier
- **Wireshark dissector**, based on Aalto5G https://github.com/Aalto5G/DECT-NR-Wireshark-dissector/tree/main + PCC parsing added
Edited only the dect_nr.lua for phy header parsing, rest of lua files must be copied from repo above to wireshark plugins, so overwrite the dect_nr.lua file with the file in here
And there can be errors!
