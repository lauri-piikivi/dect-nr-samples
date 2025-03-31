# dect-nr-samples
simple sample applications for DECT NR+ on Nordic nrf91

2025-03-31 
nrf SDK now includes hello_dect and dect_shell sample applications, removed old samples from here
sniffer remake, writes PCC and PDC to serial as hex. Simple python app forwards to (multicast) UDP port.
REQUIRES Nordic DECT PHY firmware 1.1.0
multicast allows to  record from multiple sites or multiple networks. 
UDP payload has PCC header length (5 or 10 bytes), PCC and PDC. header length is needed because both type 1 and 2 of PCC have same format 000 identifier

Wireshark dissector, based on Aalto5G https://github.com/Aalto5G/DECT-NR-Wireshark-dissector/tree/main + PCC parsing added
Edited only the dect_nr.lua for phy header parsing, rest of lua files must be copied from repo above to wireshark plugins, so overwrite the dect_nr.lua file with the file in here
And there can be errors!
