-- Copyright (c) 2023 Nordic Semiconductor ASA
--
-- All rights reserved.

DECT_NR = Proto("dect_nr", "DECT NR+")
set_plugin_info({version = "0.2.1", author = "Aapo Korhonen <aapo.korhonen@nordicsemi.no>"})

local wireshark_version = get_version()
local offset = 0
local mac_sec_value = 0;

local dect_plcf_sizes = {
	[0] = "Type 1: 40 bits",
	[1] = "Type 2: 80 bits"
}

local header_formats = {
	[0] = "format 0, type 2 requires HARQ",
	[1] = "Transmitter does not request HARQ feedback for the DF of this packet"
}

-- ETSI TS 103 636-4, Table 6.2.1-3a: Transmit Power
local tx_powers = {
	[0] = "-40 dBm",
	[1] = "-30 dBm",
	[2] = "-20 dBm",
	[3] = "-16 dBm",
	[4] = "-12 dBm",
	[5] = "-8 dBm",
	[6] = "-4 dBm",
	[7] = "0 dBm",
	[8] = "4 dBm",
	[9] = "7 dBm",
	[10] = "10 dBm",
	[11] = "13 dBm",
	[12] = "16 dBm",
	[13] = "19 dBm",
	[14] = "21 dBm",
	[15] = "23 dBm"
}

-- ETSI TS 103 636-4, Table 6.2.1-3b: Transmit Power
local tx_powers_3b = {
	[0] = "Reserved",
	[1] = "Reserved",
	[2] = "Reserved",
	[3] = "Reserved",
	[4] = "-12 dBm",
	[5] = "-8 dBm",
	[6] = "-4 dBm",
	[7] = "0 dBm",
	[8] = "4 dBm",
	[9] = "7 dBm",
	[10] = "10 dBm",
	[11] = "13 dBm",
	[12] = "16 dBm",
	[13] = "19 dBm",
	[14] = "21 dBm",
	[15] = "23 dBm"
}

local pkt_len_types = {
	[0] = "Length given in subslots",
	[1] = "Length given in slots"
}

local mcses = {
	[0] = "BPSK",
	[1] = "QPSK, R=1/2",
	[2] = "QPSK, R=3/4",
	[3] = "16-QAM, R=1/2",
	[4] = "16-QAM, R=3/4",
	[5] = "64-QAM, R=2/3",
	[6] = "64-QAM, R=3/4",
	[7] = "64-QAM, R=5/6",
	[8] = "256-QAM, R=3/4",
	[9] = "256-QAM, R=5/6",
	[10] = "1024-QAM, R=3/4",
	[11] = "1024-QAM, R=5/6"
}

local num_spatial_streams = {
	[0] = "Single spatial stream",
	[1] = "Two spatial streams",
	[2] = "Four spatial streams",
	[3] = "Eight spatial streams",
}

local feedback_format = {
	-- Table 6.2.2-1
	[0] = "No feedback. Receiver shall ignore feedback info bits",
	[1] = "Format 1",
	[2] = "Format 2",
	[3] = "Format 3",
	[4] = "Format 4",
	[5] = "Format 5",
	[6] = "Format 6",
	[15] = "Escape"
}

-- TS 103 636-4 Table 6.2.2-2a: Feedback info format 1: Transmission feedback
local fbi_tx_fb_values = {
	[0] = "NACK",
	[1] = "ACK"
}

-- TS 103 636-4 Table 6.2.2-3: Channel Quality Indicator
local cqi_values = {
	[0] = "Out of Range",
	[1] = "MCS-0",
	[2] = "MCS-1",
	[3] = "MCS-2",
	[4] = "MCS-3",
	[5] = "MCS-4",
	[6] = "MCS-5",
	[7] = "MCS-6",
	[8] = "MCS-7",
	[9] = "MCS-8",
	[10] = "MCS-9",
	[11] = "MCS-10",
	[12] = "MCS-11"
}

-- TS 103 636-4 Table 6.2.2-4: Buffer Status
local buffer_status_values = {
	[0] = "BS = 0",
	[1] = "0 < BS ≤ 16",
	[2] = "16 < BS ≤ 32",
	[3] = "32 < BS ≤ 64",
	[4] = "64 < BS ≤ 128",
	[5] = "128 < BS ≤ 256",
	[6] = "256 < BS ≤ 512",
	[7] = "512 < BS ≤ 1024",
	[8] = "1024 < BS ≤ 2048",
	[9] = "2048 < BS ≤ 4096",
	[10] = "4096 < BS ≤ 8192",
	[11] = "8192 < BS ≤ 16384",
	[12] = "16384 < BS ≤ 32768",
	[13] = "32768 < BS ≤ 65536",
	[14] = "65536 < BS ≤ 131072",
	[15] = "BS > 131072"
}

local mac_security_values = {
	-- Table 6.3.2-1
	[0] = "MAC security is not used for this MAC PDU",
	-- 1: The MAC PDU sequence number is used as PSN for security.
	-- The ciphered part starts immediately after the MAC Common header.
	[1] = "MAC security is used and the MAC Security IE is not present",
	-- 2: The ciphered part starts immediately after the MAC Security info.
	[2] = "MAC security is used and a MAC Security Info IE is in the MAC PDU",
	[3] = "Reserved"
}

local mac_header_types = {
	[0] = "Data MAC PDU header",
	[1] = "Beacon Header",
	[2] = "Unicast Header",
	[3] = "RD Broadcasting Header",
	[15] = "Escape"
}

local mac_ext_fields = {
	-- Table 6.3.4-1
	[0] = "No length field is included in the IE header. The IE type defines the length of the IE payload",
	[1] = "8 bit length included indicating the length of the IE payload",
	[2] = "16 bit length included indicating the length of the IE payload",
	[3] = "Short IE, a one bit length field is included in the IE header"
}

local mac_ext_len_bit = {
	-- Table 6.3.4-1 with value 3: IE payload size
	[0] = "IE payload size 0 bytes",
	[1] = "IE payload size is 1 byte"
}

local mux_hdr_ie_type_mac_ext_012 = {
	-- Table 6.3.4-2
	[0] = "Padding IE",
	[1] = "Higher layer signalling - flow 1",
	[2] = "Higher layer signalling - flow 2",
	[3] = "User plane data - flow 1",
	[4] = "User plane data - flow 2",
	[5] = "User plane data - flow 3",
	[6] = "User plane data - flow 4",
	[7] = "Reserved",
	[8] = "Network Beacon",
	[9] = "Cluster Beacon",
	[10] = "Association Request",
	[11] = "Association Response",
	[12] = "Association Release",
	[13] = "Reconfiguration Request",
	[14] = "Reconfiguration Response",
	[15] = "Additional MAC messages",
	[16] = "Security Info IE",
	[17] = "Route Info IE",
	[18] = "Resource Allocation IE",
	[19] = "Random Access Resource IE",
	[20] = "RD Capability IE",
	[21] = "Neighbouring IE",
	[22] = "Broadcast Indication IE",
	[23] = "Group Assignment IE",
	[24] = "Load Info IE",
	[25] = "Measurement Report IE",
	-- Reserved
	[62] = "Escape",
	[63] = "IE type extension"
}

local mux_hdr_ie_type_mac_ext_3_pl_0 = {
	-- Table 6.3.4-3
	[0] = "Padding IE",
	[1] = "Configuration Request IE",
	[2] = "Keep Alive IE",
	-- Reserved
	[16] = "MAC Security Info IE",
	-- Reserved
	[30] = "Escape"
	-- Reserved
}

local mux_hdr_ie_type_mac_ext_3_pl_1 = {
	-- Table 6.3.4-4
	[0] = "Padding IE",
	[1] = "Radio Device Status IE",
	-- Reserved
	[30] = "Escape"
	-- Reserved
}

-- Table 6.4.2.2-1: Network Beacon definitions
local nb_ie_tx_pwr = {
	[0] = "Cluster Max TX power field is not included",
	[1] = "Cluster Max TX power field is included"
}

local nb_ie_pwr_const = {
	[0] = "The RD operating in FT mode does not have power constraints",
	[1] = "The RD operating in FT mode has power constraints"
}

-- Table 6.4.2.2-1: Current
local nb_ie_current = {
	[0] = "The current cluster channel is the same as the next cluster channel",
	[1] = "The current cluster channel is the not same as the next cluster channel"
}

-- Network Beacon channels

-- Table 6.4.2.2-1: Network Beacon period
local nb_ie_nb_periods = {
	[0] = "50 ms",
	[1] = "100 ms",
	[2] = "500 ms",
	[3] = "1000 ms",
	[4] = "1500 ms",
	[5] = "2000 ms",
	[6] = "4000 ms"
}

-- Table 6.4.2.2-1: Cluster Beacon period
local nb_ie_cb_periods = {
	[0] = "10 ms",
	[1] = "50 ms",
	[2] = "100 ms",
	[3] = "500 ms",
	[4] = "1000 ms",
	[5] = "1500 ms",
	[6] = "2000 ms",
	[7] = "4000 ms",
	[8] = "8000 ms",
	[9] = "16000 ms",
	[10] = "32000 ms"
}

-- Table 6.4.2.3-1 Cluster Beacon definitions
local cb_fo = {
	[0] = "Frame Offset field is not present",
	[1] = "Frame Offset field is present"
}

local cb_next_chan_values = {
	[0] = "The same as the current cluster channel",
	[1] = "Different cluster channel; the next cluster channel field is included"
}

local cb_ttn_values = {
	[0] = "The next cluster beacon is transmitted based on Cluster beacon period",
	[1] = "The next cluster beacon is transmitted in a time location. The Time to next field is present"
}

local msi_version_bmp = {
	[0] = "Mode 1",
	[1] = "Reserved",
	[2] = "Reserved",
	[3] = "Reserved"
}

local msi_ivt_bmp = {
	[0] = "One time HPC.",
	[1] = "Resynchronizing HPC. Initiate Mode -1 security by using this HPC value in both UL and DL communication.",
	[2] = "One time HPC, with HPC request.",
	[3] = "Reserved",
	[4] = "Reserved",
	[5] = "Reserved",
	[6] = "Reserved",
	[7] = "Reserved",
	[8] = "Reserved",
	[9] = "Reserved",
	[10] = "Reserved",
	[11] = "Reserved",
	[12] = "Reserved",
	[13] = "Reserved",
	[14] = "Reserved",
	[15] = "Reserved"
}

local rar_repeat_bmp = {
	[0] = "Single allocation; repetition and validity fields not present",
	[1] = "Repeated in the following frames; periodicity in the Repetition field",
	[2] = "Repeated in the following subslots; periodicity in the Repetition field",
	[3] = "Reserved"
}

local rar_sfn_bmp = {
	[0] = "Resource allocation is immediately valid from this frame onwards (no SFN offset field)",
	[1] = "Resource allocation is valid from the frame indicated in SFN offset field onwards"
}

local rar_channel_bmp = {
	[0] = "The resource allocation is valid for current channel. The channel field is not present in the IE",
	[1] = "The channel where resource allocation is valid is indicated in the channel field of the IE"
}

local rar_chan_2_bmp = {
	[0] = "The random access response is sent on the same channel as the random access message",
	[1] = "The channel for Random access response message is included in the end of the IE"
}

local rar_dect_delay_bmp = {
	[0] = "Response window starts 3 subslots after the last subslot of the Random Access packet transmission",
	[1] = "Response window starts 0.5 frames after the start of the frame where the RA transmission was initiated"
}

-- Signalled subslot length index starts from 0 in some cases:
--  - Packet length type in the Physical Header Field (See Table 6.2.1-1)
--  - Response window: (See Ch. 6.4.3.4 Random Access Resource IE)
local signalled_ss_len = {
	[0] = "1 subslot",
	[1] = "2 subslots",
	[2] = "3 subslots",
	[3] = "4 subslots",
	[4] = "5 subslots",
	[5] = "6 subslots",
	[6] = "7 subslots",
	[7] = "8 subslots",
	[8] = "9 subslots",
	[9] = "10 subslots",
	[10] = "11 subslots",
	[11] = "12 subslots",
	[12] = "13 subslots",
	[13] = "14 subslots",
	[14] = "15 subslots",
	[15] = "16 subslots"
}

-- Table 6.4.2.4-2: Association Setup Cause IE
local ar_setup_causes = {
	[0] = "Initial association",
	[1] = "Association to request new set of flows",
	[2] = "Association due to mobility",
	[3] = "Re-association after error: Loss of connection, Security error or Other error",
	[4] = "Change of operating channel of this FT device",
	[5] = "Change of operating mode (PT->FT or FT->PT)",
	[6] = "Other"
}

-- 6.4.2.4-1: Association Request - operating modes
local ar_ft_mode = {
	[0] = "The RD operates only in PT Mode",
	[1] = "The RD operates also in FT mode. NB/CB Period, Next Cluster Channel and TTN fields are included"
}

-- 6.4.2.4-1: Association Request - MAX HARQ RE-TX or RE-RX
local ar_max_harq_re_rxtx_values = {
	[0] = "0.105 ms",
	[1] = "0.2 ms",
	[2] = "0.4 ms",
	[3] = "0.8 ms",
	[4] = "1 ms",
	[5] = "2 ms",
	[6] = "4 ms",
	[7] = "6 ms",
	[8] = "8 ms",
	[9] = "10 ms",
	[10] = "20 ms",
	[11] = "30 ms",
	[12] = "40 ms",
	[13] = "50 ms",
	[14] = "60 ms",
	[15] = "70 ms",
	[16] = "80 ms",
	[17] = "90 ms",
	[18] = "100 ms",
	[19] = "120 ms",
	[20] = "140 ms",
	[21] = "160 ms",
	[22] = "180 ms",
	[23] = "200 ms",
	[24] = "240 ms",
	[25] = "280 ms",
	[26] = "320 ms",
	[27] = "360 ms",
	[28] = "400 ms",
	[29] = "450 ms",
	[30] = "500 ms",
	[31] = "Reserved"
}

-- 6.4.2.5-1: Association Response: ACK/NACK
local ar_ack_nack = {
	[0] = "Association Rejected",
	[1] = "Association Accepted"
}

-- 6.4.2.5-1: Association Response: HARQ-mod
local ar_harq_mod = {
	[0] = "HARQ configuration accepted as configured in the Association Request; HARQ fields not present",
	[1] = "HARQ configuration present"
}

-- 6.4.2.5-1: Association Response: Number of flows
local ar_num_flows = {
	[7] = "All flows accepted as configured in the Association Request"
}

-- 6.4.2.5-1: Association Response: Group
local ar_group = {
	[0] = "Group ID and Resource Tag are not included",
	[1] = "Group ID and Resource Tag are included"
}

-- 6.4.2.5-2: Reject Cause
local assoc_rej_cause = {
	[0] = "No sufficient radio capacity",
	[1] = "No sufficient HW capacity",
	[2] = "Conflict with Short RD ID detected",
	[3] = "Non-secured Association Requests not accepted",
	[4] = "Other"
}

-- 6.4.2.5-2: Reject Time
local assoc_rej_time = {
	-- Time how long the other RDs shall prohibit sending new Association Requests to this RD
	[0] = "0 s",
	[1] = "5 s",
	[2] = "10 s",
	[3] = "30 s",
	[4] = "60 s",
	[5] = "120 s",
	[6] = "180 s",
	[7] = "300 s",
	[8] = "600 s"
}

-- 6.4.2.6-1: Association Release: Release Cause
local assoc_rel_cause = {
	[0] = "Connection termination",
	[1] = "Mobility",
	[2] = "Long inactivity",
	[3] = "Incompatible configuration",
	[4] = "No sufficient HW or memory resource",
	[5] = "No sufficient radio resources",
	[6] = "Bad radio quality",
	[7] = "Security error",
	[8] = "Other error",
	[9] = "Other reason"
}

-- 6.4.3.5-1: RD Capability IE: Release
local rdc_release = {
	[0] = "Release 1",
	[1] = "Release 2",
	[2] = "Release 3",
	[3] = "Release 4"
}

-- 6.4.3.5-1: RD Capability IE: Operating modes
local rdc_op_modes = {
	[0] = "PT mode only",
	[1] = "FT mode only",
	[2] = "PT and FT modes",
	[3] = "Reserved"
}

-- 6.4.3.5-1: RD Capability IE: Supported/unsupported bit fields
local rdc_support_bits = {
	[1] = "Supported"
}

-- 6.4.3.5-1: RD Capability IE: DLC service type
local rdc_dlc_serv_types = {
	[0] = "DLC Service type 0 supported",
	[1] = "DLC Service type 1 supported",
	[2] = "DLC Service type 2 supported",
	[3] = "DLC Service types 1, 2, 3 supported",
	[4] = "DLC Service types 0, 1, 2, 3 supported",
	[5] = "Reserved"
}

-- 6.4.3.5-1: RD Capability IE: RD Power Class
local rdc_pwr_classes = {
	[0] = "Power class I",
	[1] = "Power class II",
	[2] = "Power class III",
	[3] = "Reserved"
}

-- 6.4.3.5-1: RD Capability IE: power of two coded fields
local rdc_pwr_two_fields = {
	[0] = "1",
	[1] = "2",
	[2] = "4",
	[3] = "8",
	[4] = "Reserved"
}

-- 6.4.3.5-1: RD Capability IE: RX Gain
local rdc_rx_gains = {
	[0] = "-10 dB",
	[1] = "-8 dB",
	[2] = "-6 dB",
	[3] = "-4 dB",
	[4] = "-2 dB",
	[5] = "-0 dB",
	[6] = "2 dB",
	[7] = "4 dB",
	[8] = "6 dB"
}

-- 6.4.3.5-1: RD Capability IE: Max MCS
local rdc_max_mcses = {
	[0] = "MCS2",
	[1] = "MCS3",
	[2] = "MCS4",
	[3] = "MCS5",
	[4] = "MCS6",
	[5] = "MCS7",
	[6] = "MCS8",
	[7] = "MCS9",
	[8] = "MCS10",
	[9] = "MCS11"
}

-- 6.4.3.5-1: RD Capability IE: Soft buffer sizes
local rdc_soft_buf_sizes = {
	[0] = "16 000 B",
	[1] = "25 344 B",
	[2] = "32 000 B",
	[3] = "64 000 B",
	[4] = "128 000 B",
	[5] = "256 000 B",
	[6] = "512 000 B",
	[7] = "1 024 000 B",
	[8] = "2 048 000 B"
}

-- 6.4.3.5-1: RD Capability IE: Fourier transform scaling factor
local rdc_fourier_factor = {
	[0] = "1",
	[1] = "2",
	[2] = "4",
	[3] = "8",
	[4] = "12",
	[5] = "16",
	[6] = "Reserved"
}

-- 6.4.3.7-1: Broadcast Indication IE field definitions: Indication type
local bi_ind_types = {
	[0] = "Paging",
	[1] = "RA Response"
}

-- 6.4.3.7-1: Broadcast Indication IE field definitions: IDType
local bi_idtypes = {
	[0] = "Short RD ID",
	[1] = "Long RD ID"
}

-- 6.4.3.7-1: Broadcast Indication IE field definitions: ACK/NACK
local bi_ack_nack = {
	[0] = "Incorrectly received MAC PDU in RA TX",
	[1] = "Correctly received MAC PDU in RA TX"
}

-- 6.4.3.7-1: Broadcast Indication IE field definitions: ACK/NACK
local bi_feedback = {
	[0] = "No feedback",
	[1] = "MCS",
	[2] = "MIMO_2_antenna",
	[3] = "MIMO_4_antenna"
}

-- 6.4.3.7-1: Broadcast Indication IE field definitions: Resource allocation IE presence
local bi_ra_ie_presence = {
	[0] = "Resource Allocation IE not present in this MAC PDU",
	[1] = "Resource Allocation IE follows in this MAC PDU"
}

-- 6.4.3.13-1: Radio Device Status IE field definitions: Status flag
local rds_status_flags = {
	[0] = "Reserved",
	[1] = "Memory Full",
	[2] = "Normal operation resumed",
	[3] = "Reserved"
}

-- 6.4.3.13-1: Radio Device Status IE field definitions: Duration
local rds_durations = {
	[0] = "50 ms",
	[1] = "100 ms",
	[2] = "200 ms",
	[3] = "400 ms",
	[4] = "600 ms",
	[5] = "800 ms",
	[6] = "1000 ms",
	[7] = "1500 ms",
	[8] = "2000 ms",
	[9] = "3000 ms",
	[10] = "4000 ms",
	[11] = "Unknown"
}


-- TS 103 636-5: DLC and Convergence layer definitions

-- 5.3.1-1: DLC IE Type coding
local dlc_ie_types = {
	[0] = "Data: DLC Service type 0 with routing header",
	[1] = "Data: DLC Service type 0 without routing header",
	[2] = "Data: DLC Service type 1 or 2 or 3 with routing header",
	[3] = "Data: DLC Service type 1 or 2 or 3 without routing header",
	[4] = "DLC Timers configuration control IE",
	[14] = "Escape"
}

-- 5.3.3.1-1: DLC SI coding
local dlc_si_types = {
	[0] = "Data field contains the complete higher layer SDU",
	[1] = "Data field contains the first segment of the higher layer SDU",
	[2] = "Data field contains the last segment of the higher layer SDU",
	[3] = "Data field contains neither the first nor the last segment of the higher layer SDU"
}

-- The ProtoField's Lua table of this dissector
local f = DECT_NR.fields

-- Physical Header Field
f.phf = ProtoField.bytes("dect_nr.phf", "Physical Header Field")
f.header_format = ProtoField.uint8("dect_nr.phf.hf", "Header Format", nil, header_formats, 0xE0)
f.type = ProtoField.uint8("dect_nr.phf.type", "Packet length type", nil, pkt_len_types, 0x10)
f.packet_len_ss = ProtoField.uint8("dect_nr.phf.pkt_len", "Packet length", nil, signalled_ss_len, 0x0F)
f.short_nw_id = ProtoField.uint8("dect_nr.phf.short_nw_id", "Short Network ID", base.HEX, nil)
f.transmitter_id = ProtoField.uint16("dect_nr.phf.transmitter_id", "Transmitter Short RD ID", base.HEX, nil)
f.tx_pwr = ProtoField.uint8("dect_nr.phf.tx_pwr", "Transmit Power", nil, tx_powers, 0xF0)
f.res0 = ProtoField.uint8("dect_nr.phf.res0", "Reserved", nil, nil, 0x08)
f.df_mcs_t1 = ProtoField.uint8("dect_nr.phf.df_mcs_t1", "DF MCS (Type 1)", nil, mcses, 0x07)
f.df_mcs_t2 = ProtoField.uint8("dect_nr.phf.df_mcs_t2", "DF MCS (Type 2)", nil, mcses, 0x0F)
f.receiver_id = ProtoField.uint16("dect_nr.phf.receiver_id", "Receiver Short RD ID", base.HEX, nil)
f.spatial_streams = ProtoField.uint8("dect_nr.phf.spatial_streams", "Number of Spatial Streams", nil,
	num_spatial_streams, 0xC0)
f.df_red_version = ProtoField.uint8("dect_nr.phf.df_red_version", "DF Redundancy Version", nil, nil, 0x30)
f.df_ind = ProtoField.uint8("dect_nr.phf.df_ind", "DF New Data Indication", nil, nil, 0x08)
f.df_harq_proc = ProtoField.uint8("dect_nr.phf.df_harq_proc", "DF HARQ Process Number", nil, nil, 0x07)
f.res1_hdr_format_001 = ProtoField.uint8("dect_nr.phf.res1", "Reserved", nil, nil, 0x3F)
f.fb_format = ProtoField.uint16("dect_nr.phf.fb_format", "Feedback format", nil, feedback_format, 0xF000)

-- TS 103 636-4 Ch. 6.2.2: Coding of Feedback info
-- Table 6.2.2-2a: Feedback info format 1
f.fbi1_harq_pn = ProtoField.uint16("dect_nr.phf.fbi1.harq_pn", "HARQ FB Process number", nil, nil, 0x0E00)
f.fbi1_tx_fb = ProtoField.uint16("dect_nr.phf.fbi1.tx_feedback", "Transmission feedback", nil, fbi_tx_fb_values, 0x0100)
f.fbi1_bs = ProtoField.uint16("dect_nr.phf.fbi1.bs", "Buffer status", nil, buffer_status_values, 0x00F0)
f.fbi1_cqi = ProtoField.uint16("dect_nr.phf.fbi1.cqi", "Channel Quality Indicator", nil, cqi_values, 0x000F)

-- TODO: feedback info formats 2-5

-- Table 6.2.2-2f: Feedback info format 6
-- Using this feedback info format implicitly means a Negative Acknowledgement (NACK)
-- for the corresponding HARQ process. The HARQ retransmission with the process number
-- shall use DF Redundancy Version 0.
f.fbi6_harq_pn = ProtoField.uint16("dect_nr.phf.fbi6.harq_pn", "HARQ FB Process number", nil, nil, 0x0E00)
f.fbi6_res1 = ProtoField.uint16("dect_nr.phf.fbi6.res1", "Reserved", nil, nil, 0x0100)
f.fbi6_bs = ProtoField.uint16("dect_nr.phf.fbi6.bs", "Buffer status", nil, buffer_status_values, 0x00F0)
f.fbi6_cqi = ProtoField.uint16("dect_nr.phf.fbi6.cqi", "Channel Quality Indicator", nil, cqi_values, 0x000F)

f.fb_info = ProtoField.uint16("dect_nr.phf.fb_info", "Feedback info", nil, nil, 0x0FFF)
f.phf_padding = ProtoField.bytes("dect_nr.phf.padding", "Padding", nil, nil)

-- PING PDU
f.ping_pdu = ProtoField.bytes("nordic_ping","Nordic Ping")
local ping_type = {
	[0xe4] = "Ping Request",
	[0xe5] = "Ping Response",
	[0xe6] = "Ping Result req",
	[0xe7] = "Ping Result resp",
	[0xe8] = "Ping HARQ feedback"
}
f.ping_type = ProtoField.uint8("nordic_ping.type", "Ping msg type", base.HEX, ping_type)
f.ping_rssi = ProtoField.int8("nordic_ping.expected_rssi", "Exp RSSI", base.DEC)
f.ping_transmitter_id = ProtoField.uint16("nordic_ping.transmitter_id", "Transmitter ID", base.HEX)
f.ping_seq_num = ProtoField.uint16("nordic_ping.seq_num", "Sequence_num", base.DEC)
f.ping_len =ProtoField.uint16("nordic_ping.length", "Length", base.DEC)
f.ping_data = ProtoField.string("nordic_ping.data","Ping data ASCII")

-- MAC PDU
f.mac_pdu = ProtoField.bytes("dect_nr.mac", "MAC PDU")
f.mac_hdr_vers = ProtoField.uint8("dect_nr.mac.hdr_vers", "Version", nil, nil, 0xC0)
f.mac_sec = ProtoField.uint8("dect_nr.mac.sec", "MAC security", nil, mac_security_values, 0x30)
f.mac_hdr_type = ProtoField.uint8("dect_nr.mac.hdr_type", "MAC Header Type", nil, mac_header_types, 0x0F)

-- MAC Common Header
f.mac_hdr = ProtoField.bytes("dect_nr.mac.hdr", "MAC Common header")

-- Data MAC PDU Header
f.data_hdr = ProtoField.bytes("dect_nr.mac.hdr.data", "Data MAC PDU Header")
f.data_hdr_res1 = ProtoField.uint16("dect_nr.mac.hdr.data.res1", "Reserved", nil, nil, 0xE000)
f.data_hdr_reset = ProtoField.uint16("dect_nr.mac.hdr.data.reset", "Reset", nil, nil, 0x1000)
f.data_hdr_sn = ProtoField.uint16("dect_nr.mac.hdr.data.sn", "Sequence number", nil, nil, 0x0FFF)

-- Beacon Header
f.bc_hdr = ProtoField.bytes("dect_nr.mac.hdr.bc", "Beacon Header")
f.bc_hdr_nw_id = ProtoField.uint24("dect_nr.mac.hdr.bc.nw_id", "Network ID", base.HEX, nil)
f.bc_hdr_tx_addr = ProtoField.uint32("dect_nr.mac.hdr.bc.tx_addr", "Transmitter Address", base.HEX, nil)

-- Unicast Header
f.uc_hdr = ProtoField.bytes("dect_nr.mac.hdr.uc", "Unicast Header")
f.uc_hdr_res = ProtoField.uint8("dect_nr.mac.hdr.uc.res", "Reserved", nil, nil, 0xE0)
f.uc_hdr_rst = ProtoField.uint8("dect_nr.mac.hdr.uc.rst", "Reset", nil, nil, 0x10)
f.uc_hdr_mac_seq = ProtoField.uint8("dect_nr.mac.hdr.uc.mac_seq", "MAC Sequence", nil, nil, 0x0F)
f.uc_hdr_sn = ProtoField.uint8("dect_nr.mac.hdr.uc.sn", "Sequence Number", nil, nil)
f.uc_hdr_rx_addr = ProtoField.uint32("dect_nr.mac.hdr.uc.rx_addr", "Receiver Address", base.HEX, nil)
f.uc_hdr_tx_addr = ProtoField.uint32("dect_nr.mac.hdr.uc.tx_addr", "Transmitter Address", base.HEX, nil)

-- MAC Multiplexing Header
f.mac_mux_hdr = ProtoField.bytes("dect_nr.mac.mux_hdr", "MAC Multiplexing header")
f.mux_mac_ext = ProtoField.uint8("dect_nr.mac.mux_hdr.mac_ext", "MAC extension", nil, mac_ext_fields, 0xC0)
f.mux_len_bit = ProtoField.uint8("dect_nr.mac.mux_hdr.len", "Length bit", nil, nil, 0x20)
f.mux_ie_type_long = ProtoField.uint8("dect_nr.mac.mux_hdr.ie_type_long", "IE type", nil,
	mux_hdr_ie_type_mac_ext_012, 0x3F)
f.mux_ie_type_short_pl0 = ProtoField.uint8("dect_nr.mac.mux_hdr.ie_type_short_pl0", "IE type (no payload)",
	nil, mux_hdr_ie_type_mac_ext_3_pl_0, 0x1F)
f.mux_ie_type_short_pl1 = ProtoField.uint8("dect_nr.mac.mux_hdr.ie_type_short_pl1", "IE type (1-byte payload)",
	nil, mux_hdr_ie_type_mac_ext_3_pl_1, 0x1F)
f.mux_mac_sdu_1b = ProtoField.uint8("dect_nr.mac.mux_hdr.mac_sdu_1b", "1-byte MAC SDU", nil, nil)
f.mux_mac_ie_len_1 = ProtoField.uint8("dect_nr.mac.mux_hdr.ie_len_1", "IE length in bytes", nil, nil)
f.mux_mac_ie_len_2 = ProtoField.uint16("dect_nr.mac.mux_hdr.ie_len_2", "IE length in bytes", nil, nil)

--
-- MAC MESSAGES
--
f.mac_msg = ProtoField.bytes("dect_nr.mac.msg", "MAC Messages")

-- 6.4.2.2: Network Beacon
f.nb_msg = ProtoField.bytes("dect_nr.mac.nb.msg", "Network Beacon Message")
f.nb_res1 = ProtoField.uint8("dect_nr.mac.nb.res1", "Reserved", nil, nil, 0xE0)
f.nb_tx_pwr = ProtoField.uint8("dect_nr.mac.nb.tx_pwr", "TX Power", nil, nb_ie_tx_pwr, 0x10)
f.nb_pwr_const = ProtoField.uint8("dect_nr.mac.nb.pwr_const", "Power Const", nil, nb_ie_pwr_const, 0x08)
f.nb_current = ProtoField.uint8("dect_nr.mac.nb.current", "Current", nil, nb_ie_current, 0x04)
f.nb_channels = ProtoField.uint8("dect_nr.mac.nb.channels", "Network beacon channels", nil, nil, 0x03)
f.nb_nb_period = ProtoField.uint8("dect_nr.mac.nb.nb_period", "Network beacon period", nil, nb_ie_nb_periods, 0xF0)
f.nb_cb_period = ProtoField.uint8("dect_nr.mac.nb.cb_period", "Cluster beacon period", nil, nb_ie_cb_periods, 0x0F)
f.nb_res2 = ProtoField.uint8("dect_nr.mac.nb.res2", "Reserved", nil, nil, 0xE0)
f.nb_next_cl_chan = ProtoField.uint16("dect_nr.mac.nb.next_cl_chan", "Next Cluster Channel", nil, nil)
f.nb_ttn = ProtoField.uint32("dect_nr.mac.nb.ttn", "Time To Next (μs)", nil, nil)
f.nb_res3 = ProtoField.uint8("dect_nr.mac.nb.res3", "Reserved", nil, nil, 0xF0)
f.nb_cl_max_tx_pwr = ProtoField.uint8("dect_nr.mac.nb.cl_max_tx_pwr", "Cluster Max TX Power", nil, tx_powers_3b, 0x0F)
f.nb_res4 = ProtoField.uint8("dect_nr.mac.nb.res4", "Reserved", nil, nil, 0xE0)
f.nb_curr_cl_chan = ProtoField.uint16("dect_nr.mac.nb.curr_cl_chan", "Current Cluster Channel", nil, nil, 0x1FFF)
f.nb_res5 = ProtoField.uint8("dect_nr.mac.nb.res5", "Reserved", nil, nil, 0xE0)
f.nb_addn_nb_channels = ProtoField.uint16("dect_nr.mac.nb.addn_nb_channels", "Additional Network Beacon Channels",
	nil, nil, 0x1FFF)

-- 6.4.2.3: Cluster Beacon
f.cb_msg = ProtoField.bytes("dect_nr.mac.cb.msg", "Cluster Beacon Message")
f.cb_sfn = ProtoField.uint8("dect_nr.mac.cb.sfn", "System Frame Number", nil, nil)
f.cb_res1 = ProtoField.uint8("dect_nr.mac.cb.res1", "Reserved", nil, nil, 0xE0)
f.cb_tx_pwr = ProtoField.uint8("dect_nr.mac.cb.tx_pwr", "TX Power", nil, nb_ie_tx_pwr, 0x10)
f.cb_pwr_const = ProtoField.uint8("dect_nr.mac.cb.pwr_const", "Power Const", nil, nb_ie_pwr_const, 0x08)
f.cb_fo = ProtoField.uint8("dect_nr.mac.cb.fo", "FO", nil, cb_fo, 0x04)
f.cb_next_chan = ProtoField.uint8("dect_nr.mac.cb.next_chan", "Next Channel", nil, cb_next_chan_values, 0x02)
f.cb_ttn = ProtoField.uint8("dect_nr.mac.cb.cb_ttn", "TTN", nil, cb_ttn_values, 0x01)
f.cb_nb_period = ProtoField.uint8("dect_nr.mac.cb.nb_period", "Network beacon period", nil, nb_ie_nb_periods, 0xF0)
f.cb_cb_period = ProtoField.uint8("dect_nr.mac.cb.cb_period", "Cluster beacon period", nil, nb_ie_cb_periods, 0x0F)
f.cb_ctt = ProtoField.uint8("dect_nr.mac.cb.ctt", "Count To Trigger", nil, nil, 0xF0)
f.cb_rel_qual = ProtoField.uint8("dect_nr.mac.cb.rel_qual", "Relative Quality", nil, nil, 0x0C)
f.cb_min_qual = ProtoField.uint8("dect_nr.mac.cb.min_qual", "Minimum Quality", nil, nil, 0x03)
f.cb_res2 = ProtoField.uint8("dect_nr.mac.cb.res2", "Reserved", nil, nil, 0xF0)
f.cb_cl_max_tx_pwr = ProtoField.uint8("dect_nr.mac.cb.cl_max_tx_pwr", "Cluster Max TX Power", nil, tx_powers_3b, 0x0F)
f.cb_frame_offset = ProtoField.uint8("dect_nr.mac.cb.frame_offset", "Frame Offset", nil, nil)
f.cb_res3 = ProtoField.uint8("dect_nr.mac.cb.res3", "Reserved", nil, nil, 0xE0)
f.cb_next_cl_chan = ProtoField.uint16("dect_nr.mac.cb.next_cl_chan", "Next Cluster Channel", nil, nil, 0x1FFF)
f.cb_time_to_next = ProtoField.uint32("dect_nr.mac.cb.time_to_next", "Time To Next", nil, nil)

-- 6.4.2.4 Association Request
f.a_req_msg = ProtoField.bytes("dect_nr.mac.areq.msg", "Association Request Message")
f.a_req_setup_cause = ProtoField.uint8("dect_nr.mac.areq.sc", "Setup Cause", nil, ar_setup_causes, 0xE0)
f.a_req_nflows = ProtoField.uint8("dect_nr.mac.areq.nfows", "Number of Flows", nil, nil, 0x1C)
f.a_req_pwr_const = ProtoField.uint8("dect_nr.mac.areq.pwr_const", "Power Const", nil, nb_ie_pwr_const, 0x02)
f.a_req_ft_mode = ProtoField.uint8("dect_nr.mac.areq.ft_mode", "FT Mode", nil, ar_ft_mode, 0x01)
f.a_req_current = ProtoField.uint8("dect_nr.mac.areq.current", "Current", nil, nb_ie_current, 0x80)
f.a_req_res1 = ProtoField.uint8("dect_nr.mac.areq.res1", "Reserved", nil, nil, 0x7F)
f.a_req_harq_proc_tx = ProtoField.uint8("dect_nr.mac.areq.harq_proc_tx", "HARQ Processes TX", nil, nil, 0xE0)
f.a_req_max_harq_retx = ProtoField.uint8("dect_nr.mac.areq.max_harq_retx", "Max HARQ Re-TX",
	nil, ar_max_harq_re_rxtx_values, 0x1F)
f.a_req_harq_proc_rx = ProtoField.uint8("dect_nr.mac.areq.harq_proc_rx", "HARQ Processes RX", nil, nil, 0xE0)
f.a_req_max_harq_rerx = ProtoField.uint8("dect_nr.mac.areq.max_harq_rerx", "Max HARQ Re-RX",
	nil, ar_max_harq_re_rxtx_values, 0x1F)
f.a_req_res2 = ProtoField.uint8("dect_nr.mac.areq.res2", "Reserved", nil, nil, 0xC0)
f.a_req_flow_id = ProtoField.uint8("dect_nr.mac.areq.flow_id", "Flow ID", nil, mux_hdr_ie_type_mac_ext_012, 0x3F)
f.a_req_nb_period = ProtoField.uint8("dect_nr.mac.areq.nb_period", "Network beacon period", nil, nb_ie_nb_periods, 0xF0)
f.a_req_cb_period = ProtoField.uint8("dect_nr.mac.areq.cb_period", "Cluster beacon period", nil, nb_ie_cb_periods, 0x0F)
f.a_req_res3 = ProtoField.uint8("dect_nr.mac.areq.res3", "Reserved", nil, nil, 0xE0)
f.a_req_next_cl_chan = ProtoField.uint16("dect_nr.mac.areq.next_cl_chan", "Next Cluster Channel", nil, nil)
f.a_req_ttn = ProtoField.uint32("dect_nr.mac.areq.ttn", "Time To Next (μs)", nil, nil)
f.a_req_res4 = ProtoField.uint8("dect_nr.mac.areq.res4", "Reserved", nil, nil, 0xE0)
f.a_req_curr_cl_chan = ProtoField.uint16("dect_nr.mac.areq.curr_cl_chan", "Current Cluster Channel", nil, nil, 0x1FFF)

-- 6.4.2.5 Association Response
f.a_rsp_msg = ProtoField.bytes("dect_nr.mac.arsp.msg", "Association Response Message")
f.a_rsp_ack = ProtoField.uint8("dect_nr.mac.arsp.ack", "ACK/NACK", nil, ar_ack_nack, 0x80)
f.a_rsp_res1 = ProtoField.uint8("dect_nr.mac.arsp.res1", "Reserved", nil, nil, 0x40)
f.a_rsp_harq_mod = ProtoField.uint8("dect_nr.mac.arsp.harq_mod", "HARQ-mod", nil, ar_harq_mod, 0x20)
f.a_rsp_nflows = ProtoField.uint8("dect_nr.mac.arsp.nflows", "Number of Flows", nil, ar_num_flows, 0x1C)
f.a_rsp_group = ProtoField.uint8("dect_nr.mac.arsp.group", "Group", nil, ar_group, 0x02)
f.a_rsp_tx_pwr = ProtoField.uint8("dect_nr.mac.arsp.tx_pwr", "TX Power", nil, nil, 0x01)
f.a_rsp_rej_cause = ProtoField.uint8("dect_nr.mac.arsp.rej_cause", "Reject Cause", nil, assoc_rej_cause, 0xF0)
f.a_rsp_rej_time = ProtoField.uint8("dect_nr.mac.arsp.rej_time", "Reject Time", nil, assoc_rej_time, 0x0F)
f.a_rsp_harq_proc_rx = ProtoField.uint8("dect_nr.mac.arsp.harq_proc_rx", "HARQ Processes RX", nil, nil, 0xE0)
f.a_rsp_max_harq_rerx = ProtoField.uint8("dect_nr.mac.arsp.max_harq_rerx", "Max HARQ Re-RX",
	nil, ar_max_harq_re_rxtx_values, 0x1F)
f.a_rsp_harq_proc_tx = ProtoField.uint8("dect_nr.mac.arsp.harq_proc_tx", "HARQ Processes TX", nil, nil, 0xE0)
f.a_rsp_max_harq_retx = ProtoField.uint8("dect_nr.mac.arsp.max_harq_retx", "(RX) Max HARQ Re-TX",
	nil, ar_max_harq_re_rxtx_values, 0x1F)
f.a_rsp_res2 = ProtoField.uint8("dect_nr.mac.arsp.res2", "Reserved", nil, nil, 0xC0)
f.a_rsp_flow_id = ProtoField.uint8("dect_nr.mac.arsp.flow_id", "Flow ID", nil, mux_hdr_ie_type_mac_ext_012, 0x3F)
f.a_rsp_res3 = ProtoField.uint8("dect_nr.mac.arsp.res3", "Reserved", nil, nil, 0x80)
f.a_rsp_group_id = ProtoField.uint8("dect_nr.mac.arsp.group_id", "Group ID", nil, nil, 0x7F)
f.a_rsp_res4 = ProtoField.uint8("dect_nr.mac.arsp.res4", "Reserved", nil, nil, 0x80)
f.a_rsp_res_tag = ProtoField.uint8("dect_nr.mac.arsp.res_tag", "Resource Tag", nil, nil, 0x7F)

-- 6.4.2.6 Association Release
f.a_rel_msg = ProtoField.bytes("dect_nr.mac.arel.msg", "Association Release Message")
f.a_rel_cause = ProtoField.uint8("dect_nr.mac.arel.cause", "Release Cause", nil, assoc_rel_cause, 0xF0)
f.a_rel_res1 = ProtoField.uint8("dect_nr.mac.arel.res1", "Reserved", nil, nil, 0x0F)

--
-- MAC INFORMATION ELEMENTS
--
-- 6.4.3.1: MAC Security Info IE
f.msi_ie = ProtoField.bytes("dect_nr.mac.msi.ie", "MAC Security Info IE")
f.msi_ver = ProtoField.uint8("dect_nr.mac.msi.ver", "Version", nil, msi_version_bmp, 0xC0)
f.msi_key = ProtoField.uint8("dect_nr.mac.msi.key", "Key Index", nil, nil, 0x30)
f.msi_ivt = ProtoField.uint8("dect_nr.mac.msi.ivt", "Security IV Type", nil, msi_ivt_bmp, 0x0F)
f.msi_hpc = ProtoField.uint32("dect_nr.mac.msi.hpc", "Hyper Packet Counter", base.HEX, nil)

-- 6.4.3.4: Random Access Resource IE
f.rar_ie = ProtoField.bytes("dect_nr.mac.rar.ie", "Random Access Resource IE")
f.rar_res1 = ProtoField.uint8("dect_nr.mac.rar.res1", "Reserved", nil, nil, 0xE0)
f.rar_repeat = ProtoField.uint8("dect_nr.mac.rar.repeat", "Resource Allocation Repeat", nil, rar_repeat_bmp, 0x18)
f.rar_sfn_f = ProtoField.uint8("dect_nr.mac.rar.sfn_f", "SFN", nil, rar_sfn_bmp, 0x04)
f.rar_channel_f = ProtoField.uint8("dect_nr.mac.rar.channel_f", "Channel", nil, rar_channel_bmp, 0x02)
f.rar_chan_2_f = ProtoField.uint8("dect_nr.mac.rar.chan_2_f", "RAR Channel", nil, rar_chan_2_bmp, 0x01)
-- 8 bits or 16 bits. The start subslot indicates the first subslot where the RACH resource allocation is valid
-- in the frame. The 8 bits version is used when μ ≤ 4, and the 16 bits version is used when μ > 4
-- TODO: Selection between 8-bit and 16-bit version needed at some point?
f.rar_start_ss = ProtoField.uint8("dect_nr.mac.rar.start_ss", "Start subslot")
f.rar_len_type = ProtoField.uint8("dect_nr.mac.rar.len_type", "Length type", nil, pkt_len_types, 0x80)
f.rar_len = ProtoField.uint8("dect_nr.mac.rar.len", "Length", nil, nil, 0x7F)
f.rar_max_len_type = ProtoField.uint8("dect_nr.mac.rar.max_len_type", "MAX Len type", nil, pkt_len_types, 0x80)
f.rar_max_rach_len = ProtoField.uint8("dect_nr.mac.rar.max_rach_len", "MAX RACH Length", nil, nil, 0x78)
f.rar_cw_min_sig = ProtoField.uint8("dect_nr.mac.rar.cw_min_sig", "CW Min sig", nil, nil, 0x07)
f.rar_dect_delay = ProtoField.uint8("dect_nr.mac.rar.dect_delay", "DECT delay", nil, rar_dect_delay_bmp, 0x80)
f.rar_resp_win = ProtoField.uint8("dect_nr.mac.rar.resp_win", "Response window", nil, signalled_ss_len, 0x78)
f.rar_cw_max_sig = ProtoField.uint8("dect_nr.mac.rar.cw_max_sig", "CW Max sig", nil, nil, 0x07)
f.rar_repetition = ProtoField.uint8("dect_nr.mac.rar.repetition", "Repetition")
f.rar_validity = ProtoField.uint8("dect_nr.mac.rar.validity", "Validity")
f.rar_sfn_offset = ProtoField.uint8("dect_nr.mac.rar.sfn_offset", "SFN offset")
f.rar_channel = ProtoField.uint16("dect_nr.mac.rar.channel", "Channel", base.DEC, nil)
f.rar_channel_2 = ProtoField.uint16("dect_nr.mac.rar.channel_2", "RAR Channel", base.DEC, nil)

-- 6.4.3.5: Radio Device Capability IE
f.rdc_ie = ProtoField.bytes("dect_nr.mac.rdc.ie", "RD Capability IE")
f.rdc_num_phy_cap = ProtoField.uint8("dect_nr.mac.rdc.num_phy_cap", "Number of PHY Capabilities", nil, nil, 0xE0)
f.rdc_release = ProtoField.uint8("dect_nr.mac.rdc.release", "Release", nil, rdc_release, 0x1F)
f.rdc_res1 = ProtoField.uint8("dect_nr.mac.rdc.res1", "Reserved", nil, nil, 0xF0)
f.rdc_op_modes = ProtoField.uint8("dect_nr.mac.rdc.op_modes", "Operating modes", nil, rdc_op_modes, 0x0C)
f.rdc_mesh = ProtoField.uint8("dect_nr.mac.rdc.mesh", "Mesh", nil, rdc_support_bits, 0x02)
f.rdc_sched = ProtoField.uint8("dect_nr.mac.rdc.sched", "Scheduled data", nil, rdc_support_bits, 0x01)
f.rdc_mac_security = ProtoField.uint8("dect_nr.mac.rdc.mac_security", "MAC Security", nil, rdc_support_bits, 0xE0)
f.rdc_dlc_type = ProtoField.uint8("dect_nr.mac.rdc.dlc_type", "DLC Service Type", nil, rdc_dlc_serv_types, 0x1C)
f.rdc_res2 = ProtoField.uint8("dect_nr.mac.rdc.res2", "Reserved", nil, nil, 0x03)
f.rdc_res3 = ProtoField.uint8("dect_nr.mac.rdc.res3", "Reserved", nil, nil, 0x80)
f.rdc_pwr_class = ProtoField.uint8("dect_nr.mac.rdc.pwr_class", "RD Power Class", nil, rdc_pwr_classes, 0x70)
f.rdc_max_nss_rx = ProtoField.uint8("dect_nr.mac.rdc.max_nss_rx", "Max NSS for RX", nil, rdc_pwr_two_fields, 0x0C)
f.rdc_rx_for_tx_div = ProtoField.uint8("dect_nr.mac.rdc.rx_for_tx_div", "RX for TX diversity", nil, rdc_pwr_two_fields, 0x03)
f.rdc_rx_gain = ProtoField.uint8("dect_nr.mac.rdc.rx_gain", "RX Gain", nil, rdc_rx_gains, 0xF0)
f.rdc_max_mcs = ProtoField.uint8("dect_nr.mac.rdc.max_mcs", "Max MCS", nil, rdc_max_mcses, 0x0F)
f.rdc_soft_buf_size = ProtoField.uint8("dect_nr.mac.rdc.soft_buf_size", "Soft-buffer size", nil, rdc_soft_buf_sizes, 0xF0)
f.rdc_num_harq_proc = ProtoField.uint8("dect_nr.mac.rdc.num_harq_proc", "Number of parallel HARQ Processes", nil, rdc_pwr_two_fields, 0x0C)
f.rdc_res4 = ProtoField.uint8("dect_nr.mac.rdc.res4", "Reserved", nil, nil, 0x03)
f.rdc_harq_fb_delay = ProtoField.uint8("dect_nr.mac.rdc.harq_fb_delay", "HARQ feedback delay", nil, nil, 0xF0)
f.rdc_res5 = ProtoField.uint8("dect_nr.mac.rdc.res5", "Reserved", nil, nil, 0x0F)
f.rdc_rd_class_u = ProtoField.uint8("dect_nr.mac.rdc.rd_class_u", "Radio Device Class: μ", nil, rdc_pwr_two_fields, 0xE0)
f.rdc_rd_class_b = ProtoField.uint8("dect_nr.mac.rdc.rd_class_b", "Radio Device Class: β", nil, rdc_fourier_factor, 0x1E)
f.rdc_res6 = ProtoField.uint8("dect_nr.mac.rdc.res6", "Reserved", nil, nil, 0x01)

-- 6.4.3.7: Broadcast Indication IE
f.bi_ie = ProtoField.bytes("dect_nr.mac.bi.ie", "Broadcast Indication IE")
f.bi_ind_type = ProtoField.uint8("dect_nr.mac.bi.ind_type", "Indication type", nil, bi_ind_types, 0xE0)
f.bi_idtype = ProtoField.uint8("dect_nr.mac.bi.idtype", "IDType", nil, bi_idtypes, 0x10)
f.bi_ack = ProtoField.uint8("dect_nr.mac.bi.ack", "ACK/NACK", nil, bi_ack_nack, 0x08)
f.bi_res1 = ProtoField.uint8("dect_nr.mac.bi.res1", "Reserved", nil, nil, 0x0E)
f.bi_fb = ProtoField.uint8("dect_nr.mac.bi.fb", "Feedback", nil, bi_feedback, 0x06)
f.bi_res_alloc = ProtoField.uint8("dect_nr.mac.bi.res_alloc", "Resource Allocation", nil, bi_ra_ie_presence, 0x01)
f.bi_short_rd_id = ProtoField.uint16("dect_nr.mac.bi.short_rd_id", "Short RD ID", base.HEX, nil)
f.bi_long_rd_id = ProtoField.uint32("dect_nr.mac.bi.long_rd_id", "Long RD ID", base.HEX, nil)
-- TODO: this. 6.4.3.7-1: Broadcast Indication IE field definitions
f.bi_mcs_mimo_fb = ProtoField.uint8("dect_nr.mac.bi.mcs_mimo_fb", "MCS or MIMO Feedback", nil, nil)

-- 6.4.3.8 Padding IE
f.pd_ie = ProtoField.bytes("dect_nr.mac.pd", "Padding IE", nil, nil)
f.pd_bytes = ProtoField.bytes("dect_nr.mac.pd.bytes", "Padding", nil, nil)

-- 6.4.3.13 Radio Device Status IE
f.rds_ie = ProtoField.bytes("dect_nr.mac.rds.ie", "Radio Device Status IE")
f.rds_res1 = ProtoField.uint8("dect_nr.mac.rds.res1", "Reserved", nil, nil, 0xC0)
f.rds_sf = ProtoField.uint8("dect_nr.mac.rds.sf", "Status flag", nil, rds_status_flags, 0x30)
f.rds_dur = ProtoField.uint8("dect_nr.mac.rds.duration", "Duration", nil, rds_durations, 0x0F)

-- MIC --
f.mic_bytes = ProtoField.bytes("dect_nr.mac.mic_bytes", "Message Integrity Code (MIC)", nil, nil)


-- DLC Headers and Messages

-- DLC Service Type 0
f.dlc_st_0 = ProtoField.bytes("dect_nr.dlc.st_0", "DLC Service Type 0")
f.dlc_ie_type = ProtoField.uint8("dect_nr.dlc.st0.ie_type", "IE Type", nil, dlc_ie_types, 0xF0)
f.dlc_res1 = ProtoField.uint8("dect_nr.dlc.st0.res1", "Reserved", nil, nil, 0x0F)

-- DLC Service Type 1
f.dlc_si = ProtoField.uint8("dect_nr.dlc.st123.si", "Segmentation indication", nil, dlc_si_types, 0x0C)
f.dlc_sn = ProtoField.uint16("dect_nr.dlc.st123.sn", "Sequence number", nil, nil, 0x03FF)
f.dlc_segm_offset = ProtoField.uint16("dect_nr.dlc.st123.so", "Segmentation offset", nil, nil)

-- Higher layer signalling (as string)
f.hls_str = ProtoField.string("dect_nr.dlc.hls", "DLC data", nil, nil)

-- Error messages -----------------------------------------------------------------------------------------------------
local ef_too_short = ProtoExpert.new("dect_nr.too_short.expert", "DECT NR+ message too short",
	expert.group.MALFORMED, expert.severity.ERROR)
local ef_too_short_after_mux_hdr = ProtoExpert.new("dect_nr.too_short_after_mux_hdr.expert",
	"Not enough bytes after the MAC MUX header!", expert.group.MALFORMED, expert.severity.ERROR)
local ef_unknown_exp_length = ProtoExpert.new("dect_nr.unknown_exp_length.expert",
	"Generic failure (exp_length = -1)!", expert.group.MALFORMED, expert.severity.ERROR)
local ef_dlc_pdu_cut_short = ProtoExpert.new("dect_nr.dlc_pdu_cut_short",
    "DLC PDU incomplete, perhaps trace was cut off", expert.group.MALFORMED, expert.severity.WARN)

-- Register error messages
DECT_NR.experts = { ef_too_short, ef_too_short_after_mux_hdr, ef_unknown_exp_length, ef_dlc_pdu_cut_short }

-----------------------------------------------------------------------------------------------------------------------

function add_parameter_le(tree, field, range)
	-- TODO: Changed 17.11.2023 to add everything as big-endian.
	-- TODO: if this does not cause any issues, replace all references to
	-- TODO: 'add_parameter_le' with 'add_parameter_be'.
	-- tree:add_le(field, range)
	tree:add(field, range)
end

function add_parameter_be(tree, field, range)
	-- Big-endian parameter
	tree:add(field, range)
end

function append_info_col(pinfo, text)
	-- Add MAC message description to the Info column preserving the existing info
	local sep = ""
	if string.len(tostring(pinfo.cols.info)) > 0 then
		sep = ", "
	end
	pinfo.cols.info = tostring(pinfo.cols.info) .. sep .. tostring(text)
end

function dissect_physical_header_field(buffer, dect_tree)
	-- Physical Header Field Type is determined from 6th and 7th packet byte. For Type 1
	-- they are always zero.
	-- (Type 1: 40 bits (HF 000), or Type 2: 80 bits, (HF 000 or 001))
	local plcf = 1
	if buffer(offset + 5, 2):uint() == 0 then
		plcf = 0
	end

	-- In dect_nr, device always reserves 10 bytes for the PHF.
	-- If 5-byte version used, the remaining 5 bytes is just padding.
	local ph_tree = dect_tree:add(f.phf, buffer(offset, 10))
	ph_tree:set_text("Physical Header Field (" .. dect_plcf_sizes[plcf] .. ")")

	-- 1. Physical Header Field (Ch. 6.2)
	local header_format = buffer(offset, 1):bitfield(0, 3)
	add_parameter_le(ph_tree, f.header_format, buffer(offset, 1))
	add_parameter_le(ph_tree, f.type, buffer(offset, 1))
	-- TODO: add different interpretation if packet length is in slots
	add_parameter_le(ph_tree, f.packet_len_ss, buffer(offset, 1))
	offset = offset + 1
	local short_nw_id = buffer(offset, 1)
	add_parameter_be(ph_tree, f.short_nw_id, short_nw_id)
	offset = offset + 1
	local transmitter_id = buffer(offset, 2)
	add_parameter_be(ph_tree, f.transmitter_id, transmitter_id)
	offset = offset + 2
	add_parameter_le(ph_tree, f.tx_pwr, buffer(offset, 1))
	-- DF MCS length is 3 bits in Type 1 header, and 4 bits in Type 2 header
	if plcf == 1 then
		add_parameter_le(ph_tree, f.df_mcs_t2, buffer(offset, 1))
	else
		add_parameter_le(ph_tree, f.res0, buffer(offset, 1))
		add_parameter_le(ph_tree, f.df_mcs_t1, buffer(offset, 1))
	end
	offset = offset + 1

	-- if 80-bit (type 2) PHF is used
	if plcf == 1 then
		local receiver_id = buffer(offset, 2)
		add_parameter_be(ph_tree, f.receiver_id, receiver_id)
		offset = offset + 2
		add_parameter_le(ph_tree, f.spatial_streams, buffer(offset, 1))
		if header_format == 0 then
			add_parameter_le(ph_tree, f.df_red_version, buffer(offset, 1))
			add_parameter_le(ph_tree, f.df_ind, buffer(offset, 1))
			add_parameter_le(ph_tree, f.df_harq_proc, buffer(offset, 1))
		else
			add_parameter_le(ph_tree, f.res1_hdr_format_001, buffer(offset, 1))
		end
		offset = offset + 1
		local fb_format = buffer(offset, 2):bitfield(0, 4)
		add_parameter_le(ph_tree, f.fb_format, buffer(offset, 2))
		if fb_format == 1 then
			-- Format 1, Table 6.2.2-2a
			add_parameter_le(ph_tree, f.fbi1_harq_pn, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi1_tx_fb, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi1_bs, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi1_cqi, buffer(offset, 2))

		elseif fb_format == 2 then
			-- TODO

		elseif fb_format == 3 then
			-- TODO

		elseif fb_format == 4 then
			-- TODO

		elseif fb_format == 5 then
			-- TODO

		elseif fb_format == 6 then
			-- Format 6, Table 6.2.2-2f
			add_parameter_le(ph_tree, f.fbi6_harq_pn, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi6_res1, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi6_bs, buffer(offset, 2))
			add_parameter_le(ph_tree, f.fbi6_cqi, buffer(offset, 2))

		else
			-- Just undecoded value
			add_parameter_le(ph_tree, f.fb_info, buffer(offset, 2))
		end

		offset = offset + 2
	else
		add_parameter_le(ph_tree, f.phf_padding, buffer(offset, 5))
		offset = offset + 5
	end
end

--handle first the ping
function dissect_mac_header_type(buffer, mac_pdu_tree)
	local ping=buffer(offset,1):uint()
	if ping >= 0xe4 then
		local len=buffer:len()-offset
		mac_pdu_tree:add(f.ping_pdu, buffer(offset, len))
		mac_pdu_tree:add(f.ping_type, ping)
		offset = offset+1
		mac_pdu_tree:add(f.ping_rssi, buffer(offset,1))
		offset = offset+1
		mac_pdu_tree:add(f.ping_transmitter_id, buffer(offset, 2))
		offset = offset+2
		if ping < 0xe7 then
			mac_pdu_tree:add(f.ping_seq_num, buffer(offset, 2))
			offset = offset+2
			local lend=buffer(offset,2):uint()
			mac_pdu_tree:add(f.ping_len, lend)
			offset = offset+2
			mac_pdu_tree:add(f.ping_data, buffer(offset,lend))
			offset=offset+lend
		elseif ping == 0xe7 then
			local payload_asc= buffer(offset,buffer:len()-offset):string()
			mac_pdu_tree:add(f.ping_data, payload_asc)
			offset = buffer:len() 			
		end	
		return 
	end

	add_parameter_le(mac_pdu_tree, f.mac_hdr_vers, buffer(offset, 1))
	add_parameter_le(mac_pdu_tree, f.mac_sec, buffer(offset, 1))

	-- TODO: MAC security bits handling (how they affect the subsequent structure). Table 6.3.2-1.
	mac_sec_value = buffer(offset, 1):bitfield(2, 2)
	local hdr_type = buffer(offset, 1):bitfield(4, 4)
	add_parameter_le(mac_pdu_tree, f.mac_hdr_type, buffer(offset, 1))
	offset = offset + 1

	return hdr_type
end

function dissect_mac_hdr_type_and_common_header(buffer, pinfo, mac_pdu_tree)



	local mac_hdr_type = dissect_mac_header_type(buffer, mac_pdu_tree)

	if mac_hdr_type == 0 then
		-- 6.3.3.1 DATA MAC PDU header
		local data_hdr_len = 2
		local data_hdr_tree = mac_pdu_tree:add(f.data_hdr, buffer(offset, data_hdr_len)):
		set_text("MAC Common Header (Data MAC PDU Header)")
		-- Fixed length
		data_hdr_tree:set_len(data_hdr_len)

		local sn = buffer(offset, 2):bitfield(12, 4)
		add_parameter_be(data_hdr_tree, f.data_hdr_res1, buffer(offset, 2))
		add_parameter_be(data_hdr_tree, f.data_hdr_reset, buffer(offset, 2))
		add_parameter_be(data_hdr_tree, f.data_hdr_sn, buffer(offset, 2))
		offset = offset + 2

	elseif mac_hdr_type == 1 then
		-- 6.3.3.2 Beacon Header
		local bc_hdr_len = 7
		local bc_hdr_tree = mac_pdu_tree:add(f.bc_hdr, buffer(offset, bc_hdr_len)):
		set_text("MAC Common Header (Beacon Header)")
		-- Fixed length
		bc_hdr_tree:set_len(bc_hdr_len)

		add_parameter_be(bc_hdr_tree, f.bc_hdr_nw_id, buffer(offset, 3))
		offset = offset + 3
		local tx_addr = buffer(offset, 4)
		add_parameter_be(bc_hdr_tree, f.bc_hdr_tx_addr, tx_addr)

		-- Use Transmitter Address in the Source column
		pinfo.cols.src = "0x" .. tostring(tx_addr)
		offset = offset + 4

	elseif mac_hdr_type == 2 then
		-- 6.3.3.3 Unicast Header
		local uc_hdr_len = 10
		local uc_hdr_tree = mac_pdu_tree:add(f.uc_hdr, buffer(offset, uc_hdr_len)):
		set_text("MAC Common Header (Unicast Header)")
		-- Fixed length
		uc_hdr_tree:set_len(uc_hdr_len)

		add_parameter_le(uc_hdr_tree, f.uc_hdr_res, buffer(offset, 1))
		add_parameter_le(uc_hdr_tree, f.uc_hdr_rst, buffer(offset, 1))
		add_parameter_le(uc_hdr_tree, f.uc_hdr_mac_seq, buffer(offset, 1))
		offset = offset + 1
		add_parameter_le(uc_hdr_tree, f.uc_hdr_sn, buffer(offset, 1))
		offset = offset + 1

		local rx_addr = buffer(offset, 4)
		-- Use Receiver Address in the Destination column
		pinfo.cols.dst = "0x" .. tostring(rx_addr)
		add_parameter_be(uc_hdr_tree, f.uc_hdr_rx_addr, buffer(offset, 4))
		offset = offset + 4

		local tx_addr = buffer(offset, 4)
		-- Use Transmitter Address in the Source column
		pinfo.cols.src = "0x" .. tostring(tx_addr)
		add_parameter_be(uc_hdr_tree, f.uc_hdr_tx_addr, buffer(offset, 4))
		offset = offset + 4

	elseif mac_hdr_type == 3 then
		-- TODO: 6.3.3.4 RD Broadcasting Header

	end

end

function dissect_mac_mux_header(buffer, pinfo, mac_pdu_tree)
	-- Find out which message/IE follows and move pointer (offset) to the beginning of the SDU.
	-- NOTE: This means: past the length bytes, if length is known at this point.

	-- Returns:
	--     exp_length: Expected length of the payload in bytes. Returns -1 if unknown.
	--     ie_type:    IE type value as in Table 6.3.4-2.

	local mac_mux_hdr_tree = mac_pdu_tree:add(f.mac_mux_hdr, buffer(offset)):set_text("MAC Multiplexing header")
	local mux_hdr_start = buffer(offset):len()

	local exp_length = 0 -- Expected length of the payload (the number of length bytes subtracted from this!)
	local ie_type = 0
	local ie_type_name = ""

	add_parameter_le(mac_mux_hdr_tree, f.mux_mac_ext, buffer(offset, 1))
	-- Table 6.3.4-1: MAC extension field encoding
	local mac_ext = buffer(offset, 1):bitfield(0, 2)

	if mac_ext == 3 then
		-- One bit length field is included in the IE header. IE type is 5 bits (6.3.4-1 options a) and b))
		ie_type = buffer(offset, 1):bitfield(3, 5)

		add_parameter_le(mac_mux_hdr_tree, f.mux_len_bit, buffer(offset, 1))
		local ie_pl_size_bit = buffer(offset, 1):bitfield(2, 1)

		if ie_pl_size_bit == 0 then
			-- 6.3.4-1 option a)
			add_parameter_le(mac_mux_hdr_tree, f.mux_ie_type_short_pl0, buffer(offset, 1))
			-- The IE payload size is 0 bytes when the length bit (bit 2) is set to 0
			exp_length = 0
			ie_type_name = mux_hdr_ie_type_mac_ext_3_pl_0[ie_type]

			-- No payload, let's add IE Type to info column already
			append_info_col(pinfo, ie_type_name)

		else
			-- 6.3.4-1 option b)
			add_parameter_le(mac_mux_hdr_tree, f.mux_ie_type_short_pl1, buffer(offset, 1))
			-- Expect exactly one byte MAC SDU
			exp_length = 1
			ie_type_name = mux_hdr_ie_type_mac_ext_3_pl_1[ie_type]
		end

	else
		-- IE type is 6 bits (6.3.4-1 options c), d), e) and f))
		ie_type = buffer(offset, 1):bitfield(2, 6)
		ie_type_name = mux_hdr_ie_type_mac_ext_012[ie_type]

		add_parameter_le(mac_mux_hdr_tree, f.mux_ie_type_long, buffer(offset, 1))
		offset = offset + 1

		if mac_ext == 0 then
			-- 6.3.4-1 option c)
			-- No length field is included in the IE header. IE type defines the length of the IE payload
			-- Expect at least one byte (length unknown at this point)
			exp_length = -1

		elseif mac_ext == 1 then
			-- 6.3.4-1 option d)
			-- 8 bit length included indicating the length of the IE payload
			add_parameter_le(mac_mux_hdr_tree, f.mux_mac_ie_len_1, buffer(offset, 1))
			exp_length = buffer(offset, 1):uint()

		elseif mac_ext == 2 then
			-- 6.3.4-1 option e)
			-- 16 bit length included indicating the length of the IE payload
			add_parameter_le(mac_mux_hdr_tree, f.mux_mac_ie_len_2, buffer(offset, 2))
			exp_length = buffer(offset, 2):uint()

			-- Pointer to the last byte of the length
			offset = offset + 1
		end

	end

	-- Proceed to MAC Message start byte
	offset = offset + 1

	local mux_hdr_len = mux_hdr_start - buffer(offset):len()
	mac_mux_hdr_tree:set_len(mux_hdr_len)
	mac_mux_hdr_tree:set_text("MAC Multiplexing Header (" .. tostring(ie_type_name) .. ")")

	return ie_type, exp_length, mac_ext
end

function diss_dlc_service_type(buffer, pinfo, mac_pdu_tree, exp_len)
	local dlc_tree = mac_pdu_tree:add(f.dlc_st_0, buffer(offset)):set_text("DLC PDU")
	
	local rem_len = buffer:captured_len() - offset
	
	if rem_len < exp_len then
		-- DLC PDU not completely stored. Try best effort dissecting
		dlc_tree:set_len(rem_len)
		
		if rem_len == 0 then
			append_info_col(pinfo, "DLC PDU missing")
			return
		end
	else
		dlc_tree:set_len(exp_len)
	end
	
	-- Initialize Segmentation Indication and Sequence Number
	local si = 0
	local sn = 0
	local segm_offset = 0

	local ie_type = buffer(offset, 1):bitfield(0, 4)
	add_parameter_le(dlc_tree, f.dlc_ie_type, buffer(offset, 1))

	local pdu_header_incomplete = false
	
	if ie_type == 0 then
		-- TODO: Data: DLC Service type 0 with routing header

	elseif ie_type == 1 then
		-- Data: DLC Service type 0 without a routing header
		add_parameter_le(dlc_tree, f.dlc_res1, buffer(offset, 1))
		offset = offset + 1
		exp_len = exp_len - 1
		rem_len = rem_len - 1
		
	elseif ie_type == 2 then
		-- TODO: Data: DLC Service type 1 or 2 or 3 with routing header

	elseif ie_type == 3 then
		-- Data: DLC Service type 1 or 2 or 3 without routing header
		si = buffer(offset, 1):bitfield(4, 2)
		add_parameter_le(dlc_tree, f.dlc_si, buffer(offset, 1))
		
		if rem_len >= 2 then
			sn = buffer(offset, 2):bitfield(6, 10)
			add_parameter_le(dlc_tree, f.dlc_sn, buffer(offset, 2))
			offset = offset + 2
			exp_len = exp_len - 2
			rem_len = rem_len - 2
			
			-- Segmentation offset field is present if this is a data segment, and not the first or last one:
			-- 2 = the last segment of the higher layer SDU
			-- 3 = neither the first nor the last segment of the higher layer SDU
			if si == 2 or si == 3 then
				if rem_len >= 2 then
					segm_offset = buffer(offset, 2)
					add_parameter_le(dlc_tree, f.dlc_segm_offset, buffer(offset, 2))
					offset = offset + 2
					exp_len = exp_len - 2
					rem_len = rem_len - 2
				else
					pdu_header_incomplete = true
				end
			end
		else
			pdu_header_incomplete = true
		end

	elseif ie_type == 4 then
		-- TODO: DLC Timers configuration control IE

	end

	-- DLC SDU
	-- TODO: move out of this function?
	local data_info = ""
	if pdu_header_incomplete == true then
		data_info = "DLC PDU header incomplete, tracing cut off?"
	else
		local segm_info = "[ "
		if si == 0 then
			if ie_type == 3 then
				segm_info = "[ SN " .. sn .. ", "
			end
		elseif si == 1 then
			segm_info = "[ SN " .. sn .. " (first segment), "
		elseif si == 2 then
			segm_info = "[ SN " .. sn .. " (last segment at " .. tonumber(tostring(segm_offset), 16) .. "), "
		elseif si == 3 then
			segm_info = "[ SN " .. sn .. " (segment at " .. tonumber(tostring(segm_offset), 16) .. "), "
		end

		data_info = segm_info .. exp_len .. " bytes ]" --.. buffer(offset, exp_len):string() .. "\""
	end
	
	if rem_len < exp_len then
		add_parameter_le(dlc_tree, f.hls_str, buffer(offset, rem_len))
		offset = offset + rem_len
		data_info = data_info .. " Data incomplete, trace cut off?"
		dlc_tree:add_proto_expert_info(ef_dlc_pdu_cut_short)
	else
		add_parameter_le(dlc_tree, f.hls_str, buffer(offset, exp_len))
		offset = offset + exp_len
	end
	
	append_info_col(pinfo, data_info)
end

function diss_padding_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	-- 6.4.3.8 Padding IE
	add_parameter_le(mac_pdu_tree, f.pd_bytes, buffer(offset, exp_len))
	offset = offset + exp_len
end

function diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len, flow_name)
	append_info_col(pinfo, flow_name)
	-- TS 103 636-5 Ch. 5.3 DLC Protocol Data Units
	-- TODO: temporary. Handle the whole DLC protocol in a separate file maybe?
	diss_dlc_service_type(buffer, pinfo, mac_pdu_tree, exp_len)
end

function diss_higher_layer_sig_flow_1(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"Higher layer signalling (flow 1)")
end

function diss_higher_layer_sig_flow_2(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"Higher layer signalling (flow 2)")
end

function diss_user_plane_data_flow_1(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"User plane data - flow 1")
end

function diss_user_plane_data_flow_2(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"User plane data - flow 2")
end

function diss_user_plane_data_flow_3(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"User plane data - flow 3")
end

function diss_user_plane_data_flow_4(buffer, pinfo, mac_pdu_tree, exp_len)
	diss_dlc_flow(buffer, pinfo, mac_pdu_tree, exp_len,
		"User plane data - flow 4")
end

-- 6.4.2.2 Network Beacon message
function diss_network_beacon(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_nb_tree = mac_pdu_tree:add(f.nb_msg, buffer(offset)):set_text("Network Beacon Message")
	mac_nb_tree:set_len(exp_len)

	add_parameter_le(mac_nb_tree, f.nb_res1, buffer(offset, 1))
	local tx_pwr_flag = buffer(offset, 1):bitfield(3, 1)
	add_parameter_le(mac_nb_tree, f.nb_tx_pwr, buffer(offset, 1))
	add_parameter_le(mac_nb_tree, f.nb_pwr_const, buffer(offset, 1))
	local curr_bc_chan_flag = buffer(offset, 1):bitfield(5, 1)
	add_parameter_le(mac_nb_tree, f.nb_current, buffer(offset, 1))
	local addn_bc_chan_flag = buffer(offset, 1):bitfield(6, 2)
	add_parameter_le(mac_nb_tree, f.nb_channels, buffer(offset, 1))

	offset = offset + 1
	local nb_period = nb_ie_nb_periods[buffer(offset, 1):bitfield(0, 4)]
	local cb_period = nb_ie_cb_periods[buffer(offset, 1):bitfield(4, 4)]
	add_parameter_le(mac_nb_tree, f.nb_nb_period, buffer(offset, 1))
	add_parameter_le(mac_nb_tree, f.nb_cb_period, buffer(offset, 1))
	offset = offset + 1
	add_parameter_le(mac_nb_tree, f.nb_res2, buffer(offset, 1))
	local cluster_chan = buffer(offset, 2):bitfield(3, 13)
	-- NOTE: ignores 3 leading 'reserved' bits of the first byte and use full 2 bytess
	add_parameter_be(mac_nb_tree, f.nb_next_cl_chan, buffer(offset, 2))
	offset = offset + 2
	local ttn = tonumber(tostring(buffer(offset, 4)), 16)
	add_parameter_be(mac_nb_tree, f.nb_ttn, buffer(offset, 4))
	offset = offset + 4

	if tx_pwr_flag == 1 then
		-- Clusters Max TX power field is included
		add_parameter_le(mac_nb_tree, f.nb_res3, buffer(offset, 1))
		add_parameter_le(mac_nb_tree, f.nb_cl_max_tx_pwr, buffer(offset, 1))

		offset = offset + 1
	end

	if curr_bc_chan_flag == 1 then
		-- Current Cluster Channel field is included
		add_parameter_le(mac_nb_tree, f.nb_res4, buffer(offset, 1))
		add_parameter_be(mac_nb_tree, f.nb_curr_cl_chan, buffer(offset, 2))
		offset = offset + 2
	end

	if addn_bc_chan_flag ~= 0 then
		-- Additional Network Beacon Channel(s) included
		while addn_bc_chan_flag > 0 do
			add_parameter_le(mac_nb_tree, f.nb_res5, buffer(offset, 1))
			add_parameter_be(mac_nb_tree, f.nb_addn_nb_channels, buffer(offset, 2))
			offset = offset + 2
			addn_bc_chan_flag = addn_bc_chan_flag - 1
		end

	end

	local info_text = "Network Beacon (" .. nb_period .. ", Cluster: " .. cluster_chan
		.. " (" .. cb_period .. "), TTN: " .. ttn .. " μs)"
	append_info_col(pinfo, info_text)
end

-- 6.4.2.3 Cluster Beacon Message
function diss_cluster_beacon(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_cb_tree = mac_pdu_tree:add(f.cb_msg, buffer(offset)):set_text("Cluster Beacon Message")
	mac_cb_tree:set_len(exp_len)

	add_parameter_le(mac_cb_tree, f.cb_sfn, buffer(offset, 1))

	offset = offset + 1
	add_parameter_le(mac_cb_tree, f.cb_res1, buffer(offset, 1))
	local tx_pwr_flag = buffer(offset, 1):bitfield(3, 1)
	local fo_flag = buffer(offset, 1):bitfield(5, 1)
	local next_channel_flag = buffer(offset, 1):bitfield(6, 1)
	local ttn_flag = buffer(offset, 1):bitfield(7, 1)
	add_parameter_le(mac_cb_tree, f.cb_tx_pwr, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_pwr_const, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_fo, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_next_chan, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_ttn, buffer(offset, 1))

	offset = offset + 1
	local nb_period = nb_ie_nb_periods[buffer(offset, 1):bitfield(0, 4)]
	local cb_period = nb_ie_cb_periods[buffer(offset, 1):bitfield(4, 4)]
	add_parameter_le(mac_cb_tree, f.cb_nb_period, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_cb_period, buffer(offset, 1))

	offset = offset + 1
	add_parameter_le(mac_cb_tree, f.cb_ctt, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_rel_qual, buffer(offset, 1))
	add_parameter_le(mac_cb_tree, f.cb_min_qual, buffer(offset, 1))

	if tx_pwr_flag == 1 then
		offset = offset + 1
		add_parameter_le(mac_cb_tree, f.cb_res2, buffer(offset, 1))
		add_parameter_le(mac_cb_tree, f.cb_cl_max_tx_pwr, buffer(offset, 1))
	end

	if fo_flag == 1 then
		offset = offset + 1
		add_parameter_le(mac_cb_tree, f.cb_frame_offset, buffer(offset, 1))
	end

	local next_chan_txt = ""
	if next_channel_flag == 1 then
		offset = offset + 1
		add_parameter_be(mac_cb_tree, f.cb_res3, buffer(offset, 1))
		local next_chan = buffer(offset, 2):bitfield(3, 13)
		next_chan_txt = ", Next channel: " .. tostring(next_chan)
		add_parameter_be(mac_cb_tree, f.cb_next_cl_chan, buffer(offset, 2))
		-- point to the latter byte
		offset = offset + 1
	end

	if ttn_flag == 1 then
		offset = offset + 1
		add_parameter_be(mac_cb_tree, f.cb_time_to_next, buffer(offset, 4))
		offset = offset + 3
	end

	offset = offset + 1

	local info_text = "Cluster Beacon (" .. cb_period .. next_chan_txt .. ")"
	append_info_col(pinfo, info_text)
end

-- 6.4.2.4 Association Request Message
function diss_association_request(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_areq_tree = mac_pdu_tree:add(f.a_req_msg, buffer(offset)):set_text("Association Request")
	mac_areq_tree:set_len(exp_len)

	local setup_cause_str = ar_setup_causes[buffer(offset, 1):bitfield(0, 3)]
	local num_flows = buffer(offset, 1):bitfield(3, 3)
	local ft_mode_flag = buffer(offset, 1):bitfield(7, 1)

	add_parameter_le(mac_areq_tree, f.a_req_setup_cause, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_nflows, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_pwr_const, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_ft_mode, buffer(offset, 1))
	offset = offset + 1

	add_parameter_le(mac_areq_tree, f.a_req_current, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_res1, buffer(offset, 1))
	offset = offset + 1

	add_parameter_le(mac_areq_tree, f.a_req_harq_proc_tx, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_max_harq_retx, buffer(offset, 1))
	offset = offset + 1

	add_parameter_le(mac_areq_tree, f.a_req_harq_proc_rx, buffer(offset, 1))
	add_parameter_le(mac_areq_tree, f.a_req_max_harq_rerx, buffer(offset, 1))
	offset = offset + 1

	-- Table 6.4.2.4-1: "There shall be as many flow IDs included as indicated in the 'Number of Flows' field"
	local flow = 0
	while flow < num_flows do
		flow = flow + 1
		add_parameter_le(mac_areq_tree, f.a_req_res2, buffer(offset, 1))
		add_parameter_le(mac_areq_tree, f.a_req_flow_id, buffer(offset, 1))
		offset = offset + 1
	end

	if ft_mode_flag == 1 then
		-- Table 6.4.2.4-1: "The RD operates also in FT mode. RD shall include Network Beacon period,
		-- Cluster beacon Period, Next Cluster channel and Time to Next fields"
		add_parameter_le(mac_areq_tree, f.a_req_nb_period, buffer(offset, 1))
		add_parameter_le(mac_areq_tree, f.a_req_nb_period, buffer(offset, 1))
		offset = offset + 1

		add_parameter_be(mac_areq_tree, f.a_req_next_cl_chan, buffer(offset, 2))
		offset = offset + 2

		add_parameter_be(mac_areq_tree, f.a_req_ttn, buffer(offset, 4))
		offset = offset + 4

		add_parameter_be(mac_areq_tree, f.a_req_curr_cl_chan, buffer(offset, 2))
		offset = offset + 2
	end

	local info_text = "Association Request (" .. setup_cause_str .. ")"
	append_info_col(pinfo, info_text)
end


-- 6.4.2.5 Association Response Message
function diss_association_response(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_arsp_tree = mac_pdu_tree:add(f.a_rsp_msg, buffer(offset)):set_text("Association Response")
	mac_arsp_tree:set_len(exp_len)

	local ack_flag = buffer(offset, 1):bitfield(0, 1)
	local res_txt = ""

	if ack_flag == 1 then
		-- Association accepted

		local harq_mod_flag = buffer(offset, 1):bitfield(2, 1)
		local num_flows = buffer(offset, 1):bitfield(3, 3)
		local group_tag = buffer(offset, 1):bitfield(6, 1)
		add_parameter_le(mac_arsp_tree, f.a_rsp_ack, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_res1, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_harq_mod, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_nflows, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_group, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_tx_pwr, buffer(offset, 1))
		offset = offset + 1

		if harq_mod_flag == 1 then
			-- HARQ configuration was not accepted as requested -> HARQ configuration is present
			add_parameter_le(mac_arsp_tree, f.a_rsp_harq_proc_rx, buffer(offset, 1))
			add_parameter_le(mac_arsp_tree, f.a_rsp_max_harq_rerx, buffer(offset, 1))
			offset = offset + 1

			add_parameter_le(mac_arsp_tree, f.a_rsp_harq_proc_tx, buffer(offset, 1))
			add_parameter_le(mac_arsp_tree, f.a_rsp_max_harq_retx, buffer(offset, 1))
			offset = offset + 1
		end

		local flow = 0
		-- Value '111' (7) indicates 'All flows accepted as configured in Association Request'
		if 0 < num_flows and num_flows < 7 then
			while flow < num_flows do
				flow = flow + 1
				-- There shall be as many flow IDs included
				-- as indicated in the field <num_flows> to indicate accepted flow IDs
				add_parameter_le(mac_arsp_tree, f.a_rsp_res2, buffer(offset, 1))
				add_parameter_le(mac_arsp_tree, f.a_rsp_flow_id, buffer(offset, 1))
				offset = offset + 1
			end
		end

		if group_tag == 1 then
			-- Group ID and Resource Tag are included
			add_parameter_le(mac_arsp_tree, f.a_rsp_res3, buffer(offset, 1))
			add_parameter_le(mac_arsp_tree, f.a_rsp_group_id, buffer(offset, 1))
			offset = offset + 1

			add_parameter_le(mac_arsp_tree, f.a_rsp_res4, buffer(offset, 1))
			add_parameter_le(mac_arsp_tree, f.a_rsp_res_tag, buffer(offset, 1))
			offset = offset + 1
		end

		res_txt = "Accepted"

	else
		-- Association Rejected

		-- Bits 1-7 of the first octet are ignored by the receiver
		offset = offset + 1

		local rej_cause = buffer(offset, 1):bitfield(0, 4)
		add_parameter_le(mac_arsp_tree, f.a_rsp_rej_cause, buffer(offset, 1))
		add_parameter_le(mac_arsp_tree, f.a_rsp_rej_time, buffer(offset, 1))
		offset = offset + 1

		res_txt = "Rejected (cause " .. rej_cause .. ")"

	end

	local info_text = "Association Response (" .. res_txt .. ")"
	append_info_col(pinfo, info_text)
end

-- 6.4.2.6 Association Release Message
function diss_association_release(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_arel_tree = mac_pdu_tree:add(f.a_rel_msg, buffer(offset)):set_text("Association Release")
	mac_arel_tree:set_len(exp_len)

	local rel_cause = buffer(offset, 1):bitfield(0, 4)
	add_parameter_le(mac_arel_tree, f.a_rel_cause, buffer(offset, 1))
	add_parameter_le(mac_arel_tree, f.a_rel_res1, buffer(offset, 1))
	offset = offset + 1

	local info_text = "Association Release (" .. assoc_rel_cause[rel_cause] .. ")"
	append_info_col(pinfo, info_text)
end

-- 6.4.3.1: MAC Security Info IE
function diss_security_info_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_msi_tree = mac_pdu_tree:add(f.msi_ie, buffer(offset)):set_text("MAC Security Info IE")
	mac_msi_tree:set_len(exp_len)
	
	add_parameter_le(mac_msi_tree, f.msi_ver, buffer(offset, 1))
	add_parameter_le(mac_msi_tree, f.msi_key, buffer(offset, 1))
	add_parameter_le(mac_msi_tree, f.msi_ivt, buffer(offset, 1))
	
	offset = offset + 1
	local hpc = buffer(offset, 4)
	add_parameter_be(mac_msi_tree, f.msi_hpc, hpc)

	offset = offset + 4

	local info_text = "MAC Security Info IE"
	append_info_col(pinfo, info_text)	
end

-- 6.4.3.4: Random Access Resource IE
function diss_random_access_resource_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_rar_tree = mac_pdu_tree:add(f.rar_ie, buffer(offset)):set_text("Random Access Resource IE")
	mac_rar_tree:set_len(exp_len)

	local rar_repeat_flag = buffer(offset, 1):bitfield(3, 2)
	local rar_sfn_offset_flag = buffer(offset, 1):bitfield(5, 1)
	local rar_chan_flag = buffer(offset, 1):bitfield(6, 1)
	local rar_chan_2_flag = buffer(offset, 1):bitfield(7, 1)
	add_parameter_le(mac_rar_tree, f.rar_res1, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_repeat, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_sfn_f, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_channel_f, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_chan_2_f, buffer(offset, 1))

	offset = offset + 1
	add_parameter_le(mac_rar_tree, f.rar_start_ss, buffer(offset, 1))
	offset = offset + 1
	add_parameter_le(mac_rar_tree, f.rar_len_type, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_len, buffer(offset, 1))
	offset = offset + 1
	add_parameter_le(mac_rar_tree, f.rar_max_len_type, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_max_rach_len, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_cw_min_sig, buffer(offset, 1))
	offset = offset + 1
	add_parameter_le(mac_rar_tree, f.rar_dect_delay, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_resp_win, buffer(offset, 1))
	add_parameter_le(mac_rar_tree, f.rar_cw_max_sig, buffer(offset, 1))

	if rar_repeat_flag ~= 0 then
		offset = offset + 1
		add_parameter_le(mac_rar_tree, f.rar_repetition, buffer(offset, 1))
		offset = offset + 1
		add_parameter_le(mac_rar_tree, f.rar_validity, buffer(offset, 1))
	end

	if rar_sfn_offset_flag == 1 then
		offset = offset + 1
		add_parameter_le(mac_rar_tree, f.rar_sfn_offset, buffer(offset, 1))
	end

	if rar_chan_flag == 1 then
		offset = offset + 1
		add_parameter_be(mac_rar_tree, f.rar_channel, buffer(offset, 2))
		offset = offset + 1
	end

	if rar_chan_2_flag == 1 then
		offset = offset + 1
		add_parameter_be(mac_rar_tree, f.rar_channel_2, buffer(offset, 2))
		offset = offset + 1
	end
	offset = offset + 1

	local info_text = "Random Access Resource IE"
	append_info_col(pinfo, info_text)
end

-- 6.4.3.5: RD Capability IE
function diss_rd_capability_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_rd_tree = mac_pdu_tree:add(f.rdc_ie, buffer(offset)):set_text("RD Capability IE")
	mac_rd_tree:set_len(exp_len)

	local num_phy_capas = buffer(offset, 1):bitfield(0, 3)
	local phy_capa_count = 0

	-- Loop through all included physical layer capabilities
	while phy_capa_count <= num_phy_capas do
		if phy_capa_count == 0 then
			-- The first PHY layer capability is always present without RD class μ and β
			add_parameter_le(mac_rd_tree, f.rdc_num_phy_cap, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_release, buffer(offset, 1))
			offset = offset + 1
			add_parameter_le(mac_rd_tree, f.rdc_res1, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_op_modes, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_mesh, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_sched, buffer(offset, 1))
			offset = offset + 1
			add_parameter_le(mac_rd_tree, f.rdc_mac_security, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_dlc_type, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_res2, buffer(offset, 1))
			offset = offset + 1
		else
			-- Subsequent PHY layer capabilities begin with RD class μ and β
			add_parameter_le(mac_rd_tree, f.rdc_rd_class_u, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_rd_class_b, buffer(offset, 1))
			add_parameter_le(mac_rd_tree, f.rdc_res6, buffer(offset, 1))
			offset = offset + 1
		end
		add_parameter_le(mac_rd_tree, f.rdc_res3, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_pwr_class, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_max_nss_rx, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_rx_for_tx_div, buffer(offset, 1))
		offset = offset + 1
		add_parameter_le(mac_rd_tree, f.rdc_rx_gain, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_max_mcs, buffer(offset, 1))
		offset = offset + 1
		add_parameter_le(mac_rd_tree, f.rdc_soft_buf_size, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_num_harq_proc, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_res4, buffer(offset, 1))
		offset = offset + 1
		add_parameter_le(mac_rd_tree, f.rdc_harq_fb_delay, buffer(offset, 1))
		add_parameter_le(mac_rd_tree, f.rdc_res5, buffer(offset, 1))
		offset = offset + 1

		phy_capa_count = phy_capa_count + 1
	end

	local info_text = "RD Capability IE (" .. tostring(phy_capa_count + 1) .. " capas)"
	append_info_col(pinfo, info_text)
end

-- 6.4.3.7: Broadcast Indication IE
function diss_broadcast_indication_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_bi_tree = mac_pdu_tree:add(f.bi_ie, buffer(offset)):set_text("Broadcast Indication IE")
	mac_bi_tree:set_len(exp_len)

	local ind_type = buffer(offset, 1):bitfield(0, 3)
	local ind_type_str = bi_ind_types[ind_type]
	add_parameter_le(mac_bi_tree, f.bi_ind_type, buffer(offset, 1))
	local idtype = buffer(offset, 1):bitfield(3, 1)
	add_parameter_le(mac_bi_tree, f.bi_idtype, buffer(offset, 1))

	local feedback = 0
	if ind_type == 1 then
		-- Table 6.4.3.7-1: 'ACK/NACK' and 'Feedback' fields are present when the
		-- indication Type is 'Random access response' (1)
		add_parameter_le(mac_bi_tree, f.bi_ack, buffer(offset, 1))
		feedback = buffer(offset, 1):bitfield(5, 2)
		add_parameter_le(mac_bi_tree, f.bi_fb, buffer(offset, 1))
	else
		add_parameter_le(mac_bi_tree, f.bi_res1, buffer(offset, 1))
	end
	add_parameter_le(mac_bi_tree, f.bi_res_alloc, buffer(offset, 1))
	offset = offset + 1

	-- Short or Long RD ID follows as defined by the IDType field
	local bi_target = ""
	if idtype == 0 then
		bi_target = "0x" .. tostring(buffer(offset, 2))
		add_parameter_le(mac_bi_tree, f.bi_short_rd_id, buffer(offset, 2))
		offset = offset + 2
	else
		bi_target = "0x" .. tostring(buffer(offset, 4))
		add_parameter_le(mac_bi_tree, f.bi_long_rd_id, buffer(offset, 4))
		offset = offset + 4
	end

	if feedback > 0 then
		add_parameter_le(mac_bi_tree, f.bi_mcs_mimo_fb, buffer(offset, 1))
		offset = offset + 1
	end

	local info_text = "Broadcast Indication IE (" .. ind_type_str .. " to " .. bi_target .. ")"
	append_info_col(pinfo, info_text)
end

-- 6.4.3.13	Radio Device Status IE
function diss_radio_device_status_ie(buffer, pinfo, mac_pdu_tree, exp_len)
	local mac_rds_tree = mac_pdu_tree:add(f.rds_ie, buffer(offset)):set_text("Radio Device Status IE")
	mac_rds_tree:set_len(exp_len)

	local status_flag = buffer(offset, 1):bitfield(2, 2)
	local status_flag_str = rds_status_flags[status_flag]
	add_parameter_le(mac_rds_tree, f.rds_res1, buffer(offset, 1))
	add_parameter_le(mac_rds_tree, f.rds_sf, buffer(offset, 1))
	add_parameter_le(mac_rds_tree, f.rds_dur, buffer(offset, 1))
	offset = offset + 1

	local info_text = "Radio Device Status IE (" .. status_flag_str .. ")"
	append_info_col(pinfo, info_text)
end

local mac_msg_dissectors = {
	[0] = diss_padding_ie,
	[1] = diss_higher_layer_sig_flow_1,
	[2] = diss_higher_layer_sig_flow_2,
	[3] = diss_user_plane_data_flow_1,
	[4] = diss_user_plane_data_flow_2,
	[5] = diss_user_plane_data_flow_3,
	[6] = diss_user_plane_data_flow_4,
	[7] = diss_reserved,
	[8] = diss_network_beacon,
	[9] = diss_cluster_beacon,
	[10] = diss_association_request,
	[11] = diss_association_response,
	[12] = diss_association_release,
	[13] = diss_reconfiguration_request,
	[14] = diss_reconfiguration_response,
	[15] = diss_additional_mac_messages,
	[16] = diss_security_info_ie,
	[17] = diss_route_info_ie,
	[18] = diss_resource_allocation_ie,
	[19] = diss_random_access_resource_ie,
	[20] = diss_rd_capability_ie,
	[21] = diss_neighbouring_ie,
	[22] = diss_broadcast_indication_ie,
	[23] = diss_group_assignment_ie,
	[24] = diss_load_info_ie,
	[25] = diss_measurement_report_ie,

	[62] = diss_escape,
	[63] = diss_ie_type_extension
}

local mac_msg_dissectors_one_byte_pl = {
	[0] = diss_padding_ie,
	[1] = diss_radio_device_status_ie,
	[30] = diss_escape
}

function DECT_NR.dissector(buffer, pinfo, tree)
	-- DISSECTOR FOR DECT NR+ MAC PROTOCOL, Ref. ETSI TS 103 636-4 (V1.4.1, 2023-01)
	pinfo.cols.protocol = "DECT NR+"
	local dect_tree = tree:add(DECT_NR, buffer)
	local buffer_tot_len = buffer:len()

	-- TODO: define min length. This is just the subtype and Physical Header Field
	if buffer_tot_len < 11 then
		dect_tree:add_proto_expert_info(ef_too_short)
		return
	end

	-- TODO: Direction byte (subtype) shall be handled before calling this dissector
	-- and pass only pure DECT PHY header and MAC PDU her
	offset = 0

	-- MAC physical layer packet consists of two parts:
	-- Physical Header Field (Ch. 6.2) and MAC PDU (Ch. 6.3)

	-- 6.2 Physical Header Field
	dissect_physical_header_field(buffer, dect_tree)

	-- 6.3 MAC PDU
	--   6.3.2 MAC Header Type
	--   6.3.3 MAC Common Header
	--   --- one or more MAC SDUs ---
	--   6.3.4 MAC Multiplexing Header
	--   6.4 MAC Messages and IEs
	--   ----------------------------
	--   5.9.1 Message Integrity Code (MIC)

	local mac_pdu_tree = dect_tree:add(f.mac_pdu, buffer(offset)):set_text("MAC PDU")

	--   6.3.2 MAC Header Type
	-- 6.3.3 MAC Common header
	dissect_mac_hdr_type_and_common_header(buffer, pinfo, mac_pdu_tree)
	
	local buffer_len = buffer_tot_len
	
	if mac_sec_value ~= 0 then
		buffer_len = buffer_tot_len - 5
	end

	-- One or more MAC SDUs included in MAC PDU with MAC multiplexing header
	while offset < buffer_len do

		-- Ignore "all zero" padding in the buffer
		if buffer(offset, 1):uint() == 0 then
			return
		end

		-- 6.3.4 MAC multiplexing header
		local ie_type, exp_length, mac_ext = dissect_mac_mux_header(buffer, pinfo, mac_pdu_tree)
		local buffer_rem = buffer(offset):len()

		-- exp_length 0 means Short SDU with no payload (no more processing needed)
		if exp_length ~= 0 then
			-- Validate enough bytes remaining. Padding and DLC flows are
			-- tried to dissect event if there is not enough bytes.
			if ie_type > 6 and buffer_rem < exp_length then
				dect_tree:add_proto_expert_info(ef_too_short_after_mux_hdr)
				return
			end

			if mac_ext < 3 then
				-- Table 6.3.4-2: IE type field encoding for MAC Extension field encoding 00, 01, 10
				if mac_msg_dissectors[ie_type] then
					mac_msg_dissectors[ie_type](buffer, pinfo, mac_pdu_tree, exp_length)
				end
			else
				-- Table 6.3.4-4: IE type field encoding for MAC extension field encoding 11 and payload length of 1 byte
				if mac_msg_dissectors_one_byte_pl[ie_type] then
					mac_msg_dissectors_one_byte_pl[ie_type](buffer, pinfo, mac_pdu_tree, exp_length)
				end
			end

			-- 5.9.1: Message Integrity Code (MIC)
			-- TODO: when ciphering & integrity protection used

		end
	end
	
	if mac_sec_value ~= 0 then
		local remainder=buffer:len()
		add_parameter_le(mac_pdu_tree, f.mic_bytes, buffer(offset, remainder))
	end
end

-- register
local udp_port = DissectorTable.get("udp.port")
udp_port:add(31414, DECT_NR)



