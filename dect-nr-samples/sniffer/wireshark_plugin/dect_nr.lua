-------------------------------------------------------
-- This is a Wireshark dissector for the DECT(TM) Packet format
-------------------------------------------------------

-- Copyright 2024
-- Jaakko Niemistö <jaakko.niemisto@aalto.fi>,
-- Harikumar Narayana Iyer <harikumar.narayanaiyer@aalto.fi>,
-- Simo Hakanummi <simo.hakanummi@aalto.fi>
-- Kalle Ruttik <kalle.ruttik@aalto.fi>

-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\dect.lua")

dect_nr_proto = Proto("dect_nr","DECT NR Protocol")

DECT_UDP_PORT = 31415

-- Fields
local f_type_format1 = ProtoField.uint8("dect_phy.format", "Format 1", base.HEX, nil, 0xe0)
local f_type_format20 = ProtoField.uint8("dect_phy.format", "Format 2, type 000", base.HEX, nil, 0xe0)
local f_type_format21 = ProtoField.uint8("dect_phy.format", "Format 2, type 001", base.HEX, nil, 0xe0)

local f_type_length_type = ProtoField.uint8("dect_phy.length_type", "Packet Length Type", base.HEX, {
    [0] = "Subslots",
    [1] = "Slots"
}, 0x10)
local f_type_length = ProtoField.uint8("dect_phy.length", "Packet Length", base.HEX, nil, 0x0f)

-- Common fields
local f_short_network_id = ProtoField.uint8("dect_phy.short_network_id", "Short Network ID", base.HEX)
local f_tx_id_hi = ProtoField.uint8("dect_phy.transmitter_identity_hi", "Transmitter ID High", base.HEX)
local f_tx_id_lo = ProtoField.uint8("dect_phy.transmitter_identity_lo", "Transmitter ID Low", base.HEX)
local f_tx_power = ProtoField.uint8("dect_phy.transmit_power", "Transmit Power", base.HEX, nil, 0xf0)
local f_reserved = ProtoField.uint8("dect_phy.reserved", "Reserved", base.HEX, nil, 0x10)
local f_mcs = ProtoField.uint8("dect_phy.mcs", "DF MCS", base.HEX, nil, 0x07)
-- Type 2 specific
local f_rx_id_hi = ProtoField.uint8("dect_phy.receiver_identity_hi", "Receiver ID High", base.HEX)
local f_rx_id_lo = ProtoField.uint8("dect_phy.receiver_identity_lo", "Receiver ID Low", base.HEX)
local f_spatial_streams = ProtoField.uint8("dect_phy.spatial_streams", "Spatial Streams", base.HEX, nil, 0xc0)
local f_redundancy_version = ProtoField.uint8("dect_phy.redundancy_version", "Redundancy Version", base.HEX, nil, 0x30 )
local f_new_data_ind = ProtoField.uint8("dect_phy.new_data_toggle", "New Data Indication Toggle", base.HEX, nil, 0x08)
local f_harq_process = ProtoField.uint8("dect_phy.harq_process_number", "HARQ Process Number", base.HEX, nil, 0x07)
local f_feedback_format = ProtoField.uint8("dect_phy.feedback_format", "Feedback Format", base.HEX, nil, 0xf0)
local f_feedback = ProtoField.uint16("dect_phy.feedback", "Feedback", base.HEX, nil, 0x0fff)


-- Common header
local f_mac_security = ProtoField.uint8("dect_nr.mac_security", "MAC Security", base.HEX, mac_security, 0x30)
local f_mac_header_type = ProtoField.uint8("dect_nr.mac_header_type", "MAC Header Type", base.HEX, mac_header_type, 0xf)
local f_mac_ext = ProtoField.uint8("dect_nr.mac_ext", "MAC Ext", base.HEX, mac_ext, 0xc0)

-- Misc. header fields
local f_seq_reset = ProtoField.bool("dect_nr.reset", "Reset", 16, nil, 0x1000)
local f_sequence = ProtoField.uint16("dect_nr.sequence_number", "Sequence Number", base.DEC, nil, 0xFFF)
local f_network_address = ProtoField.bytes("dect_nr.network_address", "Network address", base.COLON)
local f_tx_long_rdid = ProtoField.bytes("dect_nr.tx_long_rdid", "Transmitter RDID", base.COLON)
local f_rx_long_rdid = ProtoField.bytes("dect_nr.rx_long_rdid", "Received RDID", base.COLON)

-- Mux header fields
local f_mux_ext_field = ProtoField.uint8("dect_nr.sdu.ext_field", "Ext. field", base.HEX, nil, 0xC0)
local f_mux_ie_type = ProtoField.uint8("dect_nr.sdu.ie_type", "IE Type", base.HEX, ie_type_name, 0x3F)
local f_mux_sdu_length = ProtoField.uint16("dect_nr.sdu.length", "Length", base.DEC)
local f_mux_ie_type_ext3 = ProtoField.uint8("dect_nr.sdu.ie_type", "IE Type", base.HEX, ie_type_name_ext3, 0x1F)
local f_mux_sdu_length_ext3 = ProtoField.uint8("dect_nr.sdu.length", "Length", base.DEC, nil, 0x20)


require("ie_network_beacon_msg")
require("ie_cluster_beacon_msg")
require("ie_association_request_msg")
require("ie_association_response_msg")
require("ie_association_release_message")
require("ie_reconfiguration_request_msg")
require("ie_reconfiguration_response_msg")
require("ie_mac_security_info_msg")
require("ie_route_info_msg")
require("ie_load_info_msg")
require("ie_rd_capability")
require("ie_broadcast_indication")
require("ie_neighbouring")
require("ie_resource_allocation")
require("ie_random_access_resource")
require("ie_measurement_report")
require("ie_radio_device_status")
require("ie_timestamp_nonstd")
dect_nr_proto.fields = {
    f_type_format1, f_type_format20,f_type_format21, f_type_length_type, f_type_length, 
    f_short_network_id, f_tx_id_hi, f_tx_id_lo,
    f_tx_power, f_reserved,f_mcs, 
    f_rx_id_hi, f_rx_id_lo,
    f_spatial_streams, f_redundancy_version, f_new_data_ind, f_harq_process,  
    f_feedback_format, f_feedback, 
    f_mac_security, 
    f_mac_header_type, 
    f_mac_ext,
    -- Mux header fields
    f_mux_ext_field,
    f_mux_ie_type,
    f_mux_sdu_length,
    f_mux_ie_type_ext3,
    f_mux_sdu_length_ext3,
    -- Miscellaneous header fields
    f_seq_reset,
    f_sequence,
    f_network_address,
    f_tx_long_rdid,
    f_rx_long_rdid,
    -- from ie_timestamp_nonstd
    f_timestamp_u64
}

local mac_version = {
    [0] = "v0",
}

local mac_security = {
[0] = "None",
[1] = "Mode 1",
}

local mac_header_type = {
    [0] = "DATA MAC PDU",
    [1] = "Beacon Header",
    [2] = "Unicast Header",
    [3] = "0011",
    [4] = "Escape"
}

local mac_ext = {
[0] = "00",
[1] = "01",
[2] = "10",
[3] = "11"}

local mac_ext_length = {
[0] = "0",
[1] = "8",
[2] = "16",
[3] = "1"}

local mac_ext_length_start = {
[0] = "Not applicable",
[1] = "0",
[2] = "0",
[3] = "2"}

local mac_ext_length_offset_start = {
[0] = "Not applicable",
[1] = "1",
[2] = "1",
[3] = "0"}

local mac_ext_ie_offset = {
[0] = "1",
[1] = "2",
[2] = "3"
}

local mac_ie = {
[0] = "000000",
[1] = "000001",
[2] = "000010",
[3] = "000011",
[4] = "000100",
[5] = "000101",
[6] = "000110",
[7] = "000111",
[8] = "001000",
[9] = "001001",
[10] = "001010",
[11] = "001011",
[12] = "001100",
[13] = "001101",
[14] = "001110",
[15] = "001111",
[16] = "010000",
[17] = "010001",
[18] = "010010",
[19] = "010011",
[20] = "010100",
[21] = "010101",
[22] = "010110",
[23] = "010111",
[24] = "011000",
[25] = "111110",
[26] = "111111",
[27] = "011001",
[28] = "00001"}

-- This structure define the handler functions associated to MAC SDUs
-- New handler functions should be added here with proper key from spec.
-- The definition of new handler function can be in separate file with
-- the name ie_<handler_name>.lua
local ie_type_handler = {
    [0x0] = ie_handler_padding,
    [0x1] = ie_handler_higher_layer_signal_flow_1,
    [0x2] = ie_handler_higher_layer_signal_flow_2,
    [0x3] = ie_handler_up_data_flow_1,
    [0x4] = ie_handler_up_data_flow_2,
    [0x5] = ie_handler_up_data_flow_3,
    [0x6] = ie_handler_up_data_flow_4,
    [0x8] = ie_handler_network_beacon_message,              --Implemented
    [0x9] = ie_handler_cluster_beacon_message,              --Implemented
    [0xA] = ie_handler_association_request_message,         --Implemented
    [0xB] = ie_handler_association_response_message,        --Implemented
    [0xC] = ie_handler_association_release_message,         --Implemented
    [0xD] = ie_handler_reconfiguration_request_message,     --Implemented
    [0xE] = ie_handler_reconfiguration_response_message,    --Implemented
    [0xF] = ie_handler_additional_mac_message,              --Reserved
    [0x10] = ie_handler_security_info,                      --Implemented
    [0x11] = ie_handler_route_info,                         --Implemented
    [0x12] = ie_handler_resource_allocation,                --Implemented, "Radio Device Class variable μ" issue hardcoded for now.
    [0x13] = ie_handler_random_access_resource,             --Implemented, "Radio Device Class variable μ" issue hardcoded for now.
    [0x14] = ie_handler_rd_capability,                      --Implemented, place where "Radio Device Class variable μ" is given/defined
    [0x15] = ie_handler_neighbouring,                       --Implemented
    [0x16] = ie_handler_broadcast_indication,               --Implemented, was unable to find some 3 bit field value list.
    [0x17] = ie_handler_group_assignment,                   --Implemented, for one resource tag
    [0x18] = ie_handler_load_info,                          --Implemented
    [0x19] = ie_handler_measurement_report,                 --Implemented
    [0x1A] = ie_handler_timestamp,
    [0x3E] = ie_handler_escape,
}

local ie_type_name = {
    [0x0] = "Padding IE",
    [0x1] = "Higher Layer Signal Flow 1 IE",
    [0x2] = "Higher Layer Signal Flow 2 IE ",
    [0x3] = "User-plane Data Flow 1 IE", 
    [0x4] = "User-plane Data Flow 2 IE",
    [0x5] = "User-plane Data Flow 3 IE",
    [0x6] = "User-plane Data Flow 4 IE",
    [0x7] = "Reserved",    
    [0x8] = "Network Beacon IE", 
    [0x9] = "Cluster Beacon IE",
    [0xA] = "Association Request Message",
    [0xB] = "Association Response Message",
    [0xC] = "Association Release Message",
    [0xD] = "Reconfiguration Request Message",
    [0xE] = "Reconfiguration Response Message",
    [0xF] = "Additional MAC Message",
    [0x10] = "Security Info IE",
    [0x11] = "Route Info IE",
    [0x12] = "Resource Allocation IE",
    [0x13] = "Random Access Resource IE",
    [0x14] = "RD Capability IE",
    [0x15] = "Neighbouring IE",
    [0x16] = "Broadcast Indication IE",
    [0x17] = "Group Assignment IE",
    [0x18] = "Load Info IE",
    [0x19] = "Measurement Report IE",
    [0x1A] = "Timestamp IE (Nonstandard)",
    [0x3E] = "Escape",
    [0x3F] = "IE type extension"
}


local ie_type_handler_5bits = {
    [0x0] =  ie_handler_padding1,                     
    [0x1] = ie_handler_radio_device_status,                 --Implemented
    [0x1E] = ie_handler_escape_ext3_length1,
    [0x1F] = ie_handler_reserved_ext3_length1
}

local ie_type_name_ext3 = {
    [0x0] = "Padding IE",
    [0x1] = "Radio Device Status IE",
    [0x1E] = "Escape",
    [0x1F] = "Reserved"    
}

-- those all are only 1 byte long
local ie_type_handler_ext3_payload_length0 = {
    [0x0] =  ie_handler_padding0,                 
    [0x1] =  ie_handler_configuration_request,
    [0x2] =  ie_handler_keep_alive,
    [0x3] =  ie_handler_reserved,
    [0x10] = ie_handler_security_info,                      
    [0x2] =  ie_handler_reserved,
    [0x3E] = ie_handler_escape_ext3_length0,
    [0x3F] = ie_handler_reserved_ext3_length0
}

local ie_type_name_ext3_payload_length0 = {
    [0x0] = "Padding IE",
    [0x1] = "Configuration Request IE",
    [0x2] = "Keep Alive IE",
    [0x3] = "Reserved",    
    [0x10] = "Security Info IE",
    [0x11] = "Reserved",
    [0x1E] = "Escape",
    [0x1F] = "Reserved"    
}



local function call_ie_type_handler(loffset, lbuffer, lpinfo, lmac_mux_header, lmac_ie_type)

    local curr_offset
    if ie_type_handler[lmac_ie_type] then
        curr_offset = ie_type_handler[lmac_ie_type](loffset, lbuffer, lpinfo, lmac_mux_header)
    end

    return curr_offset
end

local function call_ie_type_handler_5bits(loffset, lbuffer, lpinfo, lmac_mux_header, lmac_ie_type)

    local curr_offset
    if ie_type_handler_5bits[lmac_ie_type] then
        curr_offset = ie_type_handler_5bits[lmac_ie_type](loffset, lbuffer, lpinfo, lmac_mux_header)
    end

    return curr_offset
end

local function get_add_offset_length(buffer, offset, mac_ext_type)
    
    local add_offset
    if (mac_ext_type ~= 3) then
        add_offset = mac_ext_ie_offset[mac_ext_type]
    elseif (mac_ext_type == 3) then
        local length_val = buffer(offset, 1):bitfield(2, 1)
        if (length_val) then
            add_offset = 1
        else
            add_offset = 0
        end
    end

    return add_offset
end

-- TODO: This function should produce "expert info" for
-- protocol errors, such as invalid field values or SDU lengths.
local function dissect_sdu(tree, buffer, offset)
    local mux_base_header = buffer(offset, 1)
    local ext_field = buffer(offset, 1):bitfield(0, 2)
    local ie_type
    local ie_length
    local ie_length_range

    local base_offset = offset
    local header_len = 1
    local ie_label = "Unknown IE"
    if ext_field == 0 then
        ie_type = mux_base_header:bitfield(2, 6)
        ie_length = nil
        ie_label = ie_type_name[ie_type]
        return nil -- FIXME
    elseif ext_field == 1 then
        ie_type = mux_base_header:bitfield(2, 6)
        ie_length_range = buffer(offset + 1, 1)
        ie_length = ie_length_range:uint() + 1
        header_len = 2
        ie_label = ie_type_name[ie_type]
    elseif ext_field == 2 then
        ie_type = mux_base_header:bitfield(2, 6)
        ie_length_range = buffer(offset + 1, 2)
        ie_length = ie_length_range:uint() + 1
        ie_label = ie_type_name[ie_type]
        header_len = 3
    elseif ext_field == 3 then        
        ie_type = mux_base_header:bitfield(3, 5)
        ie_length_range = mux_base_header
        ie_length = mux_base_header:bitfield(2, 1)
        if ie_length == 0 then
          ie_label = ie_type_name_ext3_payload_length0[ie_type]
        elseif ie_length == 1 then        
          ie_label = ie_type_name_ext3[ie_type]
        end
    end

    if ie_label == nil then
        ie_label = "Unknown IE"
    end
    local total_len = header_len + ie_length
    local diff = buffer:len() - total_len - offset
    if diff < 0 then
        tree:add(buffer(offset, buffer:len() - offset), "<INVALID SDU LENGTH>")
        return nil
    end
    local subtree = tree:add(
        buffer(offset, total_len),
        "SDU: " .. ie_label
    )

    -- TODO: parse type 0 and use subtree:add(length):set_generated(true)
    -- to annotate the inferred length
    subtree:add(f_mux_ext_field, mux_base_header)
    if ext_field ~= 3 then
        subtree:add(f_mux_ie_type, mux_base_header)
        subtree:add(f_mux_sdu_length, ie_length_range, ie_length)

        call_ie_type_handler(offset + header_len, buffer, nil, subtree, ie_type)
    else
        subtree:add(f_mux_ie_type_ext3, mux_base_header)
        subtree:add(f_mux_sdu_length_ext3, ie_length_range, ie_length)
        
        call_ie_type_handler_5bits(offset + header_len, buffer, nil, subtree, ie_type)
    end
    

    return offset + header_len + ie_length
end



function dect_nr_proto.dissector(buffer,pinfo,tree)

    length = buffer:len()

    pinfo.cols.protocol = "dect_nr"

    local offset = 0
    local subtree = tree:add(dect_nr_proto,buffer(),"DECT-2020 New Radio PDU")
    
    -- len tells if header is short 5 byte or long 10 byte, both  short and long have format 0    
    local pcc_len = buffer(0,1):uint()
    local first_byte = buffer(1,1)
    
    -- Corrected endian interpretation: C LSB -> network MSB
    -- local format = bit.rshift(first_byte, 5)
    local format = first_byte:bitfield(0,3)
    --local packet_length_type = bit.band(bit.rshift(first_byte, 4), 0x1)
    local packet_length_type =first_byte:bitfield(3,1)
    --local packet_length = bit.band(first_byte, 0xF)
    local packet_length =first_byte:bitfield(4,4)

    local byte = buffer(1,1):uint()
    if pcc_len == 0x05 then
        subtree:add(f_type_format1, buffer(1,1), format)
    end
    if pcc_len == 0x0a and format == 0 then
        subtree:add(f_type_format20, buffer(1,1), format)
    end
    if pcc_len == 0x0a and format == 1 then
        subtree:add(f_type_format21, buffer(1,1), bit.band(byte,0xe0))
    end
    subtree:add(f_type_length_type, buffer(1,1), packet_length_type)
    subtree:add(f_type_length, buffer(1,1), packet_length)

    subtree:add(f_short_network_id, buffer(2,1))
    subtree:add(f_tx_id_hi, buffer(3,1))
    subtree:add(f_tx_id_lo, buffer(4,1))

    local offset = 5

    if pcc_len == 0x05 and format == 0 then
        local tx_power = buffer(offset,1):bitfield(0,4)
        local reserved = buffer(offset,1):bitfield(4,1)
        local df_mcs = buffer(offset,1):bitfield(5,3)

        subtree:add(f_tx_power, buffer(offset,1), tx_power)
        subtree:add(f_reserved, buffer(offset,1), reserved)
        subtree:add(f_mcs, buffer(offset,1), df_mcs)
        
        offset = offset + 1

    end    
    
    if pcc_len == 0x0a and format == 0 then
        subtree:add(f_rx_id_hi, buffer(offset,1)); offset = offset + 1
        subtree:add(f_rx_id_lo, buffer(offset,1)); offset = offset + 1

        local byte = buffer(offset,1):uint()
        subtree:add(f_spatial_streams, buffer(offset,1), bit.rshift(byte, 6))
        subtree:add(f_redundancy_version, buffer(offset,1), bit.band(bit.rshift(byte, 4), 0x03))
        subtree:add(f_new_data_ind, buffer(offset,1), bit.band(bit.rshift(byte, 3), 0x01))
        subtree:add(f_harq_process, buffer(offset,1), bit.band(byte, 0x07))
        offset = offset + 1
        subtree:add(f_feedback_format, buffer(offset,1), bit.band(byte, 0xf0))
        local short = buffer(offset,2):uint()
        subtree:add(f_feedback, buffer(offset,2),bit.band(short,0x0fff))
        offset = offset + 2
    end

    if pcc_len == 0x0a and format == 1 then
        subtree:add(f_rx_id_hi, buffer(offset,1)); offset = offset + 1
        subtree:add(f_rx_id_lo, buffer(offset,1)); offset = offset + 1

        local byte = buffer(offset,1):uint()
        subtree:add(f_spatial_streams, buffer(offset,1), bit.rshift(byte, 6))
        -- reserved field
        subtree:add(f_reserved, buffer(offset,1), bit.band(bit.lshift(byte, 2),0x3F))
        offset = offset + 1
        subtree:add(f_feedback_format, buffer(offset,1), bit.band(byte, 0xf0))
        local short = buffer(offset,2):uint()
        subtree:add(f_feedback, buffer(offset,2),bit.band(short,0x0fff))
        offset = offset + 2
    end
    


    --- MAC
    offset = offset + 5 -- Start from MAC header. Add PHY header function above this.

    local mac_packet_type = subtree:add(buffer(offset, 1), "MAC common header: " .. string.format("0x%02X", buffer(offset, 1):uint()))
    local packet_tree = mac_packet_type:add(f_mac_security, buffer(offset, 1))
    local mac_hdr_type = buffer(offset, 1):bitfield(4,4)
    packet_tree = mac_packet_type:add(f_mac_header_type, buffer(offset, 1))

    offset = offset + 1
    if mac_hdr_type == 0x0 then
        local data_mac_pdu_header = subtree:add(buffer(offset, 2), "DATA MAC PDU header")
        data_mac_pdu_header:add(f_seq_reset, buffer(offset, 2))
        data_mac_pdu_header:add(f_sequence, buffer(offset, 2))
        offset = offset + 2
    elseif mac_hdr_type == 0x1 then
        local beacon_header = subtree:add(buffer(offset, 7), "Beacon Header")
        beacon_header:add(f_network_address, buffer(offset, 3))
        beacon_header:add(f_tx_long_rdid, buffer(offset + 3, 4))
        offset = offset + 7
    elseif mac_hdr_type == 0x2 then
        local unicast_header = subtree:add(buffer(offset, 10), "Unicast Header")
        unicast_header:add(f_seq_reset, buffer(offset, 2))
		unicast_header:add(f_sequence, buffer(offset, 2))
        unicast_header:add(f_rx_long_rdid, buffer(offset + 2, 4))
        unicast_header:add(f_tx_long_rdid, buffer(offset + 6, 4))
        offset = offset + 10
    elseif mac_hdr_type == 0x3 then
        local rd_broadcast_header = subtree:add("RD Broadcasting Header")
        rd_broadcast_header:add(f_seq_reset, buffer(offset, 2))
        rd_broadcast_header:add(f_sequence, buffer(offset, 2))
        rd_broadcast_header:add(f_tx_long_rdid, buffer(offset + 2, 4))
        offset = offset + 6
    end

    -- start processing mux header and SDUs
    while offset ~= nil and offset < length do
        offset = dissect_sdu(subtree, buffer, offset)
    end
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(DECT_UDP_PORT,dect_nr_proto)
