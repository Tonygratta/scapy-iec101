#!/usr/bin/env python3

from scapy.packet import Packet
from scapy.fields import Field, XByteField, XByteEnumField, ByteField, BitField, BitEnumField, FlagsField, PacketLenField, PacketField, XStrField, MultipleTypeField
from struct import pack, unpack

FUNCTION_CODES = {
    0x0: 'SEND/CONFIRM - Reset of remote link',
    0x1: 'SEND/CONFIRM - Reset of user process',
    0x2: 'SEND/CONFIRM - Reserved for balanced transmission procedure',
    0x3: 'SEND/CONFIRM - User data',
    0x4: 'SEND/NO REPLY - User data',
    0x5: 'Reserved',
    0x6: 'Reserved for special use by agreement',
    0x7: 'Reserved for special use by agreement',
    0x8: 'REQUEST for access demand',
    0x9: 'REQUEST/RESPONSE - Status of link',
    0xa: 'REQUEST/RESPONSE - User data class 1',
    0xb: 'REQUEST/RESPONSE - User data class 2',
    0xc: 'Reserved',
    0xd: 'Reserved',
    0xe: 'Reserved for special use by agreement',
    0xf: 'Reserved for special use by agreement',
}

TYPEID_ASDU = {
    0x01: 'M_SP_NA_1 (1)',
    0x03: 'M_DP_NA_1 (3)',
    0x05: 'M_ST_NA_1 (5)',
    0x07: 'M_BO_NA_1 (7)',
    0x09: 'M_ME_NA_1 (9)',
    0x0D: 'M_ME_NC_1 (13)',
    0x1E: 'M_SP_TB_1 (30)',
    0x1F: 'M_DP_TB_1 (31)',
    0x24: 'M_ME_TF_1 (36)',
    0x2D: 'C_SC_NA_1 (45)',
    0x2E: 'C_DC_NA_1 (46)',
    0x32: 'C_SE_NC_1 (50)',
    0x46: 'M_EI_NA_1 (70)',
    0x64: 'C_IC_NA_1 (100)',
    0x67: 'C_CS_NA_1 (103)',
}

CAUSE_OF_TX = {
    0: 'not used',
    1: 'per/cyc',
    2: 'back',
    3: 'spont',
    4: 'init',
    5: 'req',
    6: 'Act',
    7: 'ActCon',
    8: 'Deact',
    9: 'DeactCon',
    10: 'ActTerm',
    11: 'retrem',
    12: 'retloc',
    13: 'file',
    20: 'inrogen',
    21: 'inro1',
    22: 'inro2',
    23: 'inro3',
    24: 'inro4',
    25: 'inro5',
    26: 'inro6',
    27: 'inro7',
    28: 'inro8',
    29: 'inro9',
    30: 'inro10',
    31: 'inro11',
    32: 'inro12',
    33: 'inro13',
    34: 'inro14',
    35: 'inro15',
    36: 'inro16',
    37: 'reqcogen',
    38: 'reqco1',
    39: 'reqco2',
    40: 'reqco3',
    41: 'reqco4',
    44: 'unknown type identification',
    45: 'unknown cause of transmission',
    46: 'unknown common address of ASDU',
    47: 'unknown information object address'
}

SQ_ENUM = {
    0: 'Single',
    1: 'Sequence'
}

class IOA(Field):

    def __init__(self, name, default):
        super().__init__(name, default, '<h')

    def addfield(self, pkt, s, val):
        if val is None:
            return s
        return s + pack('BBB', 0, val & 0xff, (val >> 8) & 0xff )

    def getfield(self, pkt, s):
        value = unpack('BBB', s[:3])
        val = int(value[1])
        val += int((value[2] << 8))
        return s[3:], self.m2i(pkt, val)

class FT12Fixed(Packet):
    name = 'FT1.2 Fixed length'
    fields_desc = [
        XByteField('start', 0x10),
        FlagsField('Control_Flags',0x4, 4, ['FCV', 'FCB', 'PRM', 'RES']),
        BitEnumField('fcode',0x9,4, FUNCTION_CODES),
        XByteField('address',0x00),
        XByteField('checksum', 0x00),
        XByteField('end', 0x16)
    ]

class VSQ(Packet):
    name = 'Variable Structure Qualifier'
    fields_desc = [
        BitEnumField('SQ',0x0, 1, SQ_ENUM),
        BitField('number',0x0,7)
    ]

class IO45(Packet):
    name = 'Single Command'
    fields_desc = [
        IOA('IOA', 0x000000),
        BitEnumField('SE',0x0, 1, {0: 'Execute', 1: 'Select'}),
        BitField('QU', 0x00, 5),
        BitField('reserved',0x0, 1),
        BitEnumField('SCS', 0, 1, {0: 'OFF', 1: 'ON'})
    ]

class IO46(Packet):
    name = 'Double Command'
    fields_desc = [
        IOA('IOA', 0x000000),
        BitEnumField('SE',0x0, 1, {0: 'Execute', 1: 'Select'}),
        BitField('QU', 0x00, 5),
        BitEnumField('DCS', 1, 2, {0: 'not permitted', 1: 'OFF', 2: 'ON', 3: 'not permitted'})
    ]

class ASDU(Packet):
    name = 'ASDU'
    fields_desc = [
        XByteEnumField('type', 0x00, TYPEID_ASDU),
        PacketLenField('VSQ', VSQ(), VSQ, length_from=lambda pkt: 1),
        FlagsField('COT_flags', 0x00, 2, ['Negative', 'Test']),
        BitEnumField('COT', 0x00, 6, CAUSE_OF_TX),
        MultipleTypeField(
            [
                (PacketField('IO', 0x00000000, IO45), lambda pkt: pkt.type == 45),
                (PacketField('IO', 0x00000000, IO46), lambda pkt: pkt.type == 46),
            ],
            XStrField('IO', b'')
        ),
    ]

class FT12Variable(Packet):
    name = 'FT1.2 Variable Length'
    fields_desc = [
        XByteField('start', 0x68),
        ByteField('length_1', 0x09),
        ByteField('length_2', 0x09),
        XByteField('start2', 0x68),
        FlagsField('Control_Flags',0x4, 4, ['FCV', 'FCB', 'PRM', 'RES']),
        BitEnumField('fcode',0x9,4, FUNCTION_CODES),
        XByteField('address',0x00),
        PacketLenField('LinkUserData', ASDU(), ASDU, length_from=lambda pkt: pkt.getfieldval('length_1') - 2),
        XByteField('checksum', 0x00),
        XByteField('end', 0x16)
    ]

class FT12Frame(Packet):

    def guess_payload_class(self, payload: bytes):
        if payload[0] == 0x10:
            return FT12Fixed
        if payload[0] == 0x68:
            return FT12Variable
        return self.default_payload_class(payload)
