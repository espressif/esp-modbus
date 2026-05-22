# SPDX-FileCopyrightText: 2024-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import struct
import time
from datetime import datetime
from typing import Type

from scapy.packet import Packet
from enum import IntEnum
from scapy.fields import (
    ShortField,
    XShortField,
    ByteField,
    XByteField,
    FieldListField,
    ByteEnumField,
    BitFieldLenField,
    ConditionalField,
)

# The below classes override the functionality of original scapy modbus module
# to workaround some dissection issues with modbus packets and do explicit dissection of PDU
# based on function code from payload for request, exception and response frames.

MB_EXCEPTION_MASK = 0x80
MB_EXCEPTION_FUNC_MASK = 0x7F


# Supported default commands
class Commands(IntEnum):
    UNDEFINED = 0x00
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_HOLDING_REGISTER = 0x06
    READ_EXCEPTION_STATE = 0x07
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_HOLDING_REGISTERS = 0x10
    CUSTOM_COMMAND_41 = 0x41
    REPORT_SLAVE_ID = 0x11


class Exceptions(IntEnum):
    UNDEFINED = 0x00
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    NEGATIVE_ACKNOWLEDGE = 0x07
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x10
    GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 0x11
    DEFAULT = 0xFE
    MAX_EXCEPTION = 0xFF


class HandlingStateEnum(IntEnum):
    DEFAULT = 0x00
    RESPONDED = 0x01
    IGNORED = 0x02
    SKIPPED = 0x03
    RANDOMIZED = 0x04
    EXCEPTION = 0x05


# The common CRC16 checksum calculation method for Modbus Serial RTU frames
def mb_crc(frame: bytes, length: int) -> int:
    crc = 0xFFFF
    for n in range(length):
        crc ^= frame[n]
        for i in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc


# Modbus MBAP basic class
class ModbusMBAP(Packet):
    name = "Modbus TCP"
    fields_desc = [
        ShortField("transId", 0),
        ShortField("protoId", 0),
        ShortField("len", 0),
        XByteField("unitId", 0),
    ]

    def get_time_stamp(self) -> float:
        print(f"Get time_stamp of TID#{self.transId}: {self.time}")
        return self.time

    def get_time_stamp_str(self) -> str:
        return datetime.fromtimestamp(self.time).strftime("%Y-%m-%d %H:%M:%S.%f")

    def set_time_stamp(self) -> float:
        self.time = time.time()
        # print(f"Set time stamp of TID#{self.transId:#x}: {self.time}")
        return self.time


# Can be used to replace all Modbus read
class ModbusPDU_Read_Generic(Packet):
    name = "Read Generic"
    fields_desc = [
        XByteField("funcCode", Commands.READ_COILS),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001),
    ]


class ModbusPDU_Exception(Packet):
    name = "Modbus Exception class"
    fields_desc = [
        XByteField("funcCode", 0x80),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x01 - Read Coils
class ModbusPDU01_Read_Coils(Packet):
    name = "Read Coils Request"
    fields_desc = [
        XByteField("funcCode", Commands.READ_COILS),
        # 0x0000 to 0xFFFF
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001),
    ]


class ModbusPDU01_Read_Coils_Answer(Packet):
    name = "Read Coils Answer"
    fields_desc = [
        XByteField("funcCode", Commands.READ_COILS),
        BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
        FieldListField(
            "coilStatus",
            [0x00],
            ByteField("", 0x00),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


class ModbusPDU01_Read_Coils_Exception(ModbusPDU_Exception):
    name = "Read Coils Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.READ_COILS | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x02 - Read Discrete Inputs
class ModbusPDU02_Read_Discrete_Inputs(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [
        XByteField("funcCode", Commands.READ_DISCRETE_INPUTS),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001),
    ]


class ModbusPDU02_Read_Discrete_Inputs_Answer(Packet):
    name = "Read Discrete Inputs Answer"
    fields_desc = [
        XByteField("funcCode", Commands.READ_DISCRETE_INPUTS),
        BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
        FieldListField(
            "inputStatus",
            [0x00],
            ByteField("", 0x00),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


class ModbusPDU02_Read_Discrete_Inputs_Exception(ModbusPDU_Exception):
    name = "Read Discrete Inputs Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.READ_DISCRETE_INPUTS | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x03 - Read Holding Registers
class ModbusPDU03_Read_Holding_Registers(Packet):
    name = "Read Holding Registers"
    fields_desc = [
        XByteField("funcCode", Commands.READ_HOLDING_REGISTERS),
        XShortField("startAddr", 0x0001),
        XShortField("quantity", 0x0002),
    ]


class ModbusPDU03_Read_Holding_Registers_Answer(Packet):
    name = "Read Holding Registers Answer"
    fields_desc = [
        XByteField("funcCode", Commands.READ_HOLDING_REGISTERS),
        BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
        FieldListField(
            "registerVal",
            [0x0000],
            XShortField("", 0x0000),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


class ModbusPDU03_Read_Holding_Registers_Exception(ModbusPDU_Exception):
    name = "Read Holding Registers Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.READ_HOLDING_REGISTERS | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x04 - Read Input Registers
class ModbusPDU04_Read_Input_Registers(Packet):
    name = "Read Input Registers"
    fields_desc = [
        XByteField("funcCode", Commands.READ_INPUT_REGISTERS),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001),
    ]


class ModbusPDU04_Read_Input_Registers_Answer(Packet):
    name = "Read Input Registers Response"
    fields_desc = [
        XByteField("funcCode", Commands.READ_INPUT_REGISTERS),
        BitFieldLenField(
            "byteCount", None, 8, count_of="registerVal", adjust=lambda pkt, x: x * 2
        ),
        FieldListField(
            "registerVal",
            [0x0000],
            XShortField("", 0x0000),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


class ModbusPDU04_Read_Input_Registers_Exception(ModbusPDU_Exception):
    name = "Read Input Registers Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.READ_INPUT_REGISTERS | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x05 - Write Single Coil
class ModbusPDU05_Write_Single_Coil(Packet):
    name = "Write Single Coil"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_SINGLE_COIL),
        XShortField("outputAddr", 0x0000),
        XShortField("outputValue", 0x0000),
    ]


class ModbusPDU05_Write_Single_Coil_Answer(Packet):
    name = "Write Single Coil"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_SINGLE_COIL),
        XShortField("outputAddr", 0x0000),
        XShortField("outputValue", 0x0000),
    ]


class ModbusPDU05_Write_Single_Coil_Exception(ModbusPDU_Exception):
    name = "Write Single Coil Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.WRITE_SINGLE_COIL | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x06 - Write Single Register
class ModbusPDU06_Write_Single_Register(Packet):
    name = "Write Single Register"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_SINGLE_HOLDING_REGISTER),
        XShortField("registerAddr", 0x0000),
        XShortField("registerValue", 0x0000),
    ]


class ModbusPDU06_Write_Single_Register_Answer(Packet):
    name = "Write Single Register Answer"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_SINGLE_HOLDING_REGISTER),
        XShortField("registerAddr", 0x0000),
        XShortField("registerValue", 0x0000),
    ]


class ModbusPDU06_Write_Single_Register_Exception(ModbusPDU_Exception):
    name = "Write Single Register Exception"
    fields_desc = [
        XByteField(
            "funcCode", (Commands.WRITE_SINGLE_HOLDING_REGISTER | MB_EXCEPTION_MASK)
        ),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x07 - Read Exception Status (Serial Line Only)
class ModbusPDU07_Read_Exception_Status(Packet):
    name = "Read Exception Status"
    fields_desc = [XByteField("funcCode", Commands.READ_EXCEPTION_STATE)]


class ModbusPDU07_Read_Exception_Status_Answer(Packet):
    name = "Read Exception Status Answer"
    fields_desc = [
        XByteField("funcCode", Commands.READ_EXCEPTION_STATE),
        XByteField("startAddr", 0x00),
    ]


class ModbusPDU07_Read_Exception_Status_Exception(ModbusPDU_Exception):
    name = "Read Exception Status Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.READ_EXCEPTION_STATE | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# 0x0F - Write Multiple Coils
class ModbusPDU0F_Write_Multiple_Coils(Packet):
    name = "Write Multiple Coils"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_MULTIPLE_COILS),
        XShortField("startAddr", 0x0000),
        XShortField("quantityOutput", 0x0001),
        BitFieldLenField(
            "byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x
        ),
        FieldListField(
            "outputsValue",
            [0x00],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


class ModbusPDU0F_Write_Multiple_Coils_Answer(Packet):
    name = "Write Multiple Coils Answer"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_MULTIPLE_COILS),
        XShortField("startAddr", 0x0000),
        XShortField("quantityOutput", 0x0001),
    ]


class ModbusPDU0F_Write_Multiple_Coils_Exception(ModbusPDU_Exception):
    name = "Write Multiple Coils Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.WRITE_MULTIPLE_COILS | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


class ModbusPDU10_Write_Multiple_Registers(Packet):
    name = "Write Multiple Registers"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_MULTIPLE_HOLDING_REGISTERS),
        XShortField("startAddr", 0x0000),
        BitFieldLenField("quantityRegisters", None, 16, count_of="outputsValue"),
        BitFieldLenField(
            "byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x: x * 2
        ),
        FieldListField(
            "outputsValue",
            [0x0000],
            XShortField("", 0x0000),
            count_from=lambda pkt: pkt.byteCount,
        ),
    ]


# class ModbusPDU10_Write_Multiple_Registers_Serial(ModbusPDU10_Write_Multiple_Registers):
#     name = "Write Multiple Registers Serial"
#     _crc: int = 0

#     def get_crc(self) -> int:
#         return self._crc

#     def post_build(self, p: bytes, pay: bytes) -> bytes:
#         self._crc = 0
#         if self.outputsValue is not None and len(self.outputsValue) > 0:
#             self._crc = mb_crc(p, len(p))
#             p = p + struct.pack("<H", self._crc)  # apply CRC16 network format
#             # self.add_payload(bytes(self._crc))
#             # self.checksum = self._crc
#         print(f"post build p={p!r}, checksum = {self._crc!r}")
#         return p

#     def guess_payload_class(self, payload: bytes) -> Any:
#         if len(payload) >= 2:
#             if mb_crc(payload, len(payload)) == 0:
#                 # if self._crc == mb_crc(payload[:-2], len(payload)-2):
#                 self._crc = struct.unpack("<H", payload[-2:])[0]
#                 # print(f"Serial Payload: {payload}, crc: {self._crc}")
#                 return ModbusPDU10_Write_Multiple_Registers_Serial
#         return Packet.guess_payload_class(self, payload)


class ModbusPDU10_Write_Multiple_Registers_Answer(Packet):
    name = "Write Multiple Registers Answer"
    fields_desc = [
        XByteField("funcCode", Commands.WRITE_MULTIPLE_HOLDING_REGISTERS),
        XShortField("startAddr", 0x0000),
        XShortField("quantityRegisters", 0x0001),
    ]


class ModbusPDU10_Write_Multiple_Registers_Exception(ModbusPDU_Exception):
    name = "Write Multiple Registers Exception"
    fields_desc = [
        XByteField(
            "funcCode", (Commands.WRITE_MULTIPLE_HOLDING_REGISTERS | MB_EXCEPTION_MASK)
        ),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# Custom command
class ModbusPDUXX_Custom_Request(Packet):
    name = "Custom Request"
    fields_desc = [FieldListField("customBytes", [0x00], XByteField("", 0x00))]


class ModbusPDUXX_Custom_Exception(ModbusPDU_Exception):
    name = "Custom Command Exception"
    fields_desc = [
        XByteField("funcCode", MB_EXCEPTION_MASK),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


# Custom command respond
class ModbusPDUXX_Custom_Answer(Packet):
    name = "Custom Command Answer"
    fields_desc = [
        ConditionalField(
            XByteField("funcCode", 0x00),
            lambda pkt: type(pkt.underlayer) is ModbusADU_Response,
        ),
        ConditionalField(
            FieldListField(
                "customBytes",
                [0x00],
                XByteField("", 0x00),
                length_from=lambda pkt: (
                    pkt.underlayer.len if pkt.underlayer is not None else 0
                ),
            ),
            lambda pkt: type(pkt.underlayer) is ModbusADU_Response,
        ),
    ]


# 0x11 - Report Slave Id
class ModbusPDU11_Report_Slave_Id(Packet):
    name = "Report Slave Id"
    fields_desc = [XByteField("funcCode", Commands.REPORT_SLAVE_ID)]


class ModbusPDU11_Report_Slave_Id_Answer(Packet):
    name = "Report Slave Id Answer"
    fields_desc = [
        XByteField("funcCode", Commands.REPORT_SLAVE_ID),
        BitFieldLenField("byteCount", None, 8, length_of="slaveUId"),
        ConditionalField(XByteField("slaveUid", 0x00), lambda pkt: pkt.byteCount > 0),
        ConditionalField(
            XByteField("runIdicatorStatus", 0x00), lambda pkt: pkt.byteCount > 0
        ),
        ConditionalField(
            FieldListField(
                "slaveIdent",
                [0x00],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.byteCount,
            ),
            lambda pkt: pkt.byteCount > 0,
        ),
        # ConditionalField(
        #     XByteField("slaveUid", 0x00),
        #     lambda pkt: pkt.byteCount>0
        # ),
        # ConditionalField(
        #     XByteField("runIdicatorStatus", 0x00),
        #     lambda pkt: pkt.byteCount>0
        # ),
        # ConditionalField(
        #     FieldListField("slaveIdent", [0x00],
        #                     XByteField("", 0x00),
        #                     count_from = lambda pkt: pkt.byteCount
        #     ),
        #     lambda pkt: pkt.byteCount>0
        # )
    ]


class ModbusPDU11_Report_Slave_Id_Exception(Packet):
    name = "Report Slave Id Exception"
    fields_desc = [
        XByteField("funcCode", (Commands.REPORT_SLAVE_ID | MB_EXCEPTION_MASK)),
        ByteEnumField("exceptCode", 1, Exceptions),
    ]


class ModbusADU_Response(ModbusMBAP):
    name = "ModbusADU Response"
    # static fields of the class used for dissection
    _mb_exception: Exceptions = Exceptions.UNDEFINED
    _last_packet: Packet = None
    _modbus_pdu: Packet = None
    _seq_num: int = 0
    fields_desc = [
        XShortField("transId", 0x0000),  # needs to be unique
        XShortField("protoId", 0x0000),  # needs to be zero (Modbus)
        XShortField("len", None),  # is calculated with payload
        XByteField(
            "unitId", 0x01
        ),  # 0xFF or 0x00 should be used for Modbus over TCP/IP
    ]

    @classmethod
    def get_sequence_num(self) -> int:
        print(f"Get sequence number: {self._seq_num}")
        return self._seq_num

    @classmethod
    def get_last_exception(self) -> Exceptions:
        return self._mb_exception

    # def get_hexcap(self):
    #     packet = self.from_hexcap()
    #     print(f"Hexcap dump: {packet}")
    #     return packet

    # def extract_padding(self, s):
    #     print(f'Extract padding: {self, s, self.len, self.underlayer}')
    #     return self.guess_payload_class( s) #, s #self.extract_pedding(self, s)

    def pre_dissect(self, s: bytes) -> bytes:
        # print(f'Pre desect class: {self, s, self.len, self.underlayer}, seq_num: {self.__class__._seq_num}')
        _last_packet = self
        self.__class__._seq_num += 1
        return s

    # Dissects packets
    def guess_payload_class(self, payload: bytes) -> Type[Packet]:
        funcCode = payload[0]
        self._mb_exception = Exceptions.UNDEFINED

        if funcCode == Commands.READ_COILS:
            self._modbus_pdu = ModbusPDU01_Read_Coils_Answer
            return ModbusPDU01_Read_Coils_Answer
        elif funcCode == (Commands.READ_COILS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU01_Read_Coils_Exception
            return ModbusPDU01_Read_Coils_Exception

        elif funcCode == Commands.READ_DISCRETE_INPUTS:
            self._modbus_pdu = ModbusPDU02_Read_Discrete_Inputs_Answer
            return ModbusPDU02_Read_Discrete_Inputs_Answer
        elif funcCode == (Commands.READ_DISCRETE_INPUTS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU02_Read_Discrete_Inputs_Exception
            return ModbusPDU02_Read_Discrete_Inputs_Exception

        elif funcCode == Commands.READ_HOLDING_REGISTERS:
            self._modbus_pdu = ModbusPDU03_Read_Holding_Registers_Answer
            return ModbusPDU03_Read_Holding_Registers_Answer
        elif funcCode == (Commands.READ_HOLDING_REGISTERS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU03_Read_Holding_Registers_Exception
            return ModbusPDU03_Read_Holding_Registers_Exception

        elif funcCode == Commands.READ_INPUT_REGISTERS:
            self._modbus_pdu = ModbusPDU04_Read_Input_Registers_Answer
            return ModbusPDU04_Read_Input_Registers_Answer
        elif funcCode == (Commands.READ_INPUT_REGISTERS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU04_Read_Input_Registers_Exception
            return ModbusPDU04_Read_Input_Registers_Exception

        elif funcCode == Commands.WRITE_SINGLE_COIL:
            self._modbus_pdu = ModbusPDU05_Write_Single_Coil_Answer
            return ModbusPDU05_Write_Single_Coil_Answer
        elif funcCode == (Commands.WRITE_SINGLE_COIL | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU05_Write_Single_Coil_Exception
            return ModbusPDU05_Write_Single_Coil_Exception

        elif funcCode == Commands.WRITE_SINGLE_HOLDING_REGISTER:
            self._modbus_pdu = ModbusPDU06_Write_Single_Register_Answer
            return ModbusPDU06_Write_Single_Register_Answer
        elif funcCode == (Commands.WRITE_SINGLE_HOLDING_REGISTER | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU06_Write_Single_Register_Exception
            return ModbusPDU06_Write_Single_Register_Exception

        elif funcCode == Commands.READ_EXCEPTION_STATE:
            self._modbus_pdu = ModbusPDU07_Read_Exception_Status_Answer
            return ModbusPDU07_Read_Exception_Status_Answer
        elif funcCode == (Commands.READ_EXCEPTION_STATE | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU07_Read_Exception_Status_Exception
            return ModbusPDU07_Read_Exception_Status_Exception

        elif funcCode == Commands.WRITE_MULTIPLE_COILS:
            self._modbus_pdu = ModbusPDU0F_Write_Multiple_Coils_Answer
            return ModbusPDU0F_Write_Multiple_Coils_Answer
        elif funcCode == (Commands.WRITE_MULTIPLE_COILS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU0F_Write_Multiple_Coils_Exception
            return ModbusPDU0F_Write_Multiple_Coils_Exception

        elif funcCode == Commands.WRITE_MULTIPLE_HOLDING_REGISTERS:
            self._modbus_pdu = ModbusPDU10_Write_Multiple_Registers_Answer
            return ModbusPDU10_Write_Multiple_Registers_Answer
        elif funcCode == (
            Commands.WRITE_MULTIPLE_HOLDING_REGISTERS | MB_EXCEPTION_MASK
        ):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU10_Write_Multiple_Registers_Exception
            return ModbusPDU10_Write_Multiple_Registers_Exception

        elif funcCode == Commands.REPORT_SLAVE_ID:
            self._modbus_pdu = ModbusPDU11_Report_Slave_Id_Answer
            return ModbusPDU11_Report_Slave_Id_Answer
        elif funcCode == (Commands.REPORT_SLAVE_ID | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            self._modbus_pdu = ModbusPDU11_Report_Slave_Id_Exception
            return ModbusPDU11_Report_Slave_Id_Exception

        else:
            if funcCode & MB_EXCEPTION_MASK:
                self._mb_exception = Exceptions(payload[1])
                self._modbus_pdu = ModbusPDUXX_Custom_Exception
                return ModbusPDUXX_Custom_Exception
            self._modbus_pdu = ModbusPDUXX_Custom_Answer
            return ModbusPDUXX_Custom_Answer
            # return Packet.guess_payload_class(self, payload)


class ModbusADU_Request(ModbusMBAP):
    name = "ModbusADU Request"
    _mb_exception: Exceptions = Exceptions.UNDEFINED
    _seq_num: int = 0
    _last_packet: Packet = None
    fields_desc = [
        XShortField("transId", 0x0000),  # needs to be unique
        XShortField("protoId", 0x0000),  # needs to be zero (Modbus)
        XShortField("len", None),  # is calculated with payload
        XByteField(
            "unitId", 0x00
        ),  # 0xFF or 0x00 should be used for Modbus over TCP/IP
    ]

    @classmethod
    def get_sequence_num(self) -> int:
        print(f"Get sequence number: {self._seq_num}")
        return self._seq_num

    def pre_dissect(self, s: bytes) -> bytes:
        # print(f'Pre desect class: {self, s, self.len, self.underlayer}, seq_num: {self.__class__._seq_num}, time: {self.time}')
        _last_packet = self
        self.__class__._seq_num += 1
        return s

    def mb_get_last_exception(self) -> Exceptions:
        return self._mb_exception

    # Dissects packets
    def guess_payload_class(self, payload: bytes) -> Packet:
        funcCode = int(payload[0])
        # try:
        #     print(f'Request guess payload class func: {funcCode}:{Commands(funcCode).name}')
        # except Exception as e:
        #     print(f'Request guess payload class func: {funcCode}:Unsupported')
        self._mb_exception = Exceptions.UNDEFINED

        if funcCode == Commands.READ_COILS:
            return ModbusPDU01_Read_Coils
        elif funcCode == (Commands.READ_COILS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU01_Read_Coils_Exception

        elif funcCode == Commands.READ_DISCRETE_INPUTS:
            return ModbusPDU02_Read_Discrete_Inputs
        elif funcCode == (Commands.READ_DISCRETE_INPUTS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU02_Read_Discrete_Inputs_Exception

        elif funcCode == Commands.READ_HOLDING_REGISTERS:
            return ModbusPDU03_Read_Holding_Registers
        elif funcCode == (Commands.READ_HOLDING_REGISTERS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU03_Read_Holding_Registers_Exception

        elif funcCode == Commands.READ_INPUT_REGISTERS:
            return ModbusPDU04_Read_Input_Registers
        elif funcCode == (Commands.READ_INPUT_REGISTERS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU04_Read_Input_Registers_Exception

        elif funcCode == Commands.WRITE_SINGLE_COIL:
            return ModbusPDU05_Write_Single_Coil
        elif funcCode == (Commands.WRITE_SINGLE_COIL | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU05_Write_Single_Coil_Exception

        elif funcCode == Commands.WRITE_SINGLE_HOLDING_REGISTER:
            return ModbusPDU06_Write_Single_Register
        elif funcCode == (Commands.WRITE_SINGLE_HOLDING_REGISTER | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU06_Write_Single_Register_Exception

        elif funcCode == Commands.READ_EXCEPTION_STATE:
            return ModbusPDU07_Read_Exception_Status
        elif funcCode == (Commands.READ_EXCEPTION_STATE | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU07_Read_Exception_Status_Exception

        elif funcCode == Commands.WRITE_MULTIPLE_COILS:
            return ModbusPDU0F_Write_Multiple_Coils
        elif funcCode == (Commands.WRITE_MULTIPLE_COILS | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU0F_Write_Multiple_Coils_Exception

        elif funcCode == Commands.REPORT_SLAVE_ID:
            return ModbusPDU11_Report_Slave_Id
        elif funcCode == (Commands.REPORT_SLAVE_ID | MB_EXCEPTION_MASK):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU11_Report_Slave_Id_Exception

        elif funcCode == (
            Commands.WRITE_MULTIPLE_HOLDING_REGISTERS | MB_EXCEPTION_MASK
        ):
            return ModbusPDU10_Write_Multiple_Registers
        elif funcCode == (
            Commands.WRITE_MULTIPLE_HOLDING_REGISTERS | MB_EXCEPTION_MASK
        ):
            self._mb_exception = Exceptions(payload[1])
            return ModbusPDU10_Write_Multiple_Registers_Exception

        else:
            if (
                funcCode < MB_EXCEPTION_MASK and len(payload) > 0
            ):  # Check for non-exception packets
                # Assume custom request if it's not a known function code
                return ModbusPDUXX_Custom_Request
            elif funcCode & MB_EXCEPTION_MASK:
                # Assume custom exception if it's an exception but unknown
                self._mb_exception = (
                    Exceptions(payload[1]) if len(payload) > 1 else Exceptions.UNDEFINED
                )
                return ModbusPDUXX_Custom_Exception

        return Packet.guess_payload_class(self, payload)

    def post_build(self, p: bytes, pay: bytes) -> bytes:  # Added type hints
        if self.len is None:
            length = len(pay) + 1  # +len(p)
            p = p[:4] + struct.pack("!H", length) + p[6:]
        return p + pay

    def my_show(self, p: Packet) -> str:
        for f in p.fields_desc:
            fvalue = p.getfieldval(f.name)
            reprval = f.i2repr(p, fvalue)
            return "%s = %s" % (f.name, reprval)
        return ""
