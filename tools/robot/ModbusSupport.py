import struct
from scapy.packet import Packet, Raw
from scapy.fields import ShortField, XShortField, ByteField, XByteField, StrLenField, \
                         FieldListField, ByteEnumField, BitFieldLenField, ConditionalField

# The below classes override the functionality of original scapy modbus module
# to workaround some dissection issues with modbus packets and do explicit dissection of PDA 
# based on function code from payload for request, exception and response frames.

modbus_exceptions = {   0: "Undefined",
                        1: "Illegal function",
                        2: "Illegal data address",
                        3: "Illegal data value",
                        4: "Slave device failure",
                        5: "Acknowledge",
                        6: "Slave device busy",
                        8: "Memory parity error",
                        10: "Gateway path unavailable",
                        11: "Gateway target device failed to respond"}

# The common CRC16 checksum calculation method for Modbus Serial RTU frames
def mb_crc(frame:Raw, length) -> int:
    crc = 0xFFFF
    for n in range(length):
        crc ^= (frame[n])
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
    fields_desc = [ ShortField("transId", 0),
                    ShortField("protoId", 0),
                    ShortField("len", 0),
                    XByteField("unitId", 0),
                    ]

# Can be used to replace all Modbus read
class ModbusPDU_Read_Generic(Packet):
    name = "Read Generic"
    fields_desc = [ XByteField("funcCode", 0x01),
            XShortField("startAddr", 0x0000),
            XShortField("quantity", 0x0001)]

# 0x01 - Read Coils
class ModbusPDU01_Read_Coils(Packet):
    name = "Read Coils Request"
    fields_desc = [ XByteField("funcCode", 0x01),
            # 0x0000 to 0xFFFF
            XShortField("startAddr", 0x0000),
            XShortField("quantity", 0x0001)]

class ModbusPDU01_Read_Coils_Answer(Packet):
    name = "Read Coils Answer"
    fields_desc = [ XByteField("funcCode", 0x01),
            BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
            FieldListField("coilStatus", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount) ]

class ModbusPDU01_Read_Coils_Exception(Packet):
    name = "Read Coils Exception"
    fields_desc = [ XByteField("funcCode", 0x81),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x02 - Read Discrete Inputs
class ModbusPDU02_Read_Discrete_Inputs(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [ XByteField("funcCode", 0x02),
            XShortField("startAddr", 0x0000),
            XShortField("quantity", 0x0001)]

class ModbusPDU02_Read_Discrete_Inputs_Answer(Packet):
    name = "Read Discrete Inputs Answer"
    fields_desc = [ XByteField("funcCode", 0x02),
            BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
            FieldListField("inputStatus", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount) ]

class ModbusPDU02_Read_Discrete_Inputs_Exception(Packet):
    name = "Read Discrete Inputs Exception"
    fields_desc = [ XByteField("funcCode", 0x82),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x03 - Read Holding Registers
class ModbusPDU03_Read_Holding_Registers(Packet):
    name = "Read Holding Registers"
    fields_desc = [ XByteField("funcCode", 0x03),
            XShortField("startAddr", 0x0001),
            XShortField("quantity", 0x0002)]

class ModbusPDU03_Read_Holding_Registers_Answer(Packet):
    name = "Read Holding Registers Answer"
    fields_desc = [ XByteField("funcCode", 0x03),
            BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
            FieldListField("registerVal", [0x0000], ShortField("",0x0000), count_from = lambda pkt: pkt.byteCount)]

class ModbusPDU03_Read_Holding_Registers_Exception(Packet):
    name = "Read Holding Registers Exception"
    fields_desc = [ XByteField("funcCode", 0x83),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x04 - Read Input Registers
class ModbusPDU04_Read_Input_Registers(Packet):
    name = "Read Input Registers"
    fields_desc = [ XByteField("funcCode", 0x04),
            XShortField("startAddr", 0x0000),
            XShortField("quantity", 0x0001)]

class ModbusPDU04_Read_Input_Registers_Answer(Packet):
    name = "Read Input Registers Response"
    fields_desc = [XByteField("funcCode", 0x04),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="registerVal",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("registerVal", [0x0000],
                                  ShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]

class ModbusPDU04_Read_Input_Registers_Exception(Packet):
    name = "Read Input Registers Exception"
    fields_desc = [ XByteField("funcCode", 0x84),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x05 - Write Single Coil
class ModbusPDU05_Write_Single_Coil(Packet):
    name = "Write Single Coil"
    fields_desc = [ XByteField("funcCode", 0x05),
            XShortField("outputAddr", 0x0000),
            XShortField("outputValue", 0x0000)]

class ModbusPDU05_Write_Single_Coil_Answer(Packet):
    name = "Write Single Coil"
    fields_desc = [ XByteField("funcCode", 0x05),
            XShortField("outputAddr", 0x0000), 
            XShortField("outputValue", 0x0000)]

class ModbusPDU05_Write_Single_Coil_Exception(Packet):
    name = "Write Single Coil Exception"
    fields_desc = [ XByteField("funcCode", 0x85),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x06 - Write Single Register
class ModbusPDU06_Write_Single_Register(Packet):
    name = "Write Single Register"
    fields_desc = [ XByteField("funcCode", 0x06),
            XShortField("registerAddr", 0x0000), 
            XShortField("registerValue", 0x0000)]

class ModbusPDU06_Write_Single_Register_Answer(Packet):
    name = "Write Single Register Answer"
    fields_desc = [ XByteField("funcCode", 0x06),
            XShortField("registerAddr", 0x0000), 
            XShortField("registerValue", 0x0000)]

class ModbusPDU06_Write_Single_Register_Exception(Packet):
    name = "Write Single Register Exception"
    fields_desc = [ XByteField("funcCode", 0x86),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x07 - Read Exception Status (Serial Line Only)
class ModbusPDU07_Read_Exception_Status(Packet):
    name = "Read Exception Status"
    fields_desc = [ XByteField("funcCode", 0x07)]

class ModbusPDU07_Read_Exception_Status_Answer(Packet):
    name = "Read Exception Status Answer"
    fields_desc = [ XByteField("funcCode", 0x07),
            XByteField("startAddr", 0x00)]

class ModbusPDU07_Read_Exception_Status_Exception(Packet):
    name = "Read Exception Status Exception"
    fields_desc = [ XByteField("funcCode", 0x87),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# 0x0F - Write Multiple Coils
class ModbusPDU0F_Write_Multiple_Coils(Packet):
    name = "Write Multiple Coils"
    fields_desc = [ XByteField("funcCode", 0x0F),
            XShortField("startAddr", 0x0000),
            XShortField("quantityOutput", 0x0001),
            BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt,x:x),
            FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from = lambda pkt: pkt.byteCount)]

class ModbusPDU0F_Write_Multiple_Coils_Answer(Packet):
    name = "Write Multiple Coils Answer"
    fields_desc = [ XByteField("funcCode", 0x0F),
            XShortField("startAddr", 0x0000),
            XShortField("quantityOutput", 0x0001)]

class ModbusPDU0F_Write_Multiple_Coils_Exception(Packet):
    name = "Write Multiple Coils Exception"
    fields_desc = [ XByteField("funcCode", 0x8F),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

class ModbusPDU10_Write_Multiple_Registers(Packet):
    name = "Write Multiple Registers"
    fields_desc = [XByteField("funcCode", 0x10),
                   XShortField("startAddr", 0x0000),
                   BitFieldLenField("quantityRegisters", None, 16,
                                    count_of="outputsValue"),
                   BitFieldLenField("byteCount", None, 8,
                                    count_of="outputsValue",
                                    adjust=lambda pkt, x: x * 2),
                   FieldListField("outputsValue", [0x0000],
                                  XShortField("", 0x0000),
                                  count_from=lambda pkt: pkt.byteCount)]

class ModbusPDU10_Write_Multiple_Registers_Serial(ModbusPDU10_Write_Multiple_Registers):
    name = "Write Multiple Registers Serial"
    _crc: int = 0

    def get_crc(self) -> int:
        return self._crc

    def post_build(self, p, pay):
        self._crc = 0
        if self.outputsValue is not None and len(self.outputsValue) > 0:
            self._crc = mb_crc(p, len(p))
            p = p + struct.pack("<H", self._crc) #apply CRC16 network format
            self.add_payload(bytes(self._crc))
            #self.checksum = self._crc
        print(f"post build p={p}, checksum = {self._crc}")
        return p

    def guess_payload_class(self, payload):
        if len(payload) >= 2:
            if mb_crc(payload, len(payload)) == 0:
            #if self._crc == mb_crc(payload[:-2], len(payload)-2):
                self._crc = struct.unpack("<H", payload[-2:])[0]
                #print(f"Serial Payload: {payload}, crc: {self._crc}")
                return ModbusPDU10_Write_Multiple_Registers_Serial
        return Packet.guess_payload_class(self, payload)

class ModbusPDU10_Write_Multiple_Registers_Answer(Packet):
    name = "Write Multiple Registers Answer"
    fields_desc = [ XByteField("funcCode", 0x10),
            XShortField("startAddr", 0x0000),
            XShortField("quantityRegisters", 0x0001)]

class ModbusPDU10_Write_Multiple_Registers_Exception(Packet):
    name = "Write Multiple Registers Exception"
    fields_desc = [ XByteField("funcCode", 0x90),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

# Custom command
class ModbusPDUXX_Custom_Request(Packet):
    name = "Custom Request"
    fields_desc = [ 
        FieldListField("customBytes", [0x00], XByteField("", 0x00))
    ]

class ModbusPDUXX_Custom_Exception(Packet):
    name = "Custom Command Exception"
    fields_desc = [ 
        XByteField("funcCode", 0x00),
        ByteEnumField("exceptCode", 1, modbus_exceptions)
    ]

# Custom command respond
class ModbusPDUXX_Custom_Answer(Packet):
    name = "Custom Command Answer"
    fields_desc = [
        ConditionalField(XByteField("funcCode", 0x00), lambda pkt: (type(pkt.underlayer) is ModbusADU_Response)),
        ConditionalField(FieldListField("customBytes", [0x00], XByteField("", 0x00), count_from = lambda pkt: pkt.underlayer.len if pkt.underlayer is not None else 0), lambda pkt: type(pkt.underlayer) is ModbusADU_Response)
    ]

# 0x11 - Report Slave Id
class ModbusPDU11_Report_Slave_Id(Packet):
    name = "Report Slave Id"
    fields_desc = [ 
        XByteField("funcCode", 0x11)
    ]

class ModbusPDU11_Report_Slave_Id_Answer(Packet):
    name = "Report Slave Id Answer"
    fields_desc = [ 
        XByteField("funcCode", 0x11),
        BitFieldLenField("byteCount", None, 8, length_of="slaveUId"),
        ConditionalField(XByteField("slaveUid", 0x00), lambda pkt: pkt.byteCount>0),
        ConditionalField(XByteField("runIdicatorStatus", 0x00), lambda pkt: pkt.byteCount>0),
        ConditionalField(FieldListField("slaveIdent", [0x00], XByteField("", 0x00), count_from = lambda pkt: pkt.byteCount), lambda pkt: pkt.byteCount>0)
    ]

class ModbusPDU11_Report_Slave_Id_Exception(Packet):
    name = "Report Slave Id Exception"
    fields_desc = [ XByteField("funcCode", 0x91),
            ByteEnumField("exceptCode", 1, modbus_exceptions)]

class ModbusADU_Request(ModbusMBAP):
    name = "ModbusADU Request"
    _mb_exception: modbus_exceptions = 0
    fields_desc = [ 
            XShortField("transId", 0x0000), # needs to be unique
            XShortField("protoId", 0x0000), # needs to be zero (Modbus)
            XShortField("len", None),       # is calculated with payload
            XByteField("unitId", 0x00)      # 0xFF or 0x00 should be used for Modbus over TCP/IP
    ]

    def mb_get_last_exception(self):
        return _mb_exception

    # Dissects packets
    def guess_payload_class(self, payload):
        funcCode = int(payload[0])
        #print(f'Request guess payload class func: {funcCode}')
        self._mb_exception = 0

        if funcCode == 0x01:
            return ModbusPDU01_Read_Coils
        elif funcCode == 0x81:
            self._mb_exception = int(payload[1])
            return ModbusPDU01_Read_Coils_Exception

        elif funcCode == 0x02:
            return ModbusPDU02_Read_Discrete_Inputs
        elif funcCode == 0x82:
            self._mb_exception = int(payload[1])
            return ModbusPDU02_Read_Discrete_Inputs_Exception

        elif funcCode == 0x03:
            return ModbusPDU03_Read_Holding_Registers
        elif funcCode == 0x83:
            self._mb_exception = int(payload[1])
            return ModbusPDU03_Read_Holding_Registers_Exception

        elif funcCode == 0x04:
            return ModbusPDU04_Read_Input_Registers
        elif funcCode == 0x84:
            self._mb_exception = int(payload[1])
            return ModbusPDU04_Read_Input_Registers_Exception

        elif funcCode == 0x05:
            return ModbusPDU05_Write_Single_Coil
        elif funcCode == 0x85:
            self._mb_exception = int(payload[1])
            return ModbusPDU05_Write_Single_Coil_Exception

        elif funcCode == 0x06:
            return ModbusPDU06_Write_Single_Register
        elif funcCode == 0x86:
            self._mb_exception = int(payload[1])
            return ModbusPDU06_Write_Single_Register_Exception

        elif funcCode == 0x07:
            return ModbusPDU07_Read_Exception_Status
        elif funcCode == 0x87:
            self._mb_exception = int(payload[1])
            return ModbusPDU07_Read_Exception_Status_Exception

        elif funcCode == 0x0F:
            return ModbusPDU0F_Write_Multiple_Coils
        elif funcCode == 0x8F:
            self._mb_exception = int(payload[1])
            return ModbusPDU0F_Write_Multiple_Coils_Exception

        elif funcCode == 0x11:
            return ModbusPDU11_Report_Slave_Id
        elif funcCode == 0x91:
            self._mb_exception = int(payload[1])
            return ModbusPDU11_Report_Slave_Id_Exception

        elif funcCode == 0x10:
            #return ModbusPDU10_Write_Multiple_Registers
            return ModbusPDU10_Write_Multiple_Registers_Serial.guess_payload_class(self, payload)
        elif funcCode == 0x90:
            self._mb_exception = int(payload[1])
            return ModbusPDU10_Write_Multiple_Registers_Exception

        else:
            return Packet.guess_payload_class(self, payload)

    def post_build(self, p, pay):
        if self.len is None:
            l = len(pay) + 1 #+len(p)
            p = p[:4]+struct.pack("!H", l) + p[6:]
        return p+pay
    
    def my_show(self, p):
        for f in p.fields_desc:
            fvalue = p.getfieldval(f.name)
            reprval = f.i2repr(p,fvalue)
            return "%s" % (reprval)

# If we know the packet is an Modbus answer, we can dissect it with
# ModbusADU_Response(str(pkt))
# Scapy will dissect it on it's own if the TCP stream is available
class ModbusADU_Response(ModbusMBAP):
    name = "ModbusADU Response"
    _mb_exception: modbus_exceptions = 0
    _current_main_packet: Packet = None
    _modbus_pdu: Packet = None
    fields_desc = [ 
            XShortField("transId", 0x0000), # needs to be unique
            XShortField("protoId", 0x0000), # needs to be zero (Modbus)
            XShortField("len", None),       # is calculated with payload
            XByteField("unitId", 0x01)]     # 0xFF or 0x00 should be used for Modbus over TCP/IP

    def mb_get_last_exception(self):
        return _mb_exception
    
    # def extract_padding(self, s):
    #     print(f'Extract pedding: {self, s, self.len, self.underlayer}')
    #     return self.guess_payload_class( s) #, s #self.extract_pedding(self, s)

    def pre_dissect(self, s):
        print(f'Pre desect: {self, s, self.len, self.underlayer}')
        _current_main_packet = self
        return s

    # Dissects packets
    def guess_payload_class(self, payload):
        funcCode = int(payload[0])

        self._mb_exception = 0

        if funcCode == 0x01:
            return ModbusPDU01_Read_Coils_Answer
        elif funcCode == 0x81:
            self._mb_exception = int(payload[1])
            return ModbusPDU01_Read_Coils_Exception

        elif funcCode == 0x02:
            return ModbusPDU02_Read_Discrete_Inputs_Answer
        elif funcCode == 0x82:
            self._mb_exception = int(payload[1])
            return ModbusPDU02_Read_Discrete_Inputs_Exception

        elif funcCode == 0x03:
            return ModbusPDU03_Read_Holding_Registers_Answer
        elif funcCode == 0x83:
            self._mb_exception = int(payload[1])
            return ModbusPDU03_Read_Holding_Registers_Exception

        elif funcCode == 0x04:
            return ModbusPDU04_Read_Input_Registers_Answer
        elif funcCode == 0x84:
            self._mb_exception = int(payload[1])
            return ModbusPDU04_Read_Input_Registers_Exception

        elif funcCode == 0x05:
            return ModbusPDU05_Write_Single_Coil_Answer
        elif funcCode == 0x85:
            self._mb_exception = int(payload[1])
            return ModbusPDU05_Write_Single_Coil_Exception

        elif funcCode == 0x06:
            return ModbusPDU06_Write_Single_Register_Answer
        elif funcCode == 0x86:
            self._mb_exception = int(payload[1])
            return ModbusPDU06_Write_Single_Register_Exception

        elif funcCode == 0x07:
            return ModbusPDU07_Read_Exception_Status_Answer
        elif funcCode == 0x87:
            self._mb_exception = int(payload[1])
            return ModbusPDU07_Read_Exception_Status_Exception

        elif funcCode == 0x0F:
            return ModbusPDU0F_Write_Multiple_Coils_Answer
        elif funcCode == 0x8F:
            self._mb_exception = int(payload[1])
            return ModbusPDU0F_Write_Multiple_Coils_Exception

        elif funcCode == 0x10:
            return ModbusPDU10_Write_Multiple_Registers_Answer
        elif funcCode == 0x90:
            self._mb_exception = int(payload[1])
            return ModbusPDU10_Write_Multiple_Registers_Exception

        elif funcCode == 0x11:
            return ModbusPDU11_Report_Slave_Id_Answer
        elif funcCode == 0x91:
            self._mb_exception = int(payload[1])
            return ModbusPDU11_Report_Slave_Id_Exception

        else:
            if (funcCode & 0x80):
                self._mb_exception = int(payload[1])
                return ModbusPDUXX_Custom_Exception
            return ModbusPDUXX_Custom_Answer
            #return Packet.guess_payload_class(self, payload)