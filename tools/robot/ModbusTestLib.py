#!/usr/bin/python

import socket
import random
import binascii
import os
from typing import Optional, Any, Tuple

from scapy.utils import wrpcap
from scapy.packet import Packet, Raw
from scapy.supersocket import StreamSocket
from scapy.layers.inet import Ether, IP, TCP
from scapy.config import conf
from scapy.error import Scapy_Exception

from robot.api.deco import keyword, library
from robot.api.logger import info, debug, trace, console

from ModbusSupport import modbus_exceptions, ModbusADU_Request, ModbusADU_Response, ModbusPDUXX_Custom_Request, ModbusPDU11_Report_Slave_Id, ModbusPDU03_Read_Holding_Registers, ModbusPDU10_Write_Multiple_Registers, \
                          ModbusPDU04_Read_Input_Registers, ModbusPDU01_Read_Coils, ModbusPDU0F_Write_Multiple_Coils, ModbusPDU02_Read_Discrete_Inputs, ModbusPDU06_Write_Single_Register

# Disable debugging of dissector, and set default padding for scapy configuration class
# to workaround issues under robot framework
conf.debug_dissector = False
conf.padding = 1

# The default values for self test of the library
MB_DEF_SERVER_IP = '127.0.0.1'
MB_DEF_PORT = 1502
MB_DEF_TRANS_ID = 0x0000
MB_DEF_FUNC_HOLDING_READ = 0x03
MB_DEF_FUNC_HOLDING_WRITE = 0x10
MB_DEF_FUNC_INPUT_READ = 0x04
MB_DEF_FUNC_COILS_READ = 0x01
MB_DEF_FUNC_COILS_WRITE = 0x0F
MB_DEF_FUNC_REPORT_SLAVE_ID = 0x11
MB_DEF_QUANTITY = 1
MB_DEF_START_OFFS = 0x0001
MB_DEF_REQ_TOUT = 5.0

MB_LOGGING_PATH = '.'

# The constructed packets for self testing

TEST_PACKET_REPORT_CUSTOM_0X41 = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0)/\
                            ModbusPDUXX_Custom_Request(customBytes=[0x41])'
TEST_PACKET_REPORT_SLAVE_ID_CUSTOM = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0)/\
                            ModbusPDUXX_Custom_Request(customBytes=[0x11])'
TEST_PACKET_REPORT_SLAVE_ID = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0)/\
                            ModbusPDU11_Report_Slave_Id(funcCode=MB_DEF_FUNC_REPORT_SLAVE_ID)'
TEST_PACKET_HOLDING_READ = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0, len=6)/\
                            ModbusPDU03_Read_Holding_Registers(funcCode=MB_DEF_FUNC_HOLDING_READ, startAddr=MB_DEF_START_OFFS, quantity=MB_DEF_QUANTITY)'
TEST_PACKET_HOLDING_WRITE = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0)/\
                            ModbusPDU10_Write_Multiple_Registers(funcCode=MB_DEF_FUNC_HOLDING_WRITE, startAddr=MB_DEF_START_OFFS, quantityRegisters=2, outputsValue=[0x1122, 0x3344])'
TEST_PACKET_INPUT_READ = 'ModbusADU_Request(transId=MB_DEF_TRANS_ID, unitId=0x01, protoId=0, len=6)/\
                            ModbusPDU04_Read_Input_Registers(funcCode=MB_DEF_FUNC_INPUT_READ, startAddr=MB_DEF_START_OFFS, quantity=MB_DEF_QUANTITY)'
TEST_PACKET_COILS_READ = 'ModbusADU_Request(unitId=0x01, protoId=0)/\
                            ModbusPDU01_Read_Coils(funcCode=MB_DEF_FUNC_COILS_READ, startAddr=MB_DEF_START_OFFS, quantity=MB_DEF_QUANTITY)'
TEST_PACKET_COILS_WRITE = 'ModbusADU_Request(unitId=0x01, protoId=0)/\
                            ModbusPDU0F_Write_Multiple_Coils(funcCode=MB_DEF_FUNC_COILS_WRITE, startAddr=MB_DEF_START_OFFS, quantityOutput=MB_DEF_QUANTITY, outputsValue=[0xFF])'

# The simplified version of custom Modbus Library to check robot framework
@library(scope='GLOBAL', version='2.0.0')
class ModbusTestLib:
    '''
        ModbusTestLib class is the custom Modbus library for robot framework.
        The test class for Modbus includes common functionality to receive and parse Modbus frames.
    '''
    MB_EXCEPTION_MASK = 0x0080
    MB_EXCEPTION_FUNC_MASK = 0x007F

    def __init__(self, ip_address = MB_DEF_SERVER_IP, port = MB_DEF_PORT, timeout = MB_DEF_REQ_TOUT) -> None:
        self._connection: StreamSocket = None
        self.class_id = random.randint(0,100) # is to track of created instance number
        self.node_port = port
        self.node_address = ip_address
        self.trans_id = 0x0001
        self.socket = None
        self.host_ip = None
        self.exception_message = None
        self.exception = None
        self.in_adu = None
        self.in_pdu = None
        self.resp_timeout = timeout
        self.pcap_file_name = "{path}/{file}_{id}.{ext}".format(path=MB_LOGGING_PATH, file='mb_frames', ext='pcap', id=str(self.class_id))
        if os.path.isfile(self.pcap_file_name):
            os.remove(self.pcap_file_name)

    @property
    def connection(self) -> Optional[StreamSocket]:
        # type: () -> Optional[Any]
        if _connection is not None:
            raise SystemError('No Connection established! Connect to server first!')
        return self._connection

    def get_slave_ip(self) -> int:
        # type: () -> int
        if self.dut_slave_ip_address is None:
            raise SystemError('Transaction is not initialized!')
        return self.trans_id
    
    def get_host_ip(self):
        # type: () -> Optional[Any]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.connect(('<broadcast>', 12345))  # use random port
        return s.getsockname()[0]

    def get_trans_id(self) -> int:
        # type: () -> int
        if self.trans_id is None:
            raise SystemError('Transaction is not initialized!')
        return self.trans_id

    def inc_trans_id(self) -> int:
         # type: () -> int
        if self.trans_id is None:
            raise SystemError('Transaction field is incorrect!')
        self.trans_id = self.trans_id + 1
        if self.trans_id > 65535:
            self.trans_id = 1
        return self.trans_id

    def get_last_adu(self) -> Optional[Packet]:
        # type: () -> Optional[Packet]
        return self.in_adu

    def get_last_pdu(self) -> Any:
        return self.in_pdu

    def mb_match_packet(self, pkt) -> bool:
        # type: (Packet, int, bool) -> Optional[Packet]
        return True if pkt.haslayer(ModbusADU_Response) else False

    # This function implements workaround for sr1 function which does not work reliable in some versions of scapy
    def _req_send_recv(self, pkt, timeout=0, verbose=True) -> Optional[Packet]:
        # type: (Packet, int, bool) -> Optional[Packet]
        if self._connection is None:
            raise ValueError("The connection is not active.")
        packet = pkt.build()
        print(f'send packet: {packet}')
        try:
            self._connection.send(packet)
            ans = self._connection.sniff(filter=f"tcp and dst host {self.node_address} and dst port {self.node_port}",
                                         prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"),
                                         count=1, timeout=timeout)
            return ans[0] if ans else None

        except Exception as exception:
                raise Scapy_Exception(f"Send fail: {exception}")

    @keyword("Get Class Id")
    def get_class_id(self) -> int:
        # type: (Any) -> Optional[Packet]
        """
            Return unique class ID for robot suit debugging.
            Args:
                None
            Returns:
                Class instance ID
        """
        return self.class_id

    # Validation of the created packet
    def _validate_packet(self, packet: Packet) -> None:
        # type: (Packet) -> None
        if not packet.haslayer(ModbusADU_Request) or packet[ModbusADU_Request].protoId != 0:
            raise ValueError("Only Modbus TCP requests are allowed!")
        if not packet[ModbusADU_Request].transId:
            packet.transId = self.get_trans_id()

    @keyword("Create Request")
    def create_request(self, packet_str) -> Packet:
        # type: (Any, int)  -> Optional[Packet]
        """
            Create a Modbus packet based on the given string representation.
            Args:
                packet_str (str): A string representing the Modbus packet.
            Returns:
                ModbusADU_Request: The created Modbus packet.
            Raises:
                ValueError: If the packet creation fails.
        """
        try:
            packet: ModbusADU_Request = eval(packet_str)
            self._validate_packet(packet)
            print("Packet created: %s" % str(packet.summary()))
            return packet

        except Exception as exception:
            raise ValueError(f"Failed to create packet: {str(exception)}")

    # Connects to a target via TCP socket
    @keyword("Connect")
    def connect(self, ip_addr=MB_DEF_SERVER_IP, port=MB_DEF_PORT) -> StreamSocket:
        # type: (Any, int) -> Optional[Any]
        """
            Create a Modbus connection to target over socket stream.
            Args:
                ip_addr (str): A string representing the Modbus server address.
                port: A server port to connect
            Returns:
                StreamSocket: The created Modbus socket.
            Raises:
                Scapy_Exception: If the packet creation fails.
        """
        if (ip_addr is None and self.node_address is None):
            print("Connection is not esteblished.")
            raise ValueError('No parameters defined!')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"Connect to server: {ip_addr}:{port}")
            s.connect((ip_addr, port))
            self._connection = StreamSocket(s, basecls=ModbusADU_Response)
            self.host_ip = self.get_host_ip()
            print(f'Host IP address: {self.host_ip}')
            self.node_address = ip_addr
            self.node_port = port
            self.socket = s
        except Exception as exception:
                self.node_address = None
                self.node_port = None
                self.socket
                raise Scapy_Exception(f"Could not connect to socket: {exception}")
        return self._connection

    @keyword("Disconnect")
    def disconnect(self) -> None:
        # type: () -> None
        """
            The disconnect from socket method to work as robot framework keyword.
            Args:
                None
            Returns:
                None
            Raises:
                Scapy_Exception: If the connection close fail.
        """
        if self._connection is not None:
            info(f"Disconnect from server.")
            try:
                self._connection.close()
                self._connection = None
                self.socket = None
            
            except Exception as exception:
                raise Scapy_Exception(f"Connection close fail, exception occurred: ({exception})")

    @keyword("Send Packet")
    def send_packet_and_get_response(self, pkt, timeout=2, verbose=True) -> Optional[bytes]:
        # type: (Packet, int, bool) -> Optional[bytes]
        """
            Wrapped send and receive function used as the robot framework keyword.
            Args:
                pkt: A Modbus packet.
                timeout: timeout to send the data
                verbose: logging information
            Returns:
                bytes: The created Modbus socket as Raw bytes.
            Raises:
                Scapy_Exception: If the packet send or receive fail.
        """
        try:
            request: Packet = pkt
            if self._connection is None:
                print("Connection is not established")
                self.connect(ip_addr=self.node_address, port=self.node_port)
            response: Packet = self._req_send_recv(request[ModbusADU_Request], timeout=timeout, verbose=verbose)
            #assert response is not None, "No respond from slave"
            if request is None or response is None:
                print("No response from slave.")
                return None
            print(f"Packet sent: {request[ModbusADU_Request].show(dump=True)}")
            print(f"Packet get: {response[ModbusADU_Response].show(dump=True)}")
            print(f"Answer bin: {bytes(response)}")
            print(f"Answer hex: {binascii.hexlify(bytes(response)).decode('ascii')}")
            # Mimic the whole Modbus frames correctly in the pcap
            dport = 502 # self.node_port, override to default port to show the packets correctly under wireshark
            if not request.haslayer(Ether):
                pcap_out = Ether()
            if not request.haslayer(IP):
                pcap_out /= IP(dst=self.node_address, src=self.host_ip)
            if not request.haslayer(TCP):
                pcap_out /= TCP(dport=dport, sport=random.randint(37000,39000))
            pcap_out /= request
            if not request.haslayer(Ether):
                pcap_in = Ether()
            if not request.haslayer(IP):
                pcap_in /= IP(src=self.node_address, dst=self.host_ip)
            if not request.haslayer(TCP):
                pcap_in /= TCP(dport=dport, sport=random.randint(37000,39000)) 
            pcap_in /= response
            # record the packets sent/received
            wrpcap(self.pcap_file_name, bytes(pcap_out), append=True)
            wrpcap(self.pcap_file_name, bytes(pcap_in), append=True)
            self.inc_trans_id()
            return bytes(response) if response else None

        except Exception as exception:
          raise Scapy_Exception(f"Send data fail, exception occurred: ({exception})")

    @keyword("Translate Response")
    def translate_response(self, pkt) -> Any:
        # type: (bytes) -> Optional[Packet]
        """
            Translates response received from server. Does dissection of the received packet.
            Args:
                pkt: A Modbus packet.
            Returns:
                bytes: The created Modbus socket as Raw bytes.
            Raises:
                Scapy_Exception: If the packet send or receive fail.
        """
        try:
            packet: Packet = ModbusADU_Response(pkt)
            if packet is None: #or not packet.haslayer(ModbusADU_Response)
                raise ValueError("Only Modbus TCP responses are allowed!")
            print(f"Packet received: {packet.show(dump=True)}")
            self.in_pdu, __ = packet.extract_padding(packet)
            print(f"Test received: pdu: {type(self.in_pdu)} {self.in_pdu}, {bytes(self.in_pdu)}")
            # workaround to use dissected packets under robot framework
            # issue with scapy dissector on incomplete packets
            if packet.haslayer(Raw):
                print(f"Test workaround PDU: {bytes(packet[Raw].load)}")
                self.in_pdu = packet.guess_payload_class(packet[Raw].load)
            if (packet.funcCode & self.MB_EXCEPTION_MASK) and \
                hasattr(self.in_pdu, 'exceptCode') and \
                    (self.in_pdu.exceptCode in modbus_exceptions):
                self.exception = packet.exceptCode
                self.exception_message = modbus_exceptions[self.exception]
            self.in_adu = packet[ModbusADU_Response]
            print(f'PDU: {self.in_pdu}')
            return self.in_pdu

        except Exception as exception:
            self.in_adu = None
            self.in_pdu = None
            raise Scapy_Exception(f"Parsing of response : ({exception})")

    def get_int(self, val) -> int:
        # type: (Any) -> int
        if isinstance(val, str):
            return int(val)
        elif isinstance(val, int):
            return val
        else:
            raise ValueError("Invalid value type")

    @keyword("Check Response")
    def check_response(self, pdu, expected_func) -> Tuple[int, str]:
        # type: (Packet, str) -> Tuple[int, str]
        """
            Check PDU frame from response. Check exception code
            Args:
                pdu: A Modbus PDU frame.
                expected_func: timeout to send the data
            Returns:
                exception: The exception code from Modbus frame
                exception_message: exception message
            Raises:
                ValueError: If the packet send or receive fail.
        """
        assert pdu is not None and isinstance(pdu, Packet), "Incorrect pdu provided."
        func_code: int = 0
        if isinstance(pdu, ModbusADU_Response):
            print(f"PDU is ModbusADU_Response, funcCode: {pdu.funcCode}")
            func_code = pdu.getfieldval('funcCode')
        elif hasattr(pdu, 'funcCode') and isinstance(pdu.funcCode, XByteField):
            print(f"Test PDU: type:{type(pdu)}, PDU:{pdu}, Func:{type(pdu.funcCode.i2repr(pdu, pdu.funcCode))}, {pdu.funcCode.i2repr(pdu, pdu.funcCode)}")
            func_code = pdu.getfieldval(pdu, 'funcCode')
            print(f"PDU has funcCode attribute, value: {pdu.funcCode} {func_code}")
        else:
            raise ValueError(f"Invalid PDU type or missing function code: {type(pdu)}, {type(pdu.funcCode)}")
        print(f"func code: {type(func_code)} {func_code}")
        if ((func_code & self.MB_EXCEPTION_MASK) and hasattr(pdu, 'exceptCode') and pdu.exceptCode):
            self.exception = pdu.exceptCode
        else:
            self.exception = 0
        exp_func = self.get_int(expected_func) if isinstance(expected_func, str) else expected_func
        assert ((func_code & self.MB_EXCEPTION_FUNC_MASK) == exp_func), f"Unexpected function code: {func_code & self.MB_EXCEPTION_FUNC_MASK}, {exp_func}"
        self.exception_message = modbus_exceptions[self.exception]
        print(f"MB exception: {self.exception}, {self.exception_message}")
        return self.exception, self.exception_message

    @keyword("Check ADU")
    def check_adu(self, adu_out, adu_in):
        # type: (Packet, Packet) -> Optional[int]
        """
            Check ADU frame fields.
            Args:
                adu_out: A Modbus ADU frame request.
                adu_in: A Modbus ADU frame response.
            Returns:
                transId: the transaction ID, if the frames are correct, otherwise returns None
            Raises:
                ValueError: If the packet send or receive fail.
        """
        assert adu_out is not None and adu_in is not None, "Incorrect adu frame provided."
        try:
            if hasattr(adu_out, 'TransId') and \
                hasattr(adu_in, 'TransId') and \
                hasattr(adu_out, 'protoId') and \
                hasattr(adu_in, 'protoId') and \
                adu_out.protoId == adu_in.protoId and \
                adu_out.TransId == adu_in.TransId:
                return  adu_out.TransId
            return None
        
        except Exception as exception:
            raise Scapy_Exception(f"Send data fail, exception occurred: ({exception})")

    @keyword("Get Bits From PDU")
    def get_bits_from_pdu(self, pdu):
        # type: (Packet) -> List[bool]
        """
            Check PDU frame, extract bits (coils or discrete) from PDU.
            Args:
                pdu: A Modbus PDU frame.
            Returns:
                bits: The list of bits of boolean type.
            Raises:
                ValueError: If the packet send or receive fail.
        """
        assert pdu is not None and isinstance(pdu, Packet) and \
                (hasattr(pdu, 'coilStatus') or hasattr(pdu, 'inputStatus')), "Incorrect pdu provided."
        bits = []
        if hasattr(pdu, 'byteCount') and (pdu.byteCount >= 1):
            data_bytes = bytes(pdu.coilStatus) if hasattr(pdu, 'coilStatus') else bytes(pdu.inputStatus)
            bits = [(data_bytes[i//8] & 1 << i%8 != 0) for i in range(len(data_bytes) * 8)]
        return  bits

    # Self test function to debug the supported methods. Todo: remove later
    def self_test(self) -> None:
       # type: () -> None
        self.connect(ip_addr=MB_DEF_SERVER_IP, port=MB_DEF_PORT)
        packet = self.create_request(TEST_PACKET_REPORT_CUSTOM_0X41)
        print(f"Test: 0x41 <Custom command> packet: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "No response from slave"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        if pdu is not None:
           print(f"Received: {pdu}")
           #print(f"PDU Exception: {self.check_response(pdu, packet.customBytes[0])}")
        packet = self.create_request(TEST_PACKET_REPORT_SLAVE_ID_CUSTOM)
        print(f"Test: 0x11 <Report Slave ID> packet: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "No response from slave"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        if pdu is not None:
           print(f"Slave identificator structure: {pdu}")
           print(f"PDU Exception: {self.check_response(pdu, packet.customBytes[0])}")
           print(f'slaveUID: {pdu.slaveUid}, runIdicatorStatus: {pdu.runIdicatorStatus}, IdStruct:  {pdu.slaveIdent}')
        packet = self.create_request(TEST_PACKET_HOLDING_READ)
        print(f"Test: Packet created: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "No response from slave"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        if pdu is not None:
            print(f"Register values: {pdu}, len:{len(pdu.registerVal)}")
            print(f"PDU Exception: {self.check_response(pdu, packet.funcCode)}")
        packet = self.create_request(TEST_PACKET_HOLDING_WRITE)
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "No response from slave"
        print(f"Write response ack: {response} ")
        if response is not None:
            print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        exception = self.check_response(pdu, packet.funcCode)
        if pdu is not None and not exception:
            print(f"PDU Exception: {self.check_response(pdu, packet.funcCode)}")
        packet = self.create_request(TEST_PACKET_INPUT_READ)
        print(f"Test: input read packet: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "incorrect response"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        exception = self.check_response(pdu, packet.funcCode)
        if pdu is not None and not exception:
            print(f"Register values: {pdu}, len:{len(pdu.registerVal)}")
        packet = self.create_request(TEST_PACKET_COILS_READ)
        print(f"Test: read coils request: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "Incorrect coil read response"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        exception = self.check_response(pdu, packet.funcCode)
        if pdu is not None and not exception:
            print(f"Register values: {pdu}, len:{len(pdu.coilStatus)}")
        packet = self.create_request(TEST_PACKET_COILS_WRITE)
        print(f"Test: write coils request: {packet}")
        response = self.send_packet_and_get_response(packet, timeout=1, verbose=0)
        assert response and len(response) > 1, "Incorrect coil read response"
        print(f"Test: received: {bytes(response)}")
        pdu = self.translate_response(response)
        exception = self.check_response(pdu, packet.funcCode)
        if pdu is not None and not exception:
            print(f"Register values: {pdu}, len: {pdu.quantityOutput}")
        self.disconnect()


    ####################################################################
    #banner = "\nRobot custom Modbus library based on scapy framework\n"

if __name__ == "__main__":
    # interact(mydict=globals(), mybanner=banner)
    test_lib = ModbusTestLib()
    test_lib.self_test()
