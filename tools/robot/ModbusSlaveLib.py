#!/usr/bin/python
# SPDX-FileCopyrightText: 2024-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import binascii
import functools
import socket
from datetime import datetime
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, cast
from threading import Event, Thread, Lock
from queue import Queue, Empty
import time
import random
import os
from scapy.all import (
    get_if_list,
    get_if_addr,
    wrpcap,
    IP,
    TCP,
    Ether,
    AnsweringMachine,
    Packet,
    conf,
    Scapy_Exception,
    AsyncSniffer,
    StreamSocket,
    PacketList,
)
from robot.api.deco import keyword, library
from ModbusSupport import (
    MB_EXCEPTION_MASK,
    MB_EXCEPTION_FUNC_MASK,
    Commands,
    Exceptions,
    HandlingStateEnum,
    ModbusPDU_Exception,
    ModbusADU_Request,
    ModbusADU_Response,
    ModbusPDUXX_Custom_Request,
    ModbusPDUXX_Custom_Answer,
    ModbusPDU11_Report_Slave_Id,
    ModbusPDU03_Read_Holding_Registers,
    ModbusPDU10_Write_Multiple_Registers,
    ModbusPDU04_Read_Input_Registers,
    ModbusPDU01_Read_Coils,
    ModbusPDU0F_Write_Multiple_Coils,
    ModbusPDU02_Read_Discrete_Inputs,
    ModbusPDU06_Write_Single_Register,
    ModbusPDU04_Read_Input_Registers_Answer,
    ModbusPDU01_Read_Coils_Answer,
    ModbusPDU02_Read_Discrete_Inputs_Answer,
    ModbusPDU03_Read_Holding_Registers_Answer,
    ModbusPDU05_Write_Single_Coil,
    ModbusPDU05_Write_Single_Coil_Answer,
    ModbusPDU06_Write_Single_Register_Answer,
    ModbusPDU07_Read_Exception_Status,
    ModbusPDU07_Read_Exception_Status_Answer,
    ModbusPDU0F_Write_Multiple_Coils_Answer,
    ModbusPDU10_Write_Multiple_Registers_Answer,
    ModbusPDU11_Report_Slave_Id_Answer,
    ModbusPDUXX_Custom_Exception,
)

MB_LOG_LEVEL = logging.INFO
MB_TRANSACTION_QUEUE_MAX_SZ = 300
MB_LOGGING_PATH = "."


class ModbusValidator:
    """Handles verification of Modbus requests and responses"""

    def __init__(self) -> None:
        self.logger = logging.getLogger("RobotFramework")

    def to_int(self, value: Any) -> Optional[int]:
        """Helper to normalize a value that may be int,
        decimal string, or hex string like '0x1A' (required for robot framework keywords)
        """
        if value is None:
            return None
        if isinstance(value, int):
            return value
        v = str(value).strip()
        if v.startswith(("0x", "0X")):
            return int(v, 16)
        # allow empty strings
        if v == "":
            return None
        return int(v, 10)

    def to_list_int(self, value: Any) -> List[Optional[int]]:
        """Helper to normalize a list of representations into List[int].
        Accepts list/tuple or string like '[0x01, 0x02]' or '0x01,0x02'.
        Note: required to call the methods as robot framework keywords.
        """
        if value is None:
            return []
        # Accept builtin list/tuple types coming from Robot framework runtime
        if isinstance(value, (list, tuple)):
            return [self.to_int(x) for x in value] if value else []
        s = str(value).strip()
        # strip surrounding brackets if present
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
        if s == "":
            return []
        parts = [p.strip() for p in s.split(",") if p.strip() != ""]
        return [self.to_int(p) for p in parts] if parts else []

    def create_request(
        self,
        uid: int = 1,
        func_code: int = Commands.UNDEFINED,
        start_addr: int = 0,
        quantity: int = 1,
        exception: int = 0,
        data: Optional[List[int]] = None,
    ) -> Optional[ModbusADU_Request]:
        """Creates a Modbus request based on the function code and parameters."""

        self.logger.info(
            f"Creating request: uid={uid}, func_code={func_code}, start_addr={start_addr}, \
                         quantity={quantity}, exception={exception}, data={data}"
        )

        if (uid > 247) or (uid < 1):
            self.logger.error(f"The UID to set is incorrect: {uid}")
            return None

        request: Optional[ModbusADU_Request] = None
        # Create the appropriate request based on the function code
        if func_code == Commands.READ_COILS:  # Read Coils
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU01_Read_Coils(
                funcCode=func_code, startAddr=start_addr, quantity=quantity
            )
        elif func_code == Commands.READ_DISCRETE_INPUTS:  # Read Discrete Inputs
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU02_Read_Discrete_Inputs(
                funcCode=func_code, startAddr=start_addr, quantity=quantity
            )
        elif func_code == Commands.READ_HOLDING_REGISTERS:  # Read Holding Registers
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU03_Read_Holding_Registers(
                funcCode=func_code, startAddr=start_addr, quantity=quantity
            )
        elif func_code == Commands.READ_INPUT_REGISTERS:  # Read Input Registers
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU04_Read_Input_Registers(
                funcCode=func_code, startAddr=start_addr, quantity=quantity
            )
        elif func_code == Commands.WRITE_SINGLE_COIL:  # Write Single Coil
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU05_Write_Single_Coil(
                funcCode=func_code, outputAddr=start_addr, outputValue=data
            )
        elif (
            func_code == Commands.WRITE_SINGLE_HOLDING_REGISTER
        ):  # Write Single Register
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=6
            ) / ModbusPDU06_Write_Single_Register(
                funcCode=func_code, registerAddr=start_addr, registerValue=data
            )
        elif func_code == Commands.READ_EXCEPTION_STATE:  # Read Exception Status
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=2
            ) / ModbusPDU07_Read_Exception_Status(funcCode=func_code)
        elif func_code == Commands.WRITE_MULTIPLE_COILS:  # Write Multiple Coils
            request = ModbusADU_Request(
                unitId=uid, protoId=0
            ) / ModbusPDU0F_Write_Multiple_Coils(
                funcCode=func_code,
                startAddr=start_addr,
                quantityOutput=quantity,
                outputsValue=data,
            )
        elif (
            func_code == Commands.WRITE_MULTIPLE_HOLDING_REGISTERS
        ):  # Write Multiple Registers
            request = ModbusADU_Request(
                unitId=uid, protoId=0
            ) / ModbusPDU10_Write_Multiple_Registers(
                funcCode=func_code,
                startAddr=start_addr,
                quantityRegisters=quantity,
                outputsValue=data,
            )
        elif func_code == Commands.REPORT_SLAVE_ID:  # Report Slave ID
            request = ModbusADU_Request(
                unitId=uid, protoId=0, len=2
            ) / ModbusPDU11_Report_Slave_Id(funcCode=func_code)
        else:  # Custom command
            request = ModbusADU_Request(
                unitId=uid, protoId=0
            ) / ModbusPDUXX_Custom_Request(
                customBytes=[func_code] + (data if data else [])
            )
        self.logger.debug(
            f"Request created: {request.show(dump=True) if request else 0}"
        )  # summary()"
        return request

    def create_response(
        self,
        uid: int,
        func_code: int,
        exception: int = 0,
        data: Optional[List[int]] = None,
    ) -> Optional[ModbusADU_Response]:
        """Creates a Modbus response based on the function code and data."""

        self.logger.info(
            f"Creating response: uid={uid}, func_code={func_code}, exception={exception}, data={data}"
        )

        response: Optional[ModbusADU_Response] = None

        if (uid > 247) or (uid < 1):
            self.logger.error(f"The UID to set is incorrect: {uid}")
            return None

        if (func_code < 0) or (func_code > 255):
            self.logger.error(f"The function code to set is incorrect: {func_code}")
            return None

        # Normalize data to a list for safe indexing
        data_list = data if data is not None else []

        # Create the appropriate response based on the function code
        # The data field can be used flexibly to inject the command errors (intentionally allow this)
        if (func_code & MB_EXCEPTION_MASK) or (
            (exception != 0) and (exception is not None)
        ):
            response = ModbusADU_Response(unitId=uid, protoId=0) / ModbusPDU_Exception(
                funcCode=(int(func_code) | MB_EXCEPTION_MASK), exceptCode=exception
            )
        elif func_code == Commands.READ_COILS:  # Read Coils
            if not data_list or len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU01_Read_Coils_Answer(
                funcCode=func_code, byteCount=len(data_list), coilStatus=data_list
            )
        elif func_code == Commands.READ_DISCRETE_INPUTS:  # Read Discrete Inputs
            if not data_list or len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU02_Read_Discrete_Inputs_Answer(
                funcCode=func_code, byteCount=len(data_list), inputStatus=data_list
            )
        elif func_code == Commands.READ_HOLDING_REGISTERS:  # Read Holding Registers
            if not data_list or len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU03_Read_Holding_Registers_Answer(
                funcCode=func_code, byteCount=len(data_list) * 2, registerVal=data_list
            )
        elif func_code == Commands.READ_INPUT_REGISTERS:  # Read Input Registers
            if not data_list or len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU04_Read_Input_Registers_Answer(
                funcCode=func_code, byteCount=len(data_list) * 2, registerVal=data_list
            )
        elif func_code == Commands.WRITE_SINGLE_COIL:  # Write Single Coil
            if not data_list or len(data_list) < 2:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 2"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU05_Write_Single_Coil_Answer(
                funcCode=func_code, outputAddr=data_list[0], outputValue=data_list[1]
            )
        elif (
            func_code == Commands.WRITE_SINGLE_HOLDING_REGISTER
        ):  # Write Single Register
            if not data_list or len(data_list) < 2:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 2"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU06_Write_Single_Register_Answer(
                funcCode=func_code,
                registerAddr=data_list[0],
                registerValue=data_list[1],
            )
        elif func_code == Commands.READ_EXCEPTION_STATE:  # Read Exception Status
            if len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU07_Read_Exception_Status_Answer(
                funcCode=func_code, startAddr=data_list[0]
            )
        elif (
            func_code == Commands.WRITE_MULTIPLE_COILS
        ):  # Write Multiple Coils (can simulate error in the response using data)
            if len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU0F_Write_Multiple_Coils_Answer(
                funcCode=func_code, startAddr=data_list[0], quantityOutput=data_list[1]
            )
        elif (
            func_code == Commands.WRITE_MULTIPLE_HOLDING_REGISTERS
        ):  # Write Multiple Registers
            if len(data_list) < 1:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 1"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDU10_Write_Multiple_Registers_Answer(
                funcCode=func_code,
                startAddr=data_list[0],
                quantityRegisters=data_list[1],
            )
        elif func_code == Commands.REPORT_SLAVE_ID:  # Report Slave ID
            if len(data_list) < 2:
                self.logger.error(
                    f"Response data length is incorrect {len(data_list)} < 2"
                )
                return None
            response = ModbusADU_Response(
                unitId=uid,
                protoId=0,
            ) / ModbusPDU11_Report_Slave_Id_Answer(
                funcCode=func_code, byteCount=len(data_list), slaveIdent=data_list
            )
        else:  # Custom command
            response = ModbusADU_Response(
                unitId=uid, protoId=0
            ) / ModbusPDUXX_Custom_Answer(
                funcCode=func_code, customBytes=data if data else []
            )
        self.logger.debug(
            f"Response created: {response.show(dump=True) if response else 0}"
        )  # summary()"
        return response

    def make_exception_response(
        self, request: ModbusADU_Request, exception: Exceptions
    ) -> ModbusADU_Response:
        """Build a Modbus exception response from the request and exception code."""
        func_code = int(bytes(request[ModbusADU_Request].payload)[0])
        return cast(
            ModbusADU_Response,
            ModbusADU_Response(unitId=request.unitId, protoId=0)
            / ModbusPDU_Exception(
                funcCode=(func_code | MB_EXCEPTION_MASK), exceptCode=int(exception)
            ),
        )

    def make_random_response(self, request: ModbusADU_Request) -> ModbusADU_Response:
        """Generate a response frame based on the request payload."""
        payload = bytes(request[ModbusADU_Request].payload)

        funcCode = int(payload[0])
        # Create a new response frame
        response = ModbusADU_Response()

        # Copy common fields from request to response
        response.transId = request.transId
        response.protoId = request.protoId
        response.unitId = request.unitId
        startAddr: int = 0
        quantity: int = 0
        byteCount: int = 0

        # Create appropriate response payload based on function code
        if funcCode == Commands.READ_COILS:  # Read Coils
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantity = int.from_bytes(payload[3:5], byteorder="big")

            # Calculate byte count (1 byte per 8 coils, rounded up)
            byteCount = (quantity + 7) // 8

            # Create response payload with random coil status
            coilStatus: list[int] = [random.randint(0, 255) for _ in range(byteCount)]
            response_payload = ModbusPDU01_Read_Coils_Answer(
                funcCode=Commands.READ_COILS, byteCount=byteCount, coilStatus=coilStatus
            )

        elif funcCode == Commands.READ_DISCRETE_INPUTS:  # Read Discrete Inputs
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantity = int.from_bytes(payload[3:5], byteorder="big")

            # Calculate byte count (1 byte per 8 inputs, rounded up)
            byteCount = (quantity + 7) // 8
            # Create response payload with random input status
            inputStatus: list[int] = [random.randint(0, 255) for _ in range(byteCount)]
            response_payload = ModbusPDU02_Read_Discrete_Inputs_Answer(
                funcCode=Commands.READ_DISCRETE_INPUTS,
                byteCount=byteCount,
                inputStatus=inputStatus,
            )

        elif funcCode == Commands.READ_HOLDING_REGISTERS:  # Read Holding Registers
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantity = int.from_bytes(payload[3:5], byteorder="big")

            # Calculate byte count (2 bytes per register)
            byteCount = quantity * 2

            # Create response payload with random register values
            response_payload = ModbusPDU03_Read_Holding_Registers_Answer(
                funcCode=Commands.READ_HOLDING_REGISTERS,
                byteCount=byteCount,
                registerVal=[random.randint(0, 65535) for _ in range(quantity)],
            )

        elif funcCode == Commands.READ_INPUT_REGISTERS:  # Read Input Registers
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantity = int.from_bytes(payload[3:5], byteorder="big")

            # Calculate byte count (2 bytes per register)
            byteCount = quantity * 2

            # Create response payload with random register values
            response_payload = ModbusPDU04_Read_Input_Registers_Answer(
                funcCode=Commands.READ_INPUT_REGISTERS,
                byteCount=byteCount,
                registerVal=[random.randint(0, 65535) for _ in range(quantity)],
            )

        elif funcCode == Commands.WRITE_SINGLE_COIL:  # Write Single Coil
            outputAddr = int.from_bytes(payload[1:3], byteorder="big")
            outputValue = int.from_bytes(payload[3:5], byteorder="big")

            response_payload = ModbusPDU05_Write_Single_Coil_Answer(
                funcCode=Commands.WRITE_SINGLE_COIL,
                outputAddr=outputAddr,
                outputValue=outputValue,
            )

        elif (
            funcCode == Commands.WRITE_SINGLE_HOLDING_REGISTER
        ):  # Write Single Register
            registerAddr = int.from_bytes(payload[1:3], byteorder="big")
            registerValue = int.from_bytes(payload[3:5], byteorder="big")

            response_payload = ModbusPDU06_Write_Single_Register_Answer(
                funcCode=Commands.WRITE_SINGLE_HOLDING_REGISTER,
                registerAddr=registerAddr,
                registerValue=registerValue,
            )

        elif funcCode == Commands.READ_EXCEPTION_STATE:  # Read Exception Status
            # Create response payload with random exception status
            response_payload = ModbusPDU07_Read_Exception_Status_Answer(
                funcCode=Commands.READ_EXCEPTION_STATE, startAddr=random.randint(0, 255)
            )

        elif funcCode == Commands.WRITE_MULTIPLE_COILS:  # Write Multiple Coils
            # Extract request parameters
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantityOutput = int.from_bytes(payload[3:5], byteorder="big")

            # Create response payload with the parameters
            response_payload = ModbusPDU0F_Write_Multiple_Coils_Answer(
                funcCode=Commands.WRITE_MULTIPLE_COILS,
                startAddr=startAddr,
                quantityOutput=quantityOutput,
            )

        elif (
            funcCode == Commands.WRITE_MULTIPLE_HOLDING_REGISTERS
        ):  # Write Multiple Registers
            # Extract request parameters
            startAddr = int.from_bytes(payload[1:3], byteorder="big")
            quantityRegisters = int.from_bytes(payload[3:5], byteorder="big")

            # Create response payload with same parameters
            response_payload = ModbusPDU10_Write_Multiple_Registers_Answer(
                funcCode=Commands.WRITE_MULTIPLE_HOLDING_REGISTERS,
                startAddr=startAddr,
                quantityRegisters=quantityRegisters,
            )

        elif funcCode == Commands.REPORT_SLAVE_ID:  # Report Slave ID
            # Create response payload with random slave ID and status
            byteCount = random.randint(1, 10)
            # slaveUid: int = response.unitId # random.randint(0, 247)
            # runIndicatorStatus: int = random.randint(0, 255)
            slaveIdent: list[int] = [random.randint(0, 255) for _ in range(byteCount)]

            response_payload = ModbusPDU11_Report_Slave_Id_Answer(
                funcCode=Commands.REPORT_SLAVE_ID,
                byteCount=byteCount,
                # slaveUid = slaveUid,
                # runIdicatorStatus = runIndicatorStatus,
                slaveIdent=slaveIdent,
            )

        else:
            # Handle custom commands
            if len(payload) > 1:
                custom_data: list[int] = list(payload[1:])
                response_payload = ModbusPDUXX_Custom_Answer(
                    funcCode=funcCode, customBytes=custom_data
                )
            else:
                # Handle unsupported function codes with exception
                response_payload = ModbusPDUXX_Custom_Exception(
                    funcCode=0x80 | funcCode, exceptCode=Exceptions.ILLEGAL_FUNCTION
                )

        response.payload = response_payload
        response.len = len(bytes(response_payload)) + 1  # +1 for the function code
        return response

    def verify_request(
        self,
        req: Optional[ModbusADU_Request],
        expected_req: Optional[ModbusADU_Request],
    ) -> Exceptions:
        """Based on command classes verify that the received request matches the expected request."""
        # Compare the UID of the frame
        if req is not None and expected_req is not None:
            if (ModbusADU_Request not in req) or (
                ModbusADU_Request not in expected_req
            ):
                self.logger.debug(
                    f"Request frame is incorrect, return {Exceptions.ILLEGAL_DATA_ADDRESS.name}."
                )
                return Exceptions.ILLEGAL_DATA_ADDRESS
            elif req.unitId != expected_req.unitId:
                self.logger.debug(
                    f"UID in req {req.unitId} != UID expected: {expected_req.unitId}."
                )
                return Exceptions.ILLEGAL_DATA_ADDRESS
        else:
            return Exceptions.ILLEGAL_FUNCTION

        req_payload: bytes = bytes(req[ModbusADU_Request].payload)
        exp_payload: bytes = bytes(expected_req[ModbusADU_Request].payload)
        req_addr: int = 0
        req_quantity: int = 0
        exp_start_addr: int = 0
        exp_quantity: int = 0

        # Compare the function codes
        func_code: int = req_payload[0] & MB_EXCEPTION_FUNC_MASK
        if func_code != exp_payload[0]:  # Function code
            self.logger.debug(
                f"FC in req {func_code} != FC expected: {exp_payload[0]}."
            )
            return Exceptions.ILLEGAL_FUNCTION

        if func_code in [
            Commands.READ_COILS,
            Commands.READ_DISCRETE_INPUTS,
            Commands.READ_HOLDING_REGISTERS,
            Commands.READ_INPUT_REGISTERS,
        ]:
            req_addr = int.from_bytes(req_payload[1:3], byteorder="big")
            req_quantity = int.from_bytes(req_payload[3:5], byteorder="big")

            exp_start_addr = int.from_bytes(exp_payload[1:3], byteorder="big")
            exp_quantity = int.from_bytes(exp_payload[3:5], byteorder="big")

            if req_addr != exp_start_addr:
                self.logger.debug(
                    f"Invalid start address: expected {exp_start_addr}, received: {req_addr}."
                )
                return Exceptions.ILLEGAL_DATA_ADDRESS

            if req_quantity != exp_quantity:
                self.logger.debug(
                    f"Invalid register quantity: expected {exp_quantity}, received: {req_quantity}."
                )
                return Exceptions.ILLEGAL_DATA_VALUE

        elif func_code in [
            Commands.WRITE_SINGLE_COIL,
            Commands.WRITE_SINGLE_HOLDING_REGISTER,
        ]:  # Write single register class
            req_addr = int.from_bytes(req_payload[1:3], byteorder="big")
            req_value = int.from_bytes(req_payload[3:5], byteorder="big")

            exp_addr = int.from_bytes(exp_payload[1:3], byteorder="big")
            exp_value = int.from_bytes(exp_payload[3:5], byteorder="big")

            if req_addr != exp_addr:
                self.logger.debug(
                    f"Invalid address: expected {exp_addr}, received: {req_addr}."
                )
                return Exceptions.ILLEGAL_DATA_ADDRESS

            if req_value != exp_value:  # Using quantity parameter for the value
                self.logger.debug(
                    f"Invalid value: expected {exp_value}, received: {req_value}."
                )
                return Exceptions.ILLEGAL_DATA_VALUE

        elif func_code in [
            Commands.WRITE_MULTIPLE_COILS,
            Commands.WRITE_MULTIPLE_HOLDING_REGISTERS,
        ]:  # Write multiple registers class
            req_addr = int.from_bytes(req_payload[1:3], byteorder="big")
            req_quantity = int.from_bytes(req_payload[3:5], byteorder="big")

            exp_addr = int.from_bytes(exp_payload[1:3], byteorder="big")
            exp_quantity = int.from_bytes(exp_payload[3:5], byteorder="big")

            if req_addr != exp_addr:
                self.logger.debug(
                    f"Invalid start address: expected {exp_addr}, received: {req_addr}"
                )
                return Exceptions.ILLEGAL_DATA_ADDRESS

            if req_quantity != exp_quantity:
                self.logger.debug(
                    f"Invalid quantity: expected {exp_quantity}, received: {req_quantity}."
                )
                return Exceptions.ILLEGAL_DATA_VALUE

            # Check data if provided
            if (len(exp_payload) > 5) and (len(req_payload)) > 5:
                req_data = list(req_payload[5:])
                exp_data = list(exp_payload[5:])
                if req_data != exp_data:
                    self.logger.debug(
                        f"Invalid data: expected {exp_data}, received: {req_data}."
                    )
                    return Exceptions.ILLEGAL_DATA_VALUE

        elif func_code == Commands.REPORT_SLAVE_ID:  # Report Slave ID
            # Vendor specific command, no additional parameters to check
            pass

        else:  # Custom command 0x41
            if (len(exp_payload) > 1) and (len(req_payload) > 1):
                min_length: int = min(len(req_payload), len(exp_payload))
                req_data = list(req_payload[1:min_length])
                exp_data = list(exp_payload[1:min_length])
                if req_data != exp_data:
                    self.logger.debug(
                        f"Invalid custom data: expected {exp_data}, received: {req_data}."
                    )
                    return Exceptions.ILLEGAL_DATA_VALUE

        return Exceptions.UNDEFINED


class Transaction(Queue):
    """Modbus transaction class to enqueue the pair of request and response and async functionality.

    The async behavior is realized through inharitance of queue. So, one thread calls the
    `confirmation_put()` to enqueue a transaction and the other side should call the
    `geconfirmation_get()` to retrieve it. It also tracks additional information.
    """

    counter: int = 0

    def __init__(
        self,
        address: Optional[Tuple] = None,
        time_stamp: Optional[float] = None,
        request: Optional[Packet] = None,
        response: Optional[Packet] = None,
    ) -> None:
        # transaction metadata
        self.address: Optional[Tuple[str, int]] = address
        self.id: int = 0
        self.state: HandlingStateEnum = HandlingStateEnum.DEFAULT
        self.exception = Exceptions.DEFAULT
        self.time_stamp: float = time_stamp if time_stamp is not None else time.time()
        self.request: Optional[Packet] = request
        self.response: Optional[Packet] = response
        self.ref_index: int = -1
        self.confirmation: Optional[Any] = None
        self.func: int = 0
        self.logger = logging.getLogger("RobotFramework")
        super().__init__(maxsize=MB_TRANSACTION_QUEUE_MAX_SZ)
        Transaction.counter += 1

    def confirmation_put(self, item: Any, timeout: float = 2.0) -> bool:
        """Put an item into the internal queue with timeout.
        Returns True on success, False on timeout or failure.
        """
        try:
            super().put(item, block=True, timeout=timeout)
            self.confirmation = item
            return True
        except Exception as e:
            self.logger.debug(f"Transaction.put failed: {e}")
            return False

    def confirmation_get(self, timeout: float = 2.0) -> Optional[Any]:
        """Get an item used as confirmation from the internal queue with timeout.
        Returns the item if available, or None on timeout.
        """
        try:
            item = super().get(block=True, timeout=timeout)
            return item
        except Empty:
            return None
        except Exception:
            # unexpected error, re-raise so caller can handle it
            raise

    def confirmation_reset(self) -> bool:
        """Reset the queue, return True if the internal queue is empty."""
        try:
            return super().empty()
        except Exception:
            return True

    def get_confirmation_size(self) -> int:
        """Return queue size."""
        try:
            return super().qsize()
        except Exception:
            return 0

    def set_request(self, request: Packet) -> Optional[Packet]:
        self.request = request
        self.get_request_id()
        return self.request

    def set_response(self, response: Packet) -> Optional[Packet]:
        self.response = response
        self.get_response_id()
        return self.response

    def get_request(self) -> Optional[Packet]:
        return self.request

    def get_response(self) -> Optional[Packet]:
        return self.response

    def get_request_id(self) -> Optional[int]:
        if (
            self.request is not None
            and hasattr(self.request, "haslayer")
            and self.request.haslayer(ModbusADU_Request)
        ):
            try:
                if (
                    self.request[ModbusADU_Request].protoId == 0
                    and self.request[ModbusADU_Request].transId
                ):
                    self.id = self.request[ModbusADU_Request].transId
                else:
                    self.id = 0
                    return 0
            except Exception:
                self.id = 0
                return None
            return self.id
        return None

    def get_response_id(self) -> Optional[int]:
        if (
            self.response is not None
            and hasattr(self.response, "haslayer")
            and self.response.haslayer(ModbusADU_Response)
        ):
            try:
                if (
                    self.response[ModbusADU_Response].protoId == 0
                    and self.response[ModbusADU_Response].transId
                ):
                    self.id = self.response[ModbusADU_Response].transId
                else:
                    self.id = 0
                    return 0
            except Exception:
                self.id = 0
                return None
            return self.id
        return None

    def set_time_stamp(self, timestamp: float) -> float:
        self.time_stamp = timestamp
        return self.time_stamp

    def get_time_stamp(self) -> float:
        return self.time_stamp


@library(scope="GLOBAL", version="2.1.1")
class ModbusSlaveLib:
    """Robot Framework library for Modbus Master testing.
    It contains the helper and wrapper functions for robot framework called as "keywords".
    """

    ROBOT_LIBRARY_SCOPE = "TEST SUITE"

    def __init__(
        self,
        frame_logging_enable: bool = True,
        slave_response_delay: Optional[float] = None,
    ) -> None:
        self.class_id = random.randint(0, 100)  # is to track of created instance number
        self.pcap_file_name: Optional[str] = None
        if frame_logging_enable:
            self.pcap_file_name = "{path}/{file}_{id}.{ext}".format(
                path=MB_LOGGING_PATH,
                file="mbs_frames",
                ext="pcap",
                id=str(self.class_id),
            )
            if os.path.isfile(self.pcap_file_name):
                os.remove(self.pcap_file_name)
        self.slave_response_delay = slave_response_delay
        self.server: Optional[ModbusServer] = ModbusServer(
            pcap_file=self.pcap_file_name,
            sock_timeout=1.0,
            slave_response_delay=slave_response_delay,
        )
        self.server_address: Optional[Tuple[str, int]] = None
        self.logger = logging.getLogger("RobotFramework")
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)
        self.logger.setLevel(MB_LOG_LEVEL)

    @keyword("Get Class Id")
    def get_class_id(self) -> int:
        """
        Return unique class ID for robot suit debugging.
        Args:
            None
        Returns:
            Class instance ID
        """
        return self.class_id

    @keyword("Get Server Address")
    def get_server_address(self) -> Optional[Tuple[str, int]]:
        """
        Return the address:port tuple of the server if active, else None.
        Args:
            None
        Returns:
            None: if server is not connected,
            Tuple of server address:port if the server is active
        """
        if self.is_server_active():
            return self.server_address
        return None

    @keyword("Start Server")
    def start_server(
        self,
        port: Optional[int] = 502,
        timeout: Optional[float] = None,
        asynchronous: bool = False,
    ) -> bool:
        """Start the Modbus server and begin capturing packets.
        Args:
            port (int, optional): Port number to use. Defaults to 502.
            timeout (float, optional): Timeout value in seconds. Defaults to None.
            pcap_file (str, optional): Path to pcap file for packet capture. Defaults to None.
            asynchronous (bool, optional): Whether to run server asynchronously. Defaults to False.
        Returns:
            bool: True if server started successfully
        """
        # Create and start the Modbus server
        try:
            if self.server:
                self.server_address = self.server.start_modbus_server(
                    port=port, timeout=timeout, asynchronous=asynchronous
                )
        except Exception as e:
            self.logger.error("Failed to start Modbus server: %s", e)
            return False
        return True

    @keyword("Stop Server")
    def stop_server(self) -> bool:
        """Stop the Modbus server."""
        server = self.server
        if server is not None and server.is_started:
            self.logger.info("Stopping Modbus server")
            server.stop_modbus_server()
            self.server = None
            self.server_address = None
        return True

    @keyword("Is Server Active")
    def is_server_active(self) -> bool:
        """Checks the server state."""
        return True if self.server and self.server.is_started else False

    @keyword("Verify Expected Request")
    def verify_expected_request_data(
        self,
        expected_request: ModbusADU_Request,
        uid: int,
        func_code: int,
        start_addr: int = 0,
        quantity: int = 1,
        exception: int = 0,
        data: Optional[List[int]] = None,
    ) -> Exceptions:
        """Construct request from individual fields and verify the request with expected one."""
        assert self.server is not None
        uid_n = self.server.validator.to_int(uid)
        fc_n = self.server.validator.to_int(func_code)
        sa_n = self.server.validator.to_int(start_addr) or 0
        q_n = self.server.validator.to_int(quantity) or 1
        ex_n = self.server.validator.to_int(exception) or 0
        data_n = self.server.validator.to_list_int(data)

        request = self.server.validator.create_request(
            uid_n or 1,
            fc_n or 0,
            sa_n,
            q_n,
            ex_n,
            [x if x is not None else 0 for x in data_n] if data_n else None,
        )
        exception = self.server.validator.verify_request(request, expected_request)
        return exception

    @keyword("Verify Request")
    def verify_request(
        self,
        request: ModbusADU_Request,
        expected_request: Optional[ModbusADU_Request] = None,
    ) -> Exceptions:
        """Verify the request with expected one."""
        assert self.server is not None
        exception = self.server.validator.verify_request(request, expected_request)
        return exception

    @keyword("Add Expected Transaction")
    def add_expected_transaction(
        self,
        uid: Optional[Any] = None,
        func_code: Optional[Any] = None,
        start_addr: Optional[Any] = None,
        quantity: Optional[Any] = None,
        exception: Optional[Any] = None,
        data: Optional[Any] = None,
        expected_data: Optional[Any] = None,
        expectations: Optional[List[Transaction]] = None,
    ) -> Transaction:
        """Add an expected request and its response to the server."""
        assert self.server is not None
        # Input values from robot framework need to be normalized
        uid_n = self.server.validator.to_int(uid)
        fc_n = self.server.validator.to_int(func_code)
        sa_n = self.server.validator.to_int(start_addr) or 0
        q_n = self.server.validator.to_int(quantity) or 1
        ex_n = self.server.validator.to_int(exception) or 0
        data_n = self.server.validator.to_list_int(data)
        exp_n = self.server.validator.to_list_int(expected_data)

        # Create the expected request
        expected_request = self.server.validator.create_request(
            uid_n or 1,
            fc_n or 0,
            sa_n,
            q_n,
            ex_n,
            [x if x is not None else 0 for x in data_n] if data_n else None,
        )

        expected_response = None
        if expected_data is not None:
            expected_response = self.server.validator.create_response(
                uid_n or 1,
                fc_n or 0,
                ex_n,
                [x if x is not None else 0 for x in exp_n] if exp_n else None,
            )

        # Add to the list of expected requests and responses
        if expected_request is None or expected_response is None:
            raise RuntimeError(
                "Can not create expected request. Please check parameters."
            )

        expected_transaction = Transaction(
            request=expected_request, response=expected_response
        )
        if self.server:
            self.server.expected_transactions.append(expected_transaction)

        if expectations is not None:
            expectations.append(expected_transaction)
            self.logger.debug(
                f"Append into expectations: {expected_transaction.request}, {expected_transaction.response}."
            )
        return expected_transaction

    @keyword("Check Client Connected")
    def check_client_connected(self, timeout: float = 10) -> bool:
        """Verify the client connection status."""
        if self.server is not None and self.server.is_started:
            return self.server.check_client_connected(timeout)
        return False

    @keyword("Wait Transaction Data")
    def wait_transaction_data(
        self, timeout: float = 2.0, *args: Any, **kwargs: Any
    ) -> Optional[Transaction]:
        """
        Wait for transaction completion and get data from the server.
        """
        if self.server is not None:
            timeout_val: float = kwargs.get("timeout", timeout)
            kwargs_no_timeout = {k: v for k, v in kwargs.items() if k != "timeout"}
            return self.server.wait_transaction_data(
                timeout=timeout_val, **kwargs_no_timeout
            )
        return None

    @keyword("Wait Transaction Confirmation")
    def wait_transaction_confirmation(
        self, transaction: Optional[Transaction] = None, timeout: Optional[float] = 2.0
    ) -> Optional[Any]:
        """
        The wrapper function as a keyword for robot framework.
        Waits for transaction confirmation and return the data from queue.
        """
        confirm: Optional[Any] = None

        if isinstance(transaction, Transaction) and self.server is not None:
            confirm = self.server.wait_transaction_data(
                timeout=timeout if timeout is not None else 2.0,
                exp_transaction=transaction,
            )
            self.logger.debug(f"Try to get confirmation: {confirm}.")
            return confirm
        else:
            raise RuntimeError("Incorrect transaction object is provided.")
        return None

    @keyword("Create Request")
    def create_request(
        self,
        uid: int = 1,
        func_code: int = Commands.UNDEFINED,
        start_addr: int = 0,
        quantity: int = 1,
        exception: int = 0,
        data: Optional[List[int]] = None,
    ) -> Optional[ModbusADU_Request]:
        """Create a Modbus request based on the function code and parameters."""
        assert self.server is not None
        self.logger.info(
            f"Creating request: uid={uid}, func_code={func_code}, start_addr={start_addr}, \
                         quantity={quantity}, exception={exception}, data={data}"
        )

        uid_n = self.server.validator.to_int(uid)
        fc_n = self.server.validator.to_int(func_code)
        sa_n = self.server.validator.to_int(start_addr) or 0
        q_n = self.server.validator.to_int(quantity) or 1
        ex_n = self.server.validator.to_int(exception) or 0
        data_n = self.server.validator.to_list_int(data)

        request = self.server.validator.create_request(
            uid_n or 1,
            fc_n or 0,
            sa_n,
            q_n,
            ex_n,
            [x if x is not None else 0 for x in data_n] if data_n else None,
        )

        return request

    @keyword("Verify Expectations")
    def verify_expectations(
        self, expectations: List[Transaction], timeout: float = 2.0
    ) -> int:
        """
        The method starts the Modbus answering machine to collect the requests
        then verifies them against expected ones.
        """
        transaction: Optional[Transaction] = None
        try:
            if not all(expectations) or len(expectations) <= 0:
                raise RuntimeError("Expectation list is empty.")

            if self.server is None or not self.server.is_started:
                raise RuntimeError("Start server first before verify expectations.")

            if not self.check_client_connected(timeout=timeout):
                raise RuntimeError("Client did not connect within timeout.")

            self.logger.debug("Server started. Waiting for transactions...")
            server = self.server
            assert server is not None
            while time.time() - server.start_time_stamp < timeout + 1:
                transaction = self.wait_transaction_data(timeout=1.0)
                if (
                    not transaction
                    or not isinstance(transaction, Transaction)
                    or transaction.request is None
                    or transaction.response is None
                ):
                    # No transaction in this interval (or disconnected)
                    continue
                self.logger.debug(
                    f"Transaction: {transaction.request.get_time_stamp_str()}, \
                    {transaction.request.summary()} ->  {transaction.response.summary()}"
                )

                matched_index: Optional[int] = None
                for i, expected_transaction in enumerate(expectations):
                    if isinstance(expected_transaction, Transaction):
                        exception: Optional[Exceptions] = (
                            self.server.validator.verify_request(
                                transaction.request, expected_transaction.request
                            )
                        )
                        if (
                            exception == Exceptions.UNDEFINED
                            and transaction.state is HandlingStateEnum.RESPONDED
                        ):
                            matched_index = i
                            break

                if matched_index is not None:
                    expectations.pop(matched_index)
                    self.logger.info(
                        f"Expectation {matched_index}, Command: {Commands(bytes(transaction.request.payload)[0]).name}, matched."
                    )
                else:
                    # No matching expected request found
                    self.logger.error(
                        "Unexpected request received (no expectation matched)."
                    )

                # Optional early exit if all expectations have been satisfied
                if len(expectations) == 0:
                    self.logger.info("All expected transactions have been validated.")
                    break

        except Exception as e:
            raise Scapy_Exception(f"Exception occurred: {str(e)}")
        # finally:
        #     self.stop_server()

        return len(expectations)


class ModbusServer(AnsweringMachine[PacketList]):
    """Modbus answering machine implementation.

    The class includes the server functionality to manage the incoming Master connections
    and handling the requests using the validator class. It registers the transaction and
    which can be handled concurrently in other thread.
    """

    optsniff: Dict[str, Any] = {"store": 0, "iface": None}
    iface: Optional[str] = None
    port: Optional[int] = None
    cls: Type[Packet] = ModbusADU_Request

    def __init__(
        self,
        pcap_file: Optional[str] = None,
        expected_transactions: Optional[List[Transaction]] = None,
        sock_timeout: float = 1.0,
        slave_response_delay: Optional[float] = None,
    ) -> None:
        super().__init__()
        self.class_id = random.randint(0, 100)  # is to track of created instance number
        # Server configuration
        self.port = None
        self.sock_timeout: float = sock_timeout
        self.expected_transactions: List[Transaction] = expected_transactions or []
        # Setup data validator
        self.validator = ModbusValidator()
        # Logging setup
        self.logger = logging.getLogger("ModbusSlaveLib")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        self.start_time_stamp: float = 0
        self.server_stop_time_stamp: float = 0
        self.slave_response_delay = slave_response_delay
        self.logger.addHandler(handler)
        self.host_ip: Optional[str] = None
        self.pcap_file: Optional[str] = pcap_file
        self.is_started: bool = False
        self.clients: List[Tuple[Tuple[str, int], AsyncSniffer, StreamSocket]] = []
        self.listen_sock: Optional[socket.socket] = None
        self.server_start_event = Event()
        self.server_start_event.clear()
        self.curr_transaction = Transaction()
        self.server_thread: Optional[Thread] = None
        self.server_thread_lock: Lock = Lock()
        self.server_data_lock: Lock = Lock()

    def get_current_ip(self) -> Optional[str]:
        """Get the current IP address of the machine."""
        ip: Optional[str] = None
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(3)
            s.connect(("<broadcast>", 12345))
            ip = s.getsockname()[0]

        except Exception as e:
            raise Scapy_Exception(f"Exception occurred: {e}")

        finally:
            s.close()

        return ip

    def find_interface_by_ip(self, ip_address: str) -> Optional[str]:
        """Find the network interface that corresponds to the given IP address."""
        interfaces: List[str] = get_if_list()
        for iface in interfaces:
            try:
                iface_ip = get_if_addr(iface)
                if iface_ip == ip_address:
                    return iface
            except Exception:
                continue
        return None

    def start_modbus_server(
        self,
        port: Optional[int] = 502,
        timeout: Optional[float] = None,
        asynchronous: bool = False,
    ) -> Optional[Tuple[str, int]]:
        """Start the Modbus server."""
        self.host_ip = self.get_current_ip()
        if self.host_ip is None:
            self.logger.warning("Failed to get host IP address.")
            return None
        default_iface: Optional[str] = self.find_interface_by_ip(self.host_ip)
        self.port = port if port is not None else 502
        self.iface = default_iface
        if not self.is_started:
            self.logger.info(
                f"Starting Modbus server instance {self.class_id} on interface: {default_iface}, port {self.port}"
            )
            self.is_started = True
            self(
                bg=asynchronous,
                server_timeout=timeout,
                iface=default_iface,
                filter=f"tcp port {self.port} or tcp port 502",
            )
        else:
            self.logger.info(
                f"Modbus server {self.class_id} is active on interface: {default_iface}, port {self.port}"
            )
        return (self.host_ip, self.port)

    def stop_modbus_server(self) -> None:
        """Stop the Modbus server."""
        if self.server_thread is not None:
            try:
                self.server_thread_lock.release()
            except Exception:
                pass
        self.is_started = False
        self.server_start_event.clear()
        self.curr_transaction.confirmation_reset()
        self.host_ip = None
        self.iface = None
        self.close()

    def join_modbus_thread(self, timeout: float) -> None:
        """Wait for the completion, of Modbus server, but do not close."""
        if self.server_thread is not None:
            self.server_thread.join(timeout=timeout)

    def check_client_connected(self, timeout: float = 0) -> bool:
        """Check if client is connected with timeout."""
        server_state: bool = False
        if self.is_started:
            server_state = self.server_start_event.wait(timeout=timeout)
        return server_state

    def wait_transaction_data(
        self, timeout: float = 10, exp_transaction: Optional[Transaction] = None
    ) -> Optional[Any]:
        """Wait incoming data event and returns last transaction."""
        data: Optional[Any] = None

        if not self.check_client_connected(timeout=timeout):
            return None

        # Wait for event with 1 second tick while the server is active
        while time.time() - self.start_time_stamp < timeout:
            if not self.is_started:
                return None
            try:
                if exp_transaction is not None and isinstance(
                    exp_transaction, Transaction
                ):
                    data = exp_transaction.confirmation_get(timeout=1.0)
                else:
                    data = self.curr_transaction.confirmation_get(timeout=1.0)

                if data is not None:
                    if isinstance(data, int):
                        self.logger.debug(f"Transaction confirmed with data = {data}")
                    if isinstance(data, Transaction):
                        self.logger.debug(
                            f"Transaction confirmed with data={data.ref_index}"
                        )
                    return data

            except Empty:
                self.logger.debug("Timeout waiting for incoming data.")
                continue

        return None

    def is_request(self, req: Packet) -> bool:
        """Check if the packet is a Modbus TCP request."""
        return ModbusADU_Request in req

    def generate_mac_address(self) -> str:
        """Generate a random MAC address for the server."""
        # Use HP vendor
        mac = [
            0x00,
            0x24,
            0x81,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(map(lambda x: "%02x" % x, mac))

    def frame_logger(
        self, address: Tuple[str, int], request: Packet, response: Packet
    ) -> None:
        """Generate fake frames to mimic the whole transactions for pcap logging.
        The lower layer data is not important here.
        """
        pcap_out: Packet
        pcap_in: Packet
        src_mac: str = self.generate_mac_address()
        dst_mac: str = self.generate_mac_address()
        if not response.haslayer(Ether):
            pcap_out = Ether(src=dst_mac, dst=src_mac)
        if not response.haslayer(IP):
            pcap_out /= IP(dst=self.host_ip, src=address[0])
        if not response.haslayer(TCP):
            pcap_out /= TCP(dport=502, sport=int(random.randint(37000, 39000)))
        pcap_out /= response
        if not request.haslayer(Ether):
            pcap_in = Ether(src=src_mac, dst=dst_mac)
        if not request.haslayer(IP):
            pcap_in /= IP(src=address[0], dst=self.host_ip)
        if not request.haslayer(TCP):
            pcap_in /= TCP(dport=502, sport=address[1])
        pcap_in /= request
        # record the packets sent/received
        wrpcap(self.pcap_file, pcap_in, append=True)
        wrpcap(self.pcap_file, pcap_out, append=True)
        self.logger.info(
            f"Received request from {self.iface}: {address}:\n {request.show(dump=True)}"
        )
        self.logger.info(
            f"Send response to {self.iface}:{address}:\n {response.show(dump=True)}"
        )

    def print_reply(self, req: Packet, reply: Packet) -> None:
        """This method prints the request and reply packets.
        This is called by the AnsweringMachine class.
        """
        # For debugging, to avoid mutable packet issues, comment it out
        # print(f"{req.summary()} ==> {reply.summary()} on {self.iface}")

    def send_reply(self, reply: Any, send_function: Optional[Callable] = None) -> None:
        if send_function:
            if reply:
                self.logger.info(
                    f"Send binary reply: {binascii.hexlify(bytes(reply)).decode('ascii')}"
                )
                if self.slave_response_delay:
                    time.sleep(
                        self.slave_response_delay
                    )  # small delay before send (emulate slow slave)
                try:
                    send_function(bytes(reply))
                except Exception as exception:
                    raise Scapy_Exception(f"Send fail: {exception}")
        else:
            self.logger.error(
                "Interface configuration is incorrect (send function is not configured)."
            )

    @staticmethod
    def _get_request_func_code_and_tid(
        request: Optional[Packet],
    ) -> Tuple[int, int]:
        """Extract function code and transaction ID from a Modbus request. Returns (0, 0) on error."""
        if request is None or ModbusADU_Request not in request:
            return (0, 0)
        try:
            adu = request[ModbusADU_Request]
            payload = bytes(adu.payload)
            func_code = int(payload[0]) if payload else 0
            tid = int(adu.transId) if adu.transId is not None else 0
            return (func_code, tid)
        except (TypeError, IndexError, ValueError, AttributeError):
            return (0, 0)

    @staticmethod
    def _get_payload_func_code(packet: Optional[Packet]) -> int:
        """Extract function code (first payload byte) from a Modbus request or response. Returns 0 on error."""
        if packet is None:
            return 0
        for layer in (ModbusADU_Request, ModbusADU_Response):
            if layer in packet:
                try:
                    payload = bytes(packet[layer].payload)
                    return int(payload[0]) if payload else 0
                except (TypeError, IndexError, ValueError):
                    pass
        return 0

    def make_reply(
        self, req: Packet, address: Optional[Tuple[str, int]] = None
    ) -> Packet:
        """Generate a Modbus TCP response based on the request.
        This method is called by the AnsweringMachine class.
        """
        if not self.server_data_lock.acquire(blocking=True, timeout=self.sock_timeout):
            self.logger.error(
                f"Can not lock the receiver {address} thread, after timeout."
            )
            raise TimeoutError(
                f"Could not acquire lock within "
                f"specified timeout of {self.sock_timeout}s"
            )
        # Verify and process the request and check for expected response
        try:
            try:
                request: Optional[ModbusADU_Request] = req
            except Exception:
                request = None
            if request is None:
                err_resp = ModbusADU_Response(
                    unitId=0, protoId=0
                ) / ModbusPDU_Exception(
                    funcCode=0x80, exceptCode=Exceptions.SLAVE_DEVICE_FAILURE
                )
                return err_resp.build()
            response: Optional[ModbusADU_Response] = None
            expected_transaction: Optional[Transaction] = None
            mb_exception: Exceptions = Exceptions.DEFAULT
            tid: int = 0

            transaction = Transaction(
                address=address,
                time_stamp=time.time(),
                request=request,
                response=response,
            )
            transaction.state = HandlingStateEnum.EXCEPTION
            transaction.func, _ = self._get_request_func_code_and_tid(request)
            for i, expected_transaction in enumerate(self.expected_transactions):
                if expected_transaction and expected_transaction.request:
                    mb_exception = self.validator.verify_request(
                        request, expected_transaction.request
                    )
                    if mb_exception == Exceptions.UNDEFINED:
                        if i < len(self.expected_transactions):
                            transaction.ref_index = i
                            expected_transaction.ref_index = i
                            if (
                                expected_transaction.response is not None
                                and self._get_payload_func_code(
                                    expected_transaction.request
                                )
                                == self._get_payload_func_code(
                                    expected_transaction.response
                                )
                            ):
                                transaction.state = HandlingStateEnum.RESPONDED
                                response = expected_transaction.response
                                response[ModbusADU_Response].unitId = request[
                                    ModbusADU_Request
                                ].unitId
                                response[ModbusADU_Response].transId = request[
                                    ModbusADU_Request
                                ].transId
                                response[ModbusADU_Response].len = (
                                    len(bytes(response[ModbusADU_Response].payload)) + 1
                                )
                                self.logger.info(
                                    f"Generated expected response: {response.summary()}"
                                )
                                request._mb_exception = mb_exception
                            else:
                                transaction.state = HandlingStateEnum.RANDOMIZED
                                response = self.validator.make_random_response(request)
                                self.logger.info(
                                    f"Generated random response: {response.summary()}"
                                )
                            self.logger.debug(
                                f"Expected request[{i}].{transaction.state.name} = "
                                f"{expected_transaction.request.summary()}."
                            )
                            transaction.set_response(response)
                            transaction.exception = mb_exception
                            transaction.func = self._get_payload_func_code(
                                expected_transaction.response
                            )
                            _, tid = self._get_request_func_code_and_tid(
                                transaction.request
                            )
                            transaction.confirmation_put(tid)
                            expected_transaction.confirmation_put(tid)
                            expected_transaction.state = transaction.state
                            expected_transaction.exception = transaction.exception
                            self.logger.debug(
                                f"Confirm transaction ref_index={transaction.ref_index}, TID={tid}"
                            )
                            break
                        else:
                            break
                    else:
                        if mb_exception > transaction.exception:
                            transaction.exception = mb_exception
                else:
                    self.logger.error(
                        f"Incorrect expected transaction {i} in the list, skip."
                    )

            self.logger.debug(
                f"Processed request from {address}: {transaction.state.name}, "
                f"{Commands(transaction.func & MB_EXCEPTION_FUNC_MASK).name}, "
                f"Exception: {transaction.exception}"
            )

            if response is None or mb_exception == Exceptions.DEFAULT:
                self.logger.info(
                    f"Request: {request.summary()}, is unexpected, exception response is sent."
                )
                transaction.state = HandlingStateEnum.EXCEPTION
                transaction.exception = (
                    Exceptions.ILLEGAL_FUNCTION
                    if mb_exception == Exceptions.DEFAULT
                    else mb_exception
                )
                response = self.validator.make_exception_response(
                    request, transaction.exception
                )
                self.logger.info(
                    f"Generate an exception response: {response.summary()}, "
                    f"exception: {transaction.exception.name}"
                )
                self.logger.debug(
                    f"Confirm transaction ref_index={transaction.ref_index}, TID={tid}"
                )

            if self.pcap_file and address is not None:
                self.frame_logger(address, request, response)

            response.set_time_stamp()  # update time stamp of response to the processing end time
            self.curr_transaction.confirmation_put(transaction, timeout=1.0)
            # Finally use the immutable binary packet over socket to avoid missing bytes
            return response.build()
        finally:
            self.server_data_lock.release()

    def parse_options(
        self,
        port: int = 1502,
        cls: Type[Packet] = ModbusADU_Request,
        server_timeout: Optional[float] = None,
    ) -> None:
        """Parse the options of the class and save them."""
        self.port = port
        self.cls = cls
        self.server_timeout = server_timeout

    def on_sniff_started(self) -> None:
        """Callback when the sniffer is started."""
        self.server_start_event.set()
        self.logger.debug("The async sniffer is started...")

    def sniff(self) -> None:
        """Main server loop to handle incoming connections and start sniffers.
        The server listens for incoming Modbus TCP connections and starts
        an AsyncSniffer for each connected client to handle Modbus requests.
        The AnsweringMachine.make_reply() method is used to generate responses for each client.
        The server runs until the active flag is set to False or a timeout occurs.
        This method can be called in a separate thread or process when needed for
        asynchronous operation.
        """
        self.logger.info("Waiting for new client connection...")
        # Create listening socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.settimeout(
            self.sock_timeout
        )  # the socket timeout will not block forever while waiting for connection
        try:
            self.listen_sock.bind(
                (get_if_addr(self.optsniff.get("iface", conf.iface)), self.port)
            )
            self.listen_sock.listen()
        except OSError:
            pass
        self.start_time_stamp = time.time()  # fix start up time stamp of the server
        self.logger.info(
            f"The server start time: {datetime.fromtimestamp(self.start_time_stamp)}"
        )
        sock: Optional[StreamSocket] = None
        try:
            # Server cycle to handle new Master connections
            while self.is_started:
                try:
                    # Wait for new client connection with timeout
                    client_sock, address = self.listen_sock.accept()
                    # Timeout to handle socket disconnection
                    client_sock.settimeout(self.sock_timeout)
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    # Create the socket associated with client
                    sock = StreamSocket(client_sock, self.cls)
                    optsniff = self.optsniff.copy()
                    optsniff["prn"] = functools.partial(
                        self.reply, send_function=sock.send, address=address
                    )
                    del optsniff["iface"]
                    # Start async Modbus answering machine for the connected client
                    sniffer = AsyncSniffer(
                        opened_socket=sock,
                        started_callback=self.on_sniff_started,
                        **optsniff,
                    )
                    sniffer.start()
                    self.clients.append((address, sniffer, sock))
                    self.logger.info(
                        f"The client {address} is connected, start sniffer on socket {sock.fileno()}."
                    )

                except socket.timeout:
                    self.logger.debug(
                        f"Handling {len(self.clients)}, active connection(s)."
                    )
                    if (
                        self.is_started
                        and self.server_timeout
                        and (time.time() - self.start_time_stamp > self.server_timeout)
                    ):
                        self.logger.debug("Server timeout reached, stop listening.")
                        self.is_started = False

                except (BlockingIOError, InterruptedError):
                    self.logger.debug("blocking error")
                    pass

                except socket.error:
                    pass

                except Exception:
                    client_sock.close()
                    raise

        finally:
            if self.is_started:
                self.is_started = False
                self.logger.debug("Server thread is not completed correctly.")
            self.server_stop_time_stamp = time.time()
            self.logger.info(
                f"The server thread stop time: {datetime.fromtimestamp(self.server_stop_time_stamp)}"
            )
            if self.server_thread:
                try:
                    self.server_thread_lock.release()
                except Exception:
                    pass
            self.server_start_event.clear()

    def sniff_bg(self) -> None:
        """Start answering machine for connection handling in separate thread
        to allow asynchronous operations.
        """
        if self.server_thread_lock.acquire(False):
            _t = Thread(target=self.sniff, name="modbus_server")
            _t.daemon = True
            _t.start()
            self.server_thread = _t
            self.logger.info(f"Server thread is started with ID: {_t.ident:x}")
        else:
            self.logger.error("Can not start server thread. Already started?")

    def close(self) -> None:
        """Close active connections and associated sniffers, client sockets, listening socket"""
        self.logger.info("Finally stop the async sniffers, free the objects.")
        if len(self.clients) >= 1:
            for address, sniffer, sock in self.clients:
                # Stop sniffer and then close communication socket for each connection
                self.logger.info(
                    f"Close Master connection: {address}, sock: {sock.fileno()}"
                )
                try:
                    sniffer.stop()
                except Exception:
                    pass
                sock.close()
        # super(AnsweringMachine, self).close()
        if self.listen_sock is not None:
            self.listen_sock.close()
        if self.server_thread is not None:
            self.server_thread = None


def self_test_register_expectations(
    slave: ModbusSlaveLib, expectations: List[Transaction] = []
) -> int:
    MB_DEF_START_OFFS = 0x0000
    MB_DEF_QUANTITY = 2
    if slave:
        # The fields: func_code, start_addr, quantity, exception, data, expected_response
        slave.add_expected_transaction(
            0x01,
            Commands.CUSTOM_COMMAND_41,
            0x0000,
            0,
            0,
            None,
            [0x11, 0x22, 0x33],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.REPORT_SLAVE_ID,
            0x0000,
            0,
            0,
            None,
            [0x01, 0x0F, 0x00],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.READ_HOLDING_REGISTERS,
            MB_DEF_START_OFFS,
            MB_DEF_QUANTITY,
            0,
            None,
            [0x1122, 0x3344],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.WRITE_SINGLE_HOLDING_REGISTER,
            MB_DEF_START_OFFS,
            0,
            0,
            [0x1234],
            [MB_DEF_START_OFFS, 0x1234],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.WRITE_SINGLE_COIL,
            MB_DEF_START_OFFS,
            MB_DEF_QUANTITY,
            0,
            [0xFF00],
            [MB_DEF_START_OFFS, 0xFF00],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.WRITE_MULTIPLE_HOLDING_REGISTERS,
            MB_DEF_START_OFFS,
            2,
            0,
            [0x1122, 0x3344],
            [MB_DEF_START_OFFS, 2],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.READ_INPUT_REGISTERS,
            MB_DEF_START_OFFS,
            MB_DEF_QUANTITY,
            0,
            None,
            [0xA5A5, 0xA5A5],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.READ_COILS,
            MB_DEF_START_OFFS,
            8,
            0,
            None,
            [0xFF],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.WRITE_MULTIPLE_COILS,
            MB_DEF_START_OFFS,
            MB_DEF_QUANTITY,
            0,
            [0xFF],
            [MB_DEF_START_OFFS, MB_DEF_QUANTITY],
            expectations,
        )
        slave.add_expected_transaction(
            0x01,
            Commands.READ_DISCRETE_INPUTS,
            MB_DEF_START_OFFS,
            8,
            0,
            None,
            [0xFF],
            expectations,
        )
    else:
        slave.logger.info("The slave object is incorrect.")
        return 0

    return len(expectations)


def self_test_register_expect_all(
    slave: ModbusSlaveLib, expectations: List[Transaction], timeout: float = 20.0
) -> int:
    left_exp: int = 0
    try:
        left_exp = slave.verify_expectations(expectations=expectations, timeout=timeout)
        if left_exp:
            if len(expectations) > 0:
                slave.logger.info("Test finished but some expectations were not met:")
                for i, exp_transaction in enumerate(expectations):
                    if (
                        exp_transaction is not None
                        and exp_transaction.response
                        and exp_transaction.request is not None
                    ):
                        slave.logger.info(
                            f"-- Remaining expectation #{i}: {exp_transaction.request.summary()} -> expected response: {exp_transaction.response.summary()}"
                        )

    except Exception:
        raise

    return left_exp


def self_test_register_expect_each(
    slave: ModbusSlaveLib, expectations: List[Transaction], timeout: float = 20.0
) -> int:
    confirmed: int = 0
    slave.start_server(port=1502, timeout=timeout, asynchronous=True)
    if not slave.check_client_connected(timeout=timeout):
        raise RuntimeError("Client did not connect within timeout.")
    trans_id: Optional[int] = None
    for i, exp_transaction in enumerate(expectations):
        if (
            exp_transaction is not None
            and exp_transaction.response
            and exp_transaction.request
        ):
            trans_id = slave.wait_transaction_confirmation(
                transaction=exp_transaction, timeout=timeout
            )
            if trans_id is not None:
                slave.logger.info(
                    f"Expectation #{i} is confirmed with TID:0x{trans_id:04x}: {exp_transaction.request.summary()} -> expected response: {exp_transaction.response.summary()}"
                )
                confirmed += 1
            else:
                slave.logger.info(
                    f"Expectation #{i} is not confirmed: {exp_transaction.request.summary()} -> expected response: {exp_transaction.response.summary()}"
                )

    return confirmed


####################################################################
# banner = "\nRobot custom Modbus slave library based on scapy framework\n"

# Self test for the library
if __name__ == "__main__":
    # interact(mydict=globals(), mybanner=banner)
    expectations: List[Transaction] = []
    slave = ModbusSlaveLib()
    result: int = 0
    counter = self_test_register_expectations(slave, expectations)
    if counter:
        slave.logger.info(f"Registered {counter} expectations.")
    else:
        raise RuntimeError("Fail to register expectations.")

    slave.start_server(port=1502, timeout=30, asynchronous=True)
    confirmed = self_test_register_expect_each(slave, expectations, 20)
    slave.logger.info(f"Confirmed {confirmed} expectations out of {len(expectations)}.")
    if confirmed == len(expectations):
        result += 1
        slave.logger.info("Test 1: PASS")
    else:
        slave.logger.info("Test 1: FAIL")

    if not slave.is_server_active():
        slave.start_server(port=1502, timeout=30, asynchronous=True)
    left = self_test_register_expect_all(slave, expectations, 10)
    if left == 0:
        result += 1
        slave.logger.info("Test 2: PASS")
    else:
        slave.logger.info("Test 2: FAIL")

    time.sleep(3)  # allow to send delayed response to Master
    slave.stop_server()

    assert result == 2
