# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=W0621  # redefined-outer-name

import logging
import os
import sys
from datetime import datetime
from enum import Enum
from statistics import mean
from typing import Any, Callable, Dict, Generator, Optional, Tuple, List, Union
from re import Match

import numpy as np
import matplotlib.pyplot as plt
from dataclasses import dataclass

import pexpect
import pytest
from _pytest.fixtures import FixtureRequest
from _pytest.monkeypatch import MonkeyPatch
from pytest_embedded.plugin import multi_dut_argument, multi_dut_fixture
from pytest_embedded_idf.app import IdfApp
from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.serial import IdfSerial
from pytest_embedded_idf import CaseTester


class Stages(Enum):
    STACK_DEFAULT = 1
    STACK_IPV4 = 2
    STACK_IPV6 = 3
    STACK_INIT = 4
    STACK_CONNECT = 5
    STACK_START = 6
    STACK_PAR_OK = 7
    STACK_PAR_FAIL = 8
    STACK_OBJECT_CREATE = 9
    STACK_DESTROY = 10
    STACK_BAD_CONNECTION = 11
    STACK_CID_RESPONSE_TIME = 12


## Object Fields
TRANSACTION_TIMESTAMP = 0
OBJ_TAG = 1
OBJ_ID = 2

## Parameters Fields
OBJ_ADDRESS = 1
CID = 2
PARAM_NAME = 3
PARAM_VAL = 4
PARAM_SUCCESS = "success"
PARAM_FAIL = "fail"

## Getter tags for readability
MASTER_TAG = "master"
SLAVE_TAG = "slave"

DEFAULT_SDKCONFIG = "default"
ALLOWED_PERCENT_OF_FAILS = 10


## Dataclass for structuring data to plot statistical graph
@dataclass
class ModbusDutStats:
    success_stats: List[int]
    fail_stats: List[int]


class MbRequestResponse:
    def __init__(
        self,
        transaction_timestamp: int,
        master_inst_address: bytes,
        cid: bytes,
    ) -> None:
        self.transaction_timestamp: int = transaction_timestamp
        self.master_inst_address: bytes = master_inst_address
        self.cid: bytes = cid


class MbParameter:
    def __init__(
        self,
        name: Union[str, bytes],
        instance_address: bytes,
        transaction_timestamp: int,
        obj_tag: str,
        status: str,
        cid: bytes,
        response_time: Optional[int],
        value: Optional[bytes],
    ) -> None:
        if isinstance(name, (bytes, bytearray)):
            self.name: str = name.decode("ascii")
        else:
            self.name = str(name)
        self.instance_address: bytes = instance_address
        self.transaction_timestamp: int = transaction_timestamp
        self.obj_tag: str = obj_tag
        self.status: str = status
        self.cid: bytes = cid
        self.response_time: Optional[int] = response_time
        self.value: Optional[bytes] = value

    def __repr__(self) -> str:
        if self.obj_tag == MASTER_TAG:
            return (
                f"Parameter name:{self.name}, Obj tag: {self.obj_tag}, Object ID:{self.instance_address!r}, "
                f"Transaction time:{self.transaction_timestamp}, Status:{self.status}, Cid:{self.cid!r}, "
                f"Value: {self.value!r}, Response time:{self.response_time}"
            )
        else:
            try:
                addr = self.instance_address.decode("ascii")
            except Exception:
                addr = repr(self.instance_address)
            return f"Parameter name:{self.name}, Obj tag: {self.obj_tag}, Object ID:{addr}, Transaction time:{self.transaction_timestamp}, Status:{self.status}"

    def get_name(self) -> str:
        """Retrieve parameter name (string)."""
        return self.name

    def get_inst(self) -> bytes:
        """Retrieve parameter instance address (bytes)."""
        return self.instance_address

    def get_timestamp(self) -> int:
        """Retrieve parameter transaction timestamp (int)."""
        return self.transaction_timestamp

    def get_tag(self) -> str:
        """Retrieve parameter tag (string)."""
        return self.obj_tag

    def get_status(self) -> str:
        """Retrieve parameter status (string)."""
        return self.status

    def get_cid(self) -> bytes:
        """Retrieve parameter cid (bytes)."""
        return self.cid

    def get_response_time(self) -> Optional[int]:
        """Retrieve parameter response time (ms) or None."""
        return self.response_time

    def get_value(self) -> Optional[bytes]:
        """Retrieve parameter value (bytes) or a sentinel b\"N/A\"."""
        return self.value if self.value is not None else b"N/A"


class MbObject:
    def __init__(self, tag: str, id: bytes, object_creation_timestamp: bytes) -> None:
        self.tag: str = tag
        self.id: bytes = id
        self.object_creation_timestamp: bytes = object_creation_timestamp
        self.parameters: List[MbParameter] = []
        self.parameter_count: int = 0

    def __repr__(self) -> str:
        try:
            obj_id = self.id.decode("ascii")
        except Exception:
            obj_id = repr(self.id)
        try:
            ts = self.object_creation_timestamp.decode("ascii")
        except Exception:
            ts = repr(self.object_creation_timestamp)
        return f"Obj Tag: {self.tag}, Obj ID: {obj_id}, Creation Timestamp: {ts}"

    def add_parameter(
        self,
        name: bytes,
        instance_address: bytes,
        transaction_timestamp: bytes,
        tag: str,
        status: str,
        cid: bytes,
        value: Optional[bytes],
    ) -> MbParameter:
        """The function add to list master or slave parameters"""
        parameter: MbParameter = MbParameter(
            name,
            instance_address,
            int(transaction_timestamp.decode("ascii")),
            tag,
            status,
            cid,
            None,
            value,
        )
        self.parameters.append(parameter)
        self.parameter_count += 1
        return parameter

    def is_master(self) -> bool:
        """The function checks for master tag in instance object"""
        if MASTER_TAG in self.tag:
            return True
        else:
            return False

    def is_slave(self) -> bool:
        """The function checks for slave tag in instance object"""
        if SLAVE_TAG in self.tag:
            return True
        else:
            return False


class ModbusTestDut(IdfDut):
    TEST_IP_PROMPT = r"Waiting IP\(([0-9]{1,2})\) from stdin:"
    TEST_IP_ADDRESS_REGEXP = r"I \([0-9]+\) example_[a-z]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    TEST_APP_NAME = r"I \([0-9]+\) [a-z_]+: Project name:\s+([_a-z]*)"

    TEST_EXPECT_STR_TIMEOUT = 120
    TEST_IP_PROMPT_TOUT = 10
    TEST_ACK_TIMEOUT = 60
    TEST_MAX_CIDS = 8

    app: IdfApp
    serial: IdfSerial  # type: ignore[override]

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        super().__init__(*args, **kwargs)
        self.logger: logging.Logger = logging.getLogger()
        self.ip_address: Optional[str] = None
        self.app_name: Optional[str] = None
        self.dut_list: Optional[List[ModbusTestDut]] = None
        self.param_fail_count: int = 0
        self.param_ok_count: int = 0
        self.test_stage: Stages = Stages.STACK_DEFAULT
        self.dictionary: Optional[Dict[Stages, bytes]] = None
        self.test_finish: bool = False
        self.mb_objects_count: int = (
            0  # number of objects (modbus instances in the test application)
        )
        self.mb_objects: List[MbObject] = []
        self.mb_request_response: List[MbRequestResponse] = []

    def close(self) -> None:
        super().close()

    def check_mb_objects_list(self) -> None:
        """Method to check if mb_objects list is not empty"""
        if not self.mb_objects:
            self.logger.error("list of modbus objects in DUT couldn't be retrieved")
            raise RuntimeError from None

        for objects in self.mb_objects:
            if objects is None:
                self.logger.error("list of modbus objects in DUT is wrongly populated")
                raise RuntimeError from None

        return None

    def validate_object_creation_tag(self, parsed_obj_tag: str) -> str:
        """Function checking and updating object creation tag master/slave if wrong"""
        if self.app_name is None:
            self.logger.error("app_name not initialized; cannot validate object tag")
            raise RuntimeError from None

        if MASTER_TAG in parsed_obj_tag or SLAVE_TAG in parsed_obj_tag:
            return parsed_obj_tag

        # Workaround to get master/slave tag from DUT class
        # Checking if app_name contains the  field. Ex: modbus_tcp_master
        obj_tag: str = ""
        if MASTER_TAG in self.app_name.lower():
            obj_tag = MASTER_TAG
        elif SLAVE_TAG in self.app_name.lower():
            obj_tag = SLAVE_TAG
        else:
            self.logger.error("Could not determine master/slave tag from app_name")
            raise RuntimeError from None

        self.logger.info(f"Object tag wrongly parsed, new tag being saved: {obj_tag}")
        return obj_tag

    def add_object(self, tag: str, id: bytes, timestamp: bytes) -> MbObject:
        """The function add to list master or slave instances in the test"""
        obj: MbObject = MbObject(tag, id, timestamp)
        self.mb_objects.append(obj)
        self.mb_objects_count += 1
        return obj

    def get_objects_by_tag(self, tag: str) -> List[MbObject]:
        """The getter retrieves object by master or slave tag"""
        objects: List[MbObject] = []
        self.check_mb_objects_list()

        for obj in self.mb_objects:
            if tag == obj.tag:
                objects.append(obj)

        if not objects:
            self.logger.error("objects list from tag couldn't be retrieved")
            raise RuntimeError from None
        else:
            return objects

    def get_object_by_id(self, id: bytes) -> Optional[MbObject]:
        """The getter retrieves master or slave object by instance address"""
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if id == obj.id:
                return obj

        self.logger.error(f"couldn't find registered object with id: {id!r}")
        return None

    def update_wrong_object_id(self, id: bytes) -> Optional[MbObject]:
        """Scan registered object list checking for a wrongly parsed object ID which is
        not 10 characters long. Ex - 0x3ffbf7bc"""
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if len(obj.id) != 10:
                self.logger.info(f"Updating wrong object id: {obj.id!r} to: {id!r}")
                obj.id = id
                return obj
        return None

    def get_params_by_name(self, name: str) -> Optional[List[MbParameter]]:
        """The getter retrieves parameters by name"""
        # import sys, pdb; pdb.Pdb(stdout=sys.__stdout__).set_trace()
        self.check_mb_objects_list()
        params: List[MbParameter] = []
        for obj in self.mb_objects:
            for param in obj.parameters:
                if name in str(param.name):
                    params.append(param)
        return params

    def get_params_by_object_id_and_status(
        self, instance_address: bytes, status: str
    ) -> Optional[List[MbParameter]]:
        """The getter retrieves parameters by instance address of object and status of request"""
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if obj.id == instance_address:
                return [
                    param
                    for param in obj.parameters
                    if param.instance_address == instance_address
                    and param.status == status
                ]
        return None

    def get_master_params_by_status(self, status: str) -> List[MbParameter]:
        """The getter retrieves master parameters by status request"""
        all_master_params: List[MbParameter] = []
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if obj.is_master():
                all_master_params.extend(
                    [
                        param
                        for param in obj.parameters
                        if param.status == status and param.obj_tag == obj.tag
                    ]
                )
        return all_master_params

    def get_slave_params_by_status(self, status: str) -> List[MbParameter]:
        """The getter retrieves slave parameters by status of request"""
        all_slave_params: List[MbParameter] = []
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if obj.is_slave():
                all_slave_params.extend(
                    [
                        param
                        for param in obj.parameters
                        if param.status == status and param.obj_tag == obj.tag
                    ]
                )
        return all_slave_params

    def get_params_by_timestamp_range(
        self, start: int, finish: int
    ) -> List[MbParameter]:
        """The getter retrieves parameters by timestamp"""
        params_by_timestamp: List[MbParameter] = []
        self.check_mb_objects_list()
        for obj in self.mb_objects:
            if obj is not None:
                params_by_timestamp.extend(
                    [
                        param
                        for param in obj.parameters
                        if start <= param.transaction_timestamp <= finish
                    ]
                )
        return params_by_timestamp

    def add_dut_list(self, dut_instance: "ModbusTestDut") -> None:
        """The function keeps track of all DUTs involved in the test"""
        if self.dut_list is None:
            self.dut_list = []

        self.dut_list.append(dut_instance)
        return None

    def send_message_destroy_other_dut_instances(self) -> None:
        """The function sends message to end all DUTs"""
        if self.dut_list is not None:
            for dut_instance in self.dut_list:
                self.logger.info("Sending destroy message to others DUT Instances")
                dut_instance.write("Destroy instances\n")
        return None

    def get_avg_response_time_master(self) -> int:
        """The function iterates over master parameters to calculate mean response time"""
        master_success_params: List[MbParameter] = self.get_master_params_by_status(
            PARAM_SUCCESS
        )
        if master_success_params:
            avg_response_time: List[int] = [
                param.response_time
                for param in master_success_params
                if param.response_time is not None
            ]
            if avg_response_time:
                return int(mean(avg_response_time))

        self.logger.info("Master Response time list couldn't be properly retrieved")
        return 0

    def send_message_destroy_dut(self) -> None:
        """The function sends message to end caller DUT"""
        self.logger.info("Sending destroy message to this DUT")
        self.write("Destroy instances\n")
        return None

    def add_request_response(
        self, transaction_timestamp: bytes, master_address: bytes, cid: bytes
    ) -> None:
        """The function gets and saves master requests"""
        request_response: MbRequestResponse = MbRequestResponse(
            int(transaction_timestamp.decode("ascii")), master_address, cid
        )
        self.mb_request_response.append(request_response)
        return None

    def add_response_time_to_param(self, param: MbParameter) -> None:
        """The function add response time to parameter entry based on request list"""
        last_request_response: MbRequestResponse = self.mb_request_response[-1]
        if (
            param.instance_address == last_request_response.master_inst_address
            and param.cid == last_request_response.cid
            and param.transaction_timestamp
            >= last_request_response.transaction_timestamp
        ):
            param.response_time = (
                param.transaction_timestamp
                - last_request_response.transaction_timestamp
            )
            self.logger.info(
                "Response time:%d for Cid:%s from Master:%s",
                param.response_time,
                param.cid,
                param.instance_address,
            )
            return None

    def dut_get_ip(self) -> Optional[str]:
        """The function gets IP address from log"""
        if self.ip_address is None:
            expect_address = self.expect(
                self.TEST_IP_ADDRESS_REGEXP, timeout=self.TEST_EXPECT_STR_TIMEOUT
            )
            if isinstance(expect_address, Match):
                self.ip_address = expect_address.group(1).decode("ascii")
        return self.ip_address

    def dut_get_name(self) -> Optional[str]:
        """The function gets project name from log"""
        if self.app_name is None:
            expect_name = self.expect(
                self.TEST_APP_NAME, timeout=self.TEST_EXPECT_STR_TIMEOUT
            )
            if isinstance(expect_name, Match):
                self.app_name = expect_name.group(1).decode("ascii")
        self.logger.info(f"Project name registered: {self.app_name}")
        return self.app_name

    def dut_send_ip(
        self, slave_ip: Optional[str] = None, port: Optional[str] = None
    ) -> Optional[int]:
        """The function sends the slave IP address defined as a parameter to master"""
        addr_num: int = 0
        try:
            self.expect(self.TEST_IP_PROMPT, timeout=self.TEST_IP_PROMPT_TOUT)
        except pexpect.TIMEOUT:
            # Workaround for unreliable parsing of the master prompt.
            # The expect() sometime does not catch it in spite it appears in the log.
            # Send the IP address anyway after the timeout.
            self.logger.error(
                "Timeout waiting for IP prompt. Try to send address anyway."
            )
        if isinstance(slave_ip, str):
            for addr_num in range(0, self.TEST_MAX_CIDS):
                message: str = r"IP{}={}".format(addr_num, slave_ip)
                if isinstance(port, str) or isinstance(port, int):
                    message += r";{}".format(str(port))
                message += r"\r\n"
                self.write(message)
                self.logger.info("{} sent to master".format(message))
        return addr_num

    def dut_stats_info(self) -> ModbusDutStats:
        """The function retrieves all success and fail parameters per DUT to plot stats graph"""
        all_success_params: List[int] = []
        all_fail_params: List[int] = []

        self.check_mb_objects_list()

        for obj in self.mb_objects:
            temp_success_params: Optional[List[MbParameter]] = (
                self.get_params_by_object_id_and_status(obj.id, PARAM_SUCCESS)
            )
            if temp_success_params is not None:
                all_success_params.append(len(temp_success_params))
            else:
                self.logger.error(
                    "Couldn't retrieve success parameters for object %s", obj.id
                )
                all_success_params.append(
                    0
                )  # propagating the None error to raise exception

            temp_fail_params: Optional[List[MbParameter]] = (
                self.get_params_by_object_id_and_status(obj.id, PARAM_FAIL)
            )
            if temp_fail_params is not None:
                all_fail_params.append(len(temp_fail_params))
            else:
                self.logger.error("Fail parameters couldn't be retrieved to plot graph")
                raise RuntimeError from None

        if (
            all(all_success_params) is False or not all_success_params
        ):  # Checking only success parameters. Slaves dont have fail parameters, they return a zero list.
            self.logger.error("success parameters couldn't be retrieved to plot graph")
            raise RuntimeError from None
        else:
            return ModbusDutStats(all_success_params, all_fail_params)

    def plot_modbus_stats(
        self,
        master_objects: List[MbObject],
        master_all_params: ModbusDutStats,
        slave_objects: List[MbObject],
        slave_all_params: ModbusDutStats,
        file_name: str,
    ) -> None:
        """The function plots graph from all success and fail parameters"""
        names: List[str] = []
        width = 0.1
        alpha = 0.5
        right = 0.55
        x_position_text = 1.03
        y_position_text = 0.98
        label_space = 0.3

        for obj in master_objects:
            names.append(f"Master \n {obj.id.decode()}")

        for obj in slave_objects:
            names.append(f"Slave \n {obj.id.decode()}")

        label_axis = np.arange(len(names)) * label_space

        text_box: str = (
            f"Master Average response time:{self.get_avg_response_time_master()} ms"
        )

        fig, ax = plt.subplots()
        plt.bar(
            label_axis,
            (master_all_params.success_stats + slave_all_params.success_stats),
            width=width,
            color="green",
            label="Success",
        )
        plt.bar(
            (label_axis + width),
            (master_all_params.fail_stats + slave_all_params.fail_stats),
            width=width,
            color="red",
            label="Fail",
        )
        plt.xticks(label_axis, names)
        props: Dict[str, Union[str, float]] = dict(
            boxstyle="round", facecolor="wheat", alpha=alpha
        )
        ax.text(
            x_position_text,
            y_position_text,
            text_box,
            transform=ax.transAxes,
            fontsize=12,
            verticalalignment="top",
            bbox=props,
        )
        plt.subplots_adjust(right=right)
        plt.legend()
        plt.title("Modbus Test Statistics")
        plt.ylabel("Parameters accessed")
        plt.savefig(f"{file_name}.png")
        plt.show()

    def get_item(self, data: Optional[List[Any]] = None, item: int = 0) -> bytes:
        """
        Safely return the requested item from a list as bytes.
        On unexpected exceptions returns a bytes sentinel b"N/A".
        """
        try:
            if not data or len(data) <= item:
                # Return sentinel when data missing to keep callers' expectations of bytes
                return b"N/A"
            val = data[item]
            if isinstance(val, bytes):
                return val
            if isinstance(val, str):
                return val.encode("utf-8")
            if isinstance(val, (int, float)):
                return str(val).encode("utf-8")
            # Fallback: stringify and encode any other object
            return str(val).encode("utf-8")
        except Exception:
            return b"N/A"

    def expect_any(
        self, *expect_items: Tuple[Optional[str], Callable], timeout: Optional[int]
    ) -> None:
        """
        expect_any(*expect_items, timeout=DEFAULT_TIMEOUT)
        expect any of the patterns.
        will call callback (if provided) if pattern match succeed and then return.
        will pass match result to the callback.

        :raise ExpectTimeout: failed to match any one of the expect items before timeout
        :raise UnsupportedExpectItem: pattern in expect_item is not string or compiled RegEx

        :arg expect_items: one or more expect items.
                           string, compiled RegEx pattern or (string or RegEx(string pattern), callback)
        :keyword timeout: timeout for expect
        :return: matched item
        """

        def process_expected_item(
            item_raw: Tuple[Optional[str], Callable[..., Any]],
        ) -> Dict[str, Any]:
            # convert item raw data to standard dict
            item = {
                "pattern": item_raw[0]
                if isinstance(item_raw, tuple)
                else item_raw or None,
                "callback": item_raw[1] if isinstance(item_raw, tuple) else None,
                "index": -1,
                "ret": None,
            }
            return item

        expect_items_list: List[Dict[str, Any]] = [
            process_expected_item(item)
            for item in expect_items
            if isinstance(item, tuple) and item[0]
        ]
        expect_patterns: List[Any] = [
            item["pattern"] for item in expect_items_list if item["pattern"] is not None
        ]
        match_item: Optional[Dict[str, Any]] = None

        if self.pexpect_proc is not None:
            match_index: int = self.pexpect_proc.expect(expect_patterns, timeout)

            if isinstance(match_index, int):
                match_item = expect_items_list[match_index]  # type: ignore
                match_item["index"] = match_index  # type: ignore # keep match index
                if (
                    isinstance(self.pexpect_proc.match, Match)
                    and len(self.pexpect_proc.match.groups()) > 0
                ):
                    match_item["ret"] = self.pexpect_proc.match.groups()
                if match_item["callback"]:
                    match_item["callback"](
                        match_item["ret"]
                    )  # execution of callback function
        else:
            self.logger.error(
                "%s: failed to parse output. Please check component versions.",
                self.app_name,
            )
            raise RuntimeError from None

    def dut_test_start(
        self, dictionary: Dict, timeout_value: Optional[int] = TEST_EXPECT_STR_TIMEOUT
    ) -> None:  # type: ignore
        """The method to initialize and handle test stages"""

        def handle_get_ip4(data: Optional[Any] = None) -> None:
            """Handle get_ip v4"""
            # Synch for handling the case where the DUT dont stablish connection from the beginning
            # DUT reboot after failing reconnecting
            if self.test_stage.value >= Stages.STACK_IPV4.value:
                self.logger.info(
                    f"Handle: {self.app_name}: Reboot loop detected on stage [{Stages.STACK_IPV4.name}]: {str(data)}"
                )
                self.send_message_destroy_other_dut_instances()
                self.send_message_destroy_dut()
                self.test_finish = True
            else:
                self.test_stage = Stages.STACK_IPV4
                self.logger.info(
                    f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
                )

        def handle_get_ip6(data: Optional[Any] = None) -> None:
            """Handle get_ip v6"""
            self.test_stage = Stages.STACK_IPV6
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )

        def handle_init(data: Optional[Any] = None) -> None:
            """Handle init"""
            self.test_stage = Stages.STACK_INIT
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )

        def handle_connect(data: Optional[Any] = None) -> None:
            """Handle connect"""
            self.test_stage = Stages.STACK_CONNECT
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )

        def handle_test_start(data: Optional[Any] = None) -> None:
            """Handle connect"""
            self.test_stage = Stages.STACK_START
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )

        def handle_cid_response_time(data: Optional[Any] = None) -> None:
            """Handle Cid sent request for response time calculation"""
            self.test_stage = Stages.STACK_CID_RESPONSE_TIME
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )
            self.add_request_response(
                self.get_item(data, TRANSACTION_TIMESTAMP),
                self.get_item(data, OBJ_ADDRESS),
                self.get_item(data, CID),
            )

        def handle_bad_connection(data: Optional[Any] = None) -> None:
            """Handle bad connection"""
            self.test_stage = Stages.STACK_BAD_CONNECTION
            self.logger.info(
                f"Handle: {self.app_name}: Reached the stage [{self.test_stage.name}]. Ending the test."
            )
            self.send_message_destroy_other_dut_instances()
            self.send_message_destroy_dut()
            self.test_finish = True

        def handle_par_ok(data: Optional[Any] = None) -> None:
            """Handle parameter ok"""
            self.test_stage = Stages.STACK_PAR_OK
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )
            # Checking if MBobject exist in the object list

            object_handle: Optional[MbObject] = self.get_object_by_id(
                self.get_item(data, OBJ_ADDRESS)
            )
            if object_handle is None:
                object_handle = self.update_wrong_object_id(
                    self.get_item(data, OBJ_ADDRESS)
                )
            assert object_handle is not None

            last_sucess_parameter: MbParameter = object_handle.add_parameter(
                self.get_item(data, PARAM_NAME),
                self.get_item(data, OBJ_ADDRESS),
                self.get_item(data, TRANSACTION_TIMESTAMP),
                object_handle.tag,
                PARAM_SUCCESS,
                self.get_item(data, CID),
                self.get_item(data, PARAM_VAL),
            )
            if object_handle.is_master():
                self.add_response_time_to_param(
                    last_sucess_parameter
                )  # adding to parameter the response time for this request
                self.logger.info(last_sucess_parameter)
            else:
                self.logger.info(last_sucess_parameter)

            self.param_ok_count += 1

        def handle_par_fail(data: Optional[Any]) -> None:
            """Handle parameter fail"""
            self.test_stage = Stages.STACK_PAR_FAIL
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )
            # Checking if MBobject exist in the object list
            object_handle: Optional[MbObject] = self.get_object_by_id(
                self.get_item(data, OBJ_ADDRESS)
            )
            if object_handle is None:
                object_handle = self.update_wrong_object_id(
                    self.get_item(data, OBJ_ADDRESS)
                )
            assert object_handle is not None

            last_fail_parameter: MbParameter = object_handle.add_parameter(
                self.get_item(data, PARAM_NAME),
                self.get_item(data, OBJ_ADDRESS),
                self.get_item(data, TRANSACTION_TIMESTAMP),
                object_handle.tag,
                PARAM_FAIL,
                self.get_item(data, CID),
                None,
            )
            self.logger.info(last_fail_parameter)

            self.param_fail_count += 1

        def handle_obj_create(data: Optional[Any]) -> None:
            """Handle creation"""
            self.test_stage = Stages.STACK_OBJECT_CREATE
            self.logger.info(
                f"Object creation handled: {self.app_name}[{self.test_stage.name}]: {str(data)}",
            )
            obj_tag = self.validate_object_creation_tag(
                self.get_item(data, OBJ_TAG).decode("ascii")
            )

            last_add_object: MbObject = self.add_object(
                obj_tag,
                self.get_item(data, OBJ_ID),
                self.get_item(data, TRANSACTION_TIMESTAMP),
            )
            self.logger.info("New added object: %s", last_add_object)

        def handle_destroy(data: Optional[Any]) -> None:
            """Handle destroy"""
            self.test_stage = Stages.STACK_DESTROY
            self.logger.info(
                f"Handle: {self.app_name}[{self.test_stage.name}]: {str(data)}"
            )
            self.send_message_destroy_other_dut_instances()
            self.test_finish = True

        while not self.test_finish:
            try:
                self.expect_any(
                    (dictionary[Stages.STACK_IPV4], handle_get_ip4),
                    (dictionary[Stages.STACK_IPV6], handle_get_ip6),
                    (dictionary[Stages.STACK_INIT], handle_init),
                    (dictionary[Stages.STACK_CONNECT], handle_connect),
                    (dictionary[Stages.STACK_START], handle_test_start),
                    (dictionary[Stages.STACK_PAR_OK], handle_par_ok),
                    (dictionary[Stages.STACK_PAR_FAIL], handle_par_fail),
                    (dictionary[Stages.STACK_OBJECT_CREATE], handle_obj_create),
                    (dictionary[Stages.STACK_DESTROY], handle_destroy),
                    (dictionary[Stages.STACK_BAD_CONNECTION], handle_bad_connection),
                    (
                        dictionary[Stages.STACK_CID_RESPONSE_TIME],
                        handle_cid_response_time,
                    ),
                    timeout=timeout_value,
                )
            except pexpect.TIMEOUT:
                self.logger.info(
                    f"{self.app_name}, expect timeout on stage {self.test_stage.name} ({timeout_value} seconds)"
                )
                self.send_message_destroy_other_dut_instances()
                self.send_message_destroy_dut()
                self.test_finish = True

    def dut_check_errors(self) -> None:
        """Verify allowed percentage of errors for the dut"""
        allowed_ok_percentage: float = 0
        if self.param_ok_count or self.param_fail_count:
            allowed_ok_percentage = (
                self.param_ok_count
                / (self.param_ok_count + self.param_fail_count)
                * 100
            )
        if allowed_ok_percentage > (100 - ALLOWED_PERCENT_OF_FAILS):
            self.logger.info(
                "%s: ok_count: %d, fail count: %d",
                self.app_name,
                self.param_ok_count,
                self.param_fail_count,
            )
        else:
            self.logger.error(
                "%s: ok_count: %d, number of failed readings: %d exceeds: %d percent",
                self.app_name,
                self.param_ok_count,
                self.param_fail_count,
                ALLOWED_PERCENT_OF_FAILS,
            )
            raise RuntimeError from None


############
# Fixtures #
############


@pytest.fixture
def case_tester(dut: IdfDut, **kwargs) -> Generator[CaseTester, Any, None]:  # type: ignore
    yield CaseTester(dut, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def session_tempdir() -> str:
    _tmpdir: str = os.path.join(
        os.path.dirname(__file__),
        "pytest_embedded_log",
        datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
    )
    os.makedirs(_tmpdir, exist_ok=True)
    return _tmpdir


@pytest.fixture(autouse=True)
@multi_dut_fixture
def junit_properties(
    test_case_name: str, record_xml_attribute: Callable[[str, object], None]
) -> None:
    """
    This fixture is autoused and will modify the junit report test case name to <target>.<config>.<case_name>
    """
    record_xml_attribute("name", test_case_name)


@pytest.fixture(scope="module")
def monkeypatch_module(request: FixtureRequest) -> MonkeyPatch:
    mp = MonkeyPatch()
    request.addfinalizer(mp.undo)
    return mp


@pytest.fixture(scope="module", autouse=True)
def replace_dut_class(monkeypatch_module: MonkeyPatch) -> None:
    monkeypatch_module.setattr("pytest_embedded_idf.IdfDut", ModbusTestDut)


@pytest.fixture
@multi_dut_argument
def config(request: FixtureRequest) -> str:
    return getattr(request, "param", None) or DEFAULT_SDKCONFIG


@pytest.fixture
@multi_dut_fixture
def build_dir(
    app_path: str, target: Optional[str], config: Optional[str]
) -> Optional[str]:
    """
    Check local build dir with the following priority:

    1. build_<target>_<config>
    2. build_<target>
    3. build_<config>
    4. build

    Args:
        app_path: app path
        target: target
        config: config

    Returns:
        valid build directory
    """
    check_dirs = []

    if target is not None and config is not None:
        check_dirs.append(f"build_{target}_{config}")
    if target is not None:
        check_dirs.append(f"build_{target}")
    if config is not None:
        check_dirs.append(f"build_{config}")
    check_dirs.append("build")

    binary_path = ""

    for check_dir in check_dirs:
        binary_path = os.path.join(app_path, check_dir)
        if os.path.isdir(binary_path):
            logging.info(f"find valid binary path: {binary_path}")
            return check_dir

        logging.warning(
            "checking binary path: %s... missing... try another place", binary_path
        )

    if config is not None and "dummy" in config:
        logging.warning(
            "no build dir valid for application: %s, config: %s. Skip test.",
            binary_path,
            config,
        )
        return None

    recommend_place = check_dirs[0]
    logging.error(
        f'no build dir valid. Please build the binary via "idf.py -B {recommend_place} build" and run pytest again'
    )

    sys.exit(1)
