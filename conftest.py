# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=W0621  # redefined-outer-name

import logging
import os
import sys
from datetime import datetime
from enum import Enum
from statistics import mean
from typing import Any, Callable, Dict, Match, Optional, Tuple, List
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
    def __init__(self, transaction_timestamp, master_inst_address, cid) -> None:
        self.transaction_timestamp: int = transaction_timestamp
        self.master_inst_address: bytes = master_inst_address
        self.cid: bytes = cid


class MbParameter:
    def __init__(
        self,
        name,
        instance_address,
        transaction_timestamp,
        obj_tag,
        status,
        cid,
        response_time,
    ) -> None:
        self.name: str = name
        self.instance_address: bytes = instance_address
        self.transaction_timestamp: int = transaction_timestamp
        self.obj_tag: str = obj_tag
        self.status: str = status
        self.cid: bytes = cid
        self.response_time: Optional[int] = response_time

    def __repr__(self) -> str:
        if self.obj_tag == MASTER_TAG:
            return f"Parameter name:{self.name}, Obj type: {self.obj_tag}, Object ID:{self.instance_address!r}, Transaction time:{self.transaction_timestamp}, Status:{self.status}, Cid:{self.cid}, Master Response time:{self.response_time}"
        else:
            return f"Parameter name:{self.name}, Obj type: {self.obj_tag}, Object ID:{self.instance_address}, Transaction time:{self.transaction_timestamp}, Status:{self.status}"


class MbObject:
    def __init__(self, tag, id, object_creation_timestamp) -> None:
        self.tag: str = tag
        self.id: bytes = id
        self.object_creation_timestamp: bytes = object_creation_timestamp
        self.parameters: List[MbParameter] = []
        self.parameter_count: int = 0

    def __repr__(self):
        return f"Obj Tag: {self.tag}, Obj ID: {self.id}, Creation Timestamp: {self.object_creation_timestamp}"

    def add_parameter(
        self,
        name: bytes,
        instance_address: bytes,
        transaction_timestamp: bytes,
        tag: str,
        status: str,
        cid: bytes,
    ) -> MbParameter:
        """The function add to list master or slave parameters"""
        parameter = MbParameter(
            name,
            instance_address,
            int(transaction_timestamp.decode("ascii")),
            tag,
            status,
            cid,
            None,
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
    TEST_IP_PROMPT = r"Waiting IP([0-9]{1,2}) from stdin:"
    TEST_IP_ADDRESS_REGEXP = r".*example_[a-z]+: .* IPv4 [a-z]+:.* ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*"
    TEST_APP_NAME = r"I \([0-9]+\) [a-z_]+: Project name:\s+([_a-z]*)"

    TEST_EXPECT_STR_TIMEOUT = 120
    TEST_ACK_TIMEOUT = 60
    TEST_MAX_CIDS = 8

    app: IdfApp
    serial: IdfSerial

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger()
        self.ip_address: Optional[str] = None
        self.app_name: Optional[str] = None
        self.dut_list: Optional[List[ModbusTestDut]] = None
        self.param_fail_count: int = 0
        self.param_ok_count: int = 0
        self.test_stage = Stages.STACK_DEFAULT
        self.dictionary = None
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

    def add_object(self, tag: str, id: bytes, timestamp: bytes) -> MbObject:
        """The function add to list master or slave instances in the test"""
        obj = MbObject(tag, id, timestamp)
        self.mb_objects.append(obj)
        self.mb_objects_count += 1
        return obj

    def get_objects_by_tag(self, tag: str) -> List[MbObject]:
        """The getter retrieves object by master or slave tag"""
        objects: List[MbObject] = []
        self.check_mb_objects_list()

        for object in self.mb_objects:
            if tag == object.tag:
                objects.append(object)

        if not objects:
            self.logger.error("objects list from tag couldn't be retrieved")
            raise RuntimeError from None
        else:
            return objects

    def get_object_by_id(self, id: bytes) -> MbObject:
        """The getter retrieves master or slave object by instance address"""
        self.check_mb_objects_list()
        for object in self.mb_objects:
            if id == object.id:
                return object

        self.logger.error("couldn't find object by id")
        raise RuntimeError from None

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
            self.dut_list: List[ModbusTestDut] = []

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
        master_success_params = self.get_master_params_by_status(PARAM_SUCCESS)
        if master_success_params:
            avg_response_time = [
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
        request_response = MbRequestResponse(
            int(transaction_timestamp.decode("ascii")), master_address, cid
        )
        self.mb_request_response.append(request_response)
        return None

    def add_response_time_to_param(self, param: MbParameter) -> None:
        """The function add response time to parameter entry based on request list"""
        last_request_response = self.mb_request_response[-1]
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
        return self.app_name

    def dut_send_ip(self, slave_ip: Optional[str]) -> Optional[int]:
        """The function sends the slave IP address defined as a parameter to master"""
        addr_num: int = 0
        self.expect(self.TEST_IP_PROMPT, timeout=self.TEST_EXPECT_STR_TIMEOUT)
        if isinstance(slave_ip, str):
            for addr_num in range(0, self.TEST_MAX_CIDS):
                message = r"IP{}={}".format(addr_num, slave_ip)
                self.logger.info("{} sent to master".format(message))
                self.write(message)
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

        text_box = (
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
        props = dict(boxstyle="round", facecolor="wheat", alpha=alpha)
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

    def expect_any(
        self, *expect_items: Tuple[str, Callable], timeout: Optional[int]
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
            item_raw: Tuple[str, Callable[..., Any]],
        ) -> Dict[str, Any]:
            # convert item raw data to standard dict
            item = {
                "pattern": item_raw[0] if isinstance(item_raw, tuple) else item_raw,
                "callback": item_raw[1] if isinstance(item_raw, tuple) else None,
                "index": -1,
                "ret": None,
            }
            return item

        expect_items_list = [process_expected_item(item) for item in expect_items]
        expect_patterns = [
            item["pattern"] for item in expect_items_list if item["pattern"] is not None
        ]
        match_item = None

        if self.pexpect_proc is not None:
            match_index = self.pexpect_proc.expect(expect_patterns, timeout)

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
        self, dictionary: Dict, timeout_value=TEST_EXPECT_STR_TIMEOUT
    ) -> None:  # type: ignore
        """The method to initialize and handle test stages"""

        def handle_get_ip4(data: Any) -> None:
            """Handle get_ip v4"""
            # Synch for handling the case where the DUT dont stablish connection from the beginning
            # DUT reboot after failing reconnecting
            if self.test_stage.value >= Stages.STACK_IPV4.value:
                self.logger.info(
                    "%s: Reboot loop detected on stage [STACK_IPV4], ending test.",
                    self.app_name,
                )
                self.send_message_destroy_other_dut_instances()
                self.send_message_destroy_dut()
                self.test_finish = True
            else:
                self.logger.info("%s[STACK_IPV4]: %s", self.app_name, str(data))
                self.test_stage = Stages.STACK_IPV4

        def handle_get_ip6(data: Any) -> None:
            """Handle get_ip v6"""
            self.logger.info("%s[STACK_IPV6]: %s", self.app_name, str(data))
            self.test_stage = Stages.STACK_IPV6

        def handle_init(data: Any) -> None:
            """Handle init"""
            self.logger.info("%s[STACK_INIT]: %s", self.app_name, str(data))
            self.test_stage = Stages.STACK_INIT

        def handle_connect(data: Any) -> None:
            """Handle connect"""
            self.logger.info("%s[STACK_CONNECT]: %s", self.app_name, str(data))
            self.test_stage = Stages.STACK_CONNECT

        def handle_test_start(data: Any) -> None:
            """Handle connect"""
            self.logger.info("%s[STACK_START]: %s", self.app_name, str(data))
            self.test_stage = Stages.STACK_START

        def handle_cid_response_time(data: Any) -> None:
            """Handle Cid sent request for response time calculation"""
            self.logger.info(
                "%s[STACK_CID_RESPONSE_TIME]: %s", self.app_name, str(data)
            )
            self.test_stage = Stages.STACK_CID_RESPONSE_TIME
            self.add_request_response(
                data[TRANSACTION_TIMESTAMP], data[OBJ_ADDRESS], data[CID]
            )

        def handle_bad_connection(data: Any) -> None:
            """Handle bad connection"""
            self.logger.info(
                "%s Reached the stage [STACK_BAD_CONNECTION]. Ending the test.",
                self.app_name,
            )
            self.test_stage = Stages.STACK_BAD_CONNECTION
            self.send_message_destroy_other_dut_instances()
            self.send_message_destroy_dut()
            self.test_finish = True

        def handle_par_ok(data: Any) -> None:
            """Handle parameter ok"""
            self.logger.info("%s[READ_PAR_OK]: %s", self.app_name, str(data))
            # Checking if MBobject exist in the object list

            object_handle = self.get_object_by_id(data[OBJ_ADDRESS])
            last_sucess_parameter = object_handle.add_parameter(
                data[PARAM_NAME],
                data[OBJ_ADDRESS],
                data[TRANSACTION_TIMESTAMP],
                object_handle.tag,
                PARAM_SUCCESS,
                data[CID],
            )
            if object_handle.is_master():
                self.add_response_time_to_param(
                    last_sucess_parameter
                )  # adding to parameter the response time for this request
                self.logger.info(last_sucess_parameter)
            else:
                self.logger.info(last_sucess_parameter)

            self.param_ok_count += 1
            self.test_stage = Stages.STACK_PAR_OK

        def handle_par_fail(data: Any) -> None:
            """Handle parameter fail"""
            self.logger.info("%s[READ_PAR_FAIL]: %s", self.app_name, str(data))
            # Checking if MBobject exist in the object list
            object_handle = self.get_object_by_id(data[OBJ_ADDRESS])
            last_fail_parameter = object_handle.add_parameter(
                data[PARAM_NAME],
                data[OBJ_ADDRESS],
                data[TRANSACTION_TIMESTAMP],
                object_handle.tag,
                PARAM_FAIL,
                data[CID],
            )
            self.logger.info(last_fail_parameter)

            self.param_fail_count += 1
            self.test_stage = Stages.STACK_PAR_FAIL

        def handle_obj_create(data: Any) -> None:
            """Handle creation"""
            self.logger.info(
                "Object creation handled: %s[%s]: %s",
                self.app_name,
                Stages.STACK_OBJECT_CREATE.name,
                str(data),
            )
            last_add_object = self.add_object(
                data[OBJ_TAG].decode("ascii"), data[OBJ_ID], data[TRANSACTION_TIMESTAMP]
            )
            self.test_stage = Stages.STACK_OBJECT_CREATE
            self.logger.info("New added object: %s", last_add_object)

        def handle_destroy(data: Any) -> None:
            """Handle destroy"""
            self.logger.info(
                "%s[%s]: %s", self.app_name, Stages.STACK_DESTROY.name, str(data)
            )
            self.test_stage = Stages.STACK_DESTROY
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
                    "%s, expect timeout on stage %s (%s seconds)",
                    self.app_name,
                    self.test_stage.name,
                    timeout_value,
                )
                self.send_message_destroy_other_dut_instances()
                self.send_message_destroy_dut()
                self.test_finish = True

    def dut_check_errors(self) -> None:
        """Verify allowed percentage of errors for the dut"""
        allowed_ok_percentage = (
            self.param_ok_count / (self.param_ok_count + self.param_fail_count + 1)
        ) * 100
        if self.param_ok_count and (
            allowed_ok_percentage > (100 - ALLOWED_PERCENT_OF_FAILS)
        ):
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
def case_tester(dut: IdfDut, **kwargs):  # type: ignore
    yield CaseTester(dut, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def session_tempdir() -> str:
    _tmpdir = os.path.join(
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
