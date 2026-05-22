# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# This is the script to reproduce the issue when the expect() is called from
# main thread in Multi DUT case.

import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple
import re

# pytest required libraries
import pytest
from robot import run
from pathlib import Path
from robot.libraries.BuiltIn import BuiltIn

TEST_DIR = Path(__file__).resolve().parent
TEST_ROBOT_DIR = (TEST_DIR / "../../tools/robot").resolve()
TEST_CONF_DIR = (TEST_DIR / "../..").resolve()

if str(TEST_ROBOT_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_ROBOT_DIR))

if str(TEST_CONF_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_CONF_DIR))

from conftest import ModbusTestDut, MbParameter, PARAM_SUCCESS, Stages  # noqa: E402

LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
ROBOT_SUITE_NAME = "ModbusTestSuiteSlave"
logger = logging.getLogger(LOGGER_NAME)


pattern_dict_master = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) example_[a-z]+: - IPv4 address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (
        r"I \(([0-9]+)\) [A-Z_]*: [0xa-f0-9,]*\s*Modbus master stack initialized"
    ),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) mb_port.tcp.master: 0x[a-f0-9]+, Connected: [0-9], [0-9], start polling."
    ),
    Stages.STACK_START: (r"I \(([0-9]+)\) [A-Z_]+: Master TCP is started"),
    Stages.STACK_PAR_OK: (
        r"[I|E] \(([0-9]+)\) [A-Z_]+: ([a-z0-9]+) Characteristic #([0-9]+) ([a-zA-Z0-9_]+) \([\%a-zA-Z_\/]*\) value = ([0-9a-zA-Z.]*)\s*([a-zA-Z0-9()]*)( read successful|, unexpected value)"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) [A-Z_]+: ([a-z0-9]+) Characteristic #([0-9]+) \(([a-zA-Z0-9_]+)\) read fail, err = [x0-9]+ \([_A-Z]+\)"
    ),
    Stages.STACK_DESTROY: (r"I \(([0-9]+)\) [A-Z_]+: (Master TCP is completed)"),
    Stages.STACK_OBJECT_CREATE: (
        r"D \(([0-9]+)\) [a-z]+_[a-z]+\.([a-z]+)\: created object mb[a-z]\_tcp[#@](0x[0-9a-f]+)"
    ),
    Stages.STACK_BAD_CONNECTION: (
        r"I \([0-9]+\) example_connect: WiFi Connect failed [0-9]* times, stop reconnect."
    ),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"D \(([0-9]+)\) mbc_[a-z]+.master: mbc_[a-z]+_master_get_parameter: ([a-zA-Z0-9]+) Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}


class ModbusDataBridge:
    ROBOT_LISTENER_API_VERSION = 2

    def __init__(
        self,
        trace_list: Optional[List[Dict[str, Any]]] = None,
        dut: Optional[ModbusTestDut] = None,
    ) -> None:
        """The constructor of the bridge interface that inherits the native robot listener API"""
        self.ROBOT_LIBRARY_LISTENER = self
        self.trace_list = trace_list
        self.dut = dut
        self.server_address: Optional[Tuple[str, int]] = None
        self.logger = logging.getLogger("RobotFramework")

    def setup_master_address(self, address: Tuple[str, int]) -> None:
        """The callback to setup master when server (slave) is ready."""
        print(f"Setting up master address: {address}")
        if self.dut:
            dut_stdin_en = self.dut.app.sdkconfig.get("MB_SLAVE_IP_FROM_STDIN")
            if dut_stdin_en:
                self.dut.dut_send_ip(slave_ip=address[0], port=str(address[1]))
                logger.info(
                    f"Initialized slave IP address for DUT {self.dut.dut_get_name()} = {address[0]}:{address[1]}."
                )
                if self.dut.send_message_start_dut():
                    logger.info(
                        f"The DUT:{self.dut.dut_get_name()} is ready for connection."
                    )

    def end_keyword(self, name: str, attributes: Dict[str, Any]) -> None:
        """This method is a listener interface wrapper for each keyword."""
        if ".Test Report Server Address" in name:
            self.logger.info(f"Server is ready: {name}, {attributes}")
            server_addr = BuiltIn().get_variable_value(
                "${MODBUS_SERVER_ADDRESS}", "127.0.0.1"
            )
            server_port = BuiltIn().get_variable_value("${MODBUS_DEF_PORT}", 1502)
            self.logger.info(
                f"Setup slave address in master: {server_addr}:{server_port}"
            )
            self.setup_master_address((server_addr, server_port))

    def end_test(self, name: str, attributes: Dict[str, Any]) -> None:
        """This method is a listener interface wrapper for each test."""
        if (
            "Test Modbus" in name
            and "Test Async Run Modbus Case" in attributes["template"]
        ):
            self.logger.info(
                f"End test: {name}, {attributes}, Message: {attributes.get('message')}"
            )
            # This will track all tags after test completion using the test message as the container for parameter names
            if self.trace_list is not None:
                self.trace_list.append(
                    {
                        "timestamp": attributes.get("starttime"),
                        "action": name,
                        "args": attributes.get("args"),
                        "tags": attributes.get("message"),
                        "status": attributes.get("status"),
                    }
                )

    def trace_test_params(self) -> None:
        """This method will track the parameter keywords for each test (server side).
        It gets the parameter data from log of master using ModbusTestDut class
        and checks the status of characteristic tag of server side.
        """
        if self.trace_list is None or self.dut is None:
            return
        self.logger.info(f"Test info List: {self.trace_list}")
        for test_info in self.trace_list:
            tags = test_info["tags"]
            tags_str = (
                tags.decode("ascii", errors="replace")
                if isinstance(tags, bytes)
                else str(tags)
                if tags is not None
                else ""
            )
            self.logger.info(f"Tags: {tags_str}")
            params: List[MbParameter] = []
            if tags_str and len(tags_str):
                for tag in re.findall(r'"(\s*[^"\s][^"]*)"', tags_str):
                    self.logger.info(
                        f'Synchronize the "{tag}" with parameters in dut: {self.dut.dut_get_name()}'
                    )
                    params = self.dut.get_params_by_name(str(tag)) or []
                    if params:
                        for param in params:
                            self.logger.info(f"Found param: {param!r}")
                            if param.status == PARAM_SUCCESS:
                                val = param.get_value()
                                val_str = (
                                    val.decode("ascii", errors="replace")
                                    if isinstance(val, bytes)
                                    else str(val)
                                    if val is not None
                                    else ""
                                )
                                self.logger.info(
                                    f"Param: {param!r}, Value: {val_str}, Status: SUCCESS"
                                )
                            else:
                                # Master did not receive response. Keep information in the log and fail the test.
                                self.logger.error(f"Param: {param!r}, Status: FAIL.")
                                raise RuntimeError(
                                    f"Param: {param!r}, Status: FAIL (Master did not get response from DUT)."
                                )
                    else:
                        # Continue test if the tag is not found
                        self.logger.error(
                            f"Could not find param with tag: {tag} in dut: {self.dut.dut_get_name()}"
                        )


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize("config", ["ethernet"], indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [(1, f"{os.path.join(os.path.dirname(__file__), 'mb_tcp_master')}")],
    indirect=True,
)
def test_modbus_tcp_master_to_host_slave_communication(
    app_path: str, dut: ModbusTestDut
) -> None:
    logger.info("DUT: %s start.", dut.dut_get_name())
    dut_master_name = dut.dut_get_name()
    dut_master_port = dut.app.sdkconfig.get("FMB_TCP_PORT_DEFAULT")

    dut_master_ip_address = dut.dut_get_ip()

    assert dut_master_ip_address is not None, "The DUT could not get IP address. Abort."
    logger.info(f"DUT: {dut_master_name}, ip address: {dut_master_ip_address}.")

    assert dut_master_port is not None, f"DUT port is not correct: {dut_master_port}"
    logger.info(
        f"Start test for the master application: {app_path}, {dut_master_ip_address}:{dut_master_port}"
    )

    try:
        trace_data: List[Dict[str, Any]] = []
        mb_data_bridge = ModbusDataBridge(trace_data, dut)

        # The robot suite will run the test cases for Modbus Master node,
        # and the data bridge will track the test parameters and their status after each test case.
        # The test parameters are tagged in robot suite and synchronized with the data in DUT using the bridge interface.
        return_code = run(
            f"{TEST_ROBOT_DIR}/{ROBOT_SUITE_NAME}.robot",
            variable=[
                f"MODBUS_DEF_IP:{dut_master_ip_address}",
                f"MODBUS_DEF_PORT:{dut_master_port}",
            ],
            outputdir=f"{ROBOT_SUITE_NAME}_logs",
            listener=mb_data_bridge,
            output="trace_data.xml",
            exitonfailure=False,
            loglevel="DEBUG",
        )

        dut.dut_test_start(dictionary=pattern_dict_master)
        mb_data_bridge.trace_test_params()
        dut.write("mb stop instances\n")  # Intentionally destroy DUT after test
        dut.dut_check_errors()

        if return_code != 0:
            raise RuntimeError(
                f"The robot suite {ROBOT_SUITE_NAME} returns an exception: {return_code}."
            )
        logger.info(
            f"Test for the Modbus Master node: {dut_master_name} is completed, return code: {return_code}."
        )

    except Exception as e:
        raise e


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-vv"]))
