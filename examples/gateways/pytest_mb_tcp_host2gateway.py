# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# This is the script to reproduce the issue when the expect() is called from
# main thread in Multi DUT case.

import logging
import os
from typing import Tuple
import pytest
from conftest import (
    ModbusTestDut,
    Stages,
)
from robot import run

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
TEST_ROBOT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tools/robot")
)
LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
ROBOT_SUITE_NAME = "ModbusTestSuiteGateway"
logger = logging.getLogger(LOGGER_NAME)

pattern_dict_serial_slave = {
    Stages.STACK_IPV4: (
        r"[ID] \([0-9]+\) example_[a-z]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"[ID] \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (r"I \(([0-9]+)\) [A-Z_]*: (Modbus slave stack initialized)."),
    Stages.STACK_CONNECT: (
        r"[ID]\s\(([0-9]+)\) port.utils: Socket \(#[0-9]+\), accept client connection from address\[port\]: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\[[0-9]+\]"
    ),
    Stages.STACK_START: (r"I\s\(([0-9]+)\) [A-Z_]+: (Start modbus test)"),
    Stages.STACK_PAR_OK: (
        r"[ID]\s\(([0-9]+)\) [A-Z_]+: OBJ (0x[a-fA-Z0-9]+), ([A-Za-z\s]+) (\([0-9]+ us\)),\s*ADDR:\s*([0-9]*),\s*TYPE:\s*([0-9]+), INST_ADDR:0x([a-fA-Z0-9]+),\s*SIZE:\s*([0-9]+)"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) SLAVE_TEST: Response time exceeds configured [0-9]+ [ms], ignore packet"
    ),
    Stages.STACK_DESTROY: (r"I\s\(([0-9]+)\) [A-Z_]+: (Destroy slave.)"),
    Stages.STACK_OBJECT_CREATE: (
        r"[DI] \(([0-9]+)\) ([a-z]+_[a-z]+\.[a-z]+)\: mb[ms]\_rtu[#@](0x[0-9a-f]+), (suspend port from task)"
    ),
    Stages.STACK_BAD_CONNECTION: (r"[WI] \([0-9]+\) [_A-Za-z]+: (Stop polling)"),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"D \(([0-9]+)\) mbc_[a-z]+.slave: mbc_[a-z]+_slave_get_parameter: Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}

pattern_dict_gateway = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) [a-z_]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) [a-z_]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (
        r"I \(([0-9]+)\) [A-Z0-9_]+: (0x[a-fA-F0-9]+), (Modbus TCP slave started) on port\s*([0-9]+),\s*gateway UID\s*([0-9]+)\."
    ),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) [A-Za-z_\.]+: Socket \((#[a-f0-9]+)\), accept client connection from address\[port\]: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\[([0-9]{1,5})\]"
    ),
    Stages.STACK_START: (
        r"I \(([0-9]+)\) [A-Z0-9_]+: (0x[a-fA-F0-9]+), (Modbus TCP gateway is running)"
    ),
    Stages.STACK_PAR_OK: (
        r"I \(([0-9]+)\) [A-Z0-9_]+: (0x[a-fA-F0-9]+), ([A-Za-z\s*]+) success,\s*UID:\s*([0-9]+),\s*fc:\s*0x([a-fA-F0-9\_]+),\s*addr:\s*([0-9]+),\s*count:\s*([0-9]+)\s*([_a-zA-Z]*)"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) [A-Z0-9_]+: (0x[a-fA-F0-9]+), ([A-Za-z\s]+) failed, UID:\s*([0-9]+),\s*fc:\s*0x([a-fA-F0-9\_]+),\s*addr:\s*([0-9]+),\s*count:\s*([0-9]+)\s*([_a-zA-Z]*)"
    ),
    Stages.STACK_DESTROY: (
        r"[IW] \([0-9]+\) ([a-z_\.]+)\: (0x[a-fA-F0-9]+), node [#@]([0-9]+, socket\([#@]([0-9]+)\)\s*\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\), connection closed\?, err=\s([\-0-9]*))"
    ),
    Stages.STACK_OBJECT_CREATE: (
        r"[DI] \(([0-9]+)\) ([0-9A-Za-z_]+)\: (0x[a-fA-F0-9]+), (Modbus TCP gateway is created)"
    ),
    Stages.STACK_BAD_CONNECTION: (
        r"[E] \([0-9]+\) ([a-z_\.]+): (0x[a-fA-F0-9]+), node [#@]([0-9]+), socket\([#@]([0-9]+)\)\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\), communication fail, err=-([0-9]+), drop connection."
    ),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"D \(([0-9]+)\) mbc_[a-z]+.master: mbc_[a-z]+_master_get_parameter: ([a-zA-Z0-9]+) Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}

LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
CONFORMANCE_TEST_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tools/robot")
)
logger = logging.getLogger(LOGGER_NAME)


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_serial
@pytest.mark.parametrize(
    "count, config, app_path",
    [
        (
            2,
            "rtu|gateway",
            f"{os.path.join(os.path.dirname(__file__), '../serial/mb_serial_slave')}|{os.path.join(os.path.dirname(__file__), 'mb_tcp_slave2serial_master')}",
        )
    ],
    indirect=True,
)

# @pytest.mark.flaky(reruns=1, reruns_delay=1)
def test_modbus_tcp_gateway(
    app_path: str, dut: Tuple[ModbusTestDut, ModbusTestDut]
) -> None:
    dut_gateway = dut[1]
    dut_ser_slave = dut[0]

    logger.info(f"DUT test application path: {app_path}.")

    dut_gateway_name = dut_gateway.dut_get_name()
    dut_ser_slave_name = dut_ser_slave.dut_get_name()

    dut_gateway_port = dut_gateway.app.sdkconfig.get("FMB_TCP_PORT_DEFAULT")
    dut_gateway_ip_address = dut_gateway.dut_get_ip()

    logger.info(
        f"DUT Gateway: {dut_gateway_name}, ip address[:port]: {dut_gateway_ip_address}:{dut_gateway_port}."
    )
    logger.info(f"DUT Slave serial: {dut_ser_slave_name}.")

    try:
        return_code = run(
            f"{TEST_ROBOT_DIR}/{ROBOT_SUITE_NAME}.robot",
            variable=[
                f"MODBUS_DEF_IP:{dut_gateway_ip_address}",
                f"MODBUS_DEF_PORT:{dut_gateway_port}",
            ],
            outputdir=f"{ROBOT_SUITE_NAME}_logs",
            # log=None,      # Prevents stdout clutter
            report="master_host_report.xml",
            exitonfailure=False,
            loglevel="DEBUG",
        )

        dut_gateway.dut_test_start(dictionary=pattern_dict_gateway)
        dut_ser_slave.dut_test_start(dictionary=pattern_dict_serial_slave)

        if return_code != 0:
            raise RuntimeError(
                f"The robot suite {ROBOT_SUITE_NAME}, returns an exception: {return_code}."
            )
        logger.info(
            f"Suite {ROBOT_SUITE_NAME} for the Modbus Gateway node: {dut_gateway_ip_address} is completed, return code: {return_code}."
        )

        ### Gateway check logging
        dut_gateway.dut_check_errors()
        dut_ser_slave.dut_check_errors()

    except Exception as e:
        logging.error(
            f"Robot suite {ROBOT_SUITE_NAME} for {dut_gateway.dut_get_name()} fail."
        )
        raise e


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize("config", ["dummy_config"])
def test_modbus_tcp_generic(config: str) -> None:
    logger.info("The generic tcp example tests are not provided yet.")


if __name__ == "__main__":
    pytest.main(["pytest_mb_tcp_master_slave.py"])
