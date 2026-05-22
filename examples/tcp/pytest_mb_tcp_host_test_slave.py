# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# This is the script to reproduce the issue when the expect() is called from
# main thread in Multi DUT case.

import logging
import os

# pytest required libraries
import pytest
from conftest import ModbusTestDut, Stages
from robot import run

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
TEST_ROBOT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tools/robot")
)
LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
ROBOT_SUITE_NAME = "ModbusTestSuiteMaster"
logger = logging.getLogger(LOGGER_NAME)

pattern_dict_slave = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) [a-z_]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) [a-z_]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (r"I \(([0-9]+)\) [A-Z_]*: (Modbus slave stack initialized)."),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) port.utils: Socket \(#[0-9]+\), accept client connection from address\[port\]: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\[[0-9]+\]"
    ),
    Stages.STACK_START: (r"I\s\(([0-9]+)\) [A-Z_]+: (Start modbus test...)"),
    Stages.STACK_PAR_OK: (
        r"I\s\(([0-9]+)\) [A-Z_]+: OBJ (0x[a-fA-Z0-9]+),() ([A-Za-z\s]+) \([0-9]+ us\),\s*[A-Z:]*\s*[0-9,]*\s*[A-Z:]*[0-9]*, TYPE:[0-9]+, INST_ADDR:0x[a-fA-Z0-9]+[()0-9a-z]+, SIZE:[0-9]+"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) SLAVE_TEST: Response time exceeds configured [0-9]+ [ms], ignore packet"
    ),
    Stages.STACK_DESTROY: (r"I\s\(([0-9]+)\) [A-Z_]+: (Destroy slave)"),
    Stages.STACK_OBJECT_CREATE: (
        r"D \(([0-9]+)\) [a-z]+_[a-z]+\.([a-z]+)\: created object mbs_tcp[#@](0x[0-9a-f]+)"
    ),
    Stages.STACK_BAD_CONNECTION: (
        r"E \([0-9]+\) mb_port[\.a-z]+: (0x[a-zA-Z0-9]+), node #[0-9]+, socket\(\#([0-9]+)\)\(([\.0-9a-f]+)\), communication fail, err= -([0-9]+)"
    ),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"D \(([0-9]+)\) mbc_[a-z]+.slave: mbc_[a-z]+_slave_get_parameter: Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize("config", ["ethernet"], indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [(1, f"{os.path.join(os.path.dirname(__file__), 'mb_tcp_slave')}")],
    indirect=True,
)
@pytest.mark.flaky(reruns=1, reruns_delay=2)
def test_modbus_tcp_host_to_slave_communication(
    app_path: str, dut: ModbusTestDut
) -> None:
    logger.info("DUT: %s start.", dut.dut_get_name())
    dut_slave_ip_address = dut.dut_get_ip()
    assert dut_slave_ip_address is not None, "The DUT could not get IP address. Abort."
    dut_slave_ip_port = dut.app.sdkconfig.get("FMB_TCP_PORT_DEFAULT")
    assert dut_slave_ip_port is not None, (
        f"DUT port is not correct: {dut_slave_ip_port}"
    )
    try:
        # Ensure the Slave test is started correctly and ready for requests
        if dut.send_message_start_dut():
            logger.info(
                f"The DUT is ready for connection with the name: {dut.dut_get_name()}"
            )
        logger.info(
            f"Start test for the slave: {app_path}, {dut_slave_ip_address}:{dut_slave_ip_port}"
        )

        return_code = run(
            f"{TEST_ROBOT_DIR}/{ROBOT_SUITE_NAME}.robot",
            variable=[
                f"MODBUS_DEF_IP:{dut_slave_ip_address}",
                f"MODBUS_DEF_PORT:{dut_slave_ip_port}",
            ],
            outputdir=f"{ROBOT_SUITE_NAME}_logs",
            # log=None,      # Prevents stdout clutter
            report="master_host_report.xml",
            exitonfailure=False,
            loglevel="DEBUG",
        )

        # Start and check DUT test sequence
        dut.dut_test_start(dictionary=pattern_dict_slave)
        logging.info(f"Explicitly destroy slave: {dut.dut_get_name()}.")
        dut.write("mb stop instances\n")  # Intentionally destroy DUT after test

        dut.dut_check_errors()

        if return_code != 0:
            raise RuntimeError(
                f"The robot suite {ROBOT_SUITE_NAME}, returns an exception: {return_code}."
            )
        logger.info(
            f"Suite {ROBOT_SUITE_NAME} for the Modbus Slave node: {dut_slave_ip_address} is completed, return code: {return_code}."
        )

    except Exception as e:
        logging.error(f"Robot suite {ROBOT_SUITE_NAME} for {dut.dut_get_name()} fail.")
        raise e


if __name__ == "__main__":
    pytest.main(["pytest_mb_tcp_host_test_slave.py"])
