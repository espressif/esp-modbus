# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import pytest
from conftest import ModbusTestDut, Stages

pattern_dict_master = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) [a-z_]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (
        r"I \(([0-9]+)\) BASIC_MODBUS_MASTER: Modbus master stack initialized"
    ),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) mb_port.tcp.master: 0x[a-f0-9]+, Connected: [0-9], [0-9], start polling."
    ),
    Stages.STACK_START: (
        r"I \(([0-9]+)\) BASIC_MODBUS_MASTER: Start Modbus basic example..."
    ),
    Stages.STACK_PAR_OK: (
        r"I \(([0-9]+)\) BASIC_MODBUS_MASTER: Master Id:([a-z0-9]+) Characteristic #([0-9]+) ([a-zA-Z0-9\_\s]+) \(--\) value = ([0-9a-zA-Z.\/]*)\s*([a-zA-Z0-9()]*) read successful"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) BASIC_MODBUS_MASTER: Master Id:([a-z0-9]+) Characteristic ID #([0-9])+ ([a-zA-Z\_]+) read fail, err = [_A-Z]+"
    ),
    Stages.STACK_DESTROY: (r"I \(([0-9]+)\) BASIC_MODBUS_MASTER: (Destroy master)..."),
    Stages.STACK_OBJECT_CREATE: (
        r"[DI] \(([0-9]+)\) [a-z]+_[a-z]+\.([a-z]+)\: created object mb[a-z]\_[a-z]+[#@](0x[0-9a-f]+)"
    ),
    Stages.STACK_BAD_CONNECTION: (
        r"I \([0-9]+\) example_connect: WiFi Connect failed [0-9]* times, stop reconnect."
    ),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"[DI] \(([0-9]+)\) mbc_[a-z]+.master: mbc_[a-z]+_master_get_parameter: ([a-zA-Z0-9]+) Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}

LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
logger = logging.getLogger(LOGGER_NAME)

test_configs = ["rtu", "ascii"]


@pytest.mark.multi_dut_modbus_serial
@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.parametrize("config", test_configs, indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [(1, f"{os.path.join(os.path.dirname(__file__), 'basic_master')}")],
    indirect=True,
)
def test_simple_example_modbus_serial_communication(
    config: str, dut: ModbusTestDut
) -> None:
    logger.info("DUT: %s start.", dut.dut_get_name())
    dut.expect(pattern_dict_master[Stages.STACK_OBJECT_CREATE], timeout=30)
    logger.info(dut.pexpect_proc.match.group(0))

    dut.expect(pattern_dict_master[Stages.STACK_INIT], timeout=30)
    logger.info(dut.pexpect_proc.match.group(0))

    dut.expect(pattern_dict_master[Stages.STACK_START], timeout=30)
    logger.info(dut.pexpect_proc.match.group(0))

    dut.expect(pattern_dict_master[Stages.STACK_PAR_FAIL], timeout=30)
    logger.info(dut.pexpect_proc.match.group(0))

    dut.expect(pattern_dict_master[Stages.STACK_DESTROY], timeout=60)
    logger.info(dut.pexpect_proc.match.group(0))


@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.parametrize("config", ["ethernet"], indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [(1, f"{os.path.join(os.path.dirname(__file__), 'basic_master')}")],
    indirect=True,
)
def test_simple_example_modbus_tcp_communication(
    config: str, dut: ModbusTestDut
) -> None:
    logger.info("DUT: %s start.", dut.dut_get_name())
    dut.dut_test_start(dictionary=pattern_dict_master)
