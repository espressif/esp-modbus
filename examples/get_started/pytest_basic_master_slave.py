# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from typing import Tuple
import pytest
from conftest import (
    ModbusTestDut,
    Stages,
    PARAM_SUCCESS,
    PARAM_FAIL,
    MASTER_TAG,
    SLAVE_TAG,
)

pattern_dict_slave = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) example_[a-z]+: - IPv4 address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (
        r"I \(([0-9]+)\) BASIC_MODBUS_SLAVE: Modbus slave stack initialized"
    ),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) port.utils: Socket \(#[0-9]+\), accept client connection from address\[port\]: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\[[0-9]+\]"
    ),
    Stages.STACK_START: (
        r"I \(([0-9]+)\) BASIC_MODBUS_SLAVE: Start Modbus basic slave example"
    ),
    Stages.STACK_PAR_OK: (
        r"I\s\(([0-9]+)\) BASIC_MODBUS_SLAVE: Slave ID:(0x[a-f0-9]+) - ()([A-Z]+) REG READ REG_AREA_ADDR:[a-z0-9]+ OFFSET:[0-9]+ NUMBER_REG:[0-9]+"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) BASIC_MODBUS_SLAVE: Response time exceeds configured [0-9]+ [ms], ignore packet"
    ),
    Stages.STACK_DESTROY: (r"I\s\(([0-9]+)\) BASIC_MODBUS_SLAVE: Destroy slave"),
    Stages.STACK_OBJECT_CREATE: (
        r"[DI] \(([0-9]+)\) [a-z]+_[a-z]+\.([a-z]+)\: created object mb[a-z]\_[a-z]+[#@](0x[0-9a-f]+)"
    ),
    Stages.STACK_BAD_CONNECTION: (
        r"I \([0-9]+\) example_connect: WiFi Connect failed [0-9]* times, stop reconnect."
    ),
    Stages.STACK_CID_RESPONSE_TIME: (
        r"D \(([0-9]+)\) mbc_[a-z]+.slave: mbc_[a-z]+_slave_get_parameter: Good response for get cid\(([0-9]+)\) = ESP_OK"
    ),
}

pattern_dict_master = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) example_[a-z]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
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
        r"I \(([0-9]+)\) BASIC_MODBUS_MASTER: Master Id:(0x[a-f0-9]+) Characteristic ID #([0-9]+) ([a-zA-Z0-9\_\s]+) value = ([0-9a-zA-Z.\/]*)\s*([a-zA-Z0-9()]*) read successful"
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
LOGGER_NAME = "basic_example"
logger = logging.getLogger(LOGGER_NAME)


def basic_master_slave_test(
    dut_slave: ModbusTestDut, dut_master: ModbusTestDut
) -> None:
    dut_master.add_dut_list(dut_slave)
    dut_slave.add_dut_list(dut_master)

    logger.info("DUT: %s start.", dut_master.dut_get_name())
    logger.info("DUT: %s start.", dut_slave.dut_get_name())

    dut_slave.dut_test_start(dictionary=pattern_dict_slave)
    dut_master.dut_test_start(dictionary=pattern_dict_master)

    ### Slave and Master objects registered
    slave_objects = dut_slave.get_objects_by_tag(SLAVE_TAG)
    for object in slave_objects:
        logger.info("Modbus slave objects: %s", object)
    logger.info("Number of slave objects: %s", len(slave_objects))

    master_objects = dut_master.get_objects_by_tag(MASTER_TAG)
    for object in master_objects:
        logger.info("Modbus master objects: %s", object)
    logger.info("Number of master objects: %s", len(master_objects))

    ### Slave Fail and Success Params
    slave_success_params = dut_slave.get_slave_params_by_status(PARAM_SUCCESS)
    logger.info("Total successful slave parameters: %d", len(slave_success_params))

    slave_fail_params = dut_slave.get_slave_params_by_status(PARAM_FAIL)
    logger.info("Total fail slave parameters: %d", len(slave_fail_params))

    all_slave_params = len(slave_success_params) + len(slave_fail_params)
    if all_slave_params:
        logger.info(
            "All slave parameters: %s, Ratio of successful slave parameters: %s",
            all_slave_params,
            (len(slave_success_params) / all_slave_params) * 100,
        )

    ### Master Fail and Success Params
    master_success_params = dut_master.get_master_params_by_status(PARAM_SUCCESS)
    logger.info("Total successful master parameters: %d", len(master_success_params))

    master_fail_params = dut_master.get_master_params_by_status(PARAM_FAIL)
    logger.info("Total fail master parameters: %d", len(master_fail_params))

    all_master_params = len(master_success_params) + len(master_fail_params)
    if all_master_params:
        logger.info(
            "All master parameters: %s, Ratio of successful master parameters: %s",
            all_master_params,
            (len(master_success_params) / all_master_params) * 100,
        )

    ### Master average response time for successful requests
    logger.info(
        "Average response time for successful master requests: %d ms",
        dut_master.get_avg_response_time_master(),
    )

    dut_slave.dut_check_errors()
    dut_master.dut_check_errors()

    ### Histogram Modbus stats
    dut_master.plot_modbus_stats(
        master_objects,
        dut_master.dut_stats_info(),
        slave_objects,
        dut_slave.dut_stats_info(),
        "modbus_stats_graph",
    )


test_configs = ["rtu", "ascii"]


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_serial
@pytest.mark.parametrize("config", test_configs, indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [
        (
            2,
            f"{os.path.join(os.path.dirname(__file__), 'basic_slave')}|{os.path.join(os.path.dirname(__file__), 'basic_master')}",
        )
    ],
    indirect=True,
)
def test_simple_example_modbus_serial_communication(
    dut: Tuple[ModbusTestDut, ModbusTestDut],
) -> None:
    dut_slave = dut[0]
    dut_master = dut[1]

    logger.info("Serial test Master-Slave basic examples")

    basic_master_slave_test(dut_slave, dut_master)


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize("config", ["ethernet"], indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [
        (
            2,
            f"{os.path.join(os.path.dirname(__file__), 'basic_slave')}|{os.path.join(os.path.dirname(__file__), 'basic_master')}",
        )
    ],
    indirect=True,
)
def test_simple_example_modbus_tcp_communication(
    dut: Tuple[ModbusTestDut, ModbusTestDut],
) -> None:
    dut_slave = dut[0]
    dut_master = dut[1]

    logger.info("TCP test Master-Slave basic examples test")

    basic_master_slave_test(dut_slave, dut_master)
