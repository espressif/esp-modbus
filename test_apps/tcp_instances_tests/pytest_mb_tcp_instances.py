# SPDX-FileCopyrightText: 2016-2025 Espressif Systems (Shanghai) CO LTD
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
    PARAM_SUCCESS,
    PARAM_FAIL,
    MASTER_TAG,
    SLAVE_TAG,
)

pattern_dict_slave = {
    Stages.STACK_IPV4: (
        r"I \([0-9]+\) example_[a-z]+: [A-Za-z\-]* IPv4 [A-Za-z\"_:\s]*address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    ),
    Stages.STACK_IPV6: (
        r"I \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})"
    ),
    Stages.STACK_INIT: (r"I \(([0-9]+)\) [A-Z_]*: (Modbus slave stack initialized)."),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) port.utils: Socket \(#[0-9]+\), accept client connection from address\[port\]: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\[[0-9]+\]"
    ),
    Stages.STACK_START: (r"I\s\(([0-9]+)\) [A-Z_]+: Slave TCP [#0-9]*\s*is started"),
    Stages.STACK_PAR_OK: (
        r"I\s\(([0-9]+)\) [A-Z_]+: OBJ (0x[a-fA-Z0-9]+),() ([A-Za-z\s]+) \([0-9]+ us\),\s*[A-Z:]*\s*[0-9,]*\s*[A-Z:]*[0-9]*, TYPE:[0-9]+, INST_ADDR:0x[a-fA-Z0-9]+[()0-9a-z]+, SIZE:[0-9]+"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) SLAVE_TEST: Response time exceeds configured [0-9]+ [ms], ignore packet"
    ),
    Stages.STACK_DESTROY: (r"I\s\(([0-9]+)\) [A-Z_]+: Destroy slave"),
    Stages.STACK_OBJECT_CREATE: (
        r"D \(([0-9]+)\) [a-z]+_[a-z]+\.([a-z]+)\: created object mb[a-z]\_tcp[#@](0x[0-9a-f]+)"
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
        r"I \(([0-9]+)\) [A-Z_]*: [0xa-f0-9,]*\s*Modbus master stack initialized"
    ),
    Stages.STACK_CONNECT: (
        r"I\s\(([0-9]+)\) mb_port.tcp.master: 0x[a-f0-9]+, Connected: [0-9], [0-9], start polling."
    ),
    Stages.STACK_START: (r"I \(([0-9]+)\) [A-Z_]+: Master TCP is started"),
    Stages.STACK_PAR_OK: (
        r"I \(([0-9]+)\) [A-Z_]+: ([a-z0-9]+) Characteristic #([0-9]+) ([a-zA-Z0-9\_]+) \([\%a-zA-Z_\/]+\) value = ([0-9a-z.A-Z]*)\s*([a-zA-Z0-9()]*) read successful"
    ),
    Stages.STACK_PAR_FAIL: (
        r"E \(([0-9]+)\) [A-Z_]+: ([a-z0-9]+) Characteristic #([0-9]+) \(([a-zA-Z0-9_]+)\) read fail, err = [x0-9]+ \([_A-Z]+\)"
    ),
    Stages.STACK_DESTROY: (r"I \(([0-9]+)\) [A-Z_]+: (Master TCP is completed.)"),
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

LOG_LEVEL = logging.DEBUG
LOGGER_NAME = "modbus_test"
CONFORMANCE_TEST_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tools/robot")
)
logger = logging.getLogger(LOGGER_NAME)

test_configs = [
    #    'wifi',
    "ethernet"
]


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize("config", test_configs, indirect=True)
@pytest.mark.parametrize(
    "count, app_path",
    [
        (
            2,
            f"{os.path.join(os.path.dirname(__file__), 'mb_tcp_slave_instances')}|{os.path.join(os.path.dirname(__file__), 'mb_tcp_master_instances')}",
        )
    ],
    indirect=True,
)
def test_modbus_tcp_communication(dut: Tuple[ModbusTestDut, ModbusTestDut]) -> None:
    dut_master = dut[1]
    dut_slave = dut[0]

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

    params_timestamp = dut_master.get_params_by_timestamp_range(40000, 45000)
    if params_timestamp:
        for param in params_timestamp:
            logger.info("Modbus params by timestamp: %s", param)

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


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize("config", ["dummy_config"])
def test_modbus_tcp_generic(config) -> None:
    logger.info("The generic tcp example tests are not provided yet.")


if __name__ == "__main__":
    pytest.main(["pytest_mb_tcp_instances.py"])
