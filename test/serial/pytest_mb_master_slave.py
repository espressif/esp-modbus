# SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# This is the script to reproduce the issue when the expect() is called from
# main thread in Multi DUT case.

import logging
import os
from typing import Tuple

import pytest

from conftest import ModbusTestDut, Stages

pattern_dict_slave = {Stages.STACK_IPV4: (r'I \([0-9]+\) example_connect: - IPv4 address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
                      Stages.STACK_IPV6: (r'I \([0-9]+\) example_connect: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})'),
                      Stages.STACK_INIT: (r'I \(([0-9]+)\) MB_TCP_SLAVE_PORT: (Protocol stack initialized).'),
                      Stages.STACK_CONNECT: (r'I\s\(([0-9]+)\) MB_TCP_SLAVE_PORT: Socket \(#[0-9]+\), accept client connection from address: '
                                             r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
                      Stages.STACK_START: (r'I\s\(([0-9]+)\) SLAVE_TEST: (Start modbus test)'),
                      Stages.STACK_PAR_OK: (r'I\s\(([0-9]+)\) SLAVE_TEST: ([A-Z]+ [A-Z]+) \([a-zA-Z0-9_]+ us\),\s'
                                            r'ADDR:([0-9]+), TYPE:[0-9]+, INST_ADDR:0x[a-zA-Z0-9]+, SIZE:[0-9]+'),
                      Stages.STACK_PAR_FAIL: (r'E \(([0-9]+)\) SLAVE_TEST: Response time exceeds configured [0-9]+ [ms], ignore packet'),
                      Stages.STACK_DESTROY: (r'I\s\(([0-9]+)\) SLAVE_TEST: (Modbus controller destroyed).')}

pattern_dict_master = {Stages.STACK_IPV4: (r'I \([0-9]+\) example_connect: - IPv4 address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
                       Stages.STACK_IPV6: (r'I \([0-9]+\) example_connect: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})'),
                       Stages.STACK_INIT: (r'I \(([0-9]+)\) MASTER_TEST: (Modbus master stack initialized)'),
                       Stages.STACK_CONNECT: (r'I\s\(([0-9]+)\) MB_TCP_MASTER_PORT: (Connected [0-9]+ slaves), start polling'),
                       Stages.STACK_START: (r'I \(([0-9]+)\) MASTER_TEST: (Start modbus test)'),
                       Stages.STACK_PAR_OK: (r'I \(([0-9]+)\) MASTER_TEST: Characteristic #[0-9]+ ([a-zA-Z0-9_]+)'
                                             r'\s\([a-zA-Z\_\%\/]+\) value =[a-zA-Z0-9\.\s]* \((0x[a-zA-Z0-9]+)\)[,\sa-z]+ successful'),
                       Stages.STACK_PAR_FAIL: (r'.*E \(([0-9]+)\) MASTER_TEST: Characteristic #[0-9]+\s\(([a-zA-Z0-9_]+)\)\s'
                                               r'read fail, err = [0-9]+ \([_A-Z]+\)'),
                       Stages.STACK_DESTROY: (r'I \(([0-9]+)\) MASTER_TEST: (Destroy master)...')}

LOG_LEVEL = logging.DEBUG
LOGGER_NAME = 'modbus_test'
logger = logging.getLogger(LOGGER_NAME)

test_configs = [
    'rtu',
    'ascii'
]

@pytest.mark.esp32
@pytest.mark.multi_dut_modbus_serial
@pytest.mark.parametrize('config', test_configs, indirect=True)
@pytest.mark.parametrize(
    'count, app_path', [
        (2, f'{os.path.join(os.path.dirname(__file__), "mb_serial_master")}|{os.path.join(os.path.dirname(__file__), "mb_serial_slave")}')
    ],
    indirect=True
)
def test_modbus_serial_communication(config: str, dut: Tuple[ModbusTestDut, ModbusTestDut]) -> None:
    dut_slave = dut[1]
    dut_master = dut[0]

    logger.info('DUT: %s start.', dut_master.dut_get_name())
    logger.info('DUT: %s start.', dut_slave.dut_get_name())

    dut_slave.dut_test_start(dictionary=pattern_dict_slave)
    dut_master.dut_test_start(dictionary=pattern_dict_master)

    dut_slave.dut_check_errors()
    dut_master.dut_check_errors()