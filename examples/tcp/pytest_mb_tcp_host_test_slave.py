# SPDX-FileCopyrightText: 2016-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

# This is the script to reproduce the issue when the expect() is called from
# main thread in Multi DUT case.

import logging
import os,sys
import subprocess

# pytest required libraries
import pytest
from conftest import ModbusTestDut, Stages


TEST_DIR = os.path.abspath(os.path.dirname(__file__))
TEST_ROBOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tools/robot'))
LOG_LEVEL = logging.DEBUG
LOGGER_NAME = 'modbus_test'
logger = logging.getLogger(LOGGER_NAME)

if os.name == 'nt':
    CLOSE_FDS = False
else:
    CLOSE_FDS = True


pattern_dict_slave = {Stages.STACK_IPV4: (r'I \([0-9]+\) example_[a-z]+: - IPv4 address: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
                      Stages.STACK_IPV6: (r'I \([0-9]+\) example_[a-z]+: - IPv6 address: (([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})'),
                      Stages.STACK_INIT: (r'I \(([0-9]+)\) MB_TCP_SLAVE_PORT: (Protocol stack initialized).'),
                      Stages.STACK_CONNECT: (r'I\s\(([0-9]+)\) MB_TCP_SLAVE_PORT: Socket \(#[0-9]+\), accept client connection from address: '
                                             r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
                      Stages.STACK_START: (r'I\s\(([0-9]+)\) SLAVE_TEST: (Start modbus test)'),
                      Stages.STACK_PAR_OK: (r'I\s\(([0-9]+)\) SLAVE_TEST: ([A-Z]+ [A-Z]+) \([a-zA-Z0-9_]+ us\),\s'
                                            r'ADDR:([0-9]+), TYPE:[0-9]+, INST_ADDR:0x[a-zA-Z0-9]+, SIZE:[0-9]+'),
                      Stages.STACK_PAR_FAIL: (r'E \(([0-9]+)\) SLAVE_TEST: Response time exceeds configured [0-9]+ [ms], ignore packet'),
                      Stages.STACK_DESTROY: (r'I\s\(([0-9]+)\) SLAVE_TEST: (Modbus controller destroyed).')}


@pytest.mark.esp32
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize('config', ['ethernet'], indirect=True)
@pytest.mark.parametrize(
    'count, app_path', [
        (1, f'{os.path.join(os.path.dirname(__file__), "mb_tcp_slave")}')
    ],
    indirect=True
)
def test_modbus_tcp_host_to_slave_communication(app_path, dut: ModbusTestDut) -> None:
    logger.info('DUT: %s start.', dut.dut_get_name())
    dut_slave_ip_address = dut.dut_get_ip()
    assert dut_slave_ip_address is not None, "The DUT could not get IP address. Abort."
    dut_slave_ip_port = dut.app.sdkconfig.get('FMB_TCP_PORT_DEFAULT')
    assert dut_slave_ip_port is not None, f"DUT port is not correct: {dut_slave_ip_port}"
    logger.info(f'Start test for the slave: {app_path}, {dut_slave_ip_address}:{dut_slave_ip_port}')
    try:
        cmd = 'robot ' + \
            f'--variable MODBUS_DEF_SERVER_IP:{dut_slave_ip_address} ' + \
            f'--variable MODBUS_DEF_SERVER_PORT:{dut_slave_ip_port} ' + \
            f'{TEST_ROBOT_DIR}/ModbusTestSuite.robot'
        p = subprocess.Popen(cmd,
                            stdin=None, stdout=None, stderr=None,
                            shell=True,
                            close_fds=CLOSE_FDS
                            )
        dut.dut_test_start(dictionary=pattern_dict_slave)
        p.wait()
        logger.info(f'Test for the node: {dut_slave_ip_address} is completed.')
        dut.dut_check_errors()

    except subprocess.CalledProcessError as e:
        logging.error('robot framework fail with error: %d', e.returncode)
        logging.debug("Command ran: '%s'", e.cmd)
        logging.debug('Command out:')
        logging.debug(e.output)
        logging.error('Check the correctneess of the suite script.')
        raise e
