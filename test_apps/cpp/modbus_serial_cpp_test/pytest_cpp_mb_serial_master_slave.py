# SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import pytest
from pytest_embedded import Dut

@pytest.mark.esp32
@pytest.mark.generic
def test_cpp_mb_serial_master_slave(dut: Dut) -> None:
    dut.expect('Setup master cpp....')
    dut.expect('Modbus master stack initialized...', timeout=5)
    dut.expect('Master test passed successfully.', timeout=5)
    dut.expect('Setup slave cpp....')
    dut.expect('Modbus slave stack initialized...', timeout=5)
    dut.expect('Slave test passed successfully.', timeout=5)
    dut.expect('Returned from app_main()')
