# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded import Dut


CONFIGS = [
    pytest.param('serial', marks=[pytest.mark.esp32, pytest.mark.esp32p4]),
    pytest.param('tcp', marks=[pytest.mark.esp32, pytest.mark.esp32p4]),
]

@pytest.mark.temp_skip_ci(targets=['esp32p4'], reason='no multi-dev runner')
@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize('config', CONFIGS, indirect=True)
def test_modbus_comm_adapter(dut: Dut) -> None:
    dut.expect_unity_test_output()
