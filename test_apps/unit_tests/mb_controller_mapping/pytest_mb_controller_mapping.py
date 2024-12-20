# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded import Dut


CONFIGS = [
    pytest.param('serial', marks=[pytest.mark.esp32, pytest.mark.esp32s2, pytest.mark.esp32s3, pytest.mark.esp32c3]),
]


@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize('config', CONFIGS, indirect=True)
def test_modbus_controller_mapping(dut: Dut) -> None:
    dut.expect_unity_test_output()
