# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded import Dut


@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize('target', ['esp32'], indirect=True)
@pytest.mark.parametrize('config', ['serial'], indirect=True)
def test_modbus_controller_mapping(dut: Dut) -> None:
    dut.expect_unity_test_output()
