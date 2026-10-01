# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded import Dut


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.parametrize("config", ["defaults"], indirect=True)
@pytest.mark.multi_dut_modbus_generic
def test_modbus_tcp_slave_lifecycle(dut: Dut) -> None:
    dut.expect_unity_test_output(timeout=300)
