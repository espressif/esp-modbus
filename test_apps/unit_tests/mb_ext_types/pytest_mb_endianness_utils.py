# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded import Dut


#@pytest.mark.supported_targets
@pytest.mark.esp32           # test on esp32 for now
@pytest.mark.multi_dut_modbus_generic
def test_mb_endianness_utils(dut: Dut) -> None:
    dut.run_all_single_board_cases()
