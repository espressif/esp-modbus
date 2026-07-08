# SPDX-FileCopyrightText: 2022-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.parametrize("count, config", [(2, "serial")], indirect=True)
@pytest.mark.multi_dut_modbus_serial
def test_modbus_comm_bcast_serial(case_tester) -> None:  # type: ignore
    for case in case_tester.test_menu:
        if (
            case.attributes.get("test_env", "multi_dut_modbus_serial")
            == "multi_dut_modbus_serial"
        ):
            print(f"Test case: {case.name}")
            case_tester.run_multi_dev_case(case=case, reset=True)
