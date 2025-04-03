# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: CC0-1.0

import pytest
from pytest_embedded_idf import CaseTester

@pytest.mark.esp32
@pytest.mark.multi_dut_modbus_serial
@pytest.mark.parametrize('count, config', [(2, 'serial')], indirect=True)
def test_modbus_comm_multi_dev_serial(case_tester) -> None:                # type: ignore
    for case in case_tester.test_menu:
        if case.attributes.get('test_env', 'multi_dut_modbus_serial') == 'multi_dut_modbus_serial':
            print(f'Test case: {case.name}')
            case_tester.run_multi_dev_case(case=case, reset=True)

@pytest.mark.esp32
@pytest.mark.multi_dut_modbus_tcp
@pytest.mark.parametrize('count, config', [(2, 'ethernet')], indirect=True)
def test_modbus_comm_multi_dev_tcp(case_tester) -> None:                # type: ignore
    for case in case_tester.test_menu:
        if case.attributes.get('test_env', 'multi_dut_modbus_tcp') == 'multi_dut_modbus_tcp':
            print(f'Test case: {case.name}')
            case_tester.run_multi_dev_case(case=case, reset=True)