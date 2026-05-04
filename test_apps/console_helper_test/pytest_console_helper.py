# SPDX-FileCopyrightText: 2016-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from pytest_embedded import Dut

MB_APP_WAIT_TOUT_SEC = 120


@pytest.mark.parametrize("target", ["esp32"], indirect=True)
@pytest.mark.multi_dut_modbus_generic
@pytest.mark.parametrize("config", ["generic"], indirect=True)
def test_mb_console_helper_flow(
    dut: Dut,
) -> None:
    # Wait for the helper to request IP from stdin (the register function prints this)
    dut.expect(r"Waiting IP\([0-9]{1,2}\) from stdin:", timeout=10)

    # Send multiple config strings matching app_config_table entries (indices 0,1,2)
    dut.write("IP 00=192.168.1.5;1502\n")
    dut.write("IP 01=10.0.0.3;1502\n")
    dut.write("IP 02=172.16.0.10;502\n")

    # After sending, helper/app should confirm the configured table entries.
    # The test app prints lines like: "Config[0] set to <string>"
    dut.expect(r"Config\[0\] set to .*192\.168\.1\.5.*1502", timeout=5)
    dut.expect(r"Config\[1\] set to .*10\.0\.0\.3.*1502", timeout=5)
    dut.expect(r"Config\[2\] set to .*172\.16\.0\.10.*502", timeout=5)

    # Trigger start command and ensure app logs the Start event
    dut.write("mb start instances\n")
    dut.expect("Start modbus instances.", timeout=5)

    # Trigger stop command and ensure app logs the Stop event
    dut.write("mb stop instances\n")
    dut.expect("Stop modbus instances.", timeout=5)
    dut.expect("Destroying console helper...", timeout=5)
    dut.write("\r\n")  # release repl correctly
    dut.expect("Console helper destroyed.", timeout=10)
