/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include "unity.h"
#include "unity_test_runner.h"
#include "unity_fixture.h"

#include "sdkconfig.h"

static void run_all_tests(void)
{
#if (CONFIG_FMB_COMM_MODE_RTU_EN || CONFIG_FMB_COMM_MODE_ASCII_EN)
    RUN_TEST_GROUP(modbus_adapter_serial);
#endif
#if (CONFIG_FMB_COMM_MODE_TCP_EN)
    RUN_TEST_GROUP(modbus_adapter_tcp);
#endif
}

void app_main(void)
{
    UNITY_MAIN_FUNC(run_all_tests);
}
