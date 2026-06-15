/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <stdlib.h>
#include <stdbool.h>
#include "unity.h"
#include "test_utils.h"

#include "sdkconfig.h"
#include "port_tcp_utils.h"
#include "test_common.h"

#define TAG "TEST_MB_CONFIG_PARSER"

// The below is the test for configuration parser of modbus master tcp

TEST_CASE("Test tcp configuration parser.", "[MB_CONFIGURATION]")
{
    mb_uid_info_t uid_info = {0};

    // UID, Hostname, Port
    int result = port_scan_addr_string((char *)"01;mb_node_tcp_01;502", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 3);
    TEST_ASSERT(uid_info.uid == 1);
    TEST_ASSERT(uid_info.node_name_str && strcmp(uid_info.node_name_str, "mb_node_tcp_01") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    TEST_ASSERT(uid_info.port == 502);
    free(uid_info.node_name_str);

    // UID, Hostname, Port, the incorect UID provided (only decimal representation is supported)
    result = port_scan_addr_string("c8;mb_slave_tcp_c8;1502", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 1);
    TEST_ASSERT(uid_info.uid == 0);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "c8") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    TEST_ASSERT(uid_info.port == 502); // default port
    free(uid_info.node_name_str);

    // UID, Hostname, Port, the incorect host name
    result = port_scan_addr_string("15;mb_slave**_tcp_c8;1502", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 1);
    TEST_ASSERT(uid_info.uid == 15);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "15") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    TEST_ASSERT(uid_info.port == 502); // default port
    free(uid_info.node_name_str);

    // Hostname only
    result = port_scan_addr_string("mb_slave_tcp_01", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 1);
    TEST_ASSERT(uid_info.uid == 0);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "mb_slave_tcp_01") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    free(uid_info.node_name_str);

        // Hostname only
    result = port_scan_addr_string("mb_slave_tcp_01;1234", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 2);
    TEST_ASSERT(uid_info.uid == 0);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "mb_slave_tcp_01") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    TEST_ASSERT(uid_info.port == 1234); // default port
    free(uid_info.node_name_str);

    // UID, IPV4 Address, Port
    result = port_scan_addr_string("2;192.168.1.1;3456", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 6);
    TEST_ASSERT(uid_info.uid == 2);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "192.168.1.1") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV4);
    TEST_ASSERT(uid_info.port == 3456); // default port
    free(uid_info.node_name_str);

    // UID, IPV6 Address, Port
    result = port_scan_addr_string("12;2001:0db8:85a3:0000:0000:8a2e:0370:7334;502", &uid_info);
    TEST_ASSERT(uid_info.node_name_str);
    printf("Test config parser result: %d, index: %d, host: %s, port: %d \r\n", result, uid_info.uid, uid_info.node_name_str, uid_info.port);
    TEST_ASSERT(result == 10);
    TEST_ASSERT(uid_info.uid == 12);
    TEST_ASSERT(strcmp(uid_info.node_name_str, "2001:0db8:85a3:0000:0000:8a2e:0370:7334") == 0);
    TEST_ASSERT(uid_info.addr_type == MB_IPV6);
    free(uid_info.node_name_str);
}

void app_main(void)
{
    unity_run_menu();
}
