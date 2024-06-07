/*
 * SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// FreeModbus Master Example ESP32

#include <string.h>
#include <sys/queue.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#if __has_include("esp_mac.h")
#include "esp_mac.h"
#endif

#include "mdns.h"
#include "protocol_examples_common.h"

#include "modbus_params.h"  // for modbus parameters structures
#include "mbcontroller.h"
#include "sdkconfig.h"

#define MB_TCP_PORT                     (CONFIG_FMB_TCP_PORT_DEFAULT)   // TCP port used by example

// The number of parameters that intended to be used in the particular control process
#define MASTER_MAX_CIDS num_device_parameters

// Number of reading of parameters from slave
#define MASTER_MAX_RETRY                (10)

// Timeout to update cid over Modbus
#define UPDATE_CIDS_TIMEOUT_MS          (500)
#define UPDATE_CIDS_TIMEOUT_TICS        (UPDATE_CIDS_TIMEOUT_MS / portTICK_PERIOD_MS)

// Timeout between polls
#define POLL_TIMEOUT_MS                 (1)
#define POLL_TIMEOUT_TICS               (POLL_TIMEOUT_MS / portTICK_PERIOD_MS)
#define MB_MDNS_PORT                    (502)

// The macro to get offset for parameter in the appropriate structure
#define HOLD_OFFSET(field) ((uint16_t)(offsetof(holding_reg_params_t, field) + 1))
#define INPUT_OFFSET(field) ((uint16_t)(offsetof(input_reg_params_t, field) + 1))
#define COIL_OFFSET(field) ((uint16_t)(offsetof(coil_reg_params_t, field) + 1))
#define DISCR_OFFSET(field) ((uint16_t)(offsetof(discrete_reg_params_t, field) + 1))

#define STR(fieldname) ((const char *)( fieldname ))
#define TEST_HOLD_REG_START(field) (HOLD_OFFSET(field) >> 1)
#define TEST_HOLD_REG_SIZE(field) (sizeof(((holding_reg_params_t *)0)->field) >> 1)

#define TEST_INPUT_REG_START(field) (INPUT_OFFSET(field) >> 1)
#define TEST_INPUT_REG_SIZE(field) (sizeof(((input_reg_params_t *)0)->field) >> 1)

#define TEST_VALUE 12345 // default test value
#define TEST_ASCII_BIN 0xAAAAAAAA

// Options can be used as bit masks or parameter limits
#define OPTS(min_val, max_val, step_val) { .opt1 = min_val, .opt2 = max_val, .opt3 = step_val }

#define MB_ID_BYTE0(id) ((uint8_t)(id))
#define MB_ID_BYTE1(id) ((uint8_t)(((uint16_t)(id) >> 8) & 0xFF))
#define MB_ID_BYTE2(id) ((uint8_t)(((uint32_t)(id) >> 16) & 0xFF))
#define MB_ID_BYTE3(id) ((uint8_t)(((uint32_t)(id) >> 24) & 0xFF))

#define MB_ID2STR(id) MB_ID_BYTE0(id), MB_ID_BYTE1(id), MB_ID_BYTE2(id), MB_ID_BYTE3(id)

#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
#define MB_DEVICE_ID (uint32_t)CONFIG_FMB_CONTROLLER_SLAVE_ID
#else
#define MB_DEVICE_ID (uint32_t)0x00112233
#endif

#define MB_MDNS_INSTANCE(pref) pref"mb_master_tcp"

#define EACH_ITEM(array, length) \
(typeof(*(array)) *pitem = (array); (pitem < &((array)[length])); pitem++)

static const char *TAG = "MASTER_TEST";

// Enumeration of modbus device addresses accessed by master device
// Each address in the table is a index of TCP slave ip address in mb_communication_info_t::tcp_ip_addr table
enum {
    MB_DEVICE_ADDR1 = 1, // Slave UID = 1
    MB_DEVICE_ADDR2 = 200,
    MB_DEVICE_ADDR3 = 35
};

// Enumeration of all supported CIDs for device (used in parameter definition table)
enum {
    CID_INP_DATA_0 = 0,
    CID_HOLD_DATA_0,
    CID_INP_DATA_1,
    CID_HOLD_DATA_1,
    CID_INP_DATA_2,
    CID_HOLD_DATA_2,
    CID_HOLD_TEST_REG,
    CID_RELAY_P1,
    CID_RELAY_P2,
    CID_DISCR_P1,
#if CONFIG_FMB_EXT_TYPE_SUPPORT
    CID_HOLD_U8_A,
    CID_HOLD_U8_B,
    CID_HOLD_U16_AB,
    CID_HOLD_U16_BA,
    CID_HOLD_UINT32_ABCD,
    CID_HOLD_UINT32_CDAB,
    CID_HOLD_UINT32_BADC,
    CID_HOLD_UINT32_DCBA,
    CID_HOLD_FLOAT_ABCD,
    CID_HOLD_FLOAT_CDAB,
    CID_HOLD_FLOAT_BADC,
    CID_HOLD_FLOAT_DCBA,
    CID_HOLD_DOUBLE_ABCDEFGH,
    CID_HOLD_DOUBLE_HGFEDCBA,
    CID_HOLD_DOUBLE_GHEFCDAB,
    CID_HOLD_DOUBLE_BADCFEHG,
#endif
    CID_COUNT
};

// Example Data (Object) Dictionary for Modbus parameters:
// The CID field in the table must be unique.
// Modbus Slave Addr field defines slave address of the device with correspond parameter.
// Modbus Reg Type - Type of Modbus register area (Holding register, Input Register and such).
// Reg Start field defines the start Modbus register number and Reg Size defines the number of registers for the characteristic accordingly.
// The Instance Offset defines offset in the appropriate parameter structure that will be used as instance to save parameter value.
// Data Type, Data Size specify type of the characteristic and its data size.
// Parameter Options field specifies the options that can be used to process parameter value (limits or masks).
// Access Mode - can be used to implement custom options for processing of characteristic (Read/Write restrictions, factory mode values and etc).
const mb_parameter_descriptor_t device_parameters[] = {
    // { CID, Param Name, Units, Modbus Slave Addr, Modbus Reg Type, Reg Start, Reg Size, Instance Offset, Data Type, Data Size, Parameter Options, Access Mode}
    { CID_INP_DATA_0, STR("Data_channel_0"), STR("Volts"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data0), TEST_INPUT_REG_SIZE(input_data0),
            INPUT_OFFSET(input_data0), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_0, STR("Humidity_1"), STR("%rH"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data0), TEST_HOLD_REG_SIZE(holding_data0),
            HOLD_OFFSET(holding_data0), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_INP_DATA_1, STR("Temperature_1"), STR("C"), MB_DEVICE_ADDR1, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data1), TEST_INPUT_REG_SIZE(input_data1),
            INPUT_OFFSET(input_data1), PARAM_TYPE_FLOAT, 4,
            OPTS( -40, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_1, STR("Humidity_2"), STR("%rH"), MB_DEVICE_ADDR2, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data1), TEST_HOLD_REG_SIZE(holding_data1),
            HOLD_OFFSET(holding_data1), PARAM_TYPE_FLOAT, 4,
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_INP_DATA_2, STR("Temperature_2"), STR("C"), MB_DEVICE_ADDR2, MB_PARAM_INPUT,
            TEST_INPUT_REG_START(input_data2), TEST_INPUT_REG_SIZE(input_data2),
            INPUT_OFFSET(input_data2), PARAM_TYPE_FLOAT, 4,
            OPTS( -40, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DATA_2, STR("Humidity_3"), STR("%rH"), MB_DEVICE_ADDR3, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_data2), TEST_HOLD_REG_SIZE(holding_data2),
            HOLD_OFFSET(holding_data2), PARAM_TYPE_FLOAT, 4, 
            OPTS( 0, 100, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_TEST_REG, STR("Test_regs"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(test_regs), 58,
            HOLD_OFFSET(test_regs), PARAM_TYPE_ASCII, 116, 
            OPTS( 0, 100, TEST_ASCII_BIN ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_RELAY_P1, STR("RelayP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 2, 6,
            COIL_OFFSET(coils_port0), PARAM_TYPE_U8, 1, 
            OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_RELAY_P2, STR("RelayP2"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_COIL, 10, 6,
            COIL_OFFSET(coils_port1), PARAM_TYPE_U8, 1, 
            OPTS( 0x55, 0x2A, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_DISCR_P1, STR("DiscreteInpP1"), STR("on/off"), MB_DEVICE_ADDR1, MB_PARAM_DISCRETE, 2, 7,
            DISCR_OFFSET(discrete_input_port1), PARAM_TYPE_U8, 1, 
            OPTS( 0xAA, 0x15, 0 ), PAR_PERMS_READ_WRITE_TRIGGER },
#if CONFIG_FMB_EXT_TYPE_SUPPORT
    { CID_HOLD_U8_A, STR("U8_A"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u8_a), TEST_HOLD_REG_SIZE(holding_u8_a),
            HOLD_OFFSET(holding_u8_a), PARAM_TYPE_U8_A, (TEST_HOLD_REG_SIZE(holding_u8_a) << 1), 
            OPTS( CHAR_MIN, 0x0055, 0x0055 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U8_B, STR("U8_B"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u8_b), TEST_HOLD_REG_SIZE(holding_u8_b),
            HOLD_OFFSET(holding_u8_b), PARAM_TYPE_U8_B, (TEST_HOLD_REG_SIZE(holding_u8_b) << 1), 
            OPTS( 0, 0x5500, 0x5500 ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U16_AB, STR("U16_AB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_u16_ab), TEST_HOLD_REG_SIZE(holding_u16_ab),
            HOLD_OFFSET(holding_u16_ab), PARAM_TYPE_U16_AB, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_U16_BA, STR("U16_BA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_u16_ba), TEST_HOLD_REG_SIZE(holding_u16_ba),
            HOLD_OFFSET(holding_u16_ba), PARAM_TYPE_U16_BA, (TEST_HOLD_REG_SIZE(holding_u16_ab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_ABCD, STR("UINT32_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_uint32_abcd), TEST_HOLD_REG_SIZE(holding_uint32_abcd),
            HOLD_OFFSET(holding_uint32_abcd), PARAM_TYPE_U32_ABCD, (TEST_HOLD_REG_SIZE(holding_uint32_abcd) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_CDAB, STR("UINT32_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_cdab), TEST_HOLD_REG_SIZE(holding_uint32_cdab),
            HOLD_OFFSET(holding_uint32_cdab), PARAM_TYPE_U32_CDAB, (TEST_HOLD_REG_SIZE(holding_uint32_cdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_BADC, STR("UINT32_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_badc), TEST_HOLD_REG_SIZE(holding_uint32_badc),
            HOLD_OFFSET(holding_uint32_badc), PARAM_TYPE_U32_BADC, (TEST_HOLD_REG_SIZE(holding_uint32_badc) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_UINT32_DCBA, STR("UINT32_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_uint32_dcba), TEST_HOLD_REG_SIZE(holding_uint32_dcba),
            HOLD_OFFSET(holding_uint32_dcba), PARAM_TYPE_U32_DCBA, (TEST_HOLD_REG_SIZE(holding_uint32_dcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_ABCD, STR("FLOAT_ABCD"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING, 
            TEST_HOLD_REG_START(holding_float_abcd), TEST_HOLD_REG_SIZE(holding_float_abcd),
            HOLD_OFFSET(holding_float_abcd), PARAM_TYPE_FLOAT_ABCD, (TEST_HOLD_REG_SIZE(holding_float_abcd) << 1),
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_CDAB, STR("FLOAT_CDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_cdab), TEST_HOLD_REG_SIZE(holding_float_cdab),
            HOLD_OFFSET(holding_float_cdab), PARAM_TYPE_FLOAT_CDAB, (TEST_HOLD_REG_SIZE(holding_float_cdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_BADC, STR("FLOAT_BADC"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_badc), TEST_HOLD_REG_SIZE(holding_float_badc),
            HOLD_OFFSET(holding_float_badc), PARAM_TYPE_FLOAT_BADC, (TEST_HOLD_REG_SIZE(holding_float_badc) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_FLOAT_DCBA, STR("FLOAT_DCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_float_dcba), TEST_HOLD_REG_SIZE(holding_float_dcba),
            HOLD_OFFSET(holding_float_dcba), PARAM_TYPE_FLOAT_DCBA, (TEST_HOLD_REG_SIZE(holding_float_dcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_ABCDEFGH, STR("DOUBLE_ABCDEFGH"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_abcdefgh), TEST_HOLD_REG_SIZE(holding_double_abcdefgh),
            HOLD_OFFSET(holding_double_abcdefgh), PARAM_TYPE_DOUBLE_ABCDEFGH, (TEST_HOLD_REG_SIZE(holding_double_abcdefgh) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_HGFEDCBA, STR("DOUBLE_HGFEDCBA"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_hgfedcba), TEST_HOLD_REG_SIZE(holding_double_hgfedcba),
            HOLD_OFFSET(holding_double_hgfedcba), PARAM_TYPE_DOUBLE_HGFEDCBA, (TEST_HOLD_REG_SIZE(holding_double_hgfedcba) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_GHEFCDAB, STR("DOUBLE_GHEFCDAB"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_ghefcdab), TEST_HOLD_REG_SIZE(holding_double_ghefcdab),
            HOLD_OFFSET(holding_double_ghefcdab), PARAM_TYPE_DOUBLE_GHEFCDAB, (TEST_HOLD_REG_SIZE(holding_double_ghefcdab) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER },
    { CID_HOLD_DOUBLE_BADCFEHG, STR("DOUBLE_BADCFEHG"), STR("__"), MB_DEVICE_ADDR1, MB_PARAM_HOLDING,
            TEST_HOLD_REG_START(holding_double_badcfehg), TEST_HOLD_REG_SIZE(holding_double_badcfehg),
            HOLD_OFFSET(holding_double_badcfehg), PARAM_TYPE_DOUBLE_BADCFEHG, (TEST_HOLD_REG_SIZE(holding_double_badcfehg) << 1), 
            OPTS( 0, TEST_VALUE, TEST_VALUE ), PAR_PERMS_READ_WRITE_TRIGGER }
#endif
};

// Calculate number of parameters in the table
const uint16_t num_device_parameters = (sizeof(device_parameters) / sizeof(device_parameters[0]));

// This table represents slave IP addresses that correspond to the short address field of the slave in device_parameters structure
// Modbus TCP stack shall use these addresses to be able to connect and read parameters from slave
char* slave_ip_address_table[] = {
#if CONFIG_MB_SLAVE_IP_FROM_STDIN
    "FROM_STDIN",     // Address corresponds to MB_DEVICE_ADDR1 and set to predefined value by user
    "FROM_STDIN",     // Corresponds to characteristic MB_DEVICE_ADDR2
    "FROM_STDIN",     // Corresponds to characteristic MB_DEVICE_ADDR3
    NULL              // End of table condition (must be included)
#elif CONFIG_MB_MDNS_IP_RESOLVER
    NULL,
    NULL,
    NULL,
    NULL
#endif
};

const size_t ip_table_sz = (size_t)(sizeof(slave_ip_address_table) / sizeof(slave_ip_address_table[0]));

#if CONFIG_MB_SLAVE_IP_FROM_STDIN

// Scan IP address according to IPV settings
char* master_scan_addr(int* index, char* buffer)
{
    char* ip_str = NULL;
    unsigned int a[8] = {0};
    int buf_cnt = 0;
#if !CONFIG_EXAMPLE_CONNECT_IPV6
    buf_cnt = sscanf(buffer, "IP%d="IPSTR, index, &a[0], &a[1], &a[2], &a[3]);
    if (buf_cnt == 5) {
        if (-1 == asprintf(&ip_str, IPSTR, a[0], a[1], a[2], a[3])) {
            abort();
        }
    }
#else
    buf_cnt = sscanf(buffer, "IP%d="IPV6STR, index, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7]);
    if (buf_cnt == 9) {
        if (-1 == asprintf(&ip_str, IPV6STR, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])) {
            abort();
        }
    }
#endif
    return ip_str;
}

static int master_get_slave_ip_stdin(char** addr_table)
{
    char buf[128];
    int index;
    char* ip_str = NULL;
    int buf_cnt = 0;
    int ip_cnt = 0;

    if (!addr_table) {
        return 0;
    }

    ESP_ERROR_CHECK(example_configure_stdin_stdout());
    while(1) {
        if (addr_table[ip_cnt] && strcmp(addr_table[ip_cnt], "FROM_STDIN") == 0) {
            printf("Waiting IP%d from stdin:\r\n", (int)ip_cnt);
            while (fgets(buf, sizeof(buf), stdin) == NULL) {
                fputs(buf, stdout);
            }
            buf_cnt = strlen(buf);
            buf[buf_cnt - 1] = '\0';
            fputc('\n', stdout);
            ip_str = master_scan_addr(&index, buf);
            if (ip_str != NULL) {
                ESP_LOGI(TAG, "IP(%d) = [%s] set from stdin.", (int)ip_cnt, ip_str);
                if ((ip_cnt >= ip_table_sz) || (index != ip_cnt)) {
                    addr_table[ip_cnt] = NULL;
                    break;
                }
                addr_table[ip_cnt++] = ip_str;
            } else {
                // End of configuration
                addr_table[ip_cnt++] = NULL;
                break;
            }
        } else {
            if (addr_table[ip_cnt]) {
                ESP_LOGI(TAG, "Leave IP(%d) = [%s] set manually.", (int)ip_cnt, addr_table[ip_cnt]);
                ip_cnt++;
            } else {
                ESP_LOGI(TAG, "IP(%d) is not set in the table.", (int)ip_cnt);
                break;
            }
        }
    }
    return ip_cnt;
}

#elif CONFIG_MB_MDNS_IP_RESOLVER

typedef struct slave_addr_entry_s {
    uint16_t index;
    char* ip_address;
    uint8_t slave_addr;
    void* p_data;
    LIST_ENTRY(slave_addr_entry_s) entries;
} slave_addr_entry_t;

LIST_HEAD(slave_addr_, slave_addr_entry_s) slave_addr_list = LIST_HEAD_INITIALIZER(slave_addr_list);

// convert MAC from binary format to string
static inline char* gen_mac_str(const uint8_t* mac, char* pref, char* mac_str)
{
    sprintf(mac_str, "%s%02X%02X%02X%02X%02X%02X", pref, MAC2STR(mac));
    return mac_str;
}

static inline char* gen_id_str(char* service_name, char* slave_id_str)
{
    sprintf(slave_id_str, "%s%02X%02X%02X%02X", service_name, MB_ID2STR(MB_DEVICE_ID));
    return slave_id_str;
}

static void master_start_mdns_service()
{
    char temp_str[32] = {0};
    uint8_t sta_mac[6] = {0};
    ESP_ERROR_CHECK(esp_read_mac(sta_mac, ESP_MAC_WIFI_STA));
    char* hostname = gen_mac_str(sta_mac, MB_MDNS_INSTANCE("")"_", temp_str);
    // initialize mDNS
    ESP_ERROR_CHECK(mdns_init());
    // set mDNS hostname (required if you want to advertise services)
    ESP_ERROR_CHECK(mdns_hostname_set(hostname));
    ESP_LOGI(TAG, "mdns hostname set to: [%s]", hostname);

    // set default mDNS instance name
    ESP_ERROR_CHECK(mdns_instance_name_set(MB_MDNS_INSTANCE("esp32_")));

    // structure with TXT records
    mdns_txt_item_t serviceTxtData[] = {
        {"board","esp32"}
    };

    // initialize service
    ESP_ERROR_CHECK(mdns_service_add(MB_MDNS_INSTANCE(""), "_modbus", "_tcp", MB_MDNS_PORT, serviceTxtData, 1));
    // add mac key string text item
    ESP_ERROR_CHECK(mdns_service_txt_item_set("_modbus", "_tcp", "mac", gen_mac_str(sta_mac, "\0", temp_str)));
    // add slave id key txt item
    ESP_ERROR_CHECK( mdns_service_txt_item_set("_modbus", "_tcp", "mb_id", gen_id_str("\0", temp_str)));
}

static char* master_get_slave_ip_str(mdns_ip_addr_t* address, mb_tcp_addr_type_t addr_type)
{
    mdns_ip_addr_t* a = address;
    char* slave_ip_str = NULL;

    while (a) {
        if ((a->addr.type == ESP_IPADDR_TYPE_V6) && (addr_type == MB_IPV6)) {
            if (-1 == asprintf(&slave_ip_str, IPV6STR, IPV62STR(a->addr.u_addr.ip6))) {
                abort();
            }
        } else if ((a->addr.type == ESP_IPADDR_TYPE_V4) && (addr_type == MB_IPV4)) {
            if (-1 == asprintf(&slave_ip_str, IPSTR, IP2STR(&(a->addr.u_addr.ip4)))) {
                abort();
            }
        }
        if (slave_ip_str) {
            break;
        }
        a = a->next;
    }
    return slave_ip_str;
}

static esp_err_t master_resolve_slave(uint8_t short_addr, mdns_result_t* result, char** resolved_ip,
                                        mb_tcp_addr_type_t addr_type)
{
    if (!short_addr || !result || !resolved_ip) {
        return ESP_ERR_INVALID_ARG;
    }
    mdns_result_t* r = result;
    int t;
    char* slave_ip = NULL;
    char slave_name[22] = {0};

    if (sprintf(slave_name, "mb_slave_tcp_%02X", short_addr) < 0) {
        ESP_LOGE(TAG, "Fail to create instance name for index: %d", (int)short_addr);
        abort();
    }
    for (; r ; r = r->next) {
        if ((r->ip_protocol == MDNS_IP_PROTOCOL_V4) && (addr_type == MB_IPV6)) {
            continue;
        } else if ((r->ip_protocol == MDNS_IP_PROTOCOL_V6) && (addr_type == MB_IPV4)) {
            continue;
        }
        // Check host name for Modbus short address and
        // append it into slave ip address table
        if ((strcmp(r->instance_name, slave_name) == 0) && (r->port == CONFIG_FMB_TCP_PORT_DEFAULT)) {
            printf("  PTR : %s\n", r->instance_name);
            if (r->txt_count) {
                printf("  TXT : [%u] ", r->txt_count);
                for ( t = 0; t < r->txt_count; t++) {
                    printf("%s=%s; ", r->txt[t].key, r->txt[t].value?r->txt[t].value:"NULL");
                }
                printf("\n");
            }
            slave_ip = master_get_slave_ip_str(r->addr, addr_type);
            if (slave_ip) {
                ESP_LOGI(TAG, "Resolved slave %s[%s]:%u", r->hostname, slave_ip, (unsigned)r->port);
                *resolved_ip = slave_ip;
                return ESP_OK;
            }
        }
    }
    *resolved_ip = NULL;
    ESP_LOGD(TAG, "Fail to resolve slave: %s", slave_name);
    return ESP_ERR_NOT_FOUND;
}

static int master_create_slave_list(mdns_result_t* results, char** addr_table,
                                        int addr_table_size, mb_tcp_addr_type_t addr_type)
{
    if (!results) {
        return -1;
    }
    int i, slave_addr, cid_resolve_cnt = 0;
    int ip_index = 0;
    const mb_parameter_descriptor_t* pdescr = &device_parameters[0];
    char** ip_table = addr_table;
    char* slave_ip = NULL;
    slave_addr_entry_t *it;

    for (i = 0; (i < num_device_parameters && pdescr); i++, pdescr++)
    {
        slave_addr = pdescr->mb_slave_addr;

        it = NULL;
        // Is the slave address already registered?
        LIST_FOREACH(it, &slave_addr_list, entries) {
            if (slave_addr == it->slave_addr) {
                break;
            }
        }
        if (!it) {
            // Resolve new slave IP address using its short address
            esp_err_t err = master_resolve_slave(slave_addr, results, &slave_ip, addr_type);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Index: %d, sl_addr: %d, failed to resolve!", (int)i, (int)slave_addr);
                // Set correspond index to NULL indicate host not resolved
                ip_table[ip_index] = NULL;
                continue;
            }
            // Register new slave address information
            slave_addr_entry_t* new_slave_entry = (slave_addr_entry_t*) heap_caps_malloc(sizeof(slave_addr_entry_t),
                                                       MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
            MB_RETURN_ON_FALSE((new_slave_entry != NULL), ESP_ERR_NO_MEM,
                                                 TAG, "Can not allocate memory for slave entry.");
            new_slave_entry->index = i;
            new_slave_entry->ip_address = slave_ip;
            new_slave_entry->slave_addr = slave_addr;
            new_slave_entry->p_data = NULL;
            LIST_INSERT_HEAD(&slave_addr_list, new_slave_entry, entries);
            ip_table[ip_index] = slave_ip;
            ESP_LOGI(TAG, "Index: %d, sl_addr: %d, resolved to IP: [%s]",
                                                (int)i, (int)slave_addr, slave_ip);
            cid_resolve_cnt++;
            if (ip_index < addr_table_size) {
                ip_index++;
            }
        } else {
            ip_table[ip_index] = it ? it->ip_address : ip_table[ip_index];
            ESP_LOGI(TAG, "Index: %d, sl_addr: %d, set to IP: [%s]",
                                    (int)i, (int)slave_addr, ip_table[ip_index]);
            cid_resolve_cnt++;
        }
    }
    ESP_LOGI(TAG, "Resolved %d cids, with %d IP addresses", (int)cid_resolve_cnt, (int)ip_index);
    return cid_resolve_cnt;
}

static int master_query_slave_service(const char * service_name, const char * proto,
                                        mb_tcp_addr_type_t addr_type)
{
    ESP_LOGI(TAG, "Query PTR: %s.%s.local", service_name, proto);

    mdns_result_t* results = NULL;
    int count = 0;

    esp_err_t err = mdns_query_ptr(service_name, proto, 3000, 20, &results);
    if(err){
        ESP_LOGE(TAG, "Query Failed: %s", esp_err_to_name(err));
        return count;
    }
    if(!results){
        ESP_LOGW(TAG, "No results found!");
        return count;
    }

    count = master_create_slave_list(results, slave_ip_address_table, ip_table_sz, addr_type);

    mdns_query_results_free(results);
    return count;
}
#endif

static void master_destroy_slave_list(char** table, size_t ip_table_size)
{
#if CONFIG_MB_MDNS_IP_RESOLVER
    slave_addr_entry_t *it;
    while ((it = LIST_FIRST(&slave_addr_list))) {
        LIST_REMOVE(it, entries);
        free(it);
    }
#endif
    for (int i = 0; ((i < ip_table_size) && table[i] != NULL); i++) {
        if (table[i]) {
#if CONFIG_MB_SLAVE_IP_FROM_STDIN
            free(table[i]);
            table[i] = "FROM_STDIN";
#elif CONFIG_MB_MDNS_IP_RESOLVER
            table[i] = NULL;
#endif
        }
    }
}

// The function to get pointer to parameter storage (instance) according to parameter description table
static void* master_get_param_data(const mb_parameter_descriptor_t* param_descriptor)
{
    assert(param_descriptor != NULL);
    void* instance_ptr = NULL;
    if (param_descriptor->param_offset != 0) {
       switch(param_descriptor->mb_param_type)
       {
           case MB_PARAM_HOLDING:
               instance_ptr = ((void*)&holding_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_INPUT:
               instance_ptr = ((void*)&input_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_COIL:
               instance_ptr = ((void*)&coil_reg_params + param_descriptor->param_offset - 1);
               break;
           case MB_PARAM_DISCRETE:
               instance_ptr = ((void*)&discrete_reg_params + param_descriptor->param_offset - 1);
               break;
           default:
               instance_ptr = NULL;
               break;
       }
    } else {
        ESP_LOGE(TAG, "Wrong parameter offset for CID #%d", (int)param_descriptor->cid);
        assert(instance_ptr != NULL);
    }
    return instance_ptr;
}

#define TEST_VERIFY_VALUES(pdescr, pinst) (__extension__(                                           \
{                                                                                                   \
    assert(pinst);                                                                                  \
    assert(pdescr);                                                                                 \
    uint8_t type = 0;                                                                               \
    esp_err_t err = ESP_FAIL;                                                                       \
    err = mbc_master_get_parameter(pdescr->cid, (char *)pdescr->param_key,                          \
                                    (uint8_t *)pinst, &type);                                       \
    if (err == ESP_OK) {                                                                            \
        bool is_correct = true;                                                                     \
        if (pdescr->param_opts.opt3) {                                                              \
            for EACH_ITEM(pinst, pdescr->param_size / sizeof(*pitem)) {                             \
                if (*pitem != (typeof(*(pinst)))pdescr->param_opts.opt3) {                          \
                    *pitem = (typeof(*(pinst)))pdescr->param_opts.opt3;                             \
                    ESP_LOGD(TAG, "Characteristic #%d (%s), initialize to 0x%" PRIx16 ".",          \
                                (int)pdescr->cid,                                                   \
                                (char *)pdescr->param_key,                                          \
                                (uint16_t)pdescr->param_opts.opt3);                                 \
                    is_correct = false;                                                             \
                }                                                                                   \
            }                                                                                       \
        }                                                                                           \
        if (!is_correct) {                                                                          \
            ESP_LOGE(TAG, "Characteristic #%d (%s), initialize.",                                   \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key);                                                 \
            err = mbc_master_set_parameter(cid, (char *)pdescr->param_key,                          \
                                                (uint8_t *)pinst, &type);                           \
            if (err != ESP_OK) {                                                                    \
                ESP_LOGE(TAG, "Characteristic #%d (%s) write fail, err = 0x%x (%s).",               \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
            } else {                                                                                \
                ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (..) write successful.",          \
                        (int)pdescr->cid,                                                           \
                        (char *)pdescr->param_key,                                                  \
                        (char *)pdescr->param_units);                                               \
            }                                                                                       \
        }                                                                                           \
    } else {                                                                                        \
        ESP_LOGE(TAG, "Characteristic #%d (%s) read fail, err = 0x%x (%s).",                        \
                            (int)pdescr->cid,                                                       \
                            (char *)pdescr->param_key,                                              \
                            (int)err,                                                               \
                            (char *)esp_err_to_name(err));                                          \
    }                                                                                               \
    (err);                                                                                          \
}                                                                                                   \
))

// User operation function to read slave values and check alarm
static void master_operation_func(void *arg)
{
    esp_err_t err = ESP_OK;
    bool alarm_state = false;
    const mb_parameter_descriptor_t* param_descriptor = NULL;

    ESP_LOGI(TAG, "Start modbus test...");

    for(uint16_t retry = 0; retry <= MASTER_MAX_RETRY && (!alarm_state); retry++) {
        // Read all found characteristics from slave(s)
        for (uint16_t cid = 0; (err != ESP_ERR_NOT_FOUND) && cid < MASTER_MAX_CIDS; cid++) {
            // Get data from parameters description table
            // and use this information to fill the characteristics description table
            // and having all required fields in just one table
            err = mbc_master_get_cid_info(cid, &param_descriptor);
            if ((err != ESP_ERR_NOT_FOUND) && (param_descriptor != NULL)) {
                void *temp_data_ptr = master_get_param_data(param_descriptor);
                assert(temp_data_ptr);
                if ((param_descriptor->param_type == PARAM_TYPE_ASCII) &&
                        (param_descriptor->cid == CID_HOLD_TEST_REG)) {
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint32_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint32_t *)temp_data_ptr);
                    }
#if CONFIG_FMB_EXT_TYPE_SUPPORT
                } else if ((param_descriptor->cid >= CID_HOLD_U16_AB) 
                            && (param_descriptor->cid <= CID_HOLD_U16_BA)) {
                    // Check the uint16 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint16_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_U8_A) 
                            && (param_descriptor->cid <= CID_HOLD_U8_B)) {
                    // Check the uint8 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint16_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = (0x%" PRIx16 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint16_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_UINT32_ABCD)
                            && (param_descriptor->cid <= CID_HOLD_UINT32_DCBA)) {
                    // Check the uint32 parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint32_t *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %" PRIu32 " (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(uint32_t *)temp_data_ptr,
                                        *(uint32_t *)temp_data_ptr);
                    }
                } else if ((param_descriptor->cid >= CID_HOLD_FLOAT_ABCD)
                            && (param_descriptor->cid <= CID_HOLD_FLOAT_DCBA)) {
                    // Check the float parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (float *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        *(float *)temp_data_ptr,
                                        *(uint32_t *)temp_data_ptr);
                    }
                } else if (param_descriptor->cid >= CID_HOLD_DOUBLE_ABCDEFGH) {
                    // Check the double parameters
                    if (TEST_VERIFY_VALUES(param_descriptor, (double *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %lf (0x%" PRIx64 ") read successful.",
                                    (int)param_descriptor->cid,
                                    (char *)param_descriptor->param_key,
                                    (char *)param_descriptor->param_units,
                                    *(double *)temp_data_ptr,
                                    *(uint64_t *)temp_data_ptr);
                    }
#endif
                } else  if (cid <= CID_HOLD_DATA_2) {
                    uint64_t start_timestamp = esp_timer_get_time(); // Get current timestamp in microseconds
                    if (TEST_VERIFY_VALUES(param_descriptor, (float *)temp_data_ptr) == ESP_OK) {
                        ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %f (0x%" PRIx32 ") read successful.",
                                (int)param_descriptor->cid,
                                (char *)param_descriptor->param_key,
                                (char *)param_descriptor->param_units,
                                *(float *)temp_data_ptr,
                                *(uint32_t *)temp_data_ptr);
                    }
                    float value = *(float *)temp_data_ptr;
                    if (((value > param_descriptor->param_opts.max) ||
                        (value < param_descriptor->param_opts.min))) {
                            alarm_state = true;
                            break;
                    }
                    mb_trans_info_t tinfo = {0}; // The transaction information structure
                    if (mbc_master_get_transaction_info(&tinfo) == ESP_OK) {
                        bool trans_is_expired = (tinfo.trans_id >= (start_timestamp + (CONFIG_FMB_MASTER_TIMEOUT_MS_RESPOND * 1000)));
                        ESP_LOGW("TRANS_INFO", "Id: %" PRIu64 ", Addr: %x, FC: 0x%x, Exception: %u, Err: %u %s",
                                    (uint64_t)tinfo.trans_id, (int)tinfo.dest_addr,
                                    (int)tinfo.func_code, (unsigned)tinfo.exception,
                                    (int)tinfo.err_type,
                                    trans_is_expired ? "(EXPIRED)" : "");
                        // Check if the response time is expired sinse start of transaction,
                        // or the other IO is performed from different thread.
                        if (trans_is_expired) {
                            ESP_LOGE("TRANS_INFO", "Transaction Id: %" PRIu64 ", is expired.", tinfo.trans_id);
                            alarm_state = true;
                            break;
                        }
                    }
                } else if ((cid >= CID_RELAY_P1) && (cid <= CID_DISCR_P1)) {
                    if (TEST_VERIFY_VALUES(param_descriptor, (uint8_t *)temp_data_ptr) == ESP_OK) {
                        uint8_t state = *(uint8_t *)temp_data_ptr;
                        const char* rw_str = (state & param_descriptor->param_opts.opt1) ? "ON" : "OFF";
                        if ((state & param_descriptor->param_opts.opt2) == param_descriptor->param_opts.opt2) {
                            ESP_LOGI(TAG, "Characteristic #%d %s (%s) value = %s (0x%" PRIx8 ") read successful.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        (const char *)rw_str,
                                        *(uint8_t *)temp_data_ptr);
                        } else {
                            ESP_LOGE(TAG, "Characteristic #%d %s (%s) value = %s (0x%" PRIx8 "), unexpected value.",
                                        (int)param_descriptor->cid,
                                        (char *)param_descriptor->param_key,
                                        (char *)param_descriptor->param_units,
                                        (const char *)rw_str,
                                        *(uint8_t *)temp_data_ptr);
                            alarm_state = true;
                            break;
                        }
                        if (state & param_descriptor->param_opts.opt1) {
                            alarm_state = true;
                            break;
                        }
                    }
                }
                vTaskDelay(POLL_TIMEOUT_TICS); // timeout between polls
            }
        }
        vTaskDelay(UPDATE_CIDS_TIMEOUT_TICS);
    }

    if (alarm_state) {
        ESP_LOGI(TAG, "Alarm triggered by cid #%d.",
                                        (int)param_descriptor->cid);
    } else {
        ESP_LOGE(TAG, "Alarm is not triggered after %d retries.",
                                        MASTER_MAX_RETRY);
    }
    ESP_LOGI(TAG, "Destroy master...");
    vTaskDelay(100);
}

static esp_err_t init_services(mb_tcp_addr_type_t ip_addr_type)
{
    esp_err_t result = nvs_flash_init();
    if (result == ESP_ERR_NVS_NO_FREE_PAGES || result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      result = nvs_flash_init();
    }
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "nvs_flash_init fail, returns(0x%x).",
                            (int)result);
    result = esp_netif_init();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "esp_netif_init fail, returns(0x%x).",
                            (int)result);
    result = esp_event_loop_create_default();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "esp_event_loop_create_default fail, returns(0x%x).",
                            (int)result);
#if CONFIG_MB_MDNS_IP_RESOLVER
    // Start mdns service and register device
    master_start_mdns_service();
#endif
    // This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    // Read "Establishing Wi-Fi or Ethernet Connection" section in
    // examples/protocols/README.md for more information about this function.
    result = example_connect();
    MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                                TAG,
                                "example_connect fail, returns(0x%x).",
                                (int)result);
#if CONFIG_EXAMPLE_CONNECT_WIFI
   result = esp_wifi_set_ps(WIFI_PS_NONE);
   MB_RETURN_ON_FALSE((result == ESP_OK), ESP_ERR_INVALID_STATE,
                                   TAG,
                                   "esp_wifi_set_ps fail, returns(0x%x).",
                                   (int)result);
#endif
#if CONFIG_MB_MDNS_IP_RESOLVER
    int res = 0;
    for (int retry = 0; (res < num_device_parameters) && (retry < 10); retry++) {
        res = master_query_slave_service("_modbus", "_tcp", ip_addr_type);
    }
    if (res < num_device_parameters) {
        ESP_LOGE(TAG, "Could not resolve one or more slave IP addresses, resolved: %d out of %d.", (uint16_t)res, (uint16_t)num_device_parameters );
        ESP_LOGE(TAG, "Make sure you configured all slaves according to device parameter table and they alive in the network.");
        return ESP_ERR_NOT_FOUND;
    }
    mdns_free();
#elif CONFIG_MB_SLAVE_IP_FROM_STDIN
    int ip_cnt = master_get_slave_ip_stdin(slave_ip_address_table);
    if (ip_cnt) {
        ESP_LOGI(TAG, "Configured %d IP addresse(s).", (int)ip_cnt);
    } else {
        ESP_LOGE(TAG, "Fail to get IP address from stdin. Continue.");
        return ESP_ERR_NOT_FOUND;
    }
#endif
    return ESP_OK;
}

static esp_err_t destroy_services(void)
{
    esp_err_t err = ESP_OK;
    master_destroy_slave_list(slave_ip_address_table, ip_table_sz);

    err = example_disconnect();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                                   TAG,
                                   "example_disconnect fail, returns(0x%x).",
                                   (int)err);
    err = esp_event_loop_delete_default();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                                       TAG,
                                       "esp_event_loop_delete_default fail, returns(0x%x).",
                                       (int)err);
    err = esp_netif_deinit();
    MB_RETURN_ON_FALSE((err == ESP_OK || err == ESP_ERR_NOT_SUPPORTED), ESP_ERR_INVALID_STATE,
                                        TAG,
                                        "esp_netif_deinit fail, returns(0x%x).",
                                        (int)err);
    err = nvs_flash_deinit();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                                TAG,
                                "nvs_flash_deinit fail, returns(0x%x).",
                                (int)err);
    return err;
}

// Modbus master initialization
static esp_err_t master_init(mb_communication_info_t* comm_info)
{
    void* master_handler = NULL;

    esp_err_t err = mbc_master_init_tcp(&master_handler);
    MB_RETURN_ON_FALSE((master_handler != NULL), ESP_ERR_INVALID_STATE,
                                TAG,
                                "mb controller initialization fail.");
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "mb controller initialization fail, returns(0x%x).",
                            (int)err); 

    err = mbc_master_setup((void*)comm_info);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "mb controller setup fail, returns(0x%x).",
                            (int)err);

    err = mbc_master_set_descriptor(&device_parameters[0], num_device_parameters);
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                                TAG,
                                "mb controller set descriptor fail, returns(0x%x).",
                                (int)err);
    ESP_LOGI(TAG, "Modbus master stack initialized...");

    err = mbc_master_start();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                            TAG,
                            "mb controller start fail, returns(0x%x).",
                            (int)err);
    vTaskDelay(5);
    return err;
}

static esp_err_t master_destroy(void)
{
    esp_err_t err = mbc_master_destroy();
    MB_RETURN_ON_FALSE((err == ESP_OK), ESP_ERR_INVALID_STATE,
                                TAG,
                                "mbc_master_destroy fail, returns(0x%x).",
                                (int)err);
    ESP_LOGI(TAG, "Modbus master stack destroy...");
    return err;
}

void app_main(void)
{
    mb_tcp_addr_type_t ip_addr_type;
#if !CONFIG_EXAMPLE_CONNECT_IPV6
    ip_addr_type = MB_IPV4;
#else
    ip_addr_type = MB_IPV6;
#endif

    ESP_ERROR_CHECK(init_services(ip_addr_type));

    mb_communication_info_t comm_info = { 0 };
    comm_info.ip_port = MB_TCP_PORT;
    comm_info.ip_addr_type = ip_addr_type;
    comm_info.ip_mode = MB_MODE_TCP;
    comm_info.ip_addr = (void*)slave_ip_address_table;
    comm_info.ip_netif_ptr = (void*)get_example_netif();

    ESP_ERROR_CHECK(master_init(&comm_info));

    master_operation_func(NULL);
    ESP_ERROR_CHECK(master_destroy());
    ESP_ERROR_CHECK(destroy_services());
}
