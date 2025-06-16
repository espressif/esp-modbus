/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "mb_types.h"
#include "sdkconfig.h"

#if __has_include("esp_idf_version.h")
#include "esp_idf_version.h"
#endif

// Workaround for atomics incompatibility issue under CPP.
#if defined(__cplusplus) && (IDF_VERSION <= ESP_IDF_VERSION_VAL(5, 0, 0))
#include <atomic>
#define _Atomic(T) std::atomic<T>
#define atomic_int int
#else
#include <stdatomic.h>
#endif

#if defined(__cplusplus)
extern "C" {
#else
// This is to verify the atomic int types for C compilation unit have the same layout as int type.
static_assert(
    (sizeof(_Atomic(int)) == sizeof(int) && sizeof(_Atomic int) == sizeof(int)),
    "the _Atomic int types are not layout compatible with int type"
);
#endif

#define MB_ATTR_WEAK __attribute__ ((weak))

typedef enum _mb_comm_mode mb_mode_type_t;

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

#include "driver/uart.h"

struct port_serial_opts_s {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uart_port_t port;               /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
    uint32_t baudrate;              /*!< Modbus baudrate */
    uart_word_length_t data_bits;   /*!< Modbus number of data bits */
    uart_stop_bits_t stop_bits;     /*!< Modbus number of stop bits */
    uart_parity_t parity;           /*!< Modbus UART parity settings */
} __attribute__((__packed__));

typedef struct port_serial_opts_s mb_serial_opts_t;

#endif

typedef enum _addr_type_enum {
    MB_NOIP = 0,
    MB_IPV4 = 1,                    /*!< TCP IPV4 addressing */
    MB_IPV6 = 2                     /*!< TCP IPV6 addressing */
} mb_addr_type_t;

struct port_common_opts_s {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uint16_t port;                  /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
} __attribute__((__packed__));

struct port_tcp_opts_s {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uint16_t port;                  /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
    mb_addr_type_t addr_type;       /*!< Modbus address type */
    void *ip_addr_table;            /*!< Modbus address or table for connection */
    void *ip_netif_ptr;             /*!< Modbus network interface */
    char *dns_name;                 /*!< Modbus node DNS name */
    bool start_disconnected;        /*!< (Master only option) do not wait for connection to all nodes before polling */
} __attribute__((__packed__));

typedef struct port_tcp_opts_s mb_tcp_opts_t;

// The common object descriptor struture (common for mb, transport, port objects)
struct _obj_descr { 
    char *parent_name;              /*!< Name of the parent (base) object */
    char *obj_name;                 /*!< Name of the object */
    void *parent;                   /*!< Pointer to the parent (base) object */
    uint32_t inst_index;            /*!< The consicutive index of the object instance */
    bool is_master;                 /*!< The current object is master or slave (false) */
};

typedef struct _obj_descr obj_descr_t;

typedef enum _mb_sock_state {
    MB_SOCK_STATE_UNDEF = 0x0000,   /*!< Default init state */
    MB_SOCK_STATE_CLOSED,           /*!< Node is closed */
    MB_SOCK_STATE_READY,            /*!< Node is ready for communication */
    MB_SOCK_STATE_OPENED,           /*!< Node is opened */
    MB_SOCK_STATE_RESOLVED,         /*!< Node address is resolved */
    MB_SOCK_STATE_CONNECTING,       /*!< Node connection is in progress */
    MB_SOCK_STATE_CONNECTED,        /*!< Node is connected */
    MB_SOCK_STATE_ACCEPTED          /*!< Slave node accepted the connection */
} mb_sock_state_t;

typedef struct _uid_info {
    uint16_t index;                 /*!< index of the address info */
    int fd;                         /*!< node global FD for VFS (reserved) */
    char *node_name_str;            /*!< node name string (host name of node to resolve) */
    char *ip_addr_str;              /*!< represents the IP address of the node */
    mb_addr_type_t addr_type;       /*!< type of IP address */
    uint16_t uid;                   /*!< node unit ID (UID) field for MBAP frame  */
    uint16_t port;                  /*!< node port number */
    mb_comm_mode_t proto;           /*!< protocol type */
    _Atomic(int) state;             /*!< node state */
    void *inst;                     /*!< pointer to linked instance */
} mb_uid_info_t;

#ifdef __cplusplus
}
#endif