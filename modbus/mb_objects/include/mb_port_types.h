/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "mb_config.h"
#include "mb_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _mb_comm_mode mb_mode_type_t;

#if (CONFIG_FMB_COMM_MODE_ASCII_EN || CONFIG_FMB_COMM_MODE_RTU_EN)

#include "driver/uart.h"

__attribute__((__packed__))
struct _port_serial_opts {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uart_port_t port;               /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
    uint32_t baudrate;              /*!< Modbus baudrate */
    uart_word_length_t data_bits;   /*!< Modbus number of data bits */
    uart_stop_bits_t stop_bits;     /*!< Modbus number of stop bits */
    uart_parity_t parity;           /*!< Modbus UART parity settings */
};

typedef struct _port_serial_opts mb_serial_opts_t;

#endif

typedef enum _addr_type_enum {
    MB_NOIP = 0,
    MB_IPV4 = 1,                    /*!< TCP IPV4 addressing */
    MB_IPV6 = 2                     /*!< TCP IPV6 addressing */
} mb_addr_type_t;

__attribute__((__packed__))
struct _port_common_opts {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uint16_t port;                  /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
};

__attribute__((__packed__))
struct _port_tcp_opts {
    mb_mode_type_t mode;            /*!< Modbus communication mode */
    uint16_t port;                  /*!< Modbus communication port (UART) number */
    uint8_t uid;                    /*!< Modbus slave address field (dummy for master) */
    uint32_t response_tout_ms;      /*!< Modbus slave response timeout */
    uint64_t test_tout_us;          /*!< Modbus test timeout (reserved) */
    mb_addr_type_t addr_type;       /*!< Modbus address type */
    void *ip_addr_table;            /*!< Modbus address or table for connection */
    void *ip_netif_ptr;             /*!< Modbus network interface */
    bool start_disconnected;        /*!< do not wait connection to all nodes before polling */
};

typedef struct _port_tcp_opts mb_tcp_opts_t;

// The common object descriptor struture (common for mb, transport, port objects)
struct _obj_descr { 
    char *parent_name;
    char *obj_name;
    void *parent;
    uint32_t inst_index;
    bool is_master;
};

typedef struct _obj_descr obj_descr_t;

typedef enum _mb_sock_state {
    MB_SOCK_STATE_UNDEF = 0x0000,
    MB_SOCK_STATE_CLOSED,
    MB_SOCK_STATE_READY,
    MB_SOCK_STATE_OPENED,
    MB_SOCK_STATE_RESOLVED,
    MB_SOCK_STATE_CONNECTING,
    MB_SOCK_STATE_CONNECTED
} mb_sock_state_t;

typedef struct _uid_info {
    uint16_t index;                 /*!< index of the address info */
    int fd;                         /*!< slave global FD for VFS (reserved) */
    char *node_name_str;            /*!< node name string (host name of slave to resolve) */
    char *ip_addr_str;              /*!< represents the IP address of the slave */
    mb_addr_type_t addr_type;       /*!< type of IP address */
    uint16_t uid;                   /*!< slave unit ID (UID) field for MBAP frame  */
    uint16_t port;                  /*!< slave port number */
    mb_comm_mode_t proto;           /*!< protocol type */
    mb_sock_state_t state;          /*!< slave state */
    void *inst;                     /*!< pointer to linked instance */
} mb_uid_info_t;

#ifdef __cplusplus
}
#endif