/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdatomic.h>

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_netif.h"
#include "net/if.h"

#include "port_tcp_common.h"

#if __has_include("esp_timer.h")
#include "esp_timer.h"
#endif

#if __has_include("esp_mac.h")
#include "esp_mac.h"
#endif

#if __has_include("mdns.h")
#include "mdns.h"
#endif

// Workaround for MDNS_NAME_BUF_LEN being defined in private header
#ifndef MDNS_NAME_BUF_LEN
#define MDNS_NAME_BUF_LEN 64
#endif

#define HOST_STR_MAX_LEN            (MDNS_NAME_BUF_LEN)
#define MB_TCP_NET_LISTEN_BACKLOG   (SOMAXCONN)

#if MB_MDNS_IS_INCLUDED

#define MB_ID_BYTE0(id)     ((uint8_t)(id))
#define MB_ID_BYTE1(id)     ((uint8_t)(((uint16_t)(id) >> 8) & 0xFF))
#define MB_ID_BYTE2(id)     ((uint8_t)(((uint32_t)(id) >> 16) & 0xFF))
#define MB_ID_BYTE3(id)     ((uint8_t)(((uint32_t)(id) >> 24) & 0xFF))

#define MB_ID2STR(id) MB_ID_BYTE0(id), MB_ID_BYTE1(id), MB_ID_BYTE2(id), MB_ID_BYTE3(id)

#if CONFIG_FMB_CONTROLLER_SLAVE_ID_SUPPORT
#define MB_DEVICE_ID (uint32_t)CONFIG_FMB_CONTROLLER_SLAVE_ID
#endif

// #define MB_SLAVE_ADDR (CONFIG_MB_SLAVE_ADDR)

#endif

#define MB_MDNS_PORT (CONFIG_FMB_TCP_PORT_DEFAULT)
#define MB_READ_TICK (500)
#define MB_MDNS_QUERY_TIME_MS (2000)

#define MB_STR_LEN_HOST 1  // "mb_node_tcp_01"
#define MB_STR_LEN_IDX_HOST 2  // "12:mb_node_tcp_01"
#define MB_STR_LEN_IDX_HOST_PORT 3 // "01:mb_node_tcp_01:1502"
#define MB_STR_LEN_IP4_ONLY 4 // "192.168.1.1"
#define MB_STR_LEN_IDX_IP4 5 // "1:192.168.1.1"
#define MB_STR_LEN_IDX_IP4_PORT 6 // "1:192.168.1.1:502"
#define MB_STR_LEN_IP6_ONLY 8 // "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
#define MB_STR_LEN_IDX_IP6 9 // "12:2001:0db8:85a3:0000:0000:8a2e:0370:7334"
#define MB_STR_LEN_IDX_IP6_PORT 10 // "12:2001:0db8:85a3:0000:0000:8a2e:0370:7334:502"

#define MB_MDNS_STR_MIN_LENGTH 10 // "mb_node_01"
#define MB_MDNS_SEGMENT_NAME "mb_tcp_segment" // "mb_node_01"

#define MB_MDNS_INST_NAME(is_master) (__extension__( \
{ \
    ((is_master) ? "mb_master_tcp" : "mb_slave_tcp"); \
} \
))

typedef struct _frame_queue_entry frame_entry_t;
typedef struct _mb_node_info mb_node_info_t;
typedef enum _addr_type_enum mb_tcp_addr_type_t;

bool port_check_host_addr(const char *host_str, ip_addr_t* host_addr);
mb_node_info_t* port_get_current_info(void *ctx);
void port_check_shutdown(void *ctx);
int64_t port_get_resp_time_left(mb_node_info_t* pinfo);
int port_enqueue_packet(QueueHandle_t queue, uint8_t *pbuf, uint16_t len);
int port_dequeue_packet(QueueHandle_t queue, frame_entry_t* pframe_info);
int port_read_packet(mb_node_info_t* pinfo);
err_t port_set_blocking(mb_node_info_t* pinfo, bool is_blocking);
int port_keep_alive(int sock);
err_t port_check_alive(mb_node_info_t* pinfo, uint32_t timeout_ms);
err_t port_connect(void *ctx, mb_node_info_t* pinfo);
bool port_close_connection(mb_node_info_t* pinfo);
int port_write_poll(mb_node_info_t* pinfo, const uint8_t *pframe, uint16_t frame_len, uint32_t timeout);
int64_t port_get_timestamp(void);

typedef struct _uid_info mb_uid_info_t;

int port_scan_addr_string(char *buffer, mb_uid_info_t *pnode_info);

#if MB_MDNS_IS_INCLUDED

// Init mdns service
esp_err_t port_start_mdns_service(char **ppdns_name, bool is_master, int uid, void *pnode_netif);
void port_stop_mdns_service(char **ppdns_name);

typedef struct mdns_ip_addr_s mdns_ip_addr_t;
typedef struct mdns_result_s mdns_result_t;

char *port_get_node_ip_str(mdns_ip_addr_t *address, mb_addr_type_t addr_type);
esp_err_t port_resolve_slave(uint8_t short_addr, mdns_result_t *result, char **resolved_ip, mb_addr_type_t addr_type);
int port_resolve_mdns_host(const char *host_name, char **paddr_str);

#endif

// Modbus slave utility functions

int port_bind_addr(const char *pbind_ip, mb_addr_type_t addr_type, mb_comm_mode_t proto, uint16_t port);
int port_accept_connection(int listen_sock_id, mb_uid_info_t *pnode_info);

#ifdef __cplusplus
}
#endif