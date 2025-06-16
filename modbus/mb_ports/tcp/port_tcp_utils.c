/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#if __has_include("esp_mac.h")
#include "esp_mac.h"
#endif

#include "port_tcp_master.h"
#include "port_tcp_utils.h"
#include "port_tcp_driver.h"
#include "sdkconfig.h"

#define TAG "port.utils"

#ifdef __cplusplus
extern "C" {
#endif

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

// Check host name and/or fill the IP address structure
bool port_check_host_addr(const char *host_str, ip_addr_t *host_addr)
{
    MB_RETURN_ON_FALSE((host_str), false, TAG, "wrong host name or IP.");
    char cstr[HOST_STR_MAX_LEN];
    char *pstr = &cstr[0];
    ip_addr_t target_addr;
    struct addrinfo hint;
    struct addrinfo *paddr_list;
    memset(&hint, 0, sizeof(hint));
    // Do name resolution for both protocols
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_ADDRCONFIG; // get IPV6 address if supported, otherwise IPV4
    hint.ai_flags |= AI_CANONNAME;
    memset(&target_addr, 0, sizeof(target_addr));

    // convert domain name to IP address
    // Todo: check EAI_FAIL error when resolve host name
    int ret = getaddrinfo(host_str, NULL, &hint, &paddr_list);
    if (ret != 0) {
        ESP_LOGD(TAG, "Incorrect host IP: %s", host_str);
        return false;
    }
    if (paddr_list->ai_family == AF_INET) {
        struct in_addr addr4 = ((struct sockaddr_in *)(paddr_list->ai_addr))->sin_addr;
        inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
        pstr = ip4addr_ntoa_r(ip_2_ip4(&target_addr), cstr, sizeof(cstr));
    }
#if CONFIG_LWIP_IPV6
    else {
        struct in6_addr addr6 = ((struct sockaddr_in6 *)(paddr_list->ai_addr))->sin6_addr;
        inet6_addr_to_ip6addr(ip_2_ip6(&target_addr), &addr6);
        pstr = ip6addr_ntoa_r(ip_2_ip6(&target_addr), cstr, sizeof(cstr));
    }
#endif
    if (host_addr) {
        *host_addr = target_addr;
    }
    ESP_LOGD(TAG, "Check name[IP]: \"%s\"[%s]", paddr_list->ai_canonname ? paddr_list->ai_canonname : "UNK", pstr);
    freeaddrinfo(paddr_list);
    return true;
}

bool port_close_connection(mb_node_info_t *pinfo)
{
    if (!pinfo) {
        return false;
    }
    if (pinfo->sock_id <= 0) {
        ESP_LOGD(TAG, "wrong socket info or disconnected socket: %d, skip.", pinfo->index);
        return false;
    }
    uint8_t tmp_buff[MB_PDU_SIZE_MAX];

    // Empty tcp buffer before shutdown
    (void)recv(pinfo->sock_id, &tmp_buff[0], MB_PDU_SIZE_MAX, MSG_DONTWAIT);
    queue_flush(pinfo->rx_queue);
    queue_flush(pinfo->tx_queue);

    if (shutdown(pinfo->sock_id, SHUT_RDWR) == -1) {
        ESP_LOGV(TAG, "Shutdown failed sock %d, errno=%d", pinfo->sock_id, (int)errno);
    }
    close(pinfo->sock_id);
    MB_SET_NODE_STATE(pinfo, MB_SOCK_STATE_OPENED);
    pinfo->sock_id = UNDEF_FD;
    return true;
}

// The helper function to get time stamp in microseconds
int64_t port_get_timestamp(void)
{
    int64_t time_stamp = esp_timer_get_time();
    return time_stamp;
}

static void port_ms_to_tv(uint16_t timeout_ms, struct timeval *tv)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms - (tv->tv_sec * 1000)) * 1000;
}

int port_enqueue_packet(QueueHandle_t queue, uint8_t *pbuf, uint16_t len)
{
    frame_entry_t frame_info = {0};
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    if (queue && pbuf) {
        frame_info.tid = MB_TCP_MBAP_GET_FIELD(pbuf, MB_TCP_TID);
        frame_info.uid = pbuf[MB_TCP_UID];
        frame_info.pid = MB_TCP_MBAP_GET_FIELD(pbuf, MB_TCP_PID);
        frame_info.len = MB_TCP_MBAP_GET_FIELD(pbuf, MB_TCP_LEN) + MB_TCP_UID;
        if (len != frame_info.len) {
            ESP_LOGE(TAG, "Packet TID (%x), length in frame %u != %u expected.", frame_info.tid, frame_info.len, len);
        }
        assert(xPortGetFreeHeapSize() > frame_info.len);

        ret = queue_push(queue, pbuf, frame_info.len, &frame_info);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Packet TID (%x), data enqueue failed.", frame_info.tid);
            // The packet send fail or the task which is waiting for event is already unblocked
            return ERR_BUF;
        } else {
            ESP_LOGD(TAG, "Enqueue data, length=%d, TID=0x%" PRIx16, frame_info.len, frame_info.tid);
            return (int)frame_info.len;
        }
    } else {
        ESP_LOGE(TAG, "Enqueue data fail, %p, length=%d.", pbuf, len);
    }
    return ERR_BUF;
}

int port_dequeue_packet(QueueHandle_t queue, frame_entry_t *pframe_info)
{
    frame_entry_t frame_info = {0};
    esp_err_t ret = ESP_ERR_INVALID_STATE;

    if (queue && pframe_info) {
        ret = queue_pop(queue, NULL, MB_TCP_BUFF_MAX_SIZE, &frame_info);
        if (ret == ESP_OK) {
            if ((frame_info.pid == 0) && (frame_info.uid < MB_ADDRESS_MAX)) {
                *pframe_info = frame_info;
                ESP_LOGD(TAG, "Dequeue data, length=%d, TID=0x%" PRIx16, (int)pframe_info->len, (int)pframe_info->tid);
                return ERR_OK;
            }
        } else {
            ESP_LOGE(TAG, "Dequeue data, failure %d", (int)ret);
        }
    }
    return ERR_BUF;
}

static int port_get_buf(mb_node_info_t *pinfo, uint8_t *pdst_buf, uint16_t len, uint16_t read_tick_ms)
{
    int ret = 0;
    uint8_t *pbuf = pdst_buf;
    uint16_t bytes_left = len;
    struct timeval time_val;

    MB_RETURN_ON_FALSE((pinfo && (pinfo->sock_id > UNDEF_FD)), -1, TAG, "Try to read incorrect socket = #%d.", pinfo->sock_id);

    // Set receive timeout for socket <= slave respond time
    time_val.tv_sec = read_tick_ms / 1000;
    time_val.tv_usec = (read_tick_ms % 1000) * 1000;
    setsockopt(pinfo->sock_id, SOL_SOCKET, SO_RCVTIMEO, &time_val, sizeof(time_val));

    // blocking read of data from socket
    ret = recv(pinfo->sock_id, pbuf, bytes_left, 0);
    if (ret < 0) {
        if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
            // Read timeout occurred, check the timeout and return
            return 0;
        } else if ((errno == ENOTCONN) || (errno == ECONNRESET)) {
            ESP_LOGD(TAG, "socket(#%d)(%s) connection closed, ret=%d, errno=%d.", 
                            pinfo->sock_id, pinfo->addr_info.ip_addr_str, ret, (int)errno);
            // Socket connection closed
            return ERR_CONN;
        } else {
            // Other error occurred during receiving
            ESP_LOGD(TAG, "Socket(#%d)(%s) receive error, ret = %d, errno = %d(%s)",
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str, ret, (int)errno, strerror(errno));
            return -1;
        }
    }
    return ret;
}

int port_read_packet(mb_node_info_t *pinfo)
{
    uint16_t temp = 0;
    int ret = 0;
    uint8_t ptemp_buf[MB_TCP_BUFF_MAX_SIZE] = {0};

    // Receive data from connected client
    if (pinfo) {
        MB_RETURN_ON_FALSE((pinfo->sock_id > 0), -1, TAG, "try to read incorrect socket = #%d.", pinfo->sock_id);
        // Read packet header
        ret = port_get_buf(pinfo, ptemp_buf, MB_TCP_UID, MB_READ_TICK);
        if (ret < 0) {
            pinfo->recv_err = ret;
            return ret;
        } else if (ret != MB_TCP_UID) {
            ESP_LOGD(TAG, "Socket (#%d)(%s), fail to read modbus header. ret=%d",
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str, ret);
            pinfo->recv_err = ERR_VAL;
            return ERR_VAL;
        }

        temp = MB_TCP_MBAP_GET_FIELD(ptemp_buf, MB_TCP_PID);
        if (temp != 0) {
            pinfo->recv_err = ERR_BUF;
            return ERR_BUF;
        }

        // If we have received the MBAP header we can analyze it and calculate
        // the number of bytes left to complete the current response.
        temp = MB_TCP_MBAP_GET_FIELD(ptemp_buf, MB_TCP_LEN);
        if (temp > MB_TCP_BUFF_MAX_SIZE) {
            ESP_LOGD(TAG, "Incorrect packet length: %d", temp);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, ptemp_buf, MB_TCP_FUNC, ESP_LOG_DEBUG);
            pinfo->recv_err = ERR_BUF;
            temp = MB_TCP_BUFF_MAX_SIZE; // read all remaining data from buffer
        }

        ret = port_get_buf(pinfo, &ptemp_buf[MB_TCP_UID], temp, MB_READ_TICK);
        if (ret < 0) {
            pinfo->recv_err = ret;
            return ret;
        } else if (ret != temp) {
            pinfo->recv_err = ERR_VAL;
            return ERR_VAL;
        }

        if (ptemp_buf[MB_TCP_UID] > MB_ADDRESS_MAX) {
            pinfo->recv_err = ERR_BUF;
            return ERR_BUF;
        }

        ret = port_enqueue_packet(pinfo->rx_queue, ptemp_buf, temp + MB_TCP_UID);
        if (ret < 0) {
            pinfo->recv_err = ret;
            return ret;
        }

        pinfo->recv_counter++;

        pinfo->recv_err = ERR_OK;
        return ret + MB_TCP_FUNC;
    }
    return -1;
}

err_t port_set_blocking(mb_node_info_t *pinfo, bool is_blocking)
{
    if (!pinfo) {
        return ERR_CONN;
    }
    // Set non blocking attribute for socket
    uint32_t flags = fcntl(pinfo->sock_id, F_GETFL);
    flags = is_blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK;
    if (fcntl(pinfo->sock_id, F_SETFL, flags) == -1) {
        ESP_LOGE(TAG, "Socket(#%d)(%s), fcntl() call error=%d",
                    pinfo->sock_id, pinfo->addr_info.ip_addr_str, (int)errno);
        return ERR_WOULDBLOCK;
    } else {
        pinfo->is_blocking = ((flags & O_NONBLOCK) != O_NONBLOCK);
    }
    return ERR_OK;
}

int port_keep_alive(int sock)
{
    int optval = 1;
    // Enable the Keepalive feature in the LWIP stack
    int ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    if (ret != 0) {
        ESP_LOGE(TAG, "Sock %d, set keep alive option fail, err= (%d).", sock, ret);
        return -1;
    }
    //  The interval between the last data packet sent and the first keepalive probe (seconds)
    optval = 1;
    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval));
    if (ret != 0) {
        ESP_LOGD(TAG, "Sock %d, set keep idle time fail, err = (%d).", sock, ret);
        return -1;
    }
    // The interval between keepalive probes (send every second)
    optval = 1;
    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval));
    if (ret != 0) {
        ESP_LOGD(TAG, "Sock %d, set keep alive probes interval fail, err = (%d).", sock, ret);
        return -1;
    }
    // Set count of probes before timing out
    optval = CONFIG_FMB_TCP_CONNECTION_TOUT_SEC;
    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval));
    if (ret != 0) {
        ESP_LOGD(TAG, "Sock %d, set keep alive probes count fail., err = (%d).", sock, ret);
        return -1;
    }
    return 0;
}

// Check connection for timeout helper
err_t port_check_alive(mb_node_info_t *pinfo, uint32_t timeout_ms)
{
    fd_set write_set;
    fd_set err_set;
    err_t err = -1;
    struct timeval time_val;

    if (pinfo && pinfo->sock_id != -1) {
        FD_ZERO(&write_set);
        FD_ZERO(&err_set);
        FD_SET(pinfo->sock_id, &write_set);
        FD_SET(pinfo->sock_id, &err_set);
        port_ms_to_tv(timeout_ms, &time_val);
        // Check if the socket is writable
        err = select(pinfo->sock_id + 1, NULL, &write_set, &err_set, &time_val);
        if ((err < 0) || FD_ISSET(pinfo->sock_id, &err_set)) {
            if (errno == EINPROGRESS) {
                err = ERR_INPROGRESS;
            } else {
                ESP_LOGV(TAG, MB_NODE_FMT(" connection, select write err(errno) = %d(%d)."),
                            pinfo->index, pinfo->sock_id, pinfo->addr_info.ip_addr_str, err, (int)errno);
                err = ERR_CONN;
            }
        } else if (err == 0) {
            ESP_LOGV(TAG, "Socket(#%d)(%s), connection timeout occurred, err(errno) = %d(%d).",
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str, err, (int)errno);
            return ERR_INPROGRESS;
        } else {
            int opt_err = 0;
            uint32_t opt_len = sizeof(opt_err);
            // Check socket error
            err = getsockopt(pinfo->sock_id, SOL_SOCKET, SO_ERROR, (void *)&opt_err, (socklen_t *)&opt_len);
            if (opt_err != 0) {
                ESP_LOGD(TAG, "Socket(#%d)(%s), sock error occurred (%d).",
                            pinfo->sock_id, pinfo->addr_info.ip_addr_str, opt_err);
                return ERR_CONN;
            }
            ESP_LOGV(TAG, "Socket(#%d)(%s), is alive.",
                        pinfo->sock_id, pinfo->addr_info.ip_addr_str);
            return ERR_OK;
        }
    } else {
        err = ERR_CONN;
    }
    return err;
}

// Unblocking connect function
err_t port_connect(void *ctx, mb_node_info_t *pinfo)
{
    if (!pinfo) {
        return ERR_CONN;
    }
    port_driver_t *pdrv_ctx = MB_GET_DRV_PTR(ctx);
    err_t err = ERR_OK;
    char str[HOST_STR_MAX_LEN];
    char *pstr = NULL;
    ip_addr_t target_addr;
    struct addrinfo hint;
    struct addrinfo *addr_list;
    struct addrinfo *pcur_addr;

    memset(&hint, 0, sizeof(hint));
    // Do name resolution for both protocols
    hint.ai_flags = AI_ADDRCONFIG | AI_CANONNAME; // get IPV6 address if supported, otherwise IPV4
    hint.ai_family = (pinfo->addr_info.addr_type == MB_IPV4) ? AF_INET : AF_INET6;
    hint.ai_socktype = (pinfo->addr_info.proto == MB_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    hint.ai_protocol = (pinfo->addr_info.proto == MB_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
    memset(&target_addr, 0, sizeof(target_addr));

    if (asprintf(&pstr, "%u", pinfo->addr_info.port) == -1) {
        abort();
    }

    // convert domain name to IP address
    int ret = getaddrinfo(pinfo->addr_info.ip_addr_str, pstr, &hint, &addr_list);
    free(pstr);
    if (ret != 0) {
        ESP_LOGE(TAG, "Cannot resolve host: %s", pinfo->addr_info.ip_addr_str);
        return ERR_CONN;
    }

    for (pcur_addr = addr_list; pcur_addr != NULL; pcur_addr = pcur_addr->ai_next) {
        if (pcur_addr->ai_family == AF_INET) {
            struct in_addr addr4 = ((struct sockaddr_in *)(pcur_addr->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
            pstr = ip4addr_ntoa_r(ip_2_ip4(&target_addr), str, sizeof(str));
        }
#if CONFIG_LWIP_IPV6
        else if (pcur_addr->ai_family == AF_INET6) {
            struct in6_addr addr6 = ((struct sockaddr_in6 *)(pcur_addr->ai_addr))->sin6_addr;
            inet6_addr_to_ip6addr(ip_2_ip6(&target_addr), &addr6);
            pstr = ip6addr_ntoa_r(ip_2_ip6(&target_addr), str, sizeof(str));
            // Set scope id to fix routing issues with local address
            ((struct sockaddr_in6 *)(pcur_addr->ai_addr))->sin6_scope_id =
                esp_netif_get_netif_impl_index(pdrv_ctx->network_iface_ptr);
        }
#endif
        if (pinfo->sock_id <= 0) {
            pinfo->sock_id = socket(pcur_addr->ai_family, pcur_addr->ai_socktype, pcur_addr->ai_protocol);
            if (pinfo->sock_id < 0) {
                ESP_LOGE(TAG, "Unable to create socket: #%d, errno %d", pinfo->sock_id, (int)errno);
                err = ERR_IF;
                continue;
            }
        } else {
            ESP_LOGV(TAG, "Socket (#%d)(%s) created.", pinfo->sock_id, str);
        }

        // Set non blocking attribute for socket
        port_set_blocking(pinfo, false);

        // Can return EINPROGRESS as an error which means
        // that connection is in progress and should be checked later
        err = connect(pinfo->sock_id, (struct sockaddr *)pcur_addr->ai_addr, pcur_addr->ai_addrlen);
        if ((err < 0) && (errno == EINPROGRESS || errno == EALREADY)) {
            // The unblocking connect is pending (check status later) or already connected
            ESP_LOGD(TAG, "Socket(#%d)(%s) connection is pending, errno %d (%s).",
                        pinfo->sock_id, str, (int)errno, strerror(errno));

            // Set keepalive option
            (void)port_keep_alive(pinfo->sock_id);
            err = port_check_alive(pinfo, MB_TCP_CHECK_ALIVE_TOUT_MS);
            continue;
        } else if ((err < 0) && (errno == EISCONN)) {
            // Socket already connected
            err = ERR_OK;
            continue;
        } else if (err != ERR_OK) {
            // Other error occurred during connection
            ESP_LOGV(TAG, "%p, "MB_NODE_FMT(" unable to connect, error=%d, errno %d (%s)"),
                        ctx, pinfo->index, pinfo->sock_id, str, err, (int)errno, strerror(errno));
            port_close_connection(pinfo);
            err = ERR_CONN;
        } else {
            ESP_LOGI(TAG, "%p, "MB_NODE_FMT(", successfully connected."),
                        ctx, pinfo->index, pinfo->sock_id, str);
            continue;
        }
    }
    freeaddrinfo(addr_list);
    port_set_blocking(pinfo, true);
    return err;
}

int port_write_poll(mb_node_info_t *pinfo, const uint8_t *pframe, uint16_t frame_len, uint32_t timeout)
{
    // Check if the socket is alive (writable and SO_ERROR == 0)
    int res = (int)port_check_alive(pinfo, timeout);
    if ((res < 0) && (res != ERR_INPROGRESS)) {
        ESP_LOGE(TAG, MB_NODE_FMT(", is not writable, error: %d, errno %d"),
                    pinfo->index, pinfo->sock_id, pinfo->addr_info.ip_addr_str, res, (int)errno);
        return res;
    }
    res = send(pinfo->sock_id, pframe, frame_len, TCP_NODELAY);
    if (res < 0) {
        ESP_LOGE(TAG, MB_NODE_FMT(", send data error: %d, errno %d"),
                    pinfo->index, pinfo->sock_id, pinfo->addr_info.ip_addr_str, res, (int)errno);
    }
    return res;
}

// Scan IP address according to IPV settings
int port_scan_addr_string(char *buffer, mb_uid_info_t *pinfo)
{
    char *phost_str = NULL;
    unsigned int a[8] = {0};
    int ret = 0;
    uint16_t index = 0;
    uint16_t port = 0;

    MB_RETURN_ON_FALSE((buffer && (strlen(buffer) < (HOST_STR_MAX_LEN - 8)) && pinfo), 
                            -1, TAG, "check input parameters fail.");

#if CONFIG_LWIP_IPV6
    // Configuration format: 
    // "12:2001:0db8:85a3:0000:0000:8a2e:0370:7334:502"
    // "12:2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    ret = sscanf(buffer, "%" PRIu16 ";" IPV6STR ";%" PRIu16, &index, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &port);
    if ((ret == MB_STR_LEN_IDX_IP6) || (ret == MB_STR_LEN_IDX_IP6_PORT)) {
        if (-1 == asprintf(&phost_str, IPV6STR, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])) {
            abort();
        }
        pinfo->node_name_str = phost_str;
        pinfo->ip_addr_str = phost_str;
        pinfo->uid = index;
        pinfo->fd = UNDEF_FD;
        pinfo->port = (ret == MB_STR_LEN_IDX_IP6_PORT) ? port : CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV6;
        pinfo->proto = MB_TCP;
        return ret;
    }

    // Configuration format:
    // "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    ret = sscanf(buffer, IPV6STR, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7]);
    if (ret == MB_STR_LEN_IP6_ONLY) {
        if (-1 == asprintf(&phost_str, IPV6STR, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])) {
            abort();
        }
        pinfo->node_name_str = phost_str;
        pinfo->ip_addr_str = phost_str;
        pinfo->uid = 0;
        pinfo->fd = UNDEF_FD;
        pinfo->port = CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV6;
        pinfo->proto = MB_TCP;
        return ret;
    }
#endif
    // Configuration format:
    // "192.168.1.1"
    ret = sscanf(buffer, IPSTR, &a[0], &a[1], &a[2], &a[3]);
    if (ret == MB_STR_LEN_IP4_ONLY) {
        if (-1 == asprintf(&phost_str, IPSTR, a[0], a[1], a[2], a[3])) {
            abort();
        }
        pinfo->node_name_str = phost_str;
        pinfo->ip_addr_str = phost_str;
        pinfo->uid = 0;
        pinfo->fd = UNDEF_FD;
        pinfo->port = CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV4;
        pinfo->proto = MB_TCP;
        return ret;
    }
    
    // Configuration format:
    // "1:192.168.1.1:502"
    ret = sscanf(buffer, "%" PRIu16 ";"IPSTR";%" PRIu16, &index, &a[0], &a[1], &a[2], &a[3], &port);
    if ((ret == MB_STR_LEN_IDX_IP4_PORT) || (ret == MB_STR_LEN_IDX_IP4)) {
        if (-1 == asprintf(&phost_str, IPSTR, a[0], a[1], a[2], a[3])) {
            abort();
        }
        pinfo->node_name_str = phost_str;
        pinfo->ip_addr_str = phost_str;
        pinfo->uid = index;
        pinfo->fd = UNDEF_FD;
        pinfo->port = (ret == MB_STR_LEN_IDX_IP4_PORT) ? port : CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV4;
        pinfo->proto = MB_TCP;
        return ret;
    }
    
    // Configuration format:
    // "01:mb_node_tcp_01:502"
    ret = sscanf(buffer,  "%" PRIu16 ";%m[a-z0-9_];%" PRIu16, (uint16_t*)&index, &phost_str, &port);
    if ((ret == MB_STR_LEN_HOST) || (ret == MB_STR_LEN_IDX_HOST_PORT)) {
        pinfo->node_name_str = (phost_str && strlen(phost_str)) ? phost_str : pinfo->node_name_str;
        pinfo->ip_addr_str = (pinfo->node_name_str) ? pinfo->node_name_str : pinfo->ip_addr_str;
        pinfo->uid = index;
        pinfo->fd = UNDEF_FD;
        pinfo->port = (ret == MB_STR_LEN_IDX_HOST_PORT) ? port : CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV4;
        pinfo->proto = MB_TCP;
        return ret;
    }
    
    // Configuration format:
    // "mb_node_tcp_01"
    ret = sscanf(buffer, "%m[a-z0-9_]", &phost_str); 
    if (ret == MB_STR_LEN_HOST) {

        pinfo->node_name_str = (phost_str && strlen(phost_str)) ? phost_str : pinfo->node_name_str;
        pinfo->ip_addr_str = (pinfo->node_name_str) ? pinfo->node_name_str : pinfo->ip_addr_str;
        pinfo->uid = index;
        pinfo->fd = UNDEF_FD;
        pinfo->port = CONFIG_FMB_TCP_PORT_DEFAULT;
        pinfo->addr_type = MB_IPV4;
        pinfo->proto = MB_TCP;
        return ret;
    }

    return -1;
}

#ifdef MB_MDNS_IS_INCLUDED

static int mdns_instance_count = 0;

// This function has limitation of working with IP6 address only
esp_err_t port_start_mdns_service(char **ppdns_name, bool is_master, int uid, void *pnode_netif)
{
    char temp_str[HOST_STR_MAX_LEN] = {0};
    esp_ip6_addr_t ip6[LWIP_IPV6_NUM_ADDRESSES];
    int ip6_addrs_count = 0;
    esp_err_t err = ESP_ERR_INVALID_STATE;
    MB_RETURN_ON_FALSE((pnode_netif),
                            err, TAG, "Invalid parameters for dns.");

    // initialize mDNS
    err = mdns_init(); // if the mdns is already initialized on higher layer, just returns
    MB_RETURN_ON_FALSE(((err == ESP_OK) && pnode_netif), err, TAG, "mdns init fail, err = %d.", (int)err);

    esp_netif_t *pnetif = (esp_netif_t*)pnode_netif;
    // set mDNS hostname (required if need to advertise services)
    err = mdns_hostname_get(temp_str);
    if (err != ESP_OK) {
        uint8_t mac[6];
        MB_RETURN_ON_FALSE((esp_netif_get_mac(pnetif, mac) == ESP_OK), 
                            err, TAG, "get MAC fail, err = %d.", (int)err);
        snprintf(temp_str, HOST_STR_MAX_LEN, "%s_%02x%02x%02x", MB_MDNS_INST_NAME(is_master), mac[3], mac[4], mac[5]);
        err = mdns_hostname_set(temp_str);
        MB_RETURN_ON_FALSE((err == ESP_OK),
                            err, TAG, "could not set mdns host name, err = %d.", (int)err);
        ESP_LOGI(TAG, "hostname set to: [%s]", temp_str);
        err = mdns_instance_name_set(temp_str);
        MB_RETURN_ON_FALSE((err == ESP_OK),
                            err, TAG, "mdns instance name set fail, err = %d.", (int)err);
    }
    // Check if the default mdns name is defined in the configuration
    if (ppdns_name && *ppdns_name && (strlen(*ppdns_name) >= MB_MDNS_STR_MIN_LENGTH)) {
        strncpy(temp_str, *ppdns_name, strlen(*ppdns_name));
        *ppdns_name[strlen(*ppdns_name)] = '\0';
    } else {
        if (snprintf(temp_str, sizeof(temp_str), "%s_%02x", MB_MDNS_INST_NAME(is_master), uid) <= 0) {
            return ESP_ERR_INVALID_STATE;
        };
    }
    
    // Setup the real assigned dns_name instead of constant string
    if (ppdns_name) {
        *ppdns_name = strdup(temp_str);
    }

    esp_netif_ip_info_t ip_info;
    mdns_ip_addr_t node_ip;
    err = esp_netif_get_ip_info(pnetif, &ip_info);
    MB_RETURN_ON_FALSE((err == ESP_OK),
                            err, TAG, "get IP info fail, err = %d.", (int)err);
    node_ip.next = NULL;
    node_ip.addr.type = ESP_IPADDR_TYPE_V4;
    node_ip.addr.u_addr.ip4 = ip_info.ip;
    node_ip.addr.u_addr.ip6.addr[1] = 0;
    node_ip.addr.u_addr.ip6.addr[2] = 0;
    node_ip.addr.u_addr.ip6.addr[3] = 0;
    node_ip.addr.u_addr.ip6.zone = 0;
    err = mdns_delegate_hostname_add(temp_str, &node_ip);
    MB_RETURN_ON_FALSE((err == ESP_OK), err, TAG, "mdns set delegate name fail, err = %d.", (int)err);

#if CONFIG_LWIP_IPV6
    // If the IP_V6 addresses supported on current interface, delegate them as well.
    ip6_addrs_count = esp_netif_get_all_ip6(pnetif, ip6);
    for (int i = 0; i < ip6_addrs_count; ++i) {
        ESP_LOGI(TAG, "IPv6 address: " IPV6STR, IPV62STR(ip6[i]));
        node_ip.next = NULL;
        node_ip.addr.type = ESP_IPADDR_TYPE_V6;
        node_ip.addr.u_addr.ip6 = ip6[i];
        err = mdns_delegate_hostname_add(temp_str, &node_ip);
        MB_RETURN_ON_FALSE((err == ESP_OK), err, TAG, "mdns set delegate name fail, err = %d.", (int)err);
    }
#endif

    // setup dns name for the modbus segment
    err = mdns_delegate_hostname_add(MB_MDNS_SEGMENT_NAME, &node_ip);
    MB_RETURN_ON_FALSE((err == ESP_OK), err, TAG, "mdns set segment name fail, err = %d.", (int)err);
    ESP_LOGI(TAG, "mdns delegate hostname set to: [%s]", temp_str);
    ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&ip_info.ip));
    ESP_LOGI(TAG, "GW: " IPSTR, IP2STR(&ip_info.gw));
    ESP_LOGI(TAG, "NETMASK: " IPSTR, IP2STR(&ip_info.netmask));

    mdns_instance_count++;

    return ESP_OK;
}

void port_stop_mdns_service(char **ppdns_name)
{
    if (ppdns_name && *ppdns_name) {
        mdns_delegate_hostname_remove(*ppdns_name);
        free(*ppdns_name);
        *ppdns_name = NULL;
        if (mdns_instance_count) {
            mdns_instance_count--;
        }
    }
    if (!mdns_instance_count) {
        mdns_delegate_hostname_remove(MB_MDNS_SEGMENT_NAME);
        mdns_service_remove_all();
        mdns_free();
    }
}

// char *port_get_node_ip_str(mdns_ip_addr_t *address, mb_addr_type_t addr_type)
// {
//     mdns_ip_addr_t *a = address;
//     char *node_ip_str = NULL;

//     while (a) {
//         if ((a->addr.type == ESP_IPADDR_TYPE_V6) && (addr_type == MB_IPV6)) {
//             if (-1 == asprintf(&node_ip_str, IPV6STR, IPV62STR(a->addr.u_addr.ip6))) {
//                 abort();
//             }
//         } else if ((a->addr.type == ESP_IPADDR_TYPE_V4) && (addr_type == MB_IPV4)) {
//             if (-1 == asprintf(&node_ip_str, IPSTR, IP2STR(&(a->addr.u_addr.ip4)))) {
//                 abort();
//             }
//         }
//         if (node_ip_str) {
//             break;
//         }
//         a = a->next;
//     }
//     return node_ip_str;
// }

// The helper to resolve host name based on service query (not used for now)
// esp_err_t port_resolve_slave(uint8_t short_addr, mdns_result_t *result, char **resolved_ip,
//                                 mb_addr_type_t addr_type)
// {
//     if (!short_addr || !result || !resolved_ip) {
//         return ESP_ERR_INVALID_ARG;
//     }
//     mdns_result_t *r = result;
//     int t;
//     char *node_ip = NULL;
//     char node_name[22] = {0};

//     if (sprintf(node_name, "mb_node_tcp_%02X", short_addr) < 0) {
//         ESP_LOGE(TAG, "Fail to create instance name for index: %d", short_addr);
//         abort();
//     }
//     for (; r; r = r->next) {
//         if ((r->ip_protocol == MDNS_IP_PROTOCOL_V4) && (addr_type == MB_IPV6)) {
//             continue;
//         } else if ((r->ip_protocol == MDNS_IP_PROTOCOL_V6) && (addr_type == MB_IPV4)) {
//             continue;
//         }
//         // Check host name for Modbus short address and
//         // append it into slave ip address table
//         if ((strcmp(r->instance_name, node_name) == 0) && (r->port == CONFIG_FMB_TCP_PORT_DEFAULT)) {
//             printf("  PTR : %s\n", r->instance_name);
//             if (r->txt_count) {
//                 printf("  TXT : [%u] ", r->txt_count);
//                 for (t = 0; t < r->txt_count; t++) {
//                     printf("%s=%s; ", r->txt[t].key, r->txt[t].value ? r->txt[t].value : "NULL");
//                 }
//                 printf("\n");
//             }
//             node_ip = port_get_node_ip_str(r->addr, addr_type);
//             if (node_ip) {
//                 ESP_LOGI(TAG, "Resolved slave %s[%s]:%u", r->hostname, node_ip, r->port);
//                 *resolved_ip = node_ip;
//                 return ESP_OK;
//             }
//         }
//     }
//     *resolved_ip = NULL;
//     ESP_LOGD(TAG, "Fail to resolve slave: %s", node_name);
//     return ESP_ERR_NOT_FOUND;
// }

int port_resolve_mdns_host(const char *host_name, char **paddr_str)
{
    ESP_LOGD(TAG, "Query A: %s.local", host_name);

    esp_ip_addr_t addr;
    char *pstr = NULL;
    bzero(&addr, sizeof(esp_ip_addr_t));

    // Try to send query to obtain the IPv4 address
    esp_err_t err = mdns_query_a(host_name, MB_MDNS_QUERY_TIME_MS, &addr.u_addr.ip4);
    if (err) {
        if (err == ESP_ERR_NOT_FOUND){
            // Try to resolve using AAAA query
            err =  mdns_query_aaaa(host_name, MB_MDNS_QUERY_TIME_MS, &addr.u_addr.ip6);
            if (err == ESP_ERR_NOT_FOUND) {
                ESP_LOGE(TAG, "Node: %s, unable to resolve!", host_name);
                return -1;
            }
            addr.type = ESP_IPADDR_TYPE_V6;
            if (asprintf(&pstr, IPV6STR, IPV62STR(addr.u_addr.ip6) == -1)) {
                abort();
            }
        } else {
            return -1;
        }
    } else {
        addr.type = ESP_IPADDR_TYPE_V4;
        if (asprintf(&pstr, IPSTR, IP2STR(&addr.u_addr.ip4)) == -1) {
            abort();
        }
    }
    if (paddr_str) {
        ESP_LOGD(TAG, "Node: %s, was resolved with IP: %s", host_name, pstr);
        *paddr_str = pstr;
    }
    return strlen(pstr);
}

#endif // #ifdef MB_MDNS_IS_INCLUDED

// Create a listening socket on pbind_ip, with ip address_type, protocol type and port
int port_bind_addr(const char *pbind_ip, mb_addr_type_t addr_type, mb_comm_mode_t proto, uint16_t port)
{
    int temp_par, ret;
    int listen_sock_fd = -1;
    struct addrinfo hint;
    struct addrinfo *paddr_list;
    struct addrinfo *pcur_addr;
    char* pstr = NULL;

    memset(&hint, 0, sizeof(hint));

    // Bind to IPv6 and/or IPv4, but only in the desired protocol
    // Todo: Find a reason why AF_UNSPEC does not work for IPv6
    hint.ai_family = AF_UNSPEC;
    //hint.ai_family = (addr_type == MB_IPV4) ? AF_INET : AF_INET6;
    hint.ai_socktype = (proto == MB_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    // The LWIP has an issue when connection to IPv6 socket
    hint.ai_protocol = (proto == MB_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
    hint.ai_flags = AI_NUMERICSERV | AI_PASSIVE | AI_CANONNAME;

    if (asprintf(&pstr, "%u", port) == -1) {
        abort();
    }

    ret = getaddrinfo(pbind_ip, pstr, &hint, &paddr_list);
    free(pstr);

    if ((ret != 0) ) {
        return -1;
    }

    // Try the sockaddr until a binding succeeds
    for (pcur_addr = paddr_list; pcur_addr != NULL; pcur_addr = pcur_addr->ai_next)
    {
        listen_sock_fd = (int)socket(pcur_addr->ai_family, pcur_addr->ai_socktype,
                                        pcur_addr->ai_protocol);
        if (listen_sock_fd < 0)
        {
            continue;
        }

        temp_par = 1;
        // Allow multi client connections
        if (setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR,
                        (const char*)&temp_par, sizeof(temp_par)) != 0)
        {
            close(listen_sock_fd);
            listen_sock_fd = UNDEF_FD;
            continue;
        }

        if (bind(listen_sock_fd, (struct sockaddr *)pcur_addr->ai_addr,
                                        (socklen_t)pcur_addr->ai_addrlen) != 0 )
        {
            close(listen_sock_fd);
            listen_sock_fd = UNDEF_FD;
            continue;
        }

        // Listen only makes sense for TCP
        if (proto == MB_TCP)
        {
            if (listen(listen_sock_fd, MB_TCP_NET_LISTEN_BACKLOG) != 0)
            {
                ESP_LOGE(TAG, "Error occurred during listen: errno=%u", (unsigned)errno);
                shutdown(listen_sock_fd, SHUT_RDWR);
                close(listen_sock_fd);
                listen_sock_fd = UNDEF_FD;
                continue;
            }
        }
        // Bind was successful
        pstr = (pcur_addr->ai_canonname == NULL) ? (char *)"\0" : pcur_addr->ai_canonname;
        ESP_LOGI(TAG, "Socket (#%d), listener %s on port: %u, errno=%u",
                                            (int)listen_sock_fd, pstr, (unsigned)port, (unsigned)errno);
        break;
    }

    freeaddrinfo(paddr_list);
    return(listen_sock_fd);
}

int port_accept_connection(int listen_sock_id, mb_uid_info_t *pinfo)
{
    MB_RETURN_ON_FALSE((pinfo), -1, TAG, "Wrong parameter pointer.");
    MB_RETURN_ON_FALSE((listen_sock_id > 0), -1, TAG, "Incorrect listen socket ID.");

    // Address structure large enough for both IPv4 or IPv6 address
    struct sockaddr_storage src_addr;
    char addr_str[128];
    int sock_id = UNDEF_FD;
    char *paddr = NULL;
    socklen_t addr_size = sizeof(struct sockaddr_storage);
    bzero(&src_addr, sizeof(struct sockaddr_storage));

    // Accept new socket connection if not active
    sock_id = accept(listen_sock_id, (struct sockaddr *)&src_addr, &addr_size);
    if (sock_id < 0) {
        ESP_LOGE(TAG, "Unable to accept connection: errno=%u", (unsigned)errno);
        close(sock_id);
    } else {
        // Get the sender's ip address as string
        if (src_addr.ss_family == PF_INET) {
            inet_ntoa_r(((struct sockaddr_in *)&src_addr)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
            pinfo->port =  ntohs(((struct sockaddr_in *)&src_addr)->sin_port);
            pinfo->addr_type = MB_IPV4;
        }
#if CONFIG_LWIP_IPV6
        else if (src_addr.ss_family == PF_INET6) {
            inet6_ntoa_r(((struct sockaddr_in6 *)&src_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
            pinfo->port =  ntohs(((struct sockaddr_in6 *)&src_addr)->sin6_port);
            pinfo->addr_type = MB_IPV6;
        }
#endif
        else {
            // Make sure ss_family is valid
            abort();
        }
        ESP_LOGI(TAG, "Socket (#%d), accept client connection from address[port]: %s[%d]", (int)sock_id, addr_str, pinfo->port);
        paddr = strdup(addr_str);
        if (paddr) {
            pinfo->fd = sock_id;
            pinfo->ip_addr_str = paddr;
            pinfo->node_name_str = paddr;
            pinfo->proto = MB_TCP;
            pinfo->uid = 0;
        }
    }
    return sock_id;
}

#endif

#ifdef __cplusplus
}
#endif
