#pragma once

/* ----------------------- Platform includes --------------------------------*/
#include "esp_log.h"

#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_timer.h"
#include "sys/time.h"
#include "esp_netif.h"

#include "mb_common.h"
#include "mb_frame.h"

#include "esp_modbus_common.h"      // for common types for network options
#include "port_tcp_driver.h"
#include "sys/queue.h"

#if (CONFIG_FMB_COMM_MODE_TCP_EN)

#define TRANSACTION_TICKS pdMS_TO_TICKS(50)

/**
 * @brief Modbus slave addr list item for the master
 */
typedef struct mb_data_entry_s {
    int node_id;
    uint64_t token;
    mb_node_info_t *pnode;
    frame_entry_t frame;
    bool pending;
    STAILQ_ENTRY(mb_data_entry_s) entries;
} mb_data_item_t;


MB_EVENT_HANDLER(mbs_on_ready);
MB_EVENT_HANDLER(mbs_on_open);
MB_EVENT_HANDLER(mbs_on_resolve);
MB_EVENT_HANDLER(mbs_on_connect);
MB_EVENT_HANDLER(mbs_on_send_data);
MB_EVENT_HANDLER(mbs_on_recv_data);
MB_EVENT_HANDLER(mbs_on_error);
MB_EVENT_HANDLER(mbs_on_close);
MB_EVENT_HANDLER(mbs_on_timeout);

#endif