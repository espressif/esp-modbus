/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Lifecycle tests of the Modbus TCP slave: start / stop / delete of the listener.
// The tests use the loopback interface only, so they do not need a network connection.

#include <string.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "unity.h"

#include "esp_modbus_common.h"
#include "esp_modbus_slave.h"

#define TEST_PORT               (1502)
#define TEST_PORT_2             (1503)
#define TEST_UID                (1)
#define TEST_RECV_TIMEOUT_MS    (2000)
#define TEST_HEAP_TOLERANCE     (512)

static const char *TAG = "test_lifecycle";

static uint16_t s_holding[4] = {0x1234, 0x5678, 0x9abc, 0xdef0};

void setUp(void)
{
}

void tearDown(void)
{
}

static void *slave_create(uint16_t port, const char *bind_addr)
{
    mb_communication_info_t config = {
        .tcp_opts.port = port,
        .tcp_opts.mode = MB_TCP,
        .tcp_opts.addr_type = MB_IPV4,
        .tcp_opts.ip_addr_table = (void *)bind_addr,
        .tcp_opts.ip_netif_ptr = NULL,
        .tcp_opts.uid = TEST_UID
    };
    void *handle = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_create_tcp(&config, &handle));
    TEST_ASSERT_NOT_NULL(handle);
    mb_register_area_descriptor_t area = {
        .type = MB_PARAM_HOLDING,
        .start_offset = 0,
        .address = (void *)s_holding,
        .size = sizeof(s_holding),
        .access = MB_ACCESS_RW
    };
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_set_descriptor(handle, area));
    return handle;
}

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

// Returns a connected socket, or -1 with errno set
static int client_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    struct timeval tv = {.tv_sec = TEST_RECV_TIMEOUT_MS / 1000, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

static void client_close(int fd)
{
    struct linger lin = {.l_onoff = 1, .l_linger = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
    close(fd);
}

static bool client_send_read_request(int fd, uint16_t tid)
{
    uint8_t req[12] = {
        (uint8_t)(tid >> 8), (uint8_t)tid,  // TID
        0, 0,                               // protocol
        0, 6,                               // length
        TEST_UID,
        0x03,                               // read holding registers
        0, 0,                               // address
        0, 1                                // count
    };
    return send(fd, req, sizeof(req), 0) == sizeof(req);
}

// Reads one holding register, returns true if the correct answer is received
static bool client_read(int fd, uint16_t tid)
{
    if (!client_send_read_request(fd, tid)) {
        return false;
    }
    uint8_t resp[11] = {0};
    size_t got = 0;
    while (got < sizeof(resp)) {
        int n = recv(fd, resp + got, sizeof(resp) - got, 0);
        if (n <= 0) {
            return false;
        }
        got += n;
    }
    uint16_t resp_tid = (resp[0] << 8) | resp[1];
    uint16_t value = (resp[9] << 8) | resp[10];
    return (resp_tid == tid) && (resp[7] == 0x03) && (resp[8] == 2) && (value == s_holding[0]);
}

static bool port_accepts(uint16_t port)
{
    int fd = client_connect(port);
    if (fd < 0) {
        return false;
    }
    bool ok = client_read(fd, 1);
    client_close(fd);
    return ok;
}

static bool port_refuses(uint16_t port)
{
    int fd = client_connect(port);
    if (fd >= 0) {
        client_close(fd);
        return false;
    }
    return (errno == ECONNREFUSED) || (errno == ECONNRESET);
}

// A listener that does not allow the address reuse, so the slave can not bind the port
static int blocker_open(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    TEST_ASSERT_EQUAL(0, bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    TEST_ASSERT_EQUAL(0, listen(fd, 1));
    return fd;
}

// The listener is closed by stop, so the same port can be started again right away
static void test_start_stop_restart(void)
{
    void *handle = slave_create(TEST_PORT, NULL);
    size_t heap_before = 0;
    // The first cycles fill the lwIP pool of closed client connections (TIME_WAIT),
    // so the heap is compared after that.
    for (int i = 0; i < 40; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
        TEST_ASSERT_TRUE_MESSAGE(port_accepts(TEST_PORT), "slave does not answer after start");
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
        TEST_ASSERT_TRUE_MESSAGE(port_refuses(TEST_PORT), "port still listening after stop");
        if (i == 20) {
            heap_before = esp_get_free_heap_size();
        }
    }
    size_t heap_after = esp_get_free_heap_size();
    ESP_LOGI(TAG, "heap before: %u, after: %u", (unsigned)heap_before, (unsigned)heap_after);
    TEST_ASSERT_LESS_OR_EQUAL(TEST_HEAP_TOLERANCE, (int)heap_before - (int)heap_after);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// Start fails with a timeout when the port stays in use, and the slave can be started later
static void test_port_in_use(void)
{
    int blocker = blocker_open(TEST_PORT);
    void *handle = slave_create(TEST_PORT, NULL);
    int64_t t0 = now_ms();
    TEST_ASSERT_EQUAL(ESP_ERR_TIMEOUT, mbc_slave_start(handle));
    int64_t elapsed = now_ms() - t0;
    ESP_LOGI(TAG, "start failed after %d ms", (int)elapsed);
    TEST_ASSERT_INT_WITHIN(1000, 5000, (int)elapsed);
    // The failed start leaves the slave stopped
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, mbc_slave_stop(handle));
    close(blocker);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    TEST_ASSERT_TRUE(port_accepts(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
    TEST_ASSERT_TRUE(port_refuses(TEST_PORT));
}

static void blocker_release_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    close((int)(intptr_t)arg);
    vTaskDelete(NULL);
}

// Start retries while the port is in use and succeeds once it is released
static void test_port_released_during_start(void)
{
    int blocker = blocker_open(TEST_PORT);
    void *handle = slave_create(TEST_PORT, NULL);
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(blocker_release_task, "release", 2048,
                                          (void *)(intptr_t)blocker, 5, NULL));
    int64_t t0 = now_ms();
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    int64_t elapsed = now_ms() - t0;
    ESP_LOGI(TAG, "start succeeded after %d ms", (int)elapsed);
    TEST_ASSERT_GREATER_OR_EQUAL(400, (int)elapsed);
    TEST_ASSERT_LESS_THAN(2000, (int)elapsed);
    TEST_ASSERT_TRUE(port_accepts(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// An address that can not be used fails right away
static void test_invalid_bind_address(void)
{
    void *handle = slave_create(TEST_PORT, "300.1.1.1");
    int64_t t0 = now_ms();
    esp_err_t err = mbc_slave_start(handle);
    int64_t elapsed = now_ms() - t0;
    ESP_LOGI(TAG, "start returned %s after %d ms", esp_err_to_name(err), (int)elapsed);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);
    TEST_ASSERT_LESS_THAN(1000, (int)elapsed);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// Stop and start report the wrong state, and never hang
static void test_invalid_state(void)
{
    void *handle = slave_create(TEST_PORT, NULL);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, mbc_slave_stop(handle));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, mbc_slave_start(handle));
    TEST_ASSERT_TRUE(port_accepts(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, mbc_slave_stop(handle));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// Delete works in every state and closes the port
static void test_delete_from_any_state(void)
{
    size_t heap_before = 0;
    for (int i = 0; i < 10; i++) {
        // created, never started
        int64_t t0 = now_ms();
        void *handle = slave_create(TEST_PORT, NULL);
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
        TEST_ASSERT_LESS_THAN(1000, (int)(now_ms() - t0));

        // started, with a connected client
        handle = slave_create(TEST_PORT, NULL);
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
        int fd = client_connect(TEST_PORT);
        TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
        TEST_ASSERT_TRUE(client_read(fd, 1));
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
        TEST_ASSERT_TRUE(port_refuses(TEST_PORT));
        client_close(fd);

        // stopped
        handle = slave_create(TEST_PORT, NULL);
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));

        // start failed
        handle = slave_create(TEST_PORT, "300.1.1.1");
        TEST_ASSERT_NOT_EQUAL(ESP_OK, mbc_slave_start(handle));
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));

        if (i == 1) {
            heap_before = esp_get_free_heap_size();
        }
    }
    size_t heap_after = esp_get_free_heap_size();
    ESP_LOGI(TAG, "heap before: %u, after: %u", (unsigned)heap_before, (unsigned)heap_after);
    TEST_ASSERT_LESS_OR_EQUAL(TEST_HEAP_TOLERANCE, (int)heap_before - (int)heap_after);
}

// A failed start of one instance does not disturb the other one
static void test_two_instances(void)
{
    void *first = slave_create(TEST_PORT, NULL);
    void *second = slave_create(TEST_PORT_2, NULL);
    void *third = slave_create(TEST_PORT, NULL);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(first));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(second));
    int fd = client_connect(TEST_PORT);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    // the port is used by the first instance
    TEST_ASSERT_EQUAL(ESP_ERR_TIMEOUT, mbc_slave_start(third));
    for (uint16_t tid = 1; tid < 10; tid++) {
        TEST_ASSERT_TRUE(client_read(fd, tid));
    }
    TEST_ASSERT_TRUE(port_accepts(TEST_PORT_2));
    // Stop of the second instance does not close the connections of the first one
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(second));
    TEST_ASSERT_TRUE(client_read(fd, 10));
    TEST_ASSERT_TRUE(port_refuses(TEST_PORT_2));
    client_close(fd);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(third));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(second));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(first));
}

// Stop in the middle of a request, the next session answers the requests
static void test_stop_during_request(void)
{
    void *handle = slave_create(TEST_PORT, NULL);
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
        int fd = client_connect(TEST_PORT);
        TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
        TEST_ASSERT_TRUE(client_read(fd, 1));
        TEST_ASSERT_TRUE(client_send_read_request(fd, 2));
        // The request can be in any stage of the processing here
        vTaskDelay(i % 3);
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
        // The connection is closed by the stop
        uint8_t buf[16];
        int n;
        do {
            n = recv(fd, buf, sizeof(buf), 0);
        } while (n > 0);
        TEST_ASSERT_TRUE((n == 0) || (errno == ECONNRESET) || (errno == ENOTCONN));
        client_close(fd);
    }
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_TRUE_MESSAGE(port_accepts(TEST_PORT), "request not answered after the restart");
    }
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// Waits for the notifications of the helper tasks, the tasks can complete in any order and
// before the wait starts, so a single take can return more than one notification
static bool wait_for_tasks(uint32_t count, TickType_t timeout)
{
    uint32_t done = 0;
    TickType_t start = xTaskGetTickCount();
    while (done < count) {
        TickType_t elapsed = xTaskGetTickCount() - start;
        if (elapsed >= timeout) {
            return false;
        }
        done += ulTaskNotifyTake(pdTRUE, timeout - elapsed);
    }
    return done == count;
}

typedef struct {
    void *handle;
    int ok_count;
    int state_err_count;
    int other_err_count;
    TaskHandle_t notify;
} race_ctx_t;

static void race_task(void *arg)
{
    race_ctx_t *ctx = (race_ctx_t *)arg;
    for (int i = 0; i < 20; i++) {
        vTaskDelay(esp_random() % 3);
        esp_err_t err = (i & 1) ? mbc_slave_stop(ctx->handle) : mbc_slave_start(ctx->handle);
        if (err == ESP_OK) {
            ctx->ok_count++;
        } else if (err == ESP_ERR_INVALID_STATE) {
            ctx->state_err_count++;
        } else {
            ctx->other_err_count++;
        }
    }
    xTaskNotifyGive(ctx->notify);
    vTaskDelete(NULL);
}

// Start and stop from two tasks at the same time keep the state consistent
static void test_concurrent_start_stop(void)
{
    void *handle = slave_create(TEST_PORT, NULL);
    race_ctx_t a = {.handle = handle, .notify = xTaskGetCurrentTaskHandle()};
    race_ctx_t b = a;
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(race_task, "race_a", 4096, &a, 5, NULL));
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(race_task, "race_b", 4096, &b, 5, NULL));
    TEST_ASSERT_TRUE(wait_for_tasks(2, pdMS_TO_TICKS(60000)));
    ESP_LOGI(TAG, "a: ok=%d state=%d other=%d, b: ok=%d state=%d other=%d",
             a.ok_count, a.state_err_count, a.other_err_count,
             b.ok_count, b.state_err_count, b.other_err_count);
    TEST_ASSERT_EQUAL(0, a.other_err_count);
    TEST_ASSERT_EQUAL(0, b.other_err_count);
    // Both tasks end with a stop, so the slave is stopped now
    TEST_ASSERT_TRUE(port_refuses(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    TEST_ASSERT_TRUE(port_accepts(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

// A frame with a wrong protocol ID, the slave drops this connection with an error event
static void client_send_garbage(int fd)
{
    uint8_t req[12] = {0, 1, 0x55, 0x55, 0, 6, TEST_UID, 0x03, 0, 0, 0, 1};
    (void)send(fd, req, sizeof(req), 0);
}

// Restarts with the traffic and error events of the old clients still pending.
// The clients of the next session reuse the same node indexes and must be served normally.
static void test_stale_events_after_restart(void)
{
    enum { OLD_CLIENTS = 3, NEW_CLIENTS = 3, REQUESTS = 5 };
    void *handle = slave_create(TEST_PORT, NULL);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
    for (int i = 0; i < 15; i++) {
        int old_fd[OLD_CLIENTS];
        for (int c = 0; c < OLD_CLIENTS; c++) {
            old_fd[c] = client_connect(TEST_PORT);
            TEST_ASSERT_GREATER_OR_EQUAL(0, old_fd[c]);
        }
        client_send_garbage(old_fd[0]);
        for (int c = 1; c < OLD_CLIENTS; c++) {
            for (int r = 0; r < 3; r++) {
                (void)client_send_read_request(old_fd[c], (uint16_t)(r + 1));
            }
        }
        // Restart while the events of the old clients are still pending
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
        TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_start(handle));
        for (int c = 0; c < OLD_CLIENTS; c++) {
            client_close(old_fd[c]);
        }
        int new_fd[NEW_CLIENTS];
        for (int c = 0; c < NEW_CLIENTS; c++) {
            new_fd[c] = client_connect(TEST_PORT);
            TEST_ASSERT_GREATER_OR_EQUAL(0, new_fd[c]);
        }
        for (int r = 0; r < REQUESTS; r++) {
            for (int c = 0; c < NEW_CLIENTS; c++) {
                TEST_ASSERT_TRUE_MESSAGE(client_read(new_fd[c], (uint16_t)(100 + r)),
                                         "client of the new session is not served");
            }
        }
        for (int c = 0; c < NEW_CLIENTS; c++) {
            client_close(new_fd[c]);
        }
    }
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

typedef struct {
    void *handle;
    esp_err_t err;
    TaskHandle_t notify;
} start_ctx_t;

static void start_task(void *arg)
{
    start_ctx_t *ctx = (start_ctx_t *)arg;
    ctx->err = mbc_slave_start(ctx->handle);
    xTaskNotifyGive(ctx->notify);
    vTaskDelete(NULL);
}

// A stop called while a start is in progress in another task waits for the start to complete
static void test_stop_waits_for_start(void)
{
    void *handle = slave_create(TEST_PORT, NULL);
    int blocker = blocker_open(TEST_PORT);
    start_ctx_t ctx = {.handle = handle, .err = ESP_FAIL, .notify = xTaskGetCurrentTaskHandle()};
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(start_task, "start", 4096, &ctx, 5, NULL));
    vTaskDelay(pdMS_TO_TICKS(200));
    // Release the port, so the pending start succeeds, then stop the slave
    close(blocker);
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_stop(handle));
    TEST_ASSERT_TRUE(wait_for_tasks(1, pdMS_TO_TICKS(10000)));
    TEST_ASSERT_EQUAL(ESP_OK, ctx.err);
    TEST_ASSERT_TRUE(port_refuses(TEST_PORT));
    TEST_ASSERT_EQUAL(ESP_OK, mbc_slave_delete(handle));
}

void app_main(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_log_level_set("vfs_calls", ESP_LOG_NONE);

    UNITY_BEGIN();
    RUN_TEST(test_start_stop_restart);
    RUN_TEST(test_port_in_use);
    RUN_TEST(test_port_released_during_start);
    RUN_TEST(test_invalid_bind_address);
    RUN_TEST(test_invalid_state);
    RUN_TEST(test_delete_from_any_state);
    RUN_TEST(test_two_instances);
    RUN_TEST(test_stop_during_request);
    RUN_TEST(test_concurrent_start_stop);
    RUN_TEST(test_stale_events_after_restart);
    RUN_TEST(test_stop_waits_for_start);
    UNITY_END();
}
