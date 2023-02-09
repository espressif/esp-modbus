/*
 * SPDX-FileCopyrightText: 2013 Armink
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * SPDX-FileContributor: 2016-2021 Espressif Systems (Shanghai) CO LTD
 */
/*
 * FreeModbus Libary: ESP32 Port
 * Copyright (C) 2013 Armink <armink.ztl@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * IF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * File: $Id: portserial.c,v 1.60 2013/08/13 15:07:05 Armink add Master Functions $
 */

#include <string.h>
#include "driver/uart.h"
#include "soc/dport_access.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "sdkconfig.h"

/* ----------------------- Modbus includes ----------------------------------*/
#include "port.h"
#include "mbport.h"
#include "mb_m.h"
#include "mbrtu.h"
#include "mbconfig.h"
#include "port_serial_master.h"

/* ----------------------- Defines ------------------------------------------*/
#define MB_SERIAL_RX_SEMA_TOUT_MS   (1000)
#define MB_SERIAL_RX_SEMA_TOUT      (pdMS_TO_TICKS(MB_SERIAL_RX_SEMA_TOUT_MS))
#define MB_SERIAL_RX_FLUSH_RETRY    (2)

/* ----------------------- Static variables ---------------------------------*/
static const CHAR *TAG = "MB_MASTER_SERIAL";

// Serial communication context structure
static MBMSerialContext_t xMBMCtx = {
    .xMbUartQueue = NULL,
    .xMbTaskHandle = NULL,
    .ucUartNumber = UART_NUM_MAX - 1,
    .xRxSemaHandle = NULL,
    .bTxStateEnabled = FALSE,
    .bRxStateEnabled = FALSE,
    .ulParityErrors = 0,            // Debug counters, can overrun
    .ulFrameErrors = 0
};

static BOOL xMBMasterPortRxSemaInit( void )
{
    xMBMCtx.xRxSemaHandle = xSemaphoreCreateBinary();
    MB_PORT_CHECK((xMBMCtx.xRxSemaHandle != NULL), FALSE , "%s: RX semaphore create failure.", __func__);
    return TRUE;
}

static void vMBMasterPortRxSemaClose( void )
{
    if (xMBMCtx.xRxSemaHandle) {
        vSemaphoreDelete(xMBMCtx.xRxSemaHandle);
        xMBMCtx.xRxSemaHandle = NULL;
    }
}

static BOOL xMBMasterPortRxSemaTake( LONG lTimeOut )
{
    BaseType_t xStatus = pdTRUE;
    xStatus = xSemaphoreTake(xMBMCtx.xRxSemaHandle, lTimeOut );
    if (xStatus != pdTRUE) {
        ESP_LOGD(TAG, "%s: RX semaphore take failure.", __func__);
    }
    ESP_LOGV(MB_PORT_TAG,"%s:Take RX semaphore (%lu ticks).", __func__, lTimeOut);
    return TRUE;
}

static void vMBMasterRxSemaRelease( void )
{
    BaseType_t xStatus = pdFALSE;
    xStatus = xSemaphoreGive(xMBMCtx.xRxSemaHandle);
    if (xStatus != pdTRUE) {
        ESP_LOGD(MB_PORT_TAG,"%s:RX semaphore is free.", __func__);
    }
}

static BOOL vMBMasterRxSemaIsBusy( void )
{
    BaseType_t xStatus = pdFALSE;
    xStatus = (uxSemaphoreGetCount(xMBMCtx.xRxSemaHandle) == 0) ? TRUE : FALSE;
    return xStatus;
}

void vMBMasterRxFlush( void )
{
    size_t xSize = 1;
    esp_err_t xErr = ESP_OK;
    for (int xCount = 0; (xCount < MB_SERIAL_RX_FLUSH_RETRY) && xSize; xCount++) {
        xErr = uart_get_buffered_data_len(xMBMCtx.ucUartNumber, &xSize);
        MB_PORT_CHECK((xErr == ESP_OK), ; , "mb flush serial fail, error = 0x%x.", xErr);
        BaseType_t xStatus = xQueueReset(xMBMCtx.xMbUartQueue);
        if (xStatus) {
            xErr = uart_flush_input(xMBMCtx.ucUartNumber);
            MB_PORT_CHECK((xErr == ESP_OK), ; , "mb flush serial fail, error = 0x%x.", xErr);
        }
    }
}

void vMBMasterPortSerialEnable(BOOL bRxEnable, BOOL bTxEnable)
{
    // This function can be called from xMBRTUTransmitFSM() of different task
    if (bTxEnable) {
        vMBMasterRxFlush();
        xMBMCtx.bTxStateEnabled = TRUE;
    } else {
        xMBMCtx.bTxStateEnabled = FALSE;
    }
    if (bRxEnable) {
        xMBMCtx.bRxStateEnabled = TRUE;
        vMBMasterRxSemaRelease();
        vTaskResume(xMBMCtx.xMbTaskHandle); // Resume receiver task
    } else {
        vTaskSuspend(xMBMCtx.xMbTaskHandle); // Block receiver task
        xMBMCtx.bRxStateEnabled = FALSE;
    }
}

static USHORT usMBMasterPortSerialRxPoll(size_t xEventSize)
{
    BOOL xStatus = TRUE;
    USHORT usCnt = 0;

    xStatus = xMBMasterPortRxSemaTake(MB_SERIAL_RX_SEMA_TOUT);
    if (xStatus) {
        while(xStatus && (usCnt++ <= xEventSize)) {
            // Call the Modbus stack callback function and let it fill the stack buffers.
            xStatus = pxMBMasterFrameCBByteReceived(); // callback to receive FSM
        }
        // The buffer is transferred into Modbus stack and is not needed here any more
        uart_flush_input(xMBMCtx.ucUartNumber);
        ESP_LOGD(TAG, "Received data: %d(bytes in buffer)\n", (uint32_t)usCnt);
#if !CONFIG_FMB_TIMER_PORT_ENABLED
        vMBMasterSetCurTimerMode(MB_TMODE_T35);
        xStatus = pxMBMasterPortCBTimerExpired();
        if (!xStatus) {
            xMBMasterPortEventPost(EV_MASTER_FRAME_RECEIVED);
            ESP_LOGD(TAG, "Send additional RX ready event.");
        }
#endif
    } else {
        ESP_LOGE(TAG, "%s: bRxState disabled but junk data (%d bytes) received. ", __func__, xEventSize);
    }
    return usCnt;
}

BOOL xMBMasterPortSerialTxPoll(void)
{
    USHORT usCount = 0;
    BOOL bNeedPoll = TRUE;

    if(xMBMCtx.bTxStateEnabled) {
        // Continue while all response bytes put in buffer or out of buffer
        while(bNeedPoll && (usCount++ < MB_SERIAL_BUF_SIZE)) {
            // Calls the modbus stack callback function to let it fill the UART transmit buffer.
            bNeedPoll = pxMBMasterFrameCBTransmitterEmpty( ); // callback to transmit FSM
        }
        ESP_LOGD(TAG, "MB_TX_buffer sent: (%d) bytes.", (uint16_t)(usCount - 1));
        // Waits while UART sending the packet
        esp_err_t xTxStatus = uart_wait_tx_done(xMBMCtx.ucUartNumber, MB_SERIAL_TX_TOUT_TICKS);
        vMBMasterPortSerialEnable(TRUE, FALSE);
        MB_PORT_CHECK((xTxStatus == ESP_OK), FALSE, "mb serial sent buffer failure.");
        return TRUE;
    }
    return FALSE;
}

// UART receive event task
static void vUartTask(void* pvParameters)
{
    uart_event_t xEvent;
    USHORT usResult = 0;
    for(;;) {
        if (xMBPortSerialWaitEvent(xMBMCtx.xMbUartQueue, (void*)&xEvent, portMAX_DELAY)) {
            ESP_LOGD(TAG, "MB_uart[%d] event:", xMBMCtx.ucUartNumber);
            switch(xEvent.type) {
                //Event of UART receiving data
                case UART_DATA:
                    ESP_LOGD(TAG,"Data event, len: %d.", xEvent.size);
                    // This flag set in the event means that no more
                    // data received during configured timeout and UART TOUT feature is triggered
                    if (xEvent.timeout_flag) {
                        // Response is received but previous packet processing is pending
                        // Do not wait completion of processing and just discard received data as incorrect
                        if (vMBMasterRxSemaIsBusy()) {
                            vMBMasterRxFlush();
                            vMBMasterSetErrorType(EV_ERROR_RECEIVE_DATA);
                            xMBMasterPortEventPost(EV_MASTER_ERROR_PROCESS);
                            break;
                        }
                        // Get buffered data length
                        ESP_ERROR_CHECK(uart_get_buffered_data_len(xMBMCtx.ucUartNumber, &xEvent.size));
                        // Read received data and send it to modbus stack
                        usResult = usMBMasterPortSerialRxPoll(xEvent.size);
                        ESP_LOGD(TAG,"Timeout occured, processed: %d bytes", usResult);
                    }
                    break;
                //Event of HW FIFO overflow detected
                case UART_FIFO_OVF:
                    ESP_LOGD(TAG, "hw fifo overflow.");
                    xQueueReset(xMBMCtx.xMbUartQueue);
                    break;
                //Event of UART ring buffer full
                case UART_BUFFER_FULL:
                    ESP_LOGD(TAG, "ring buffer full.");
                    xQueueReset(xMBMCtx.xMbUartQueue);
                    uart_flush_input(xMBMCtx.ucUartNumber);
                    break;
                //Event of UART RX break detected
                case UART_BREAK:
                    ESP_LOGD(TAG, "uart rx break.");
                    break;
                //Event of UART parity check error
                case UART_PARITY_ERR:
                    ESP_LOGD(TAG, "uart parity error, count: %lu.", xMBMCtx.ulParityErrors);
                    xMBMasterPortRxSemaTake(0);
                    xMBMCtx.ulParityErrors++;
                    break;
                //Event of UART frame error
                case UART_FRAME_ERR:
                    ESP_LOGD(TAG, "uart frame error, count: %lu.", xMBMCtx.ulFrameErrors);
                    xMBMasterPortRxSemaTake(0);
                    xMBMCtx.ulFrameErrors++;
                    break;
                default:
                    ESP_LOGD(TAG, "uart event type: %d.", xEvent.type);
                    break;
            }
        }
    }
    vTaskDelete(NULL);
}

/* ----------------------- Start implementation -----------------------------*/
BOOL xMBMasterPortSerialInit( UCHAR ucPORT, ULONG ulBaudRate, UCHAR ucDataBits, eMBParity eParity )
{
    esp_err_t xErr = ESP_OK;
    // Set communication port number
    xMBMCtx.ucUartNumber = ucPORT;
    xMBMCtx.ulParityErrors = 0;
    xMBMCtx.ulFrameErrors = 0;
    // Configure serial communication parameters
    UCHAR ucParity = UART_PARITY_DISABLE;
    UCHAR ucData = UART_DATA_8_BITS;
    switch(eParity){
        case MB_PAR_NONE:
            ucParity = UART_PARITY_DISABLE;
            break;
        case MB_PAR_ODD:
            ucParity = UART_PARITY_ODD;
            break;
        case MB_PAR_EVEN:
            ucParity = UART_PARITY_EVEN;
            break;
        default:
            ESP_LOGE(TAG, "Incorrect parity option: %d", eParity);
            return FALSE;
    }
    switch(ucDataBits){
        case 5:
            ucData = UART_DATA_5_BITS;
            break;
        case 6:
            ucData = UART_DATA_6_BITS;
            break;
        case 7:
            ucData = UART_DATA_7_BITS;
            break;
        case 8:
            ucData = UART_DATA_8_BITS;
            break;
        default:
            ucData = UART_DATA_8_BITS;
            break;
    }
    uart_config_t xUartConfig = {
        .baud_rate = ulBaudRate,
        .data_bits = ucData,
        .parity = ucParity,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 2,
#if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0))
        .source_clk = UART_SCLK_DEFAULT,
#else
        .source_clk = UART_SCLK_APB,
#endif
    };
    // Set UART config
    xErr = uart_param_config(xMBMCtx.ucUartNumber, &xUartConfig);
    MB_PORT_CHECK((xErr == ESP_OK),
            FALSE, "mb config failure, uart_param_config() returned (0x%x).", xErr);
    // Install UART driver, and get the queue.
    xErr = uart_driver_install(xMBMCtx.ucUartNumber, MB_SERIAL_BUF_SIZE, MB_SERIAL_BUF_SIZE,
                                    MB_QUEUE_LENGTH, &xMBMCtx.xMbUartQueue, MB_PORT_SERIAL_ISR_FLAG);
    MB_PORT_CHECK((xErr == ESP_OK), FALSE,
            "mb serial driver failure, uart_driver_install() returned (0x%x).", xErr);
    // Set timeout for TOUT interrupt (T3.5 modbus time)
    xErr = uart_set_rx_timeout(xMBMCtx.ucUartNumber, MB_SERIAL_TOUT);
    MB_PORT_CHECK((xErr == ESP_OK), FALSE,
            "mb serial set rx timeout failure, uart_set_rx_timeout() returned (0x%x).", xErr);
    // Set always timeout flag to trigger timeout interrupt even after rx fifo full
    uart_set_always_rx_timeout(xMBMCtx.ucUartNumber, true);
    MB_PORT_CHECK((xMBMasterPortRxSemaInit()), FALSE,
                        "mb serial RX semaphore create fail.");
    // Create a task to handle UART events
    BaseType_t xStatus = xTaskCreatePinnedToCore(vUartTask, "uart_queue_task",
                                                    MB_SERIAL_TASK_STACK_SIZE,
                                                    NULL, MB_SERIAL_TASK_PRIO,
                                                    &xMBMCtx.xMbTaskHandle, MB_PORT_TASK_AFFINITY);
    if (xStatus != pdPASS) {
        vTaskDelete(xMBMCtx.xMbTaskHandle);
        // Force exit from function with failure
        MB_PORT_CHECK(FALSE, FALSE,
                "mb stack serial task creation error. xTaskCreate() returned (0x%x).",
                xStatus);
    } else {
        vTaskSuspend(xMBMCtx.xMbTaskHandle); // Suspend serial task while stack is not started
    }
    ESP_LOGD(MB_PORT_TAG,"%s Init serial.", __func__);
    return TRUE;
}

void vMBMasterPortSerialClose(void)
{
    vMBMasterPortRxSemaClose();
    (void)vTaskDelete(xMBMCtx.xMbTaskHandle);
    ESP_ERROR_CHECK(uart_driver_delete(xMBMCtx.ucUartNumber));
}

BOOL xMBMasterPortSerialPutByte(CHAR ucByte)
{
    // Send one byte to UART transmission buffer
    // This function is called by Modbus stack
    UCHAR ucLength = uart_write_bytes(xMBMCtx.ucUartNumber, &ucByte, 1);
    return (ucLength == 1);
}

// Get one byte from intermediate RX buffer
BOOL xMBMasterPortSerialGetByte(CHAR* pucByte)
{
    assert(pucByte != NULL);
    USHORT usLength = uart_read_bytes(xMBMCtx.ucUartNumber, (uint8_t*)pucByte, 1, MB_SERIAL_RX_TOUT_TICKS);
    return (usLength == 1);
}
