/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include "ascii_lrc.h"

/* ----------------------- functions ---------------------------------*/
uint8_t mb_char2bin(uint8_t char_val)
{
    if ((char_val >= '0') && (char_val <= '9')) {
        return (uint8_t)(char_val - '0');
    } else if ((char_val >= 'A') && (char_val <= 'F')) {
        return (uint8_t)(char_val - 'A' + 0x0A);
    } else {
        return 0xFF;
    }
}

uint8_t mb_bin2char(uint8_t byte_val)
{
    if (byte_val <= 0x09) {
        return (uint8_t)('0' + byte_val);
    } else if ((byte_val >= 0x0A) && (byte_val <= 0x0F)) {
        return (uint8_t)(byte_val - 0x0A + 'A');
    } else {
        /* Programming error. */
        assert(0);
    }
    return '0';
}

uint8_t __attribute__ ((unused)) mb_lrc(uint8_t *pframe, uint16_t length)
{
    uint8_t lrc = 0; /* LRC char initialized */

    while (length--) {
        lrc += *pframe++; /* Add buffer byte without carry */
    }

    /* Return twos complement */
    lrc = (uint8_t)(-((char)lrc));
    return lrc;
}

// The helper function to fill ASCII frame buffer
int mb_ascii_set_buf(const uint8_t *pdata, uint8_t *pbuf, int bin_length)
{
    int bin_idx = 0;
    int frm_idx = 0;
    uint8_t lrc = 0;

    assert(pdata && pbuf);

    pbuf[0] = MB_ASCII_START;
    for (frm_idx = 1; (bin_idx < bin_length); bin_idx++) {
        pbuf[frm_idx++] = mb_bin2char((uint8_t)(pdata[bin_idx] >> 4));   // High nibble
        pbuf[frm_idx++] = mb_bin2char((uint8_t)(pdata[bin_idx] & 0X0F)); // Low nibble
        lrc += pdata[bin_idx];
    }
    lrc = (uint8_t)(-((char)lrc));
    pbuf[frm_idx++] = mb_bin2char((uint8_t)(lrc >> 4));
    pbuf[frm_idx++] = mb_bin2char((uint8_t)(lrc & 0X0F));
    pbuf[frm_idx++] = MB_ASCII_CR;
    pbuf[frm_idx++] = MB_ASCII_LF;

    return frm_idx;
}

int mb_ascii_get_binary_buf(uint8_t *pdata, int length)
{
    int bin_idx = 0;
    uint8_t lrc = 0;

    assert(pdata);

    if ((pdata[0] == ':') && (pdata[length - 1] == '\n') && (pdata[length - 2] == '\r')) {
        for (int str_idx = 1; (str_idx < length) && (pdata[str_idx] > ' '); str_idx += 2) {
            pdata[bin_idx] = (mb_char2bin(pdata[str_idx]) << 4); // High nibble
            pdata[bin_idx] |= mb_char2bin(pdata[str_idx + 1]);   // Low nibble
            lrc += pdata[bin_idx++];
        }
    }
    
    lrc = (uint8_t)(-((char)lrc));
    bin_idx = ((lrc == 0) && (bin_idx == ((length - 3) >> 1))) ? bin_idx : -1;
    return bin_idx;
}

