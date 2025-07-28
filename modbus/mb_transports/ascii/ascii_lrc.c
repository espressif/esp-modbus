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
    uint8_t symb = 0xFF;
    if ((char_val >= '0') && (char_val <= '9')) {
        symb = (uint8_t)(char_val - '0');
    } else if ((char_val >= 'A') && (char_val <= 'F')) {
        symb = (uint8_t)(char_val - 'A' + 0x0A);
    }
    return symb;
}

uint8_t mb_bin2char(uint8_t byte_val)
{
    uint8_t symb = '0';
    if (byte_val <= 0x09) {
        symb = (uint8_t)('0' + byte_val);
    } else if ((byte_val >= 0x0A) && (byte_val <= 0x0F)) {
        symb = (uint8_t)(byte_val - 0x0A + 'A');
    } else {
        /* Programming error. */
        assert(0);
    }
    return symb;
}

uint8_t __attribute__ ((unused)) mb_lrc(uint8_t *frame, uint16_t length)
{
    uint8_t lrc = 0; /* LRC char initialized */

    while (length--) {
        lrc += *frame++; /* Add buffer byte without carry */
    }

    /* Return twos complement */
    lrc = (uint8_t)(-((char)lrc));
    return lrc;
}

// The helper function to fill ASCII frame buffer
int mb_ascii_set_buf(const uint8_t *data_ptr, uint8_t *buf, int bin_length)
{
    int bin_idx = 0;
    int frm_idx = 0;
    uint8_t lrc = 0;

    assert(data_ptr && buf);

    buf[0] = MB_ASCII_START;
    for (frm_idx = 1; (bin_idx < bin_length); bin_idx++) {
        buf[frm_idx++] = mb_bin2char((uint8_t)(data_ptr[bin_idx] >> 4));   // High nibble
        buf[frm_idx++] = mb_bin2char((uint8_t)(data_ptr[bin_idx] & 0X0F)); // Low nibble
        lrc += data_ptr[bin_idx];
    }
    lrc = (uint8_t)(-((char)lrc));
    buf[frm_idx++] = mb_bin2char((uint8_t)(lrc >> 4));
    buf[frm_idx++] = mb_bin2char((uint8_t)(lrc & 0X0F));
    buf[frm_idx++] = MB_ASCII_CR;
    buf[frm_idx++] = MB_ASCII_LF;

    return frm_idx;
}

int mb_ascii_get_binary_buf(uint8_t *data_ptr, int length)
{
    int bin_idx = 0;
    uint8_t lrc = 0;

    assert(data_ptr);

    if ((data_ptr[0] == ':') && (data_ptr[length - 1] == '\n') && (data_ptr[length - 2] == '\r')) {
        for (int str_idx = 1; (str_idx < length) && (data_ptr[str_idx] > ' '); str_idx += 2) {
            data_ptr[bin_idx] = (mb_char2bin(data_ptr[str_idx]) << 4); // High nibble
            data_ptr[bin_idx] |= mb_char2bin(data_ptr[str_idx + 1]);   // Low nibble
            lrc += data_ptr[bin_idx++];
        }
    }
    
    lrc = (uint8_t)(-((char)lrc));
    bin_idx = ((lrc == 0) && (bin_idx == ((length - 3) >> 1))) ? bin_idx : -1;
    return bin_idx;
}

