/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define MB_ASCII_CR         '\r'                          /*!< Default CR character for Modbus ASCII. */
#define MB_ASCII_LF         '\n'                          /*!< Default LF character for Modbus ASCII. */
#define MB_ASCII_START       ':'                          /*!< Start of frame for Modbus ASCII. */

/* ----------------------- Static functions ---------------------------------*/
uint8_t mb_char2bin(uint8_t char_val);
uint8_t mb_bin2char(uint8_t byte_val);
uint8_t mb_lrc(uint8_t *frame, uint16_t length);
int mb_ascii_get_binary_buf(uint8_t *data_ptr, int length);
int mb_ascii_set_buf(const uint8_t *data_ptr, uint8_t *buf, int bin_length);