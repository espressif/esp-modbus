/*
 * SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <stdlib.h>
#include <stdbool.h>
#include "unity.h"
#include "test_utils.h"

#include "sdkconfig.h"
#include "mb_endianness_utils.h"

#define TAG "MB_ENDIANNESS_TEST"

// The below is the data used for endianness conversion test

const uint16_t TEST_INT8_A = 0x00F6;
const uint16_t TEST_INT8_B = 0xF600;

const uint16_t TEST_UINT8_A = 0x0037;
const uint16_t TEST_UINT8_B = 0x3700;

const uint16_t TEST_UINT16_AB = 0x3039;
const uint16_t TEST_UINT16_BA = 0x3930;
const uint16_t TEST_INT16_AB = 0x3039;
const uint16_t TEST_INT16_BA = 0x3930;

const uint32_t TEST_FLOAT_ABCD = 0x4640e400;
const uint32_t TEST_FLOAT_DCBA = 0x00e44046;
const uint32_t TEST_FLOAT_BADC = 0x404600e4;
const uint32_t TEST_FLOAT_CDAB = 0xe4004640;

const uint32_t TEST_UINT32_ABCD = 0x11223344;
const uint32_t TEST_UINT32_DCBA = 0x44332211;
const uint32_t TEST_UINT32_BADC = 0x22114433;
const uint32_t TEST_UINT32_CDAB = 0x33441122;

const uint64_t TEST_DOUBLE_ABCDEFGH = 0x40c81c8000000000;
const uint64_t TEST_DOUBLE_HGFEDCBA = 0x00000000801cc840;
const uint64_t TEST_DOUBLE_GHEFCDAB = 0x000000001c8040c8;
const uint64_t TEST_DOUBLE_BADCFEHG = 0xc840801c00000000;

const uint64_t TEST_INT64_ABCDEFGH = 0xffffffffffffcfc7;
const uint64_t TEST_INT64_HGFEDCBA = 0xc7cfffffffffffff;
const uint64_t TEST_INT64_GHEFCDAB = 0xcfc7ffffffffffff;
const uint64_t TEST_INT64_BADCFEHG = 0xffffffffffffc7cf;

const uint64_t TEST_UINT64_ABCDEFGH = 0x1122334455667788;
const uint64_t TEST_UINT64_HGFEDCBA = 0x8877665544332211;
const uint64_t TEST_UINT64_GHEFCDAB = 0x7788556633441122;
const uint64_t TEST_UINT64_BADCFEHG = 0x2211443366558877;

TEST_CASE("Test endianness conversion for all extended Modbus types.", "[MB_ENDIANNESS]")
{
    val_16_arr arr_16 = {0};
    val_32_arr arr_32 = {0};
    val_64_arr arr_64 = {0};

    TEST_ASSERT(mb_set_uint8_a(&arr_16, (uint8_t)55) == TEST_UINT8_A);
    TEST_ASSERT(mb_get_uint8_a(&arr_16) == (uint8_t)55);
    TEST_ASSERT(mb_set_int8_a(&arr_16, (int8_t)-10) == TEST_INT8_A);
    TEST_ASSERT(mb_get_int8_a(&arr_16) == (int8_t)-10);

    TEST_ASSERT(mb_set_uint8_b(&arr_16, (uint8_t)55) == TEST_UINT8_B);
    TEST_ASSERT(mb_get_uint8_b(&arr_16) == (uint8_t)55);
    TEST_ASSERT(mb_set_int8_b(&arr_16, (int8_t)-10) == TEST_INT8_B);
    TEST_ASSERT(mb_get_int8_b(&arr_16) == (int8_t)-10);

    TEST_ASSERT(mb_set_uint16_ab(&arr_16, (uint16_t)12345) == TEST_UINT16_AB);
    TEST_ASSERT(mb_get_uint16_ab(&arr_16) == (uint16_t)12345);
    TEST_ASSERT(mb_set_int16_ab(&arr_16, (int16_t)12345) == TEST_INT16_AB);
    TEST_ASSERT(mb_get_int16_ab(&arr_16) == (int16_t)12345);

    TEST_ASSERT(mb_set_uint16_ba(&arr_16, (uint16_t)12345) == TEST_UINT16_BA);
    TEST_ASSERT(mb_get_uint16_ba(&arr_16) == (uint16_t)12345);
    TEST_ASSERT(mb_set_int16_ba(&arr_16, (int16_t)12345) == TEST_INT16_BA);
    TEST_ASSERT(mb_get_int16_ba(&arr_16) == (int16_t)12345);

    TEST_ASSERT(mb_set_uint16_ab(&arr_16, (uint16_t)12345) == TEST_UINT16_AB);
    TEST_ASSERT(mb_get_uint16_ab(&arr_16) == (uint16_t)12345);
    TEST_ASSERT(mb_set_int16_ab(&arr_16, (int16_t)12345) == TEST_INT16_AB);
    TEST_ASSERT(mb_get_int16_ab(&arr_16) == (int16_t)12345);

    TEST_ASSERT(mb_set_float_abcd(&arr_32, (float)12345.0) == TEST_FLOAT_ABCD);
    TEST_ASSERT(mb_get_float_abcd(&arr_32) == (float)12345.0);

    TEST_ASSERT(mb_set_float_badc(&arr_32, (float)12345.0) == TEST_FLOAT_BADC);
    TEST_ASSERT(mb_get_float_badc(&arr_32) == (float)12345.0);

    TEST_ASSERT(mb_set_float_cdab(&arr_32, (float)12345.0) == TEST_FLOAT_CDAB);
    TEST_ASSERT(mb_get_float_cdab(&arr_32) == (float)12345.0);

    TEST_ASSERT(mb_set_float_dcba(&arr_32, (float)12345.0) == TEST_FLOAT_DCBA);
    TEST_ASSERT(mb_get_float_dcba(&arr_32) == (float)12345.0);

    TEST_ASSERT(mb_set_uint32_abcd(&arr_32, (uint32_t)0x11223344) == TEST_UINT32_ABCD);
    TEST_ASSERT(mb_get_uint32_abcd(&arr_32) == (uint32_t)0x11223344);
    TEST_ASSERT(mb_set_int32_abcd(&arr_32, (int32_t)0x11223344) == TEST_UINT32_ABCD);
    TEST_ASSERT(mb_get_int32_abcd(&arr_32) == (int32_t)0x11223344);

    TEST_ASSERT(mb_set_uint32_badc(&arr_32, (uint32_t)0x11223344) == TEST_UINT32_BADC);
    TEST_ASSERT(mb_get_uint32_badc(&arr_32) == (uint32_t)0x11223344);
    TEST_ASSERT(mb_set_int32_badc(&arr_32, (int32_t)0x11223344) == TEST_UINT32_BADC);
    TEST_ASSERT(mb_get_int32_badc(&arr_32) == (int32_t)0x11223344);

    TEST_ASSERT(mb_set_uint32_cdab(&arr_32, (uint32_t)0x11223344) == TEST_UINT32_CDAB);
    TEST_ASSERT(mb_get_uint32_cdab(&arr_32) == (uint32_t)0x11223344);
    TEST_ASSERT(mb_set_int32_cdab(&arr_32, (int32_t)0x11223344) == TEST_UINT32_CDAB);
    TEST_ASSERT(mb_get_int32_cdab(&arr_32) == (int32_t)0x11223344);

    TEST_ASSERT(mb_set_uint32_dcba(&arr_32, (uint32_t)0x11223344) == TEST_UINT32_DCBA);
    TEST_ASSERT(mb_get_uint32_dcba(&arr_32) == (uint32_t)0x11223344);
    TEST_ASSERT(mb_set_int32_dcba(&arr_32, (int32_t)0x11223344) == TEST_UINT32_DCBA);
    TEST_ASSERT(mb_get_int32_dcba(&arr_32) == (int32_t)0x11223344);
    
    TEST_ASSERT(mb_set_double_abcdefgh(&arr_64, (double)12345.0) == TEST_DOUBLE_ABCDEFGH);
    TEST_ASSERT(mb_get_double_abcdefgh(&arr_64) == (double)12345.0);
    TEST_ASSERT(mb_set_uint64_abcdefgh(&arr_64, (uint64_t)0x1122334455667788) == TEST_UINT64_ABCDEFGH);
    TEST_ASSERT(mb_get_uint64_abcdefgh(&arr_64) == (uint64_t)0x1122334455667788);
    TEST_ASSERT(mb_set_int64_abcdefgh(&arr_64, (int64_t)-12345) == TEST_INT64_ABCDEFGH);
    TEST_ASSERT(mb_get_int64_abcdefgh(&arr_64) == (int64_t)-12345);

    TEST_ASSERT(mb_set_double_hgfedcba(&arr_64, (double)12345.0) == TEST_DOUBLE_HGFEDCBA);
    TEST_ASSERT(mb_get_double_hgfedcba(&arr_64) == (double)12345.0);
    TEST_ASSERT(mb_set_uint64_hgfedcba(&arr_64, (uint64_t)0x1122334455667788) == TEST_UINT64_HGFEDCBA);
    TEST_ASSERT(mb_get_uint64_hgfedcba(&arr_64) == (uint64_t)0x1122334455667788);
    TEST_ASSERT(mb_set_int64_hgfedcba(&arr_64, (int64_t)-12345) == TEST_INT64_HGFEDCBA);
    TEST_ASSERT(mb_get_int64_hgfedcba(&arr_64) == (int64_t)-12345);

    TEST_ASSERT(mb_set_double_ghefcdab(&arr_64, (double)12345.0) == TEST_DOUBLE_GHEFCDAB);
    TEST_ASSERT(mb_get_double_ghefcdab(&arr_64) == (double)12345.0);
    TEST_ASSERT(mb_set_uint64_ghefcdab(&arr_64, (uint64_t)0x1122334455667788) == TEST_UINT64_GHEFCDAB);
    TEST_ASSERT(mb_get_uint64_ghefcdab(&arr_64) == (uint64_t)0x1122334455667788);
    TEST_ASSERT(mb_set_int64_ghefcdab(&arr_64, (int64_t)-12345) == TEST_INT64_GHEFCDAB);
    TEST_ASSERT(mb_get_int64_ghefcdab(&arr_64) == (int64_t)-12345);

    TEST_ASSERT(mb_set_double_badcfehg(&arr_64, (double)12345.0) == TEST_DOUBLE_BADCFEHG);
    TEST_ASSERT(mb_get_double_badcfehg(&arr_64) == (double)12345.0);
    TEST_ASSERT(mb_set_uint64_badcfehg(&arr_64, (uint64_t)0x1122334455667788) == TEST_UINT64_BADCFEHG);
    TEST_ASSERT(mb_get_uint64_badcfehg(&arr_64) == (uint64_t)0x1122334455667788);
    TEST_ASSERT(mb_set_int64_badcfehg(&arr_64, (int64_t)-12345) == TEST_INT64_BADCFEHG);
    TEST_ASSERT(mb_get_int64_badcfehg(&arr_64) == (int64_t)-12345);
}

void app_main(void)
{
    unity_run_menu();
}
