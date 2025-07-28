/*
 * SPDX-FileCopyrightText: 2016-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdbool.h>

#include "mb_endianness_utils.h"

#define INLINE inline __attribute__((always_inline))

static INLINE int16_t mb_get_int16_generic(int n0, int n1, val_16_arr *src_ptr)
{
    val_16_arr *pv = src_ptr;
    union {
        val_16_arr arr;
        int16_t value;
    } bov;
    bov.arr[n0] = (*pv)[MB_BO16_0];
    bov.arr[n1] = (*pv)[MB_BO16_1];
    return (bov.value);
}

static INLINE uint16_t mb_get_uint16_generic(int n0, int n1, val_16_arr *src_ptr)
{
    val_16_arr *pv = src_ptr;
    union {
        val_16_arr arr;
        uint16_t value;
    } bov;
    bov.arr[n0] = (*pv)[MB_BO16_0];
    bov.arr[n1] = (*pv)[MB_BO16_1];
    return (bov.value);
}

static INLINE uint16_t mb_set_uint16_generic(int n0, int n1, val_16_arr *dest_ptr, uint16_t val)
{
    val_16_arr *pv = dest_ptr;
    union {
        val_16_arr arr;
        uint16_t value;
    } bov;
    bov.value = val;
    (*pv)[MB_BO16_0] = bov.arr[n0];
    (*pv)[MB_BO16_1] = bov.arr[n1];
    return (*((uint16_t *)pv));
}

static INLINE int16_t mb_set_int16_generic(int n0, int n1, val_16_arr *dest_ptr, int16_t val)
{
    val_16_arr *pv = dest_ptr;
    union {
        val_16_arr arr;
        int16_t value;
    } bov;
    bov.value = val;
    (*pv)[MB_BO16_0] = bov.arr[n0];
    (*pv)[MB_BO16_1] = bov.arr[n1];
    return (*((uint16_t *)pv));
}

static INLINE uint32_t mb_get_uint32_generic(int n0, int n1, int n2, int n3, val_32_arr *src_ptr)
{
    val_32_arr *pv = src_ptr;
    union {
        val_32_arr arr;
        uint32_t value;
    } bov;
    bov.arr[n0] = (*pv)[MB_BO32_0];
    bov.arr[n1] = (*pv)[MB_BO32_1];
    bov.arr[n2] = (*pv)[MB_BO32_2];
    bov.arr[n3] = (*pv)[MB_BO32_3];
    return (bov.value);
}

static INLINE int32_t mb_get_int32_generic(int n0, int n1, int n2, int n3, val_32_arr *src_ptr)
{
    val_32_arr *pv = src_ptr;
    union {
        val_32_arr arr;
        int32_t value;
    } bov;
    bov.arr[n0] = (*pv)[MB_BO32_0];
    bov.arr[n1] = (*pv)[MB_BO32_1];
    bov.arr[n2] = (*pv)[MB_BO32_2];
    bov.arr[n3] = (*pv)[MB_BO32_3];
    return (bov.value);
}

static INLINE float mb_get_float_generic(int n0, int n1, int n2, int n3, val_32_arr *src_ptr)
{
    val_32_arr *pv = src_ptr;
    union {
        val_32_arr arr;
        float value;
    } bov;
    bov.arr[n0] = (*pv)[MB_BO32_0];
    bov.arr[n1] = (*pv)[MB_BO32_1];
    bov.arr[n2] = (*pv)[MB_BO32_2];
    bov.arr[n3] = (*pv)[MB_BO32_3];
    return (bov.value);
}

static INLINE uint32_t mb_set_int32_generic(int n0, int n1, int n2, int n3, val_32_arr *dest_ptr, int32_t val)
{
    val_32_arr *pv = dest_ptr;
    union {
        val_32_arr arr;
        int32_t value;
    } bov;
    bov.value = val;
    (*pv)[MB_BO32_0] = bov.arr[n0];
    (*pv)[MB_BO32_1] = bov.arr[n1];
    (*pv)[MB_BO32_2] = bov.arr[n2];
    (*pv)[MB_BO32_3] = bov.arr[n3];
    return (*((uint32_t *)pv));
}

static INLINE uint32_t mb_set_uint32_generic(int n0, int n1, int n2, int n3, val_32_arr *dest_ptr, uint32_t val)
{
    val_32_arr *pv = dest_ptr;
    union {
        val_32_arr arr;
        uint32_t value;
    } bov;
    bov.value = val;
    (*pv)[MB_BO32_0] = bov.arr[n0];
    (*pv)[MB_BO32_1] = bov.arr[n1];
    (*pv)[MB_BO32_2] = bov.arr[n2];
    (*pv)[MB_BO32_3] = bov.arr[n3];
    return (*((uint32_t *)pv));
}

static INLINE uint32_t mb_set_float_generic(int n0, int n1, int n2, int n3, val_32_arr *dest_ptr, float val)
{
    val_32_arr *pv = dest_ptr;
    union {
        val_32_arr arr;
        float value;
    } bov;
    bov.value = val;
    (*pv)[MB_BO32_0] = bov.arr[n0];
    (*pv)[MB_BO32_1] = bov.arr[n1];
    (*pv)[MB_BO32_2] = bov.arr[n2];
    (*pv)[MB_BO32_3] = bov.arr[n3];
    return (*((uint32_t *)pv));
}

static INLINE int64_t mb_get_int64_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *src_ptr)
{
    val_64_arr *pv64 = src_ptr;
    union {
        val_64_arr arr;
        int64_t value;
    } bo64;
    bo64.arr[n0] = (*pv64)[MB_BO64_0];
    bo64.arr[n1] = (*pv64)[MB_BO64_1];
    bo64.arr[n2] = (*pv64)[MB_BO64_2];
    bo64.arr[n3] = (*pv64)[MB_BO64_3];
    bo64.arr[n4] = (*pv64)[MB_BO64_4];
    bo64.arr[n5] = (*pv64)[MB_BO64_5];
    bo64.arr[n6] = (*pv64)[MB_BO64_6];
    bo64.arr[n7] = (*pv64)[MB_BO64_7];
    return (bo64.value);
}

static INLINE uint64_t mb_get_uint64_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *src_ptr)
{
    val_64_arr *pv64 = src_ptr;
    union {
        val_64_arr arr;
        uint64_t value;
    } bo64;
    bo64.arr[n0] = (*pv64)[MB_BO64_0];
    bo64.arr[n1] = (*pv64)[MB_BO64_1];
    bo64.arr[n2] = (*pv64)[MB_BO64_2];
    bo64.arr[n3] = (*pv64)[MB_BO64_3];
    bo64.arr[n4] = (*pv64)[MB_BO64_4];
    bo64.arr[n5] = (*pv64)[MB_BO64_5];
    bo64.arr[n6] = (*pv64)[MB_BO64_6];
    bo64.arr[n7] = (*pv64)[MB_BO64_7];
    return (bo64.value);
}

static INLINE double mb_get_double_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *src_ptr)
{
    val_64_arr *pv64 = src_ptr;
    union {
        val_64_arr arr;
        double value;
    } bo64;
    bo64.arr[n0] = (*pv64)[MB_BO64_0];
    bo64.arr[n1] = (*pv64)[MB_BO64_1];
    bo64.arr[n2] = (*pv64)[MB_BO64_2];
    bo64.arr[n3] = (*pv64)[MB_BO64_3];
    bo64.arr[n4] = (*pv64)[MB_BO64_4];
    bo64.arr[n5] = (*pv64)[MB_BO64_5];
    bo64.arr[n6] = (*pv64)[MB_BO64_6];
    bo64.arr[n7] = (*pv64)[MB_BO64_7];
    return (bo64.value);
}

static INLINE uint64_t mb_set_int64_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *dest_ptr, int64_t val)
{
    val_64_arr *pv = dest_ptr;
    union {
        val_64_arr arr;
        int64_t value;
    } bo64;
    bo64.value = val;
    (*pv)[MB_BO64_0] = bo64.arr[n0];
    (*pv)[MB_BO64_1] = bo64.arr[n1];
    (*pv)[MB_BO64_2] = bo64.arr[n2];
    (*pv)[MB_BO64_3] = bo64.arr[n3];
    (*pv)[MB_BO64_4] = bo64.arr[n4];
    (*pv)[MB_BO64_5] = bo64.arr[n5];
    (*pv)[MB_BO64_6] = bo64.arr[n6];
    (*pv)[MB_BO64_7] = bo64.arr[n7];
    return (*((uint64_t *)pv));
}

static INLINE uint64_t mb_set_uint64_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *dest_ptr, uint64_t val)
{
    val_64_arr *pv = dest_ptr;
    union {
        val_64_arr arr;
        uint64_t value;
    } bo64;
    bo64.value = val;
    (*pv)[MB_BO64_0] = bo64.arr[n0];
    (*pv)[MB_BO64_1] = bo64.arr[n1];
    (*pv)[MB_BO64_2] = bo64.arr[n2];
    (*pv)[MB_BO64_3] = bo64.arr[n3];
    (*pv)[MB_BO64_4] = bo64.arr[n4];
    (*pv)[MB_BO64_5] = bo64.arr[n5];
    (*pv)[MB_BO64_6] = bo64.arr[n6];
    (*pv)[MB_BO64_7] = bo64.arr[n7];
    return (*((uint64_t *)pv));
}

static INLINE uint64_t mb_set_double_generic(int n0, int n1, int n2, int n3, int n4, int n5, int n6, int n7, val_64_arr *dest_ptr, double val)
{
    val_64_arr *pv = dest_ptr;
    union {
        val_64_arr arr;
        double value;
    } bo64;
    bo64.value = val;
    (*pv)[MB_BO64_0] = bo64.arr[n0];
    (*pv)[MB_BO64_1] = bo64.arr[n1];
    (*pv)[MB_BO64_2] = bo64.arr[n2];
    (*pv)[MB_BO64_3] = bo64.arr[n3];
    (*pv)[MB_BO64_4] = bo64.arr[n4];
    (*pv)[MB_BO64_5] = bo64.arr[n5];
    (*pv)[MB_BO64_6] = bo64.arr[n6];
    (*pv)[MB_BO64_7] = bo64.arr[n7];
    return (*((uint64_t *)pv));
}

int8_t mb_get_int8_a(val_16_arr *pi16)
{
    return((int8_t)(*pi16)[MB_BO16_0]);
}

uint16_t mb_set_int8_a(val_16_arr *pi16, int8_t i8)
{
    (*pi16)[MB_BO16_0] = (char)i8;
    (*pi16)[MB_BO16_1] = 0;
    return (*((uint16_t *)pi16));
}

int8_t mb_get_int8_b(val_16_arr *pi16)
{
    return((int8_t)(*pi16)[MB_BO16_1]);
}

uint16_t mb_set_int8_b(val_16_arr *pi16, int8_t i8)
{
    (*pi16)[MB_BO16_0] = 0;
    (*pi16)[MB_BO16_1] = (char)i8;
    return (*((uint16_t *)pi16));
}

uint8_t mb_get_uint8_a(val_16_arr *pu16)
{
    return((*pu16)[MB_BO16_0]);
}

uint16_t mb_set_uint8_a(val_16_arr *pu16, uint8_t u8)
{
    (*pu16)[MB_BO16_0] = (char)u8;
    (*pu16)[MB_BO16_1] = 0;
    return (*((uint16_t *)pu16));
}

uint8_t mb_get_uint8_b(val_16_arr *pu16)
{
    return((*pu16)[MB_BO16_1]);
}

uint16_t mb_set_uint8_b(val_16_arr *pu16, uint8_t u8)
{
    (*pu16)[MB_BO16_0] = 0;
    (*pu16)[MB_BO16_1] = (char)u8;
    return (*((uint16_t *)pu16));
}

int16_t mb_get_int16_ab(val_16_arr *pi16)
{
    return mb_get_int16_generic(0, 1, pi16);
}

uint16_t mb_set_int16_ab(val_16_arr *pi16, int16_t i16)
{
    return mb_set_int16_generic(0, 1, pi16, i16);
}

uint16_t mb_get_uint16_ab(val_16_arr *pu16)
{
    return mb_get_uint16_generic(0, 1, pu16);
}

uint16_t mb_set_uint16_ab(val_16_arr *pu16, uint16_t u16)
{
    return mb_set_uint16_generic(0, 1, pu16, u16);
}

int16_t mb_get_int16_ba(val_16_arr *pi16)
{
    return mb_get_int16_generic(1, 0, pi16);
}

uint16_t mb_set_int16_ba(val_16_arr *pi16, int16_t i16)
{
    return mb_set_int16_generic(1, 0, pi16, i16);
}

uint16_t mb_get_uint16_ba(val_16_arr *pu16)
{
    return mb_get_int16_generic(1, 0, pu16);
}

uint16_t mb_set_uint16_ba(val_16_arr *pu16, uint16_t u16)
{
    return mb_set_int16_generic(1, 0, pu16, u16);
}

int32_t mb_get_int32_abcd(val_32_arr *pi32)
{
    return mb_get_int32_generic(0, 1, 2, 3, pi32);
}

uint32_t mb_set_int32_abcd(val_32_arr *pi32, int32_t i32)
{
    return mb_set_int32_generic(0, 1, 2, 3, pi32, i32);
}

uint32_t mb_get_uint32_abcd(val_32_arr *pu32)
{
    return mb_get_uint32_generic(0, 1, 2, 3, pu32);
}

uint32_t mb_set_uint32_abcd(val_32_arr *pu32, uint32_t u32)
{
    return mb_set_uint32_generic(0, 1, 2, 3, pu32, u32);
}

int32_t mb_get_int32_badc(val_32_arr *pi32)
{
    return mb_get_int32_generic(1, 0, 3, 2, pi32);
}

uint32_t mb_set_int32_badc(val_32_arr *pi32, int32_t i32)
{
    return mb_set_int32_generic(1, 0, 3, 2, pi32, i32);
}

uint32_t mb_get_uint32_badc(val_32_arr *pu32)
{
    return mb_get_uint32_generic(1, 0, 3, 2, pu32);
}

uint32_t mb_set_uint32_badc(val_32_arr *pu32, uint32_t u32)
{
    return mb_set_uint32_generic(1, 0, 3, 2, pu32, u32);
}

int32_t mb_get_int32_cdab(val_32_arr *pi32)
{
    return mb_get_int32_generic(2, 3, 0, 1, pi32);
}

uint32_t mb_set_int32_cdab(val_32_arr *pi32, int32_t i32)
{
    return mb_set_int32_generic(2, 3, 0, 1, pi32, i32);
}

uint32_t mb_get_uint32_cdab(val_32_arr *pu32)
{
    return mb_get_uint32_generic(2, 3, 0, 1, pu32);
}

uint32_t mb_set_uint32_cdab(val_32_arr *pu32, uint32_t u32)
{
    return mb_set_uint32_generic(2, 3, 0, 1, pu32, u32);
}

int32_t mb_get_int32_dcba(val_32_arr *pi32)
{
    return mb_get_int32_generic(3, 2, 1, 0, pi32);
}

uint32_t mb_set_int32_dcba(val_32_arr *pi32, int32_t i32)
{
    return mb_set_int32_generic(3, 2, 1, 0, pi32, i32);
}

uint32_t mb_get_uint32_dcba(val_32_arr *pu32)
{
    return mb_get_uint32_generic(3, 2, 1, 0, pu32);
}

uint32_t mb_set_uint32_dcba(val_32_arr *pu32, uint32_t u32)
{
    return mb_set_uint32_generic(3, 2, 1, 0, pu32, u32);
}

float mb_get_float_abcd(val_32_arr *pf)
{
    return mb_get_float_generic(0, 1, 2, 3, pf);
}

uint32_t mb_set_float_abcd(val_32_arr *pf, float f)
{
    return mb_set_float_generic(0, 1, 2, 3, pf, f);
}

float mb_get_float_badc(val_32_arr *pf)
{
    return mb_get_float_generic(1, 0, 3, 2, pf);
}

uint32_t mb_set_float_badc(val_32_arr *pf, float f)
{
    return mb_set_float_generic(1, 0, 3, 2, pf, f);
}

float mb_get_float_cdab(val_32_arr *pf)
{
    return mb_get_float_generic(2, 3, 0, 1, pf);
}

uint32_t mb_set_float_cdab(val_32_arr *pf, float f)
{
    return mb_set_float_generic(2, 3, 0, 1, pf, f);
}

float mb_get_float_dcba(val_32_arr *pf)
{
    return mb_get_float_generic(3, 2, 1, 0, pf);
}

uint32_t mb_set_float_dcba(val_32_arr *pf, float f)
{
    return mb_set_float_generic(3, 2, 1, 0, pf, f);
}

double mb_get_double_abcdefgh(val_64_arr *pd)
{
    return mb_get_double_generic(0, 1, 2, 3, 4, 5, 6, 7, pd);
}

uint64_t mb_set_double_abcdefgh(val_64_arr *pd, double d)
{
    return mb_set_double_generic(0, 1, 2, 3, 4, 5, 6, 7, pd, d);
}

double mb_get_double_hgfedcba(val_64_arr *pd)
{
    return mb_get_double_generic(7, 6, 5, 4, 3, 2, 1, 0, pd);
}

uint64_t mb_set_double_hgfedcba(val_64_arr *pd, double d)
{
    return mb_set_double_generic(7, 6, 5, 4, 3, 2, 1, 0, pd, d);
}

double mb_get_double_ghefcdab(val_64_arr *pd)
{
    return mb_get_double_generic(6, 7, 4, 5, 2, 3, 0, 1, pd);
}

uint64_t mb_set_double_ghefcdab(val_64_arr *pd, double d)
{
    return mb_set_double_generic(6, 7, 4, 5, 2, 3, 0, 1, pd, d);
}

double mb_get_double_badcfehg(val_64_arr *pd)
{
    return mb_get_double_generic(1, 0, 3, 2, 5, 4, 7, 6, pd);
}

uint64_t mb_set_double_badcfehg(val_64_arr *pd, double d)
{
    return mb_set_double_generic(1, 0, 3, 2, 5, 4, 7, 6, pd, d);
}

int64_t mb_get_int64_abcdefgh(val_64_arr *pi64)
{
    return mb_get_int64_generic(0, 1, 2, 3, 4, 5, 6, 7, pi64);
}

uint64_t mb_set_int64_abcdefgh(val_64_arr *pi, int64_t i)
{
    return mb_set_int64_generic(0, 1, 2, 3, 4, 5, 6, 7, pi, i);
}

int64_t mb_get_int64_hgfedcba(val_64_arr *pi64)
{
    return mb_get_int64_generic(7, 6, 5, 4, 3, 2, 1, 0, pi64);
}

uint64_t mb_set_int64_hgfedcba(val_64_arr *pi, int64_t i)
{
    return mb_set_int64_generic(7, 6, 5, 4, 3, 2, 1, 0, pi, i);
}

int64_t mb_get_int64_ghefcdab(val_64_arr *pi64)
{
    return mb_get_int64_generic(6, 7, 4, 5, 2, 3, 0, 1, pi64);
}

uint64_t mb_set_int64_ghefcdab(val_64_arr *pi, int64_t i)
{
    return mb_set_int64_generic(6, 7, 4, 5, 2, 3, 0, 1, pi, i);
}

int64_t mb_get_int64_badcfehg(val_64_arr *pi64)
{
    return mb_get_int64_generic(1, 0, 3, 2, 5, 4, 7, 6, pi64);
}

uint64_t mb_set_int64_badcfehg(val_64_arr *pi, int64_t i)
{
    return mb_set_int64_generic(1, 0, 3, 2, 5, 4, 7, 6, pi, i);
}

uint64_t mb_get_uint64_abcdefgh(val_64_arr *pui)
{
    return mb_get_uint64_generic(0, 1, 2, 3, 4, 5, 6, 7, pui);
}

uint64_t mb_set_uint64_abcdefgh(val_64_arr *pui, uint64_t ui)
{
    return mb_set_uint64_generic(0, 1, 2, 3, 4, 5, 6, 7, pui, ui);
}

uint64_t mb_get_uint64_hgfedcba(val_64_arr *pui)
{
    return mb_get_uint64_generic(7, 6, 5, 4, 3, 2, 1, 0, pui);
}

uint64_t mb_set_uint64_hgfedcba(val_64_arr *pui, uint64_t ui)
{
    return mb_set_uint64_generic(7, 6, 5, 4, 3, 2, 1, 0, pui, ui);
}

uint64_t mb_get_uint64_ghefcdab(val_64_arr *pui)
{
    return mb_get_uint64_generic(6, 7, 4, 5, 2, 3, 0, 1, pui);
}

uint64_t mb_set_uint64_ghefcdab(val_64_arr *pui, uint64_t ui)
{
    return mb_set_uint64_generic(6, 7, 4, 5, 2, 3, 0, 1, pui, ui);
}

uint64_t mb_get_uint64_badcfehg(val_64_arr *pui)
{
    return mb_get_int64_generic(1, 0, 3, 2, 5, 4, 7, 6, pui);
}

uint64_t mb_set_uint64_badcfehg(val_64_arr *pui, uint64_t ui)
{
    return mb_set_uint64_generic(1, 0, 3, 2, 5, 4, 7, 6, pui, ui);
}
