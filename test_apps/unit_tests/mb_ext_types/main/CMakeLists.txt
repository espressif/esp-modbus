set(srcs "test_mb_endianness_utils.c")

idf_component_register(SRCS ${srcs}
                        PRIV_INCLUDE_DIRS "."
                        PRIV_REQUIRES esp-modbus test_utils unity)


