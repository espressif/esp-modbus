set(srcs "test_config_parser.c")

idf_component_register(SRCS ${srcs}
                        PRIV_INCLUDE_DIRS "."
                        PRIV_REQUIRES test_common test_utils unity)
