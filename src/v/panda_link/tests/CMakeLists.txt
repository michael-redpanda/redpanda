rp_test(
    UNIT_TEST
    GTEST
    BINARY_NAME write_at_offset_stm_test
    SOURCES
        write_at_offset_stm_test.cc
    LIBRARIES
        v::gtest_main
        v::write_at_offset_stm
    LABELS write_at_offset
    ARGS "-- -c 1"
)