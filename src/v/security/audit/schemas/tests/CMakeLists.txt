rp_test(
    UNIT_TEST
    BINARY_NAME security_audit_schemas_unit
    SOURCES
      audit_schemas.cc
    DEFINITIONS BOOST_TEST_DYN_LINK
    LIBRARIES v::seastar_testing_main v::json
    LABELS audit
)
