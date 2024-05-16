#define BOOST_TEST_MODULE pickles_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>

using namespace nil::crypto3;
                
BOOST_AUTO_TEST_SUITE(pickles_kimchi_to_group_test_suite)

BOOST_AUTO_TEST_CASE(pickles_kimchi_to_field_test_case_1){
    using curve_type = algebra::curves::vesta;
    using field_type = curve_type::base_field_type;

    zk::snark::group_map<curve_type> map;

    field_type::value_type value = field_type::value_type(0x2060BAF54AE1E0CE2BA2AA4B7629A41FE5768E1BAB024882BAC729FF5747F100_cppui_modular256);
    auto result = map.to_group(value);
    BOOST_CHECK(result.X == field_type::value_type(0x344483C5EC8A0B6619CD78B13B20A32E68064ACC43DA911EF5FDD8DF8EB15CA9_cppui_modular256));
    BOOST_CHECK(result.Y == field_type::value_type(0x184C418DCCDD4751FF8F2FA1ADC1E617F8BAC4FDA7C177B42F3863A957B7EAA8_cppui_modular256));

}

BOOST_AUTO_TEST_SUITE_END()