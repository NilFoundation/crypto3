//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE poseidon_test

#include<boost/predef/architecture/x86/64.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

// This test data was taken from https://github.com/o1-labs/proof-systems/blob/a36c088b3e81d17f5720abfff82a49cf9cb1ad5b/poseidon/src/tests/test_vectors/kimchi.json.
// For some reason bytes in their test data are in Big Endian, while we need in Small Endian, I.E. you need to reverse the order of bytes to create our test data.
// We have NO TESTS for Vesta Field so far, since Mina code doesn't have tests and test vectors for it either.

template<typename field_type>
void test_poseidon(std::vector<typename field_type::value_type> input, 
                    typename field_type::value_type expected_result) {
    using poseidon_policy = hashes::detail::mina_poseidon_policy<field_type>;
    using sponge_construction_type = hashes::detail::poseidon_sponge_construction<poseidon_policy>;

    sponge_construction_type pallas_sponge;
    
    pallas_sponge.absorb(input);
    typename field_type::value_type res = pallas_sponge.squeeze();

    BOOST_CHECK_EQUAL(res, expected_result);
}

BOOST_AUTO_TEST_SUITE(poseidon_manual_tests)

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_0) {
    test_poseidon<fields::pallas_base_field>(
        {}, 0x2FADBE2852044D028597455BC2ABBD1BC873AF205DFABB8A304600F3E09EEBA8_cppui256);
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_1) {
    test_poseidon<fields::pallas_base_field>(
        {0x36FB00AD544E073B92B4E700D9C49DE6FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui256},
        0x3D4F050775295C04619E72176746AD1290D391D73FF4955933F9075CF69259FB_cppui256
    );
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_2) {
    test_poseidon<fields::pallas_base_field>(
        {0x3793E30AC691700012BAF26BB813D6D70BD379BEED8050A1DEEE3C188F1C3FBD_cppui256,
         0x2FC4C98E50E0B1AAE6ECB468E28C0B7D80A7E0EEC7136DB0BA0677B84AF0E465_cppui256},
        0x336C73D08AD408CEB7D1264867096F0817A1D0558B313312A1207602F23624FE_cppui256
    );
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_3) {
    test_poseidon<fields::pallas_base_field>(
        {0x0024FB5773CAC987CF3A17DDD6134BA12D3E1CA4F6C43D3695347747CE61EAF5_cppui256,
        0x18E0ED2B46ED1EC258DF721A1D3145B0AA6ABDD02EE851A14B8B659CF47385F2_cppui256,
        0x1A842A688E600F012637FE181292F70C4347B5AE0D9EA9CE7CF18592C345CF73_cppui256},
        0x3F4B0EABB64E025F920457AF8D090A9F6472CAE11F3D62A749AF544A44941B9B_cppui256);
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_4) {
    test_poseidon<fields::pallas_base_field>(
        {0x2059462D60621F70620EA697FA1382EC5553A3DADB3CF9072201E09871B8284C_cppui256,
         0x2747337D1C4F9894747074C771E8EC7F570640E5D0CAF30FDDC446C00FA48707_cppui256,
         0x2DD5047C3EEEF37930E8FA4AD9691B27CF86D3ED39D4DEC4FC6D4E8EE4FF0415_cppui256,
         0x12C387C69BDD436F65AB607A4ED7C62714872EDBF800518B58E76F5106650B29_cppui256},
        0x165A8CECF6660C6E0054CB9B4DBA9D68047166D7F3CED2F8DC86ED2EBFD3EC47_cppui256);
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_5) {
    test_poseidon<fields::pallas_base_field>(
        {0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui256,
         0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui256,
         0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui256,
         0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui256,
         0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui256},
        0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui256);
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_6) {
    using field_type = fields::pallas_base_field;
    using poseidon_policy = hashes::detail::mina_poseidon_policy<field_type>;
    using sponge_construction_type = hashes::detail::poseidon_sponge_construction<poseidon_policy>;

    std::vector<field_type::value_type> input = {
        0x1A3FBD7D8C00BD0C3D4BC1DD41BF7FAA5903518DA636955D98712F9AC6D6DDFA_cppui256,
        0x1AA195509819DF535E832D7D8AF809B385EF96A85A5A2DCE0DB7F9D72954F829_cppui256};
    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words> expected_state = {
        0x1A3FBD7D8C00BD0C3D4BC1DD41BF7FAA5903518DA636955D98712F9AC6D6DDFA_cppui256,
        0x1AA195509819DF535E832D7D8AF809B385EF96A85A5A2DCE0DB7F9D72954F829_cppui256,
        0
    };
    sponge_construction_type pallas_sponge;
    
    pallas_sponge.absorb(input);

    BOOST_CHECK(pallas_sponge.state == expected_state);
}

BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_7) {
    using field_type = fields::pallas_base_field;
    using poseidon_policy = hashes::detail::mina_poseidon_policy<field_type>;
    using sponge_construction_type = hashes::detail::poseidon_sponge_construction<poseidon_policy>;

    std::vector<field_type::value_type> input = {
        0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui256,
        0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui256,
        0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui256,
        0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui256,
        0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui256};

    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words>  expected_state_absorb = {
        0x2437F72484D8C5483D75F898376BC3EE29EDF2F7EF5305A3C61B937654954000_cppui256,
        0x16F954CD8F2B73D797170C5124F31A65160A3FCA92B77709E564075C2405BF80_cppui256,
        0x3696E4E8F08273FFEFDAD72C5002D103E9B8976F6579A010D6CC2A75B276851F_cppui256};
    sponge_construction_type pallas_sponge;
    
    pallas_sponge.absorb(input);

    BOOST_CHECK(pallas_sponge.state == expected_state_absorb);

    typename poseidon_policy::element_type expected_challenge = 
        0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui256;
    typename poseidon_policy::element_type challenge = pallas_sponge.squeeze();

    BOOST_CHECK(challenge == expected_challenge);
}

BOOST_AUTO_TEST_SUITE_END()
