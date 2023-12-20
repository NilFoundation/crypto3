//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE poseidon_test

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
#include <nil/crypto3/hash/detail/poseidon/poseidon_constants_generator.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes::detail;


namespace boost {
    namespace test_tools {
        namespace tt_detail {

            // Functions required by boost, to be able to print the compared values, when assertion fails.
            // TODO(martun): it would be better to implement operator<< for each field element type.
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    os << e.data << std::endl;
                }
            };

            template<typename FieldParams, size_t array_size>
            struct print_log_value<std::array<typename fields::detail::element_fp<FieldParams>, array_size>> {
                void operator()(std::ostream &os, std::array<typename fields::detail::element_fp<FieldParams>, array_size> const &arr) {
                    for (auto& e : arr) {
                        os << e.data << std::endl;
                    }
                }
            };

            //template<template<typename, typename> class P, typename K, typename V>
            //struct print_log_value<P<K, V>> {
            //    void operator()(std::ostream &, P<K, V> const &) {
            //    }
            //};

        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

// Test data for Mina version was taken from https://github.com/o1-labs/proof-systems/blob/a36c088b3e81d17f5720abfff82a49cf9cb1ad5b/poseidon/src/tests/test_vectors/kimchi.json, test vectors of the original version are taken from https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt.
// For some reason bytes in their test data are in Big Endian, while we need in Small Endian, I.E. you need to reverse the order of bytes to create our test data.
// We have NO TESTS for Vesta Field so far, since Mina code doesn't have tests and test vectors for it.

template<typename field_type>
void test_mina_poseidon(std::vector<typename field_type::value_type> input, 
                    typename field_type::value_type expected_result) {
    using policy = mina_poseidon_policy<field_type>;
    using sponge_construction_type = poseidon_sponge_construction<policy>;

    sponge_construction_type sponge;
    
    sponge.absorb(input);
    typename field_type::value_type res = sponge.squeeze();

    BOOST_CHECK_EQUAL(res, expected_result);
}

template<typename field_type, size_t Rate>
void test_original_poseidon(
        typename poseidon_policy<field_type, 128, Rate>::state_type input, 
        typename poseidon_policy<field_type, 128, Rate>::state_type expected_result) {
    using policy = poseidon_policy<field_type, 128, Rate>;

    // This permutes in place.
    poseidon_permutation<policy>::permute(input);
    BOOST_CHECK_EQUAL(input, expected_result);
}

BOOST_AUTO_TEST_SUITE(poseidon_tests)

// All the tests for mina poseidon will fail, since we made a decision to take the last element of the permuted state 
// (which is state[2] for Rate = 2) as the result of hash after squeeze. Mina poseidon uses the first element state[0] as the result. 
// So after this change, their test vectors do not apply any more.
// In case we decide to undo this change, these test vectors will be used again.
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_0) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {}, 0x2FADBE2852044D028597455BC2ABBD1BC873AF205DFABB8A304600F3E09EEBA8_cppui254);
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_1) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {0x36FB00AD544E073B92B4E700D9C49DE6FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui254},
//        0x3D4F050775295C04619E72176746AD1290D391D73FF4955933F9075CF69259FB_cppui254
//    );
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_2) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {0x3793E30AC691700012BAF26BB813D6D70BD379BEED8050A1DEEE3C188F1C3FBD_cppui254,
//         0x2FC4C98E50E0B1AAE6ECB468E28C0B7D80A7E0EEC7136DB0BA0677B84AF0E465_cppui254},
//        0x336C73D08AD408CEB7D1264867096F0817A1D0558B313312A1207602F23624FE_cppui254
//    );
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_3) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {0x0024FB5773CAC987CF3A17DDD6134BA12D3E1CA4F6C43D3695347747CE61EAF5_cppui254,
//        0x18E0ED2B46ED1EC258DF721A1D3145B0AA6ABDD02EE851A14B8B659CF47385F2_cppui254,
//        0x1A842A688E600F012637FE181292F70C4347B5AE0D9EA9CE7CF18592C345CF73_cppui254},
//        0x3F4B0EABB64E025F920457AF8D090A9F6472CAE11F3D62A749AF544A44941B9B_cppui254);
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_4) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {0x2059462D60621F70620EA697FA1382EC5553A3DADB3CF9072201E09871B8284C_cppui254,
//         0x2747337D1C4F9894747074C771E8EC7F570640E5D0CAF30FDDC446C00FA48707_cppui254,
//         0x2DD5047C3EEEF37930E8FA4AD9691B27CF86D3ED39D4DEC4FC6D4E8EE4FF0415_cppui254,
//         0x12C387C69BDD436F65AB607A4ED7C62714872EDBF800518B58E76F5106650B29_cppui254},
//        0x165A8CECF6660C6E0054CB9B4DBA9D68047166D7F3CED2F8DC86ED2EBFD3EC47_cppui254);
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_5) {
//    test_mina_poseidon<fields::pallas_base_field>(
//        {0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui254,
//         0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui254,
//         0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui254,
//         0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui254,
//         0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui254},
//        0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui254);
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_6) {
//    // This test just checks, that absorb does nothing when squeeze not called.
//    using field_type = fields::pallas_base_field;
//    using poseidon_policy = mina_poseidon_policy<field_type>;
//    using sponge_construction_type = poseidon_sponge_construction<poseidon_policy>;
//
//    std::vector<field_type::value_type> input = {
//        0x1A3FBD7D8C00BD0C3D4BC1DD41BF7FAA5903518DA636955D98712F9AC6D6DDFA_cppui254,
//        0x1AA195509819DF535E832D7D8AF809B385EF96A85A5A2DCE0DB7F9D72954F829_cppui254};
//    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words> expected_state = {
//        0x1A3FBD7D8C00BD0C3D4BC1DD41BF7FAA5903518DA636955D98712F9AC6D6DDFA_cppui254,
//        0x1AA195509819DF535E832D7D8AF809B385EF96A85A5A2DCE0DB7F9D72954F829_cppui254,
//        0
//    };
//    sponge_construction_type sponge;
//    
//    sponge.absorb(input);
//
//    BOOST_CHECK_EQUAL(sponge.state, expected_state);
//}
//
//BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_7) {
//    using field_type = fields::pallas_base_field;
//    using poseidon_policy = mina_poseidon_policy<field_type>;
//    using sponge_construction_type = poseidon_sponge_construction<poseidon_policy>;
//
//    std::vector<field_type::value_type> input = {
//        0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui254,
//        0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui254,
//        0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui254,
//        0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui254,
//        0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui254};
//
//    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words>  expected_state_absorb = {
//        0x2437F72484D8C5483D75F898376BC3EE29EDF2F7EF5305A3C61B937654954000_cppui254,
//        0x16F954CD8F2B73D797170C5124F31A65160A3FCA92B77709E564075C2405BF80_cppui254,
//        0x3696E4E8F08273FFEFDAD72C5002D103E9B8976F6579A010D6CC2A75B276851F_cppui254};
//    sponge_construction_type sponge;
//    
//    sponge.absorb(input);
//
//    BOOST_CHECK(sponge.state == expected_state_absorb);
//
//    typename poseidon_policy::element_type expected_challenge = 
//        0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui254;
//    typename poseidon_policy::element_type challenge = sponge.squeeze();
//
//    BOOST_CHECK_EQUAL(challenge, expected_challenge);
//}

BOOST_AUTO_TEST_CASE(poseidon_original_test_254_2) {
    test_original_poseidon<fields::alt_bn128_scalar_field<254>, 2>(
        {0x0000000000000000000000000000000000000000000000000000000000000000_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000001_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000002_cppui254
         },
        {0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a_cppui254, 
         0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29_cppui254,
         0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c_cppui254
         }
    );
}

BOOST_AUTO_TEST_CASE(poseidon_original_test_254_4) {
    test_original_poseidon<fields::alt_bn128_scalar_field<254>, 4>(
        {0x0000000000000000000000000000000000000000000000000000000000000000_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000001_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000002_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000003_cppui254,
         0x0000000000000000000000000000000000000000000000000000000000000004_cppui254
         },
        {0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465_cppui254, 
         0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d_cppui254,
         0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907_cppui254,
         0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e_cppui254,
         0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7_cppui254
         }
    );
}

BOOST_AUTO_TEST_CASE(poseidon_original_test_255_2) {
    test_original_poseidon<fields::bls12_scalar_field<381>, 2>(
        {0x0000000000000000000000000000000000000000000000000000000000000000_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000001_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000002_cppui255
        },
        {0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a_cppui255,
          0x51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4_cppui255,
          0x3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a_cppui255
        }
    );
}

BOOST_AUTO_TEST_CASE(poseidon_original_test_255_4) {
    test_original_poseidon<fields::bls12_scalar_field<381>, 4>(
        {0x0000000000000000000000000000000000000000000000000000000000000000_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000001_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000002_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000003_cppui255,
         0x0000000000000000000000000000000000000000000000000000000000000004_cppui255
        },
        {0x2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18_cppui255,
         0x65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7_cppui255,
         0x2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce_cppui255,
         0x4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566_cppui255,
         0x03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1_cppui255
        }
    );
}

// This test can be useful for constants generation in the future.
//BOOST_AUTO_TEST_CASE(poseidon_generate_pallas_constants) {
//    
//    typedef poseidon_policy<nil::crypto3::algebra::fields::pallas_base_field, 128, 2> poseidon_policy_type;
//    typedef poseidon_constants_generator<poseidon_policy_type> generator_type;
//    generator_type generator;
//    auto constants = generator.generate_constants();
//}

BOOST_AUTO_TEST_SUITE_END()
