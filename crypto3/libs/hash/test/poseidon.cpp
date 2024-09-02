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

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/block_to_field_elements_wrapper.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::accumulators;
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
                void operator()(std::ostream &os,
                                std::array<typename fields::detail::element_fp<FieldParams>, array_size> const &arr) {
                    for (auto &e: arr) {
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

template<typename field_type>
void test_mina_poseidon(std::vector<typename field_type::value_type> input,
                        typename field_type::value_type expected_result) {
    using policy = mina_poseidon_policy<field_type>;
    using hash_t = hashes::original_poseidon<policy>;

    typename policy::digest_type d = hash<hash_t>(input);
    BOOST_CHECK_EQUAL(d, expected_result);

    accumulator_set<hash_t> acc;

    for (auto &val: input) {
        acc(val);
    }
    typename hash_t::digest_type d_acc = extract::hash<hash_t>(acc);
    BOOST_CHECK_EQUAL(d_acc, expected_result);
}

template<typename FieldType, size_t Rate>
void test_poseidon_permutation(
        typename poseidon_policy<FieldType, 128, Rate>::state_type input,
        typename poseidon_policy<FieldType, 128, Rate>::state_type expected_result) {
    using policy = poseidon_policy<FieldType, 128, Rate>;

    // This permutes in place.
    poseidon_permutation<policy>::permute(input);
    BOOST_CHECK_EQUAL(input, expected_result);
}

BOOST_AUTO_TEST_SUITE(poseidon_tests)

// Test data for Mina version was taken from https://github.com/o1-labs/proof-systems/blob/a36c088b3e81d17f5720abfff82a49cf9cb1ad5b/poseidon/src/tests/test_vectors/kimchi.json.
// For some reason bytes in their test data are in Big Endian, while we need in Small Endian, I.E. you need to reverse the order of bytes to create our test data.
// We have NO TESTS for Vesta Field so far, since Mina code doesn't have tests and test vectors for it.
    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_0) {
        test_mina_poseidon<fields::pallas_base_field>(
                {}, 0x2FADBE2852044D028597455BC2ABBD1BC873AF205DFABB8A304600F3E09EEBA8_cppui_modular254);
    }

    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_1) {
        test_mina_poseidon<fields::pallas_base_field>(
                {0x36FB00AD544E073B92B4E700D9C49DE6FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui_modular254},
                0x3D4F050775295C04619E72176746AD1290D391D73FF4955933F9075CF69259FB_cppui_modular254
        );
    }
// works up to this
    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_2) {
        test_mina_poseidon<fields::pallas_base_field>(
                {0x3793E30AC691700012BAF26BB813D6D70BD379BEED8050A1DEEE3C188F1C3FBD_cppui_modular254,
                 0x2FC4C98E50E0B1AAE6ECB468E28C0B7D80A7E0EEC7136DB0BA0677B84AF0E465_cppui_modular254},
                0x336C73D08AD408CEB7D1264867096F0817A1D0558B313312A1207602F23624FE_cppui_modular254
        );
    }

    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_3) {
        test_mina_poseidon<fields::pallas_base_field>(
                {0x0024FB5773CAC987CF3A17DDD6134BA12D3E1CA4F6C43D3695347747CE61EAF5_cppui_modular254,
                 0x18E0ED2B46ED1EC258DF721A1D3145B0AA6ABDD02EE851A14B8B659CF47385F2_cppui_modular254,
                 0x1A842A688E600F012637FE181292F70C4347B5AE0D9EA9CE7CF18592C345CF73_cppui_modular254},
                0x3F4B0EABB64E025F920457AF8D090A9F6472CAE11F3D62A749AF544A44941B9B_cppui_modular254);
    }


    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_4) {
        test_mina_poseidon<fields::pallas_base_field>(
                {0x2059462D60621F70620EA697FA1382EC5553A3DADB3CF9072201E09871B8284C_cppui_modular254,
                 0x2747337D1C4F9894747074C771E8EC7F570640E5D0CAF30FDDC446C00FA48707_cppui_modular254,
                 0x2DD5047C3EEEF37930E8FA4AD9691B27CF86D3ED39D4DEC4FC6D4E8EE4FF0415_cppui_modular254,
                 0x12C387C69BDD436F65AB607A4ED7C62714872EDBF800518B58E76F5106650B29_cppui_modular254},
                0x165A8CECF6660C6E0054CB9B4DBA9D68047166D7F3CED2F8DC86ED2EBFD3EC47_cppui_modular254);
    }

    BOOST_AUTO_TEST_CASE(poseidon_kimchi_test_5) {
        test_mina_poseidon<fields::pallas_base_field>(
                {0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui_modular254,
                 0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui_modular254,
                 0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui_modular254,
                 0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui_modular254,
                 0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui_modular254},
                0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui_modular254);
    }

// Poseidon permutation test vectors are taken from:
//   https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/208b5a164c6a252b137997694d90931b2bb851c5/code/test_vectors.txt
    BOOST_AUTO_TEST_CASE(poseidon_permutation_254_2) {
        test_poseidon_permutation<fields::alt_bn128_scalar_field<254>, 2>(
                {0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000001_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000002_cppui_modular254
                },
                {0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a_cppui_modular254,
                 0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29_cppui_modular254,
                 0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c_cppui_modular254
                }
        );
    }

    BOOST_AUTO_TEST_CASE(poseidon_permutation_254_4) {
        test_poseidon_permutation<fields::alt_bn128_scalar_field<254>, 4>(
                {0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000001_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000002_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000003_cppui_modular254,
                 0x0000000000000000000000000000000000000000000000000000000000000004_cppui_modular254
                },
                {0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465_cppui_modular254,
                 0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d_cppui_modular254,
                 0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907_cppui_modular254,
                 0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e_cppui_modular254,
                 0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7_cppui_modular254
                }
        );
    }

    BOOST_AUTO_TEST_CASE(poseidon_permutation_255_3) {
        test_poseidon_permutation<fields::bls12_scalar_field<381>, 2>(
                {0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000001_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000002_cppui_modular255
                },
                {0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a_cppui_modular255,
                 0x51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4_cppui_modular255,
                 0x3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a_cppui_modular255
                }
        );
    }

    BOOST_AUTO_TEST_CASE(poseidon_permutation_255_4) {
        test_poseidon_permutation<fields::bls12_scalar_field<381>, 4>(
                {0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000001_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000002_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000003_cppui_modular255,
                 0x0000000000000000000000000000000000000000000000000000000000000004_cppui_modular255
                },
                {0x2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18_cppui_modular255,
                 0x65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7_cppui_modular255,
                 0x2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce_cppui_modular255,
                 0x4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566_cppui_modular255,
                 0x03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1_cppui_modular255
                }
        );
    }

    BOOST_AUTO_TEST_CASE(nil_poseidon_accumulator_255_4) {
        using policy = poseidon_policy<fields::bls12_scalar_field<381>, 128, /*Rate=*/ 4>;
        using hash_t = hashes::poseidon<policy>;
        accumulator_set<hash_t> acc;

        policy::word_type val = 0u;

        acc(val);

        hash_t::digest_type s = extract::hash<hash_t>(acc);

        BOOST_CHECK_EQUAL(s, 0x20CDA7B88718C51A894AE697F804FACD408616B1A7811A55023EA0E6060AA61C_cppui_modular255);
    }

    BOOST_AUTO_TEST_CASE(nil_poseidon_stream_255_4) {
        // Since we don't have any test vectors for such a custom structure, just make sure
        // it produces something consistent
        using field_type = fields::bls12_scalar_field<381>;
        using policy = poseidon_policy<field_type, 128, /*Rate=*/ 4>;
        using hash_t = hashes::poseidon<policy>;

        std::vector<typename field_type::value_type> input = {
                0x0_cppui_modular255,
                0x0_cppui_modular255,
                0x0_cppui_modular255,
                0x0_cppui_modular255,
                0x0_cppui_modular255
        };

        typename policy::digest_type d = hash<hash_t>(input);
        BOOST_CHECK_EQUAL(d, 0x44753e7f86d80790e762345ff8cb156be18eb0318f8846641193f815fbd64038_cppui_modular255);

        input = {
                0x2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18_cppui_modular255,
                0x65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7_cppui_modular255,
                0x2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce_cppui_modular255,
                0x4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566_cppui_modular255,
                0x03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1_cppui_modular255
        };

        d = hash<hash_t>(input);
        BOOST_CHECK_EQUAL(d, 0x44bff12d3a4713b18bd79c17eaabf8e69e29ce45ca48d7afb702baa1c37f3695_cppui_modular255);
    }

    BOOST_AUTO_TEST_CASE(nil_poseidon_wrapped_255_4) {
        // Make sure nil_block_poseidon converts non-field input to field elements as we expect
        using field_type = fields::bls12_scalar_field<381>;
        using policy = poseidon_policy<field_type, 128, /*Rate=*/ 4>;
        using hash_t = hashes::poseidon<policy>;

        std::vector<std::uint8_t> uint8_input = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
                0xEF, // 256 bits up to this place, the last value should be moved to
                // the next field element.

        };

        std::vector<typename field_type::value_type> field_input = {
                0x000123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD_cppui_modular255,
                0x00000000000000000000000000000000000000000000000000000000000000EF_cppui_modular255,
        };

        typename policy::digest_type d_uint8 = hash<hash_t>(
                hashes::conditional_block_to_field_elements_wrapper<hash_t::word_type, decltype(uint8_input)>(
                        uint8_input)
        );
        typename policy::digest_type d_field = hash<hash_t>(field_input);
        BOOST_CHECK_EQUAL(d_uint8, d_field);
    }

// This test can be useful for constants generation in the future.
//BOOST_AUTO_TEST_CASE(poseidon_generate_pallas_constants) {
//
//    typedef poseidon_policy<nil::crypto3::algebra::fields::pallas_base_field, 128, 2> PolicyType;
//    typedef poseidon_constants_generator<PolicyType> generator_type;
//    generator_type generator;
//    auto constants = generator.generate_constants();
//}

BOOST_AUTO_TEST_SUITE_END()
