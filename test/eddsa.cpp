//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE eddsa_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>

#include <nil/crypto3/pkpad/emsa/emsa1.hpp>

#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::marshalling;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename CurveGroupElement>
void print_fp_projective_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename CurveGroupElement>
void print_fp_extended_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.T.data << " : " << e.Z.data << " )"
       << std::endl;
}

template<typename CurveGroupElement>
void print_fp_affine_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " )" << std::endl;
}

template<typename CurveGroupElement>
void print_fp2_projective_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::twisted_edwards,
                                                                 curves::coordinates::extended_with_a_minus_1>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::twisted_edwards,
                                                              curves::coordinates::extended_with_a_minus_1> const &p) {
                    print_fp_extended_curve_group_element(os, p);
                }
            };

            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::twisted_edwards,
                                                                 curves::coordinates::affine>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::twisted_edwards,
                                                              curves::coordinates::affine> const &p) {
                    print_fp_affine_curve_group_element(os, p);
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

struct test_eddsa_params {
    typedef std::vector<std::uint8_t> context_type;
    static inline const context_type context = {0x66, 0x6f, 0x6f};
};

BOOST_AUTO_TEST_SUITE(eddsa_manual_test_suite)

BOOST_AUTO_TEST_CASE(eddsa_conformity_test) {

    using curve_type = algebra::curves::curve25519;
    using group_type = typename curve_type::g1_type<>;
    using group_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using group_value_type = typename group_type::value_type;
    using group_affine_value_type = typename group_affine_type::value_type;
    using group_marshalling_type = group_element_serializer<group_type>;
    using base_field_type = typename group_type::params_type::base_field_type;
    using base_field_value_type = typename base_field_type::value_type;
    using base_integral_type = typename base_field_type::integral_type;

    using scheme_type = pubkey::eddsa<group_type, pubkey::EddsaVariant::ctx, test_eddsa_params>;
    using private_key_type = pubkey::private_key<scheme_type>;
    using public_key_type = pubkey::public_key<scheme_type>;
    using _private_key_type = typename private_key_type::private_key_type;
    using _public_key_type = typename public_key_type::public_key_type;

    _private_key_type privkey = {0x03, 0x05, 0x33, 0x4e, 0x38, 0x1a, 0xf7, 0x8f, 0x14, 0x1c, 0xb6, 0x66, 0xf6, 0x19, 0x9f, 0x57, 0xbc, 0x34, 0x95, 0x33, 0x5a, 0x25, 0x6a, 0x95, 0xbd, 0x2a, 0x55, 0xbf, 0x54, 0x66, 0x63, 0xf6};
    _public_key_type etalon_pubkey = {0xdf, 0xc9, 0x42, 0x5e, 0x4f, 0x96, 0x8f, 0x7f, 0x0c, 0x29, 0xf0, 0x25, 0x9c, 0xf5, 0xf9, 0xae, 0xd6, 0x85, 0x1c, 0x2b, 0xb4, 0xad, 0x8b, 0xfb, 0x86, 0x0c, 0xfe, 0xe0, 0xab, 0x24, 0x82, 0x92};
    private_key_type private_key(privkey);
    BOOST_CHECK(etalon_pubkey == private_key.public_key_data());
}

BOOST_AUTO_TEST_SUITE_END()
