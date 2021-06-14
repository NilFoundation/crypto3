//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE curves_algebra_test

#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <type_traits>
#include <tuple>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/detail/h2c/ep.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/ep2.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/h2c_expand.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/accumulators/hash.hpp>

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves::detail;
using namespace nil::crypto3::algebra::curves;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )";
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
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

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
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

template<typename Expander,
         typename DstType,
         typename MsgType,
         typename ResultType,
         typename = typename std::enable_if<std::is_same<std::uint8_t, typename DstType::value_type>::value &&
                                            std::is_same<std::uint8_t, typename MsgType::value_type>::value &&
                                            std::is_same<std::uint8_t, typename ResultType::value_type>::value>::type>
void check_expand_message(std::size_t len_in_bytes, const DstType &dst, const MsgType &msg, const ResultType &result) {
    auto result_compare = [&result](auto my_result) {
        if (result.size() != my_result.size()) {
            return false;
        }
        bool ret = true;
        for (std::size_t i = 0; i < result.size(); i++) {
            ret &= result[i] == my_result[i];
        }
        return ret;
    };
    std::vector<std::uint8_t> uniform_bytes(len_in_bytes, 0);
    Expander::template process(len_in_bytes, msg, dst, uniform_bytes);
    BOOST_CHECK(result_compare(uniform_bytes));
}

template<std::size_t N,
         typename H2CType,
         typename FieldValueType,
         typename DstType,
         typename = typename std::enable_if<std::is_same<std::uint8_t, typename DstType::value_type>::value>::type>
void check_hash_to_field_ro(const std::string &msg_str,
                            const std::array<FieldValueType, N> &result,
                            const DstType &dst) {
    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    auto u = H2CType::template hash_to_field<N, typename H2CType::expand_message_ro>(msg, dst);
    for (std::size_t i = 0; i < N; i++) {
        BOOST_CHECK_EQUAL(u[i], result[i]);
    }
}

template<typename H2CType,
         typename GroupValueType,
         typename DstType,
         typename = typename std::enable_if<std::is_same<std::uint8_t, typename DstType::value_type>::value>::type>
void check_hash_to_curve(const std::string &msg_str, const GroupValueType &expected, const DstType &dst) {
    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    GroupValueType result = H2CType::hash_to_curve(msg, dst);
    BOOST_CHECK_EQUAL(result.to_affine(), expected);
}

BOOST_AUTO_TEST_SUITE(h2c_manual_tests)

BOOST_AUTO_TEST_CASE(expand_message_xmd_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-K.1
    using hash_type = hashes::sha2<256>;
    using expand_message = expand_message_xmd<128, hash_type>;

    std::string DST_str("QUUX-V01-CS02-with-expander");
    std::vector<std::uint8_t> DST(DST_str.begin(), DST_str.end());

    // {len_in_bytes, msg, uniform_bytes}
    using samples_type = std::vector<std::tuple<std::size_t, std::vector<std::uint8_t>, std::vector<std::uint8_t>>>;
    samples_type samples {
        {0x20, {}, {0xf6, 0x59, 0x81, 0x9a, 0x64, 0x73, 0xc1, 0x83, 0x5b, 0x25, 0xea, 0x59, 0xe3, 0xd3, 0x89, 0x14,
                    0xc9, 0x8b, 0x37, 0x4f, 0x9,  0x70, 0xb7, 0xe4, 0xc9, 0x21, 0x81, 0xdf, 0x92, 0x8f, 0xca, 0x88}},
        {0x20, {0x61, 0x62, 0x63}, {0x1c, 0x38, 0xf7, 0xc2, 0x11, 0xef, 0x23, 0x33, 0x67, 0xb2, 0x42,
                                    0xd,  0x4,  0x79, 0x8f, 0xa4, 0x69, 0x80, 0x80, 0xa8, 0x90, 0x10,
                                    0x21, 0xa7, 0x95, 0xa1, 0x15, 0x17, 0x75, 0xfe, 0x4d, 0xa7}},
        {0x20,
         {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39},
         {0x8f, 0x7e, 0x7b, 0x66, 0x79, 0x1f, 0xd, 0xa0, 0xdb, 0xb5, 0xec, 0x7c, 0x22, 0xec, 0x63, 0x7f,
          0x79, 0x75, 0x8c, 0xa,  0x48, 0x17, 0xb, 0xfb, 0x7c, 0x46, 0x11, 0xbd, 0x30, 0x4e, 0xce, 0x89}},
        {0x20,
         {0x71, 0x31, 0x32, 0x38, 0x5f, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71},
         {0x72, 0xd5, 0xaa, 0x5e, 0xc8, 0x10, 0x37, 0xd,  0x1f, 0x0,  0x13, 0xc0, 0xdf, 0x2f, 0x1d, 0x65,
          0x69, 0x94, 0x94, 0xee, 0x2a, 0x39, 0xf7, 0x2e, 0x17, 0x16, 0xb1, 0xb9, 0x64, 0xe1, 0xc6, 0x42}},
        {0x20,
         {0x61, 0x35, 0x31, 0x32, 0x5f, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
         {0x3b, 0x8e, 0x70, 0x4f, 0xc4, 0x83, 0x36, 0xac, 0xa4, 0xc2, 0xa1, 0x21, 0x95, 0xb7, 0x20, 0x88,
          0x2f, 0x21, 0x62, 0xa4, 0xb7, 0xb1, 0x3a, 0x9c, 0x35, 0xd,  0xb4, 0x6f, 0x42, 0x9b, 0x77, 0x1b}},
        {0x80, {}, {0x8b, 0xcf, 0xfd, 0x1a, 0x3c, 0xae, 0x24, 0xcf, 0x9c, 0xd7, 0xab, 0x85, 0x62, 0x8f, 0xd1, 0x11,
                    0xbb, 0x17, 0xe3, 0x73, 0x9d, 0x3b, 0x53, 0xf8, 0x95, 0x80, 0xd2, 0x17, 0xaa, 0x79, 0x52, 0x6f,
                    0x17, 0x8,  0x35, 0x4a, 0x76, 0xa4, 0x2,  0xd3, 0x56, 0x9d, 0x6a, 0x9d, 0x19, 0xef, 0x3d, 0xe4,
                    0xd0, 0xb9, 0x91, 0xe4, 0xf5, 0x4b, 0x9f, 0x20, 0xdc, 0xde, 0x9b, 0x95, 0xa6, 0x68, 0x24, 0xcb,
                    0xdf, 0x6c, 0x1a, 0x96, 0x3a, 0x19, 0x13, 0xd4, 0x3f, 0xd7, 0xac, 0x44, 0x3a, 0x2,  0xfc, 0x5d,
                    0x9d, 0x8d, 0x77, 0xe2, 0x7,  0x1b, 0x86, 0xab, 0x11, 0x4a, 0x9f, 0x34, 0x15, 0x9,  0x54, 0xa7,
                    0x53, 0x1d, 0xa5, 0x68, 0xa1, 0xea, 0x8c, 0x76, 0x8,  0x61, 0xc0, 0xcd, 0xe2, 0x0,  0x5a, 0xfc,
                    0x2c, 0x11, 0x40, 0x42, 0xee, 0x7b, 0x58, 0x48, 0xf5, 0x30, 0x3f, 0x6,  0x11, 0xcf, 0x29, 0x7f}},
        {0x80,
         {0x61, 0x62, 0x63},
         {0xfe, 0x99, 0x4e, 0xc5, 0x1b, 0xda, 0xa8, 0x21, 0x59, 0x80, 0x47, 0xb3, 0x12, 0x1c, 0x14, 0x9b,
          0x36, 0x4b, 0x17, 0x86, 0x6,  0xd5, 0xe7, 0x2b, 0xfb, 0xb7, 0x13, 0x93, 0x3a, 0xcc, 0x29, 0xc1,
          0x86, 0xf3, 0x16, 0xba, 0xec, 0xf7, 0xea, 0x22, 0x21, 0x2f, 0x24, 0x96, 0xef, 0x3f, 0x78, 0x5a,
          0x27, 0xe8, 0x4a, 0x40, 0xd8, 0xb2, 0x99, 0xce, 0xc5, 0x60, 0x32, 0x76, 0x3e, 0xce, 0xef, 0xf4,
          0xc6, 0x1b, 0xd1, 0xfe, 0x65, 0xed, 0x81, 0xde, 0xca, 0xff, 0xf4, 0xa3, 0x1d, 0x1,  0x98, 0x61,
          0x9c, 0xa,  0xa0, 0xc6, 0xc5, 0x1f, 0xca, 0x15, 0x52, 0x7,  0x89, 0x92, 0x5e, 0x81, 0x3d, 0xcf,
          0xd3, 0x18, 0xb5, 0x42, 0xf8, 0x79, 0x94, 0x41, 0x27, 0x1f, 0x4d, 0xb9, 0xee, 0x3b, 0x80, 0x92,
          0xa7, 0xa2, 0xe8, 0xd5, 0xb7, 0x5b, 0x73, 0xe2, 0x8f, 0xb1, 0xab, 0x6b, 0x45, 0x73, 0xc1, 0x92}},
        {0x80,
         {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39},
         {0xc9, 0xec, 0x79, 0x41, 0x81, 0x1b, 0x1e, 0x19, 0xce, 0x98, 0xe2, 0x1d, 0xb2, 0x8d, 0x22, 0x25,
          0x93, 0x54, 0xd4, 0xd0, 0x64, 0x3e, 0x30, 0x11, 0x75, 0xe2, 0xf4, 0x74, 0xe0, 0x30, 0xd3, 0x26,
          0x94, 0xe9, 0xdd, 0x55, 0x20, 0xdd, 0xe9, 0x3f, 0x36, 0x0,  0xd8, 0xed, 0xad, 0x94, 0xe5, 0xc3,
          0x64, 0x90, 0x30, 0x88, 0xa7, 0x22, 0x8c, 0xc9, 0xef, 0xf6, 0x85, 0xd7, 0xea, 0xac, 0x50, 0xd5,
          0xa5, 0xa8, 0x22, 0x9d, 0x8,  0x3b, 0x51, 0xde, 0x4c, 0xcc, 0x37, 0x33, 0x91, 0x7f, 0x4b, 0x95,
          0x35, 0xa8, 0x19, 0xb4, 0x45, 0x81, 0x48, 0x90, 0xb7, 0x2,  0x9b, 0x5d, 0xe8, 0x5,  0xbf, 0x62,
          0xb3, 0x3a, 0x4d, 0xc7, 0xe2, 0x4a, 0xcd, 0xf2, 0xc9, 0x24, 0xe9, 0xfe, 0x50, 0xd5, 0x5a, 0x6b,
          0x83, 0x2c, 0x8c, 0x84, 0xc7, 0xf8, 0x24, 0x74, 0xb3, 0x4e, 0x48, 0xc6, 0xd4, 0x38, 0x67, 0xbe}},
        {0x80,
         {0x71, 0x31, 0x32, 0x38, 0x5f, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
          0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71},
         {0x48, 0xe2, 0x56, 0xdd, 0xba, 0x72, 0x20, 0x53, 0xba, 0x46, 0x2b, 0x2b, 0x93, 0x35, 0x1f, 0xc9,
          0x66, 0x2,  0x6e, 0x6d, 0x6d, 0xb4, 0x93, 0x18, 0x97, 0x98, 0x18, 0x1c, 0x5f, 0x3f, 0xee, 0xa3,
          0x77, 0xb5, 0xa6, 0xf1, 0xd8, 0x36, 0x8d, 0x74, 0x53, 0xfa, 0xef, 0x71, 0x5f, 0x9a, 0xec, 0xb0,
          0x78, 0xcd, 0x40, 0x2c, 0xbd, 0x54, 0x8c, 0xe,  0x17, 0x9c, 0x4e, 0xd1, 0xe4, 0xc7, 0xe5, 0xb0,
          0x48, 0xe0, 0xa3, 0x9d, 0x31, 0x81, 0x7b, 0x5b, 0x24, 0xf5, 0xd,  0xb5, 0x8b, 0xb3, 0x72, 0xf,
          0xe9, 0x6b, 0xa5, 0x3d, 0xb9, 0x47, 0x84, 0x21, 0x20, 0xa0, 0x68, 0x81, 0x6a, 0xc0, 0x5c, 0x15,
          0x9b, 0xb5, 0x26, 0x6c, 0x63, 0x65, 0x8b, 0x4f, 0x0,  0xc,  0xbf, 0x87, 0xb1, 0x20, 0x9a, 0x22,
          0x5d, 0xef, 0x8e, 0xf1, 0xdc, 0xa9, 0x17, 0xbc, 0xda, 0x79, 0xa1, 0xe4, 0x2a, 0xcd, 0x80, 0x69}},
        {0x80,
         {0x61, 0x35, 0x31, 0x32, 0x5f, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
         {0x39, 0x69, 0x62, 0xdb, 0x47, 0xf7, 0x49, 0xec, 0x3b, 0x50, 0x42, 0xce, 0x24, 0x52, 0xb6, 0x19,
          0x60, 0x7f, 0x27, 0xfd, 0x39, 0x39, 0xec, 0xe2, 0x74, 0x6a, 0x76, 0x14, 0xfb, 0x83, 0xa1, 0xd0,
          0x97, 0xf5, 0x54, 0xdf, 0x39, 0x27, 0xb0, 0x84, 0xe5, 0x5d, 0xe9, 0x2c, 0x78, 0x71, 0x43, 0xd,
          0x6b, 0x95, 0xc2, 0xa1, 0x38, 0x96, 0xd8, 0xa3, 0x3b, 0xc4, 0x85, 0x87, 0xb1, 0xf6, 0x6d, 0x21,
          0xb1, 0x28, 0xa1, 0xa8, 0x24, 0xd,  0x5b, 0xc,  0x26, 0xdf, 0xe7, 0x95, 0xa1, 0xa8, 0x42, 0xa0,
          0x80, 0x7b, 0xb1, 0x48, 0xb7, 0x7c, 0x2e, 0xf8, 0x2e, 0xd4, 0xb6, 0xc9, 0xf7, 0xfc, 0xb7, 0x32,
          0xe7, 0xf9, 0x44, 0x66, 0xc8, 0xb5, 0x1e, 0x52, 0xbf, 0x37, 0x8f, 0xba, 0x4,  0x4a, 0x31, 0xf5,
          0xcb, 0x44, 0x58, 0x3a, 0x89, 0x2f, 0x59, 0x69, 0xdc, 0xd7, 0x3b, 0x3f, 0xa1, 0x28, 0x81, 0x6e}}};

    for (const auto &s : samples) {
        check_expand_message<expand_message>(std::get<0>(s), DST, std::get<1>(s), std::get<2>(s));
    }
}

BOOST_AUTO_TEST_CASE(hash_to_field_bls12_381_g1_h2c_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.9.1
    using curve_type = bls12_381;
    using group_type = typename curve_type::g1_type;
    using h2c_type = ep_map<group_type>;
    typedef typename group_type::underlying_field_type::value_type field_value_type;
    typedef typename curve_type::number_type number_type;

    std::string default_tag_str = "QUUX-V01-CS02-with-";
    std::vector<std::uint8_t> dst(default_tag_str.begin(), default_tag_str.end());
    dst.insert(dst.end(), h2c_type::suite_type::suite_id.begin(), h2c_type::suite_type::suite_id.end());

    using samples_type = std::vector<std::tuple<std::string, std::array<field_value_type, 2>>>;
    samples_type samples = {
        {"",
         {field_value_type(number_type("1790030616568561980207134218344899338736900885118493183248255875682123737756800"
                                       "213955590674957414534085508415116879")),
          field_value_type(number_type("2474702583317621523708233292803940741700450584532633563728739973751669085848991"
                                       "00434893060702108665825589810322121"))}},
        {"abc",
         {field_value_type(number_type("2088728490498894818688784437928579501848367107744050576780266498473771518428420"
                                       "173373487118890161663886009635645777")),
          field_value_type(number_type("3213892493831086209316960640873433141017158792584421675273329354360198845384332"
                                       "7878077294514665889481436558332217"))}},
        {"abcdef0123456789",
         {field_value_type(number_type("9505970308164648217789710156734861296414103440788614747505275085378045493860586"
                                       "12983484048401731236595379325781716")),
          field_value_type(number_type("1979385000937648348925653198641340374887185657649818450486460034420643425685140"
                                       "133042050299078521896600910613745210"))}},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         {field_value_type(number_type("1565983848840546529547071507571383550794102107851138573768250148104411885455485"
                                       "95465313883035731540725116276838022")),
          field_value_type(number_type("1709027689043323463259398100486189187238532958310276339146988040422594808842792"
                                       "053521671901476006506290292962489454"))}},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         {field_value_type(number_type("1625704516324785166230868561544190006281306318060308039760768255839116494270087"
                                       "378351796462565313509233883467016390")),
          field_value_type(number_type("8973476190440398924261230730510508241136153370908604317306021021786458550458325"
                                       "65883684732229117125155988066429111"))}}
        // {"", {field_value_type(number_type("")), field_value_type(number_type(""))}}
    };

    for (auto &s : samples) {
        check_hash_to_field_ro<2, h2c_type>(std::get<0>(s), std::get<1>(s), dst);
    }
}

BOOST_AUTO_TEST_CASE(hash_to_field_bls12_381_g2_h2c_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
    using curve_type = bls12_381;
    using group_type = typename curve_type::g2_type;
    using h2c_type = ep2_map<group_type>;
    typedef typename group_type::underlying_field_type::value_type field_value_type;
    typedef typename curve_type::number_type number_type;

    std::string default_tag_str = "QUUX-V01-CS02-with-";
    std::vector<std::uint8_t> dst(default_tag_str.begin(), default_tag_str.end());
    dst.insert(dst.end(), h2c_type::suite_type::suite_id.begin(), h2c_type::suite_type::suite_id.end());

    using samples_type = std::vector<std::tuple<std::string, std::array<field_value_type, 2>>>;
    samples_type samples = {
        {"",
         {field_value_type(number_type("5938684483100054485611722523870295163604099457864574398759743150316400213898356"
                                       "49561235021338510064922970633805048"),
                           number_type("8673753094890675127974598608873659518770540387638184480573261903027016498888499"
                                       "97836339069389536967202878289851290")),
          field_value_type(number_type("4578897045199488434740260225626419694433157155954591591128744980829534319713238"
                                       "09145630315884223143822925947137684"),
                           number_type("3132697209754082586339430915081913810572071485832539443682634025529375380328136"
                                       "128542015469873094481703191673087029"))}},
        {"abc",
         {field_value_type(number_type("3381151350286428005095780827831774583653641216459357823974407145557165174365389"
                                       "989442078766443621078367363453769585"),
                           number_type("2741746953704442638534180707453397316404679193551841082537168795196953970699630"
                                       "34977795744692362177212201505728989")),
          field_value_type(number_type("3761918608077574755256083960277010506684793456226386707192711779006489497410866"
                                       "269311252402421709839991039401264868"),
                           number_type("1342131492846344403298252211066711749849099599627623100864413228392326132610002"
                                       "371925674088601653350525231531947366"))}},
        {"abcdef0123456789",
         {field_value_type(number_type("4736756665618245326244300857865191860224326611904114213007749037224882541543738"
                                       "95989233527517731907580580706354657"),
                           number_type("9520540557415691916362510867127307131683791692159959526594533787977337613244945"
                                       "87640793580119096894387397115436943")),
          field_value_type(number_type("3574336717567028224405133950386477048284620456829914449302272757384276784667241"
                                       "972055005113408837488328262928878231"),
                           number_type("2365602345707797244937763470382803726723577073883311775921418854730692345417958"
                                       "26215789679703490403053611203549557"))}},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         {field_value_type(number_type("3608131929677217503005188861991391449980483387988256142839334881042292007389752"
                                       "19634991234987258997592645316502099"),
                           number_type("5009904385311786096049606538586133897401985944525938049981086917265658825017777"
                                       "15476408413735192405455364595747963")),
          field_value_type(number_type("1414201600433038156752401103621159164529164806638579329495300394501933973057103"
                                       "319123042671630779248244072674138005"),
                           number_type("2580989994757912640015815541704972436791025324967858519264081257257405036397177"
                                       "981572950833626047365407639272235247"))}},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         {field_value_type(number_type("3854656460966118202185202795415969034444473478700041637108073179423449626727403"
                                       "291696647010132509133525205314259253"),
                           number_type("2873494353363126311409085895530381085174075451844000378947122252646711114869905"
                                       "923958066527312260237781765269081913")),
          field_value_type(number_type("2218682278840147973132952196327912255143646871258838127959845658885016361690895"
                                       "544274403462155614933990666846598837"),
                           number_type("2692054640040186323570630735219910885988179020142391687801930252786130591827501"
                                       "100656577702624784849458500251540952"))}},

        // {"",
        //  {field_value_type(number_type(""),
        //                    number_type("")),
        //   field_value_type(number_type(""),
        //                    number_type(""))}},
    };

    for (auto &s : samples) {
        check_hash_to_field_ro<2, h2c_type>(std::get<0>(s), std::get<1>(s), dst);
    }
}

BOOST_AUTO_TEST_CASE(hash_to_curve_bls12_381_g1_h2c_sha256_test) {
    using curve_type = bls12_381;
    using group_type = typename curve_type::g1_type;
    using h2c_type = ep_map<group_type>;
    typedef typename group_type::value_type group_value_type;
    typedef typename group_type::underlying_field_type::value_type field_value_type;
    typedef typename curve_type::number_type number_type;

    std::string default_tag_str = "QUUX-V01-CS02-with-";
    std::vector<std::uint8_t> dst(default_tag_str.begin(), default_tag_str.end());
    dst.insert(dst.end(), h2c_type::suite_type::suite_id.begin(), h2c_type::suite_type::suite_id.end());

    using samples_type = std::vector<std::tuple<std::string, group_value_type>>;
    samples_type samples {
        {"", group_value_type(number_type("7943115757214008313629570493037810448520063234226241118933528595574500083086"
                                          "20925451441746926395141598720928151969"),
                              number_type("1343412193624222137939591894701031123123641958980729764240763391191550653712"
                                          "890272928110356903136085217047453540965"),
                              1)},
        {"abc", group_value_type(number_type("5137384602176159439212852477034485676478758747455673727961641554723831277"
                                             "56567780059136521508428662765965997467907"),
                                 number_type("1786897908129645780825838873875416513994655004408749907941296449131605892"
                                             "957529391590865627492442562626458913769565"),
                                 1)},
        {"abcdef0123456789", group_value_type(number_type("275162876137213708468320729543710526816637518402774837215695"
                                                          "2770986741873369176463286511518644061904904607431667096"),
                                              number_type("563036982304416203921640398061260377444881693369806087719971"
                                                          "277317609936727208012968659302318886963927918562170633"),
                                              1)},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         group_value_type(number_type("33804326948876744397730824181920837205847480807049591729785862299214753152204341"
                                      "65460350679208315690319508336723080"),
                          number_type("36985267390728644087495710822706285617644155774454041155969909198015237931383482"
                                      "54443092179877354467167123794222392"),
                          1)},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         group_value_type(number_type("12569674255428230696945135509180256894900364785011816005259446539528461008878487"
                                      "29514132077573887342346961531624702"),
                          number_type("88037208240369454347695990925650426721558805545001688510379770085674653213458594"
                                      "2561958795215862304181527267736264"),
                          1)},
        // {"",
        //  group_value_type(
        //      number_type(""),
        //      number_type(""),
        //      1)},
    };

    for (auto &s : samples) {
        check_hash_to_curve<h2c_type>(std::get<0>(s), std::get<1>(s), dst);
    }
}

BOOST_AUTO_TEST_CASE(hash_to_curve_bls12_381_g2_h2c_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
    using curve_type = bls12_381;
    using group_type = typename curve_type::g2_type;
    using h2c_type = ep2_map<group_type>;
    typedef typename group_type::value_type group_value_type;
    typedef typename group_type::underlying_field_type::value_type field_value_type;
    typedef typename curve_type::number_type number_type;

    std::string default_tag_str = "QUUX-V01-CS02-with-";
    std::vector<std::uint8_t> dst(default_tag_str.begin(), default_tag_str.end());
    dst.insert(dst.end(), h2c_type::suite_type::suite_id.begin(), h2c_type::suite_type::suite_id.end());

    using samples_type = std::vector<std::tuple<std::string, group_value_type>>;
    samples_type samples {
        {"", group_value_type(field_value_type(number_type("19354805336845174941142151562851080662656573665208680741935"
                                                           "4395577367693778571452628423727082668900187036482254730"),
                                               number_type("89193000964309942330810277795125089969455920364772498836102"
                                                           "2851024990473423938537113948850338098230396747396259901")),
                              field_value_type(number_type("77171727205583415237828170597267125700535714547880090837365"
                                                           "9404991537354153455452961747174765859335819766715637138"),
                                               number_type("28103101185821266340411334541807053043930791391032529565024"
                                                           "04531123692847658283858246402311867775854528543237781718")),
                              field_value_type::one())},
        {"abc",
         group_value_type(field_value_type(number_type("424958340463073975547762735517193206833255107941790909009827635"
                                                       "556634414746056077714431786321247871628515967727334"),
                                           number_type("301867980397012787726282639381447252855741350432919474049536385"
                                                       "2840690589001358162447917674089074634504498585239512")),
                          field_value_type(number_type("362130818512839545988899552652712755661476860447213217606042330"
                                                       "2734876099689739385100475320409412954617897892887112"),
                                           number_type("102447784096837908713257069727879782642075240724579670654226801"
                                                       "345708452018676587771714457671432122751958633012502")),
                          field_value_type::one())},
        {"abcdef0123456789",
         group_value_type(field_value_type(number_type("278579072823914661770244330824853538101603574852069839969013232"
                                                       "5213972292102741627498014391457605127656937478044880"),
                                           number_type("385570939363183188091016781827643518714796337112619879965480309"
                                                       "9743427431977934703201153169947378798970358200024876")),
                          field_value_type(number_type("821938378705205565995357931232097952117504537366318395539093959"
                                                       "918654729488074273868834599496909844419980823111624"),
                                           number_type("180242033557577995098293558042145430208756792638522270794752735"
                                                       "3462942499437987207287862072369052390195154530059198")),
                          field_value_type::one())},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         group_value_type(field_value_type(number_type("394904109851368845549123118074972479469719294319673003085328501"
                                                       "1755806989731870696216017360514887069032515603535834"),
                                           number_type("141689369450613197680900293521221631713294194257076384932306538"
                                                       "1335907430566747765697423320407614734575486820936593")),
                          field_value_type(number_type("322745371086383503299296260585144940139139935513544272889379018"
                                                       "6263669279022343042444878900124369614767241382891922"),
                                           number_type("149873883407375987188646612293399676447188951453282792720277792"
                                                       "2460876335493588931070034160657995151627624577390178")),
                          field_value_type::one())},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         group_value_type(field_value_type(number_type("254155017921606149907129844368549510385368618440139550318910532"
                                                       "874259603395336903946742408725761795820224536519988"),
                                           number_type("276843145929673042677916621854414979160158598623313058301150172"
                                                       "7704972362141149700714785450629498506208393873593705")),
                          field_value_type(number_type("175533934474433745731856511606202566998475061793772124522071142"
                                                       "5551575490663761638802010265668157125441634554205566"),
                                           number_type("560643043433789571968941329642646582974304556331567393300563909"
                                                       "451776257854214387388500126524984624222885267024722")),
                          field_value_type::one())},
        // {"",
        //  group_value_type(
        //      field_value_type(number_type(""),
        //                       number_type("")),
        //      field_value_type(number_type(""),
        //                       number_type("")),
        //      field_value_type::one())},
    };

    for (auto &s : samples) {
        check_hash_to_curve<h2c_type>(std::get<0>(s), std::get<1>(s), dst);
    }
}

BOOST_AUTO_TEST_SUITE_END()
