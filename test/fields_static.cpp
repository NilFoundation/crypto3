//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_fields_static_test

#include <iostream>
#include <cstdint>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

// #include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
// #include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
// #include <nil/crypto3/algebra/fields/dsa_botan.hpp>
// #include <nil/crypto3/algebra/fields/dsa_jce.hpp>
// #include <nil/crypto3/algebra/fields/ed25519_fe.hpp>
// #include <nil/crypto3/algebra/fields/ffdhe_ietf.hpp>
// #include <nil/crypto3/algebra/fields/field.hpp>
// #include <nil/crypto3/algebra/fields/modp_ietf.hpp>
// #include <nil/crypto3/algebra/fields/modp_srp.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp4<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_3over2<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_2over3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]";
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

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp3<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp3<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp4<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp4<FieldParams> const &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp6_2over3<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_2over3<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
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

typedef std::size_t constant_type;
enum field_operation_test_constants : std::size_t { C1, constants_set_size };

enum field_operation_test_elements : std::size_t {
    e1,
    e2,
    e1_plus_e2,
    e1_minus_e2,
    e1_mul_e2,
    e1_dbl,
    e2_inv,
    e1_pow_C1,
    e2_pow_2,
    e2_pow_2_sqrt,
    minus_e1,

    elements_set_size
};

template<typename ElementsRange, typename ConstantsRange>
constexpr bool check_field_operations_static(const ElementsRange &elements, const ConstantsRange &constants) {
    static_assert(elements[e1] + elements[e2] == elements[e1_plus_e2], "add error");
    static_assert(elements[e1] - elements[e2] == elements[e1_minus_e2], "sub error");
    static_assert(elements[e1] * elements[e2] == elements[e1_mul_e2], "mul error");
    static_assert(elements[e1].doubled() == elements[e1_dbl], "dbl error");
    static_assert(elements[e2].inversed() == elements[e2_inv], "inv error");
    // static_assert(elements[e1].pow(constants[C1]) == elements[e1_pow_C1], "pow error");
    static_assert(elements[e2].squared() == elements[e2_pow_2], "sqr error");
    static_assert((elements[e2].squared()).sqrt() == elements[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements[e1] == elements[minus_e1], "neg error");
    return true;
}

BOOST_AUTO_TEST_SUITE(fields_manual_static_tests)

BOOST_AUTO_TEST_CASE(field_operation_test_bls12_381_fr) {
    using policy_type = fields::bls12_fr<381>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    // TODO: scalar field precision could be less than for base field
    constexpr test_set_t elements1 = {0x209a9bf596288853d71eb5a070164b2d81fe36e956f8f70376712767fabb15d9_cppui381,
                                      0x661ad4fb4d130b7afaea293348f2107d9f4a62308af88282297733628cfc5ae7_cppui381,
                                      0x12c7c99db99e16869ecf06cbaf6683a5cd8af516e1f31d869fe85acb87b770bf_cppui381,
                                      0x2e6d6e4d72b2fa210f6e647530c612b5367178bbcbfed0804cf9f4046dbebaf3_cppui381,
                                      0x65915fd6511eb3afcf0648a4b4b1c3f298433ecaee3cdd97254aa3ce8a67303d_cppui381,
                                      0x413537eb2c5110a7ae3d6b40e02c965b03fc6dd2adf1ee06ece24ecff5762bb2_cppui381,
                                      0x1c40f7a911c57190db5382d3fc2d96473780452b78e60474add8fb7f1eddda6_cppui381,
                                      0x49757b377fe2a1de10c484db929a74ae02fdfae3aaab6098ea2ab8accfe613f0_cppui381,
                                      0x363f979f222c9970dc4291b62bc3e8d77c31c1b2caa88afeb414f3584b952000_cppui381,
                                      0x661ad4fb4d130b7afaea293348f2107d9f4a62308af88282297733628cfc5ae7_cppui381,
                                      0x53530b5d9374f4f45c1b2267998b8cd7d1bf6d19a90564fb898ed8970544ea28_cppui381};
    constexpr const_set_t constants1 = {811706348};

    // TODO: the reason of the error "function parameter 'elements' with unknown value cannot be used in a constant
    // expression" constexpr
    //     bool res = check_field_operations_static(elements1, constants1);

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_bls12_381_fq) {
    using policy_type = fields::bls12_fq<381>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        0x3d9cb62ebac9d6c7b94245d2d6144d500f218bb90a16a1e4f70d98fd44b4b9ee274de15a0a3d231dac1eaa449d31404_cppui381,
        0x15c88779fc8a30cca95ec4bbf71aa4c302bccf7dc571e6e45fbf1ed24989ec23dff741ca00597f4ab1fc628304e8761b_cppui381,
        0x19a252dce836ce3924f2e919247be99803aee83956135102af2ff8621dd537c2c26c1fdfa0fd517c8cbe4d274ebb8a1f_cppui381,
        0x81255d328a2533a1d51075779924ce962ac94c2beb495f956e28d5e8172559f21299c4a519e52e6e2c4882144ea4894_cppui381,
        0x4e02d210a60d52212c21056e050b7f7b6aa45c2fb85e692b1fef9e3e6fb43b2bf8103105f43daca458e4dccc9f5236c_cppui381,
        0x7b396c5d7593ad8f72848ba5ac289aa01e431772142d43c9ee1b31fa896973dc4e9bc2b4147a463b583d54893a62808_cppui381,
        0x68241cb698160ee94897ec6600bc997de3fed563dfc36a758334c71dc76a2473571cfbc0f674038ee748add41e4277a_cppui381,
        0xbb4588b98237fefeba65f928e69da9106c690e02c70361947b39d0f5a6d462096431d375d4b66ae7e4daef9f2400a09_cppui381,
        0x2e7ebd9b39f65a9485b32b52269baa84b2d33a80c8747c994b1e58c0caa09b4acf7685583898549db1029a1de657d8a_cppui381,
        0x4388a703cf5b5cda1bce2fa4c31081461ba7c072e132bdb0771b3cead270a003eb4be34b0fa80b508029d7cfb173490_cppui381,
        0x162746874dd3492dcf87835915ea6802638532c962e3a8a117bff9112265aa853c3721e910b02dcddf3d155bb62c96a7_cppui381};
    constexpr const_set_t constants1 = {865433380};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");

    constexpr value_type not_square1 = {
        0x122ca301fc65d4c9fd02b7d919e691c448b3209081835c99fab65c12c0e60a25f7eabe1b506e494b45175b95a4a9ebfe_cppui381,
    };
    static_assert(not_square1.is_square() == false, "not square error");
    static_assert(not_square1.pow(2).is_square() == true, "square error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_bls12_381_fq2) {
    using policy_type = fields::fp2<fields::bls12_fq<381>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        {{
             0x5aa9d5160c21229d4c73871dab039631da3722131b00713055854b2e6ff4f8abe4430358fc70ba351fda87dc9abdbb2_cppui381,
             0x2ccc1503d823ead782507cf3eb7c6b03ec4503bf8bb725111abe86ce8809f9c52ed32fa7178cdeb057f8ddb351b2de4_cppui381,
         },
         {
             0xe9042dd6be3a4248432d05bdf942a3b7574fa29fabc16dd474af9b64aea7d6e66d5be0bb505a97d67105d045d5e533d_cppui381,
             0x79d8473ab5a748a8321a5f996ddde6cbaa2f723bfffcf3da67045bd122fbb639f1ea54d5bc7c7dcc9cec9834c666f37_cppui381,
         },
         {
             0x143ae02ecca5b64e58fa08cdba44639e93186c4b2c6c1df04ca34e6931e9ccf92519ee4144ccb520b90e0582270a2eef_cppui381,
             0xa6a45c3e8dcb337fb46adc8d595a51cf967475fb8bb418eb81c2e29fab05afff20bd847cd4095c7cf4e575e81819d1b_cppui381,
         },
         {
             0x111b6c5e2e5e549f9bb00fcc3e67bbff0ca5c37c2a7902f5253e2d9d92c5c840761a72288c156225a4ec4b796c4d3320_cppui381,
             0x15304ec6cba7b0bd401f098beb25951ae898a49d2c40b5d2d26c7550cd01da5cd27a8dabc705060df5afc457e8b46958_cppui381,
         },
         {
             0x16c00305e0c73e7c87eff62ffcadc3b54e06d73bc6ba13bf64a6e12881b3be9a8bd441e174fa59bb75287609946ad160_cppui381,
             0x121e6a16e0b5a24b03bbb18ffb108c934781f5ecde689729b47c69a575592c4f6e3cf19d34140428cbf71a48dfef8bcb_cppui381,
         },
         {
             0xb553aa2c1842453a98e70e3b56072c63b46e44263600e260ab0a965cdfe9f157c88606b1f8e1746a3fb50fb9357b764_cppui381,
             0x59982a07b047d5af04a0f9e7d6f8d607d88a077f176e4a22357d0d9d1013f38a5da65f4e2f19bd60aff1bb66a365bc8_cppui381,
         },
         {
             0x1004f42fded04e85fa8e21b945dc955abd3b349e52494a628d102e1240123038bdadd47f92750bdb8355b798d119a030_cppui381,
             0xe7eeef4fb0a1d7470dad9548096233fcf664d7178e62b8c8d716197b84e31d7da79bbf5be757d63519b997c81d5c95e_cppui381,
         },
         {
             0xef716581f3a2e7e2bf0f2850ea9bd3bbccf4933d4f4dcf616b181e1a894eb07e194b611cf5a2d532637b6ae800e33b6_cppui381,
             0x2054d1d319feb67161dcd0ba4ab91a498197d89f44158513b8ddee4e46a8b50b6752621e17a61e0952d6daf2e0d9e8a_cppui381,
         },
         {
             0x9f218e6d8b2f410874af5f7a8290dfa6ba23f059630fc7afe87138081863aed2730b5b19c3945c3bf5a03780d276861_cppui381,
             0x120c0b9fea1fdde517eee773dc43ba6c0f14b8594a7fd86e93b40a71e7ae9b118444713de4606eedc4391acfab10218a_cppui381,
         },
         {
             0xe9042dd6be3a4248432d05bdf942a3b7574fa29fabc16dd474af9b64aea7d6e66d5be0bb505a97d67105d045d5e533d_cppui381,
             0x79d8473ab5a748a8321a5f996ddde6cbaa2f723bfffcf3da67045bd122fbb639f1ea54d5bc7c7dcc9cec9834c666f37_cppui381,
         },
         {
             0x14567498d8bdd47076546f44689b737446d3d963c1d50bac61d87dee0fb1a6996067cfc9218cf45c680157823653cef9_cppui381,
             0x17345099fbfda7ecd2f69fe70493e62725b2fb48fac9a06e5584ea340e305687cbbecd043fdb3214b47f7224cae47cc7_cppui381,
         }}};
    constexpr const_set_t constants1 = {928943650};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");

    constexpr value_type not_square1 = {
        0x72076a0fb063f674c504b550525707cbea30259021a274bc9dcba7a9fdaf9e36011466eea87f70870c4b91a400d3395_cppui381,
        0x1127508c363a11a7b6f6572124fe882786e91ad0a2ce25e139949d37b8a3d6f6392920c23b07e3896dd4e8f743c2567f_cppui381,
    };
    static_assert(not_square1.is_square() == false, "not square error");
    static_assert(not_square1.pow(2).is_square() == true, "square error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_bls12_381_fq6) {
    using policy_type = fields::fp6_3over2<fields::bls12_fq<381>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size - 1>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr value_type element1(
        {{0xe35bdcd1e6bea40fb5a65a36a415ef84cb2260e7c7a21b479352a56a257128bbd2f6b8e5d96dca7917292801387ca3f_cppui381,
          0x842c6e159819c8c3119def19ef737ef9d412ac4f720e96f807739f66f612fc3efa0ddefa8948bb897af24c57ffb0847_cppui381}},
        {{0x530d34cbd121e5d4889dc058b70e8c4d1113cb8fda0d324ca7c04e86b39f93a569946fb5896e04494e99aab3af56417_cppui381,
          0x66c9141b489a64a63108c7b1f019e760e4475a1c3deb8ca5805758a8d3bc99bba1e9cac8f610e9bc7b8ef295527957d_cppui381}},
        {{0x191648b522c815d6b754d0ae9811b8009faa26fad2fa9ebe1ec57d29575c5667cbf0cae8e048167f55b9f5f107de315_cppui381,
          0x18874ddc2384d2512f6b9c61dc1650f8c3f013e86e260af76dd326c6505041962b4c652db429eb9751788d323a9fe14d_cppui381}});
    constexpr value_type element2(
        {{
            0x12c6da93e6f1749bb5b55d45be19c3447ac88cefa858ff5ed5eccb5e8cb36ccf8923ed675278d5ed0b21f04d3770e191_cppui381,
            0x298353679126c9fad35a3ea30ab0a3307a256877ca8689641bc43d1689c801d215110906ed9ef31c0f03df8e1a1bbac_cppui381,
        }},
        {{
            0x19af88a6400fc27b35efde0bfd718cb83f7cf34abc1a66ae709a889084847930a94b1b706a3e0d8859f77c6cbdfb005c_cppui381,
            0x11d0d2e8f588862f71072a1131d2a680183e37687d73ea2271c50233e63be12dd7e3ced525de82aefde44d9c7dc4548d_cppui381,
        }},
        {{
            0x3953b4d910cbcf606bd2e1cff60d71686058fe97df3f565e38c5eb62919e761123f27da473b7d74ab1b2c263acf8a67_cppui381,
            0xa5b6acd4357f48cdb0d890dc2f1dd294ca52aa4a63423b4208fa9b3865f6e6f663b02505b64d3383423ab07f155b0e0_cppui381,
        }});
    constexpr value_type element_add(
        {{
            0x6fb8676cbdd784265f41b32e50f756563036779314e0e53e7f123143859893727a758f6febbb294e29582cd4af90125_cppui381,
            0xadafc17d294092bde4f82dbcfa24222a4e3814c73c95205c2337dc7d7fdafe110f1ee80176e7aea589f62be619cc3f3_cppui381,
        }},
        {{
            0x4df4a08c3a1fa3e335e125b4596c8a5ac16e47ec6362713d3e5bad7f90d7c46e138626d1180edcd34e21717f8f0b9c8_cppui381,
            0x183d642aaa122c79d417b68c50d444f62682ad0a4152a2ecc9ca77be7377aac992026b81b53f914ac59d3cc5d2ebea0a_cppui381,
        }},
        {{
            0x5269fd8e3393e5372327b27e8e1f296900032592b239f51c578b688be8facc78efe3488d53ffedca076cb854b4d6d7c_cppui381,
            0x8e1a6bf2d5ce043bf5d7db95bbc814aac1df30820d51bec2731fdd8dffeb9e172db677f5e3abecfcb9d383a2bf5e782_cppui381,
        }});
    constexpr value_type element_sub(
        {{
            0x156ff52370fa5c3f90c0b013ef73488b3660e4a3c7a635150a7931990c549be052b77e25bc7206ba404fa232dc169359_cppui381,
            0x5aa91aae06f2fec83e43b076e4c2dbc959ed43d7a7880d93ebaf62506c4afa6ce4fcd5f39ba9c86d6bee6cc9e594c9b_cppui381,
        }},
        {{
            0x5825c90b682427c5db5a5afd14b08e3f60b94f3350b7f35c1124ef8dd66762dcbfa2b899facd2bbf4f11e3e7cfa0e66_cppui381,
            0xe9cd042f88106b53d250a20307aa4cd5a7d89be39efe1674d7145f79db0de9200e6cdd61ad68bec83d3a18cd762eb9b_cppui381,
        }},
        {{
            0x17fd3b27fa9fab01afd3c6a42d6bf140e86c5e0b22c0c7456590cbbd630cd429892be4d2f81d03f3043f7338d5ae0359_cppui381,
            0xe2be30ee02cddc4545e1354192473cf774ae943c7f1e7434d437d12c9f0d326c51162dd58c5185f1d54e22a494a306d_cppui381,
        }});
    constexpr value_type element_mul(
        {{
            0xee860564acc5f0b9735eeb963c12b5f13e7185ee07cc64faa29f7625722ab4f22c5de62ba7bfbb2f4b89271e1c08cf5_cppui381,
            0x15da2707b1131595a4c8f52d21033bf4effa6f8bb329b87ff145c246996a06e5658f600cf48194d3de04de2b12440b05_cppui381,
        }},
        {{
            0x7d5becd415aa1ab429792cd7886c38f099b8822fe2addde4be8a4d6474b942ca3e1748e05f554399c4b91cd3b3f16a8_cppui381,
            0xa76f981e0a2529242f4ff7aed73d90f0edbbf42fb6eeafe7c2c1b00a06410cffd8aeb068642fd6acdc620d34b112d4c_cppui381,
        }},
        {{
            0x13cf641327fca9e6e6f030760e3c15db66560f38f9e3c0b01c145a618cabeff77a4eecb05ce3dd6fbcbacefd30be8d06_cppui381,
            0xc6d2165eb733e306f8cb4fa077fbcf150ddca205f82ed83018a9f25df5356029d6cebbcd949869db0d1fde551fbe5fb_cppui381,
        }});
    constexpr value_type element_dbl(
        {{
            0x26a69b00357ede7ab9923909137111934ed0098056f30a98b39820c4dfd2ef35bb2d71e09d9b94f68e62500270fe9d3_cppui381,
            0x10858dc2b30339186233bde33dee6fdf3a825589ee41d2df00ee73ecdec25f87df41bbdf512917712f5e498afff6108e_cppui381,
        }},
        {{
            0xa61a6997a243cba9113b80b16e1d189a2227971fb41a64994f809d0d673f274ad328df6b12dc08929d3355675eac82e_cppui381,
            0xcd9228369134c94c62118f63e033cec1c88eb4387bd7194b00aeb151a779337743d39591ec21d378f71de52aa4f2afa_cppui381,
        }},
        {{
            0x322c916a45902bad6ea9a15d302370013f544df5a5f53d7c3d8afa52aeb8accf97e195d1c0902cfeab73ebe20fbc62a_cppui381,
            0x170d89ce0d89be0813bb910d74e0f51a2368dc4be8c7032f74757aeba9ef8d0837ecca5cb6ffd72ee8f21a64754017ef_cppui381,
        }});
    constexpr value_type element_inv(
        {{
            0x12ee7ea5e0d228be7def0065aadeb7da8095517cb58fc1db216d0b7b2d744534757ae10609732ec72999898bdbbdf399_cppui381,
            0x6626a59529d1a4a5639122be3bf0c9840f0c47e083a6d2d7fd8fb11400d19efe488e987e3fcf90ae89d098fae2adb15_cppui381,
        }},
        {{
            0x987d5a6a07024d1728020ddc12fe8359aaa166216145d3830e01f8c397aa1b5b0df5b42f4c82b8481f8b327b20fc8b7_cppui381,
            0xd4566bba6b0d25880bb0c3be74ae401b0988116914166df91f1a61af5af32a7aec7967d12e040e528629136a3c8c9bc_cppui381,
        }},
        {{
            0xd7a5de8dc422548facb0cd895f0fb045dbbf0872d5c257a91720916fc59552d14879c0a1954661e452606be48cf7bc6_cppui381,
            0x41669d95d4700d9d78b96f4292bfa008b60170188c8f6737157800c6cb8bd8887afa3411ff6e700f89f480ba8b889a3_cppui381,
        }});
    constexpr value_type element_pow_C(
        {{
            0x289ab5220ebbed9d65e184825cc39c3ad9288269839db599ddc54fed213cb8dc29f668ef33a28352cb76133d3003f3b_cppui381,
            0x1924a52997eef1bd7ae41fb0ec3983e4cf1c6c2da62ad149e6f4d4bdbad63f701c5cff340d29d23516d058aea2deb5b4_cppui381,
        }},
        {{
            0xcd023da96a2033fd26952aecdaad57c57f62ba9ce4864486d81991f8fcd8075b736cf799ee243d8d9291c20285dfc5d_cppui381,
            0x146f298a42cf556357a296833b14967329b954633f3b0dff55fbd269317c79d1d67ae65c6626032261fda641f7121f1_cppui381,
        }},
        {{
            0x18da863345461ccc88fa8918d151de5fa527839e59ece3575c73ab805a78f66e712974f2e27e641e18731934dd72c484_cppui381,
            0x7e8b156d32a43b79e904543ff5e79949488e5993c6a86c976b07826ec0b48957b4de5287333bd3452cfb34aabc63db8_cppui381,
        }});
    constexpr int C1 = 980386333;
    constexpr value_type element_pow_2(
        {{
            0xd021823530aa495ad91e8ef633c8b36a6c6d5e5812fdb235aa35082f610dd3e5417f3f9b5476a5715bad9a03f41f531_cppui381,
            0x2ea43195614413f4c50621a1113ebc172ebb7d6233f741e4cc6c668d11937364a33df9bd3aec396eebc57c37d51cd19_cppui381,
        }},
        {{
            0xe28656d2e81bf9db44a2ed61847fcf8d1413b99a8e4f056cb8d33cc72953745cb3d9142ff9c1270741cf8e91ee7017a_cppui381,
            0x101cb4244b677c1f85235503d9215dd97521158b008bf22fcea5700a1bd7b9e83ecaa5c371e4259727b6984781409022_cppui381,
        }},
        {{
            0x96d2835c975421e540a1d70cdbbcf1f90ea98c39d5b894ab7185ae631efd6e4d0aa3896dca1cd280031806546151d9d_cppui381,
            0x194d9e3edf767e4c871506bf5d9b026f0998d835e46f1dd4717ba13922b78fec335ca5d9d1305420269bf7a423540b84_cppui381,
        }});
    constexpr value_type minus_element(
        {{
            0xbcb541d1b13fc594fc14212d90a4ddf17c52576770af10aedfba84a5459e398617c947053bd2358288c6d7fec77e06c_cppui381,
            0x11be4b08dffe4a0e1a01c8c4a45474e7c73620bffc64294fe6b998aa874fc6602f0b220f08bf7447224fdb3a8004a264_cppui381,
        }},
        {{
            0x14d03e9d7c6dc83d0291cbb0b7dac41293660ecbf5e43f9a9cb4cdb88b76fce9c812b90358bd1fbb25156554c50a4694_cppui381,
            0x139480a884f6404fe80b1b3b244a0e615632d5e32fa659f50f2b5d1669752c88648d635221f2f163f24610d6aad8152e_cppui381,
        }},
        {{
            0x186fad5ee753653cdfa65aab59ca91575a7ca915465568d385447ace613b30bda1ecf350234f7e97c4a360a0ef81c796_cppui381,
            0x179c40e15fb14491bb00b5467355bdea087379c855f07c7f95dabdaa660b48df35f9ad0fd2a1468688672cdc55fc95e_cppui381,
        }});

    static_assert(element1 + element2 == element_add, "add error");
    static_assert(element1 - element2 == element_sub, "sub error");
    static_assert(element1 * element2 == element_mul, "mul error");
    static_assert(element1.doubled() == element_dbl, "dbl error");
    static_assert(element2.inversed() == element_inv, "inv error");
    static_assert(element1.pow(C1) == element_pow_C, "pow error");
    static_assert(element2.squared() == element_pow_2, "pow error");
    static_assert(-element1 == minus_element, "minus error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt4_fq) {
    using policy_type = fields::mnt4<298>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        0x1a1f0b89abd62c63c669a0cafeaa872558eeb1dffedc21f8ded61768d6ae02a0b973de3139b_cppui298,
        0x13557b8d70144c7c1a18ce98b3f9f52fbadbcda323d5cb293304f09f24b8ce2cf00cce7a2e9_cppui298,
        0x2d7487171bea78dfe0826f63b2a47c5513ca7f8322b1ed2211db0807fb66d0cda980acab684_cppui298,
        0x6c98ffc3bc1dfe7ac50d2324ab091f59e12e43cdb0656cfabd126c9b1f53473c9670fb70b2_cppui298,
        0x1a2fe564e8a33991ffa2e6ae2b09192db6f041ebc2019591666e27112edf80a4b1ca21f8721_cppui298,
        0x343e171357ac58c78cd34195fd550e4ab1dd63bffdb843f1bdac2ed1ad5c054172e7bc62736_cppui298,
        0x33d2be79b5b111967f10c7e3873bdf19f47ca81c5eee3601cbe0514fbde6a5f756a0e47b663_cppui298,
        0x70c2a23f094063c8a1f7cad92abfa0e8988973db14a1d71dcd1e2706fdbd57204f00e60df5_cppui298,
        0xc5b94b8804b94b443d9fd27dd32200114bccb9ffa650ad2ef53048c53ad1c8723e31f1ba90_cppui298,
        0x287a003fd725d9e62fc1ac6c94f2b9bcdb5a038feace4f7502e02161bc73c2a0759a47e5d18_cppui298,
        0x21b070439b63f9fe8370da3a4a4227c73d471f530fc7f8a5570efa980a7e8e2cac33382ec66_cppui298};
    constexpr const_set_t constants1 = {72022261};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt4_fq2) {
    using policy_type = fields::fp2<fields::mnt4<298>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        {{
             0x1151c6efca2088ebb32162cb5d04bd8f95a6c5e45cb9e83551692a0073e7315ee195036fcc9_cppui298,
             0x2e2ba3c821f4d8efe6fc374a478954a2ea9081032d6e63cdc1398d234f189e0c31547552516_cppui298,
         },
         {
             0x19c25638d56bdfd7ac08d72ec325d17ec5c1fa835f75669818f1012dce65a3e1c09fde080b5_cppui298,
             0x886a482d7d20161b9a9952def31f16025a1e9063d38dab6594e964ec56de38fd93a7b47994_cppui298,
         },
         {
             0x2b141d289f8c68c35f2a39fa202a8f0e5b68c067bc2f4ecd6a5a2b2e424cd540a234e177d7e_cppui298,
             0x36b2484af9c6da51a0a5cc7836bb460310326a096aa73e841a8823721486819c0a8ef099eaa_cppui298,
         },
         {
             0x335eec843beecf7650f306a1e2cb9afd661a9c940be89c3b6e5d3ad386ae1e4a869c3bc7c15_cppui298,
             0x25a4ff454a22d78e2d52a21c58576342c4ee97fcf035891767eaf6d489aaba7c5819fa0ab82_cppui298,
         },
         {
             0x231b2db64e90b460eb4b5eebcc66ac09a7546b0d1fff02b81dc61c82a840d32680117a98e79_cppui298,
             0x21c4451e3efba1d3deee73d089740ff6fc2e4318ab8a5d8cb68ec9235f5262809110ce05bbd_cppui298,
         },
         {
             0x22a38ddf944111d76642c596ba097b1f2b4d8bc8b973d06aa2d25400e7ce62bdc32a06df992_cppui298,
             0x2087cbc2fcaf8b7d841df38f4625fa593eeb30d34c38acfd4c8e0845bd04ab4afd01d444a2b_cppui298,
         },
         {
             0x33eb8e3c5c5cf4e81905e973afc4b1809df27c74f41cd41228f5b807e25d30948a673525aff_cppui298,
             0x3666450712d00c28ce3b6c17d7be4d41cc15882ff7813140ff4985b80c69eabafdc9e702da2_cppui298,
         },
         {
             0x3b00f0f648ec6defbc68d6135d08331e58d16f9928496abfe6933dc4d0bece2ff435b3f1045_cppui298,
             0x1dfb4d888d1b137534826bc566536e54c0c3df69ba26f2173577bad45d7709d18fe89a2b3b5_cppui298,
         },
         {
             0x31226162b0ed7eb00b3bd868ac9850f8d652056121a55e3f6d639877f5697a940aca9d5634c_cppui298,
             0x26a24e91b8347e0ca08efef5b20a5f1636c1270de7be1c5f378bb2628f17e6ca36ff6f203c2_cppui298,
         },
         {
             0x220d259471ce468a9dd1a3d685c6dd6dd073d6afaf2eb4061cf410d312c6eceba5073857f4c_cppui298,
             0x3348d74a6f6825009030e5d759babd8c7093e82cd16b3fe7dc967bb21bbead3d8c6c9b1866d_cppui298,
         },
         {
             0x2a7db4dd7d199d7696b91839ebe7f15d008f0b4eb1ea3268e47be8006d455f6e841212f0338_cppui298,
             0xda3d80525454d7262de43bb01635a49aba5502fe135b6d074ab84dd9213f2c13452a10daeb_cppui298,
         }}};
    constexpr const_set_t constants1 = {11963068};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt4_fq4) {
    using policy_type = fields::fp4<fields::mnt4<298>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size - 1>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr value_type element1(
        {{
            0x2ec8702bfdda6a3cf3155e0b0fed1a45bdaeab2a50aeb383af86516091fdffb1dd929f408d4_cppui298,
            0x2db7a9802c314b194556ba1937cdf0e8fc38ecf09133815788dc03758c2a744cc0621330a85_cppui298,
        }},
        {{
            0x110b67194f3169301ef71fce5c6bd9734f5d59c83f311b79d1e90e3554a824092e83ee3d1aa_cppui298,
            0x4d71748423267212fc9b71f2851f906b7caff8a8a371f4948e2f4cea3fbca99854b384f062_cppui298,
        }});
    constexpr value_type element2(
        {{
            0x309f7b7995abfbc6b15f27b8e54d5179a473af5a22277fcad58416ff58c91d2ea14c618323a_cppui298,
            0x260b66c38ced3023011d2588d0f6b91bc73ed3df10dbafcaec7b8554e2957183759796ff89d_cppui298,
        }},
        {{
            0x277a801ef759c8fad30f16f3bb49ccbd22668b1dd1bc56f48be064b357f5f2248a6d4852d3e_cppui298,
            0x220b88fccb81a6ccaacfe031ad6c5d909e3d6415428afbe548f6111593e3310455b7ef1c6be_cppui298,
        }});
    constexpr value_type element_add(
        {{
            0x23986fd84c4c3fa15a9a0abeac4dbcd2cbec8951643218b04f25565f099a8c131937ea63b0d_cppui298,
            0x17f3947671e454d9fc99649cbfd7fb182d41ef9c936b16843f7276c98d935502d05293d0321_cppui298,
        }},
        {{
            0x3885e738468b322af20636c217b5a63071c3e4e610ed726e5dc972e8ac9e162db8f1368fee8_cppui298,
            0x26e2a0450db40dedda999750d5be56975608639fccc21b2e91d905e437defb9ddb03276b720_cppui298,
        }});
    constexpr value_type element_sub(
        {{
            0x39f8707faf6894d88b90b157738c77b8af70cd033d2b4e570fe74c621a617350a1ed541d69b_cppui298,
            0x7ac42bc9f441af64439949066d737cd34fa19118057d18c9c607e20a99502c94aca7c311e8_cppui298,
        }},
        {{
            0x256062c79f11c69795c283dfea0ebba2c32c9fdd7c18df237bedbb82dddec2b209bdbc4a46d_cppui298,
            0x1e9b0a18bdeae6b6ced451f2c3d24a62afc36ca856503e0235d1f5b9f1452a62953a5f929a5_cppui298,
        }});
    constexpr value_type element_mul(
        {{
            0x27adde109a6630689fafb4c98b4acafbbdf160d0149621253a6f216a963151d9d0b52cb9cd2_cppui298,
            0x37b128ce2442b354ea55c96ee99bb1d01eb2e51d999143d26348f5294c1568a824de5201c65_cppui298,
        }},
        {{
            0x2df4acf1f2669edc372a8fe2aa867cb43c6474034226815dcb27208b3795f66be5983574224_cppui298,
            0x2bad83d2b5ea04a48f2378550261b0ff190d4844c01791a81e46cf172891e4fdeebdc9aab90_cppui298,
        }});
    constexpr value_type element_dbl(
        {{
            0x21c1648ab47aae179c504110d6ed859ee527852192b94c69292790c042cf6e96557e28211a7_cppui298,
            0x1f9fd73311286fd040d2f92d26af32e5623c08ae13c2e810dbd2f4ea372857cc1b1d1001509_cppui298,
        }},
        {{
            0x2216ce329e62d2603dee3f9cb8d7b2e69ebab3907e6236f3a3d21c6aa95048125d07dc7a354_cppui298,
            0x9ae2e908464ce425f936e3e50a3f20d6f95ff15146e3e9291c5e99d47f795330a96709e0c4_cppui298,
        }});
    constexpr value_type element_inv(
        {{
            0x275fe52589436c84119e92e612e306bb38a2bc6b0d2285f569de5c172b58ceb759043300dd_cppui298,
            0x9f87ebb8f67b631cbdf45085d4d658b850f08be02e1fcb059cbc390b52fe0b2cdfffc694a1_cppui298,
        }},
        {{
            0x931764a541aedb5a54fd67d1de71b0d5060c4aa4f7616208caa1eca6f5d946556a9986d631_cppui298,
            0x38bf08f1554cbfd41d3973d1c82cc9c4bfada40c384601ab53394165e86b32cebcb8b2c8397_cppui298,
        }});
    constexpr value_type element_pow_C(
        {{
            0x1f856985ef90234acadd1a697214747a04c1dd270cdf98ca6a5c11ad800aa1d250b42457e0e_cppui298,
            0x2490e9fb909e98c51289b5effd25cdbdd6a996406ab808dd4d12f76105de85c739bf750909e_cppui298,
        }},
        {{
            0x243e7c0206aae33c5a4d9354486eeef1a784906a8217630c568edc3e0334ad03e8fb1831bd_cppui298,
            0x92a71ad08691b8a9daeb9be8c7419443a5fe4bf5fb6fb91ce362b376f54aabd065fc0c02e5_cppui298,
        }});
    constexpr int C1 = 702385922;
    constexpr value_type element_pow_2(
        {{
            0x3181739b8b5fcd6cc2bc6512bf1611ccac5b7018a0c63fa9841d6fb052ff6482a8721e4ca5f_cppui298,
            0x25bd4e0f0f15467cee761e28f8f9e2a693a50472d21744e08e254d14f75dff1fe16bacc266d_cppui298,
        }},
        {{
            0x1ac6a8f976369568d460f31c1df537a605c50fc6b1de558ff243d66b3d1f1ba4180eb981961_cppui298,
            0x1c017b5dfeadd6387bb4798bf3630eca6dcc3c8a4be79fc9b834c698dc1b7a3bc927eb6ce1_cppui298,
        }});
    constexpr value_type minus_element(
        {{
            0xd070ba1495fbc2556c51cfa38ff94a6d8872608bdf5671a865ec0a04f2e911b8814771f72d_cppui298,
            0xe17d24d1b08db490483c0ec111ebe0399fce4427d709946ad090e8b55021c80a545032f57c_cppui298,
        }},
        {{
            0x2ac414b3f808bd322ae35b36ec80d57946d8776acf72ff2463fc03cb8c846cc437232822e57_cppui298,
            0x36f864850507bf411a10c3e6209ab5e5de6ad1a8846cfb54ed021d323d30c633e05bde10f9f_cppui298,
        }});

    static_assert(element1 + element2 == element_add, "add error");
    static_assert(element1 - element2 == element_sub, "sub error");
    static_assert(element1 * element2 == element_mul, "mul error");
    static_assert(element1.doubled() == element_dbl, "dbl error");
    static_assert(element2.inversed() == element_inv, "inv error");
    static_assert(element1.pow(C1) == element_pow_C, "pow error");
    static_assert(element2.squared() == element_pow_2, "pow error");
    static_assert(-element1 == minus_element, "minus error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt6_fq) {
    using policy_type = fields::mnt6<298>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        0x13e0a5422b598aaf0c031434995b02459b127b91c1d19c61a0b7e6305b367e9d6c4ecef24ca_cppui298,
        0x3a2ee65237145a6fec8c095b3acfa5e6e969214f2b1dfb4f47fd258dd1eeadf4a606892870e_cppui298,
        0x12400fc71b33bebcaeb4a28a8b3df93fee45cd9cd39fe31c283be5e77fe9785ec815581abd7_cppui298,
        0x15813abd3b7f56a1695185dea7780b4b47df2986b00355a71933e679368384dc108845c9dbd_cppui298,
        0xdfd40332fa67aaf44e1616dbed9461cc900b87a694ef5531100271a1a620c361c6b0944a2e_cppui298,
        0x27c14a8456b3155e1806286932b6048b3624f72383a338c3416fcc60b66cfd3ad89d9de4994_cppui298,
        0x27f311284963f256e9c61f2f413960b1baebdfe7052158a992b9239586173c5ef5d48021c0b_cppui298,
        0x3191fd7720fb4dbf2833ec75eeda111fa486fa664a30355b5328ade83a1901b876542cd1c4c_cppui298,
        0x2a5232860338c9a2e55e313e9ccd6f738b5e09d156f002f151295a73f188f688a5228623423_cppui298,
        0x1a0957b1025cbf25d4e71aa0e1d0905acccadf4ee31b945787c0048db4d063ea43976d78f3_cppui298,
        0x27eed68b1be09bb33dd766d0af91aca6fb2353b2577e18331fc13fa652053595ddf1310db37_cppui298};
    constexpr const_set_t constants1 = {332771434};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt6_fq3) {
    using policy_type = fields::fp3<fields::mnt6<298>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr test_set_t elements1 = {
        {{
             0x2ca04ab44858078455357ce7027f603b2e60169f6e2728089c31d43de94857de0f8cf4fecff_cppui298,
             0x17fe793178a3dc42295619e37d3c39c9ae5dc0a738d046d9744e9bdf8058661f0c3c82295af_cppui298,
             0x1806278fd83496047a6ff4572fe4dabe56820a6b4d73c0b06771d763a8f37d1f4c1745525be_cppui298,
         },
         {
             0x39abbb38fd5dd88b187dc951f6853610c3bbda388b4040b59f85217073c9c7ee2639cdf06d5_cppui298,
             0x24e79da3e9004c8fa879550da47f43e42a1150804cdc9df23dd0597b7d7ae189a118b102252_cppui298,
             0x32cb5f242ff7a6e77fde5deb2257f93218176b243f55c0f764bdb40ec9319ee5bf8491383b7_cppui298,
         },
         {
             0x2a7c8a1ffe7bb9ad23d8cb33b017e75f5be62193e017b4297b3dcfd7afd66b98eb86c2ef3d3_cppui298,
             0x1169b081a6a026f87f4f3ebd8cecec1423941e36c5d3036f1a5cf84509793756315332b800_cppui298,
             0xf020ae6c0f21689b073d73d09502503d863a64b7379cd130bb6659bc4e967d1c15bd68a974_cppui298,
         },
         {
             0x2ec40b489234555b86922e9a54e6d91700da0baafc369be7bd25d8a422ba44233393270e62b_cppui298,
             0x2ee6575ad6ddb614cab73fdb21a9a4d21a823f6b05435d7bf6f7683ab01938c8b563d12735e_cppui298,
             0x210a4438ef77157f446c117156799078d4a06e8b276db44dc32d492b8cfd926cd6d2b41a208_cppui298,
         },
         {
             0x7e14908ff393a62f5c6e25db37271be6f44b06b1dfef0a4d359c6e98d2ad9eca128616b7ce_cppui298,
             0x307fb33edfa7981503d8f8236f9139d1e850e720d0c2a3ac956fc1882504ba72d3cf8056c88_cppui298,
             0x2c214a535d65c86b01d87d7a1609595037ccc97565bb242a93ff057a679728315267d4d3035_cppui298,
         },
         {
             0x1d71199b4975e8a660907ec8bc121189c68a5dfac2fe9b7c77ea82a52554fb88d4d9e9fd9fd_cppui298,
             0x2ffcf262f147b88452ac33c6fa7873935cbb814e71a08db2e89d37bf00b0cc3e18790452b5e_cppui298,
             0x300c4f1fb0692c08f4dfe8ae5fc9b57cad0414d69ae78160cee3aec751e6fa3e982e8aa4b7c_cppui298,
         },
         {
             0x24daec3d446e4157ea7d86931c7cab59005910419fa7bcca958bdef9bb0484751421c7be9a7_cppui298,
             0x1fc4de5a19d41e618210e55a07a542061d6a32b4617b18cd144f71d805f68911378d08697a_cppui298,
             0x2064daaf7ff56ed4460a7689139a2313270bdb5f204a03ad6d2f7aff766941f06e27e9a119e_cppui298,
         },
         {
             0x296448823914574c22b9cd9ccdc259206663d2d968fa3a4a017656de00a9da52417bf8c2b52_cppui298,
             0x3b3681274845f285af891a0d1d1ff27fcb167d902cb65b3a9bdccfab33b150d02eb20282f1b_cppui298,
             0x29a3f16f714a6894390659a393bef1c31bf8cad70868ef2e5cb7b2383159f6de9c938ae7d82_cppui298,
         },
         {
             0x1177e716e67def7292e404a289d4d931d353ca156b80072db8dbd2dbad9cf7b6259d8e5cf5_cppui298,
             0x2f7454d98c65041a40025a34485c4878a29e8c0065a72eefb9b5919d23906ef61261c14cb8_cppui298,
             0x1a53d2ba023b90bbaf5941b79dcd7d131bc9eba69c5cc78f00a0deedd904745cc00d2ff6bef_cppui298,
         },
         {
             0x39abbb38fd5dd88b187dc951f6853610c3bbda388b4040b59f85217073c9c7ee2639cdf06d5_cppui298,
             0x24e79da3e9004c8fa879550da47f43e42a1150804cdc9df23dd0597b7d7ae189a118b102252_cppui298,
             0x32cb5f242ff7a6e77fde5deb2257f93218176b243f55c0f764bdb40ec9319ee5bf8491383b7_cppui298,
         },
         {
             0xf2f3118fee21eddf4a4fe1e466d4eb167d5b8a4ab288c8c24475198c3f35c553ab30b01302_cppui298,
             0x23d1029bce964a2020846121cbb07522e7d80e9ce07f6dbb4c2a89f72ce34e143e037dd6a52_cppui298,
             0x23c9543d6f05905dcf6a86ae1907d42e3fb3c4d8cbdbf3e459074e7304483713fe28baada43_cppui298,
         }}};
    constexpr const_set_t constants1 = {1042617086};

    static_assert(elements1[e1] + elements1[e2] == elements1[e1_plus_e2], "add error");
    static_assert(elements1[e1] - elements1[e2] == elements1[e1_minus_e2], "sub error");
    static_assert(elements1[e1] * elements1[e2] == elements1[e1_mul_e2], "mul error");
    static_assert(elements1[e1].doubled() == elements1[e1_dbl], "dbl error");
    static_assert(elements1[e2].inversed() == elements1[e2_inv], "inv error");
    static_assert(elements1[e1].pow(constants1[C1]) == elements1[e1_pow_C1], "pow error");
    static_assert(elements1[e2].squared() == elements1[e2_pow_2], "sqr error");
    static_assert((elements1[e2].squared()).sqrt() == elements1[e2_pow_2_sqrt], "sqrt error");
    static_assert(-elements1[e1] == elements1[minus_e1], "neg error");
}

BOOST_AUTO_TEST_CASE(field_operation_test_mnt6_fq6) {
    using policy_type = fields::fp6_2over3<fields::mnt6<298>>;
    using value_type = typename policy_type::value_type;
    using test_set_t = std::array<value_type, elements_set_size - 1>;
    using const_set_t = std::array<constant_type, constants_set_size>;

    constexpr value_type element1(
        {{
            0x2b254b9c632ab1cb93e575c1b0c5d890eb0a7ee656612c7c37d1c5f03fd346cbd4f9ceae2e1_cppui298,
            0x7370368322d2e40fa97c49d1b9cdc00cc6005a779b8e377dff6108bc7416b71c8f0bfa9938_cppui298,
            0x25b755a137f30bc5da6b21b28357a20669667eb5f6cbb6b821d8939d1370a2886334e7f90b7_cppui298,
        }},
        {{
            0x37020ec205dfd50d6629d194bb28e0231094f047902048bed7db660cadd135b05cc5b187c39_cppui298,
            0x30dfac7da797127d24d3bd5b66895c5139146b253e894bcc68a9a9229849079d46ab1821c95_cppui298,
            0xc5e81aaf1ed4f51ffad6ff70fa2c46d9eda55721079f37f4a9899c394719d0280aabfbf094_cppui298,
        }});
    constexpr value_type element2(
        {{
            0x938d85408f45627918f1ccebb48acf97d3fad71ebbcb368dcbb1fa32d17a05bd452164ab02_cppui298,
            0x2c475110a74073f1b9e81bb00fd5eb59e4c7fbcdb4fe4c9eeaa820074d058fd59d61376e916_cppui298,
            0x195d2d3dabdbbbdcfaceba4f7aba9aa58b45a3f06df7344cff6afe5df3a4806deaee9b50a6_cppui298,
        }},
        {{
            0x2a7aec578f966ff93df221571efd5cb4f8a6d250f90a68f0f74b0ee56321df789c4611cfa1f_cppui298,
            0x21464c1876b0a316b6b927c9aa93cff327a0e4ea1e24cbce279ccbdd62eaa00d723ebe70606_cppui298,
            0xea64135530377ac3298f41053bab4e9de742ae37453aed2f1bbfedbed5f970d529f08c6a42_cppui298,
        }});
    constexpr value_type element_add(
        {{
            0x345e23f06c1f07f3257492906c0e858a684a2c58421ddfe5148ce5936ceae727a94be4f8de3_cppui298,
            0x337e5478d96da232b47fe04d2b72c75ab12801752eb73016ca9e30931446fb476651f71824e_cppui298,
            0x274d287512b0c783aa180d577b034bb0c21ad8f4fdab29fcf1cf4382f2aaea8f41e3d1ae15d_cppui298,
        }},
        {{
            0x25ad7f4c4e3c1ea45a4177e691398deb7305f3546fdafd1b0ead4f1b63b760f5aecbc357657_cppui298,
            0x16567cc8d70d8f3191b26a1fc8307d57ca7f80cb435e6305cfcd4f294df7f3776ea9d69229a_cppui298,
            0x1b04c2e044f0c6fe32466407635d79577d4e805584cda2523c54989f81d1340fd349c885ad6_cppui298,
        }});
    constexpr value_type element_sub(
        {{
            0x21ec73485a365ba4025658f2f57d2b976dcad1746aa479135b16a64d12bba67000a7b8637df_cppui298,
            0x16bf2e24d226e0b18a8a23f254b39f937dcdd91dde0a4b6db5c7165b27778fcf75cf883b023_cppui298,
            0x242182cd5d3550080abe360d8babf85c10b22476efec437351e1e3b734365a818485fe44011_cppui298,
        }},
        {{
            0xc87226a764965142837b03d9c2b836e17ee1df69715dfcde09057274aaf5637c07f9fb821a_cppui298,
            0xf99606530e66f666e1a9591bbf58c5e1173863b20647ffe410cdd45355e678fd46c59b168f_cppui298,
            0x3987bc42e623fe0816eef6ec04d4be70569bf9d2b575f9411955c0be544dba28784bb6f8653_cppui298,
        }});
    constexpr value_type element_mul(
        {{
            0x8d3a722d66e3deb9e3e23a817a672e4a7777b7227633de0cdbe83f3de0db084860ed6e05f5_cppui298,
            0x1d9da0ee2873cbddc6cbea8bd130b642a58252233a9517d821b23105867d1cc8f8e3762096c_cppui298,
            0x1ca200fb84e152e8e4cece1be0dc2c892996064d5127bea290c50cb5538c2d9a4d93a8e545e_cppui298,
        }},
        {{
            0x32d226e51e190838ce9857905d0baf2fe1893f23139523b467ac924adec99c81b0337d98e08_cppui298,
            0x279a3e076479ed256f9165dcff1c51903cd36e7d043177fa8eac4015d4b16dfcefe18db1392_cppui298,
            0x37b12fff7cb9a2602ab0a1e6ad39cbf4e2e16ae51507528e836e837fda74e19d3964c6518d0_cppui298,
        }});
    constexpr value_type element_dbl(
        {{
            0x1a7b1b6b7f1b3d34ddf0707e189f02353fdf2e889372a463af2a6609d26ad9645fb39d5c5c1_cppui298,
            0xe6e06d0645a5c81f52f893a3739b80198c00b4ef371c6efbfec21178e82d6e391e17f53270_cppui298,
            0xf9f2f7528abf1296afbc85fbdc295203c972e27d447b8db8338016379a590dd7c29cff216d_cppui298,
        }},
        {{
            0x3234a1b6c48583b8827928242d6511598af4114b06f0dce8ef3da642ae66b72d6f4b630f871_cppui298,
            0x25efdd2e07f3fe97ffccffb1842609b5dbf3070663c2e30410da2c6e83565b0743163043929_cppui298,
            0x18bd0355e3da9ea3ff5adfee1f4588db3db4aae420f3e6fe9531338728e33a0501557f7e128_cppui298,
        }});
    constexpr value_type element_inv(
        {{
            0x2229740213208804b7a307caecd43fae547ce1d4a393980be860a3ca420037a6fb3fedecdc8_cppui298,
            0x2c21a740569cfb57d5c15e6743b60af44fccd06ed1088ee0b126af8e26ef78d1513759ce38e_cppui298,
            0x2f372d4fb01505ba001564145f042ce04d94cc88f008922a6cd8ed6d8357afa68e18b0da09a_cppui298,
        }},
        {{
            0xbe1724a204fce65a1de9f1f6f5145dc012216eb836a0026d202fa913aee26166c271bb609_cppui298,
            0x22b82b44d7d1b00961e24fd93e35729ef571a5bbfcd087f8b8cbf8898719d9ebc972555655e_cppui298,
            0x1cd0fd8863f24b2bce803c67a11f46a07c5d9458d5377def93cd8eda67a76280f9135e447d4_cppui298,
        }});
    constexpr value_type element_pow_C(
        {{
            0x13f6912825e1f33c39c955863e222227e40b01a5d609dbf9823754cc371fb75459ba0e4832e_cppui298,
            0x27bcef7ccb3cedd9fc14b02f2e5f72f9df9375c9ce236eea4a4938f2559ea68dd6745dd114a_cppui298,
            0x26b25efbe6119e9ffe0ef0930f9f6e676c9d2a0363cd26e428ced3a5c6b5e45f9171c4ed025_cppui298,
        }},
        {{
            0x3a216edce558c508d70fa737a2165214e1040f52bdcb7bd982fb2ed3473b81ca0ab3d6224f8_cppui298,
            0x11fb3ef9eb611f7b499ab1a4966b50aee43d130ef1bd2dab0dd4d157e09c4f3522d32327bc_cppui298,
            0x2cb3c29d951cdc7e154524cb358680f48cfe823a4fa4bba794003b2682fb49efe7d7e13ce69_cppui298,
        }});
    constexpr int C1 = 671190979;
    constexpr value_type element_pow_2(
        {{
            0x39a90e53a451db4bd16cd928809d27b64dd89e69bf8d7550aaaf5ecb166527806f909b06272_cppui298,
            0x1f854c19c9a4e19b7fa4c05f119f0b01a8678c0b8f94244d07e56872f27569bde500d542cff_cppui298,
            0x369cd4cb21ddf49cbd57a11f7d59331dc46c98bd6e35eda00ce9d3a31501e5b72d3614f74a0_cppui298,
        }},
        {{
            0x373b855899523e4c57836379670894e20c69c49864dec3a935b3953332f9909e021755b5b37_cppui298,
            0x1f7ba018368f998f5361fc232c07fac7a3a34d90b53492ab9f7d0c1f34b4935b17bc242fda0_cppui298,
            0x1cbab6642ca9a2c1111552f87aeb3d87dfc6fd9a89e77add4a829d3321af7916982bd42cde6_cppui298,
        }});
    constexpr value_type minus_element(
        {{
            0x10aa3030e40f7496b5f505439826d65bab2b505dc2ee881888a75fe66d686d6775463151d20_cppui298,
            0x34987865150cf8214f42b6682d4fd2ebc9d5c99c9f96d11ce083154ae5fa48c1814f40566c9_cppui298,
            0x1618262c0f471a9c6f6f5952c5950ce62ccf508e2283fddc9ea0923999cb11aae70b1806f4a_cppui298,
        }},
        {{
            0x4cd6d0b415a5154e3b0a9708dc3cec985a0defc892f6bd5e89dbfc9ff6a7e82ed7a4e783c8_cppui298,
            0xaefcf4f9fa313e52506bda9e263529b5d21641edac668c857cf7cb414f2ac960394e7de36c_cppui298,
            0x2f70fa22554cd7104a2d0b0e3949ea7ef75b79d208d5c11575e08c1318ca1730c9954040f6d_cppui298,
        }});

    static_assert(element1 + element2 == element_add, "add error");
    static_assert(element1 - element2 == element_sub, "sub error");
    static_assert(element1 * element2 == element_mul, "mul error");
    static_assert(element1.doubled() == element_dbl, "dbl error");
    static_assert(element2.inversed() == element_inv, "inv error");
    static_assert(element1.pow(C1) == element_pow_C, "pow error");
    static_assert(element2.squared() == element_pow_2, "pow error");
    static_assert(-element1 == minus_element, "minus error");
}

BOOST_AUTO_TEST_SUITE_END()
