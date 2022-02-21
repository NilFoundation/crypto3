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

#define BOOST_TEST_MODULE hash_h2c_test

#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <type_traits>
#include <tuple>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/h2c.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/type_traits.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    std::cout << e.data[0].data << ", " << e.data[1].data << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, curves::coordinates::jacobian_with_a4_0>::value>::type
    print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "], Z:[";
    print_field_element(os, p.Z);
    os << "] )" << std::endl;
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

            template<typename CurveParams, typename Form, typename Coordinates>
            struct print_log_value<curves::detail::curve_element<CurveParams, Form, Coordinates>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams, Form, Coordinates> const &p) {
                    print_curve_point(os, p);
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

template<typename Hash>
typename std::enable_if<hashes::is_h2c<Hash>::value>::type
    check_hash_to_curve(const std::string &msg_str, const typename Hash::digest_type &expected) {

    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    typename Hash::digest_type result = hash<Hash>(msg);
    BOOST_CHECK_EQUAL(result, expected);

    if (msg.size() > 1) {
        std::size_t offset = std::rand() % (msg.size() - 1) + 1;
        auto acc_deducible = hash<Hash>(msg.cbegin(), msg.cbegin() + offset);
        nil::crypto3::accumulator_set<Hash> &acc = acc_deducible;
        hash<Hash>(msg.cbegin() + offset, msg.cend(), acc);
        typename Hash::digest_type result1 = nil::crypto3::accumulators::extract::hash<Hash>(acc);
        BOOST_CHECK_EQUAL(result1, expected);
    }
}

BOOST_AUTO_TEST_SUITE(hash_h2c_manual_tests)

BOOST_AUTO_TEST_CASE(hash_to_curve_bls12_381_g1_h2c_sha256_test) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type<>;
    using group_value_type = typename group_type::value_type;
    using integral_type = typename group_type::field_type::integral_type;
    using hash_type = hashes::h2c<group_type>;

    using samples_type = std::vector<std::tuple<std::string, group_value_type>>;
    samples_type samples {
        {"",
         group_value_type(integral_type("7943115757214008313629570493037810448520063234226241118933528595574500083086"
                                        "20925451441746926395141598720928151969"),
                          integral_type("1343412193624222137939591894701031123123641958980729764240763391191550653712"
                                        "890272928110356903136085217047453540965"),
                          1)},
        {"abc",
         group_value_type(integral_type("5137384602176159439212852477034485676478758747455673727961641554723831277"
                                        "56567780059136521508428662765965997467907"),
                          integral_type("1786897908129645780825838873875416513994655004408749907941296449131605892"
                                        "957529391590865627492442562626458913769565"),
                          1)},
        {"abcdef0123456789",
         group_value_type(integral_type("275162876137213708468320729543710526816637518402774837215695"
                                        "2770986741873369176463286511518644061904904607431667096"),
                          integral_type("563036982304416203921640398061260377444881693369806087719971"
                                        "277317609936727208012968659302318886963927918562170633"),
                          1)},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         group_value_type(
             integral_type("33804326948876744397730824181920837205847480807049591729785862299214753152204341"
                           "65460350679208315690319508336723080"),
             integral_type("36985267390728644087495710822706285617644155774454041155969909198015237931383482"
                           "54443092179877354467167123794222392"),
             1)},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         group_value_type(
             integral_type("12569674255428230696945135509180256894900364785011816005259446539528461008878487"
                           "29514132077573887342346961531624702"),
             integral_type("88037208240369454347695990925650426721558805545001688510379770085674653213458594"
                           "2561958795215862304181527267736264"),
             1)},
        // {"",
        //  group_value_type(
        //      integral_type(""),
        //      integral_type(""),
        //      1)},
    };

    for (auto &s : samples) {
        check_hash_to_curve<hash_type>(std::get<0>(s), std::get<1>(s));
    }
}

// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
BOOST_AUTO_TEST_CASE(hash_to_curve_bls12_381_g2_h2c_sha256_test) {
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g2_type<>;
    using group_value_type = typename group_type::value_type;
    using field_value_type = typename group_type::field_type::value_type;
    using integral_type = typename group_type::field_type::integral_type;
    using hash_type = hashes::h2c<group_type>;

    using samples_type = std::vector<std::tuple<std::string, group_value_type>>;
    samples_type samples {
        {"",
         group_value_type(field_value_type(integral_type("19354805336845174941142151562851080662656573665208680741935"
                                                         "4395577367693778571452628423727082668900187036482254730"),
                                           integral_type("89193000964309942330810277795125089969455920364772498836102"
                                                         "2851024990473423938537113948850338098230396747396259901")),
                          field_value_type(integral_type("77171727205583415237828170597267125700535714547880090837365"
                                                         "9404991537354153455452961747174765859335819766715637138"),
                                           integral_type("28103101185821266340411334541807053043930791391032529565024"
                                                         "04531123692847658283858246402311867775854528543237781718")),
                          field_value_type::one())},
        {"abc", group_value_type(
                    field_value_type(integral_type("424958340463073975547762735517193206833255107941790909009827635"
                                                   "556634414746056077714431786321247871628515967727334"),
                                     integral_type("301867980397012787726282639381447252855741350432919474049536385"
                                                   "2840690589001358162447917674089074634504498585239512")),
                    field_value_type(integral_type("362130818512839545988899552652712755661476860447213217606042330"
                                                   "2734876099689739385100475320409412954617897892887112"),
                                     integral_type("102447784096837908713257069727879782642075240724579670654226801"
                                                   "345708452018676587771714457671432122751958633012502")),
                    field_value_type::one())},
        {"abcdef0123456789",
         group_value_type(
             field_value_type(integral_type("278579072823914661770244330824853538101603574852069839969013232"
                                            "5213972292102741627498014391457605127656937478044880"),
                              integral_type("385570939363183188091016781827643518714796337112619879965480309"
                                            "9743427431977934703201153169947378798970358200024876")),
             field_value_type(integral_type("821938378705205565995357931232097952117504537366318395539093959"
                                            "918654729488074273868834599496909844419980823111624"),
                              integral_type("180242033557577995098293558042145430208756792638522270794752735"
                                            "3462942499437987207287862072369052390195154530059198")),
             field_value_type::one())},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         group_value_type(
             field_value_type(integral_type("394904109851368845549123118074972479469719294319673003085328501"
                                            "1755806989731870696216017360514887069032515603535834"),
                              integral_type("141689369450613197680900293521221631713294194257076384932306538"
                                            "1335907430566747765697423320407614734575486820936593")),
             field_value_type(integral_type("322745371086383503299296260585144940139139935513544272889379018"
                                            "6263669279022343042444878900124369614767241382891922"),
                              integral_type("149873883407375987188646612293399676447188951453282792720277792"
                                            "2460876335493588931070034160657995151627624577390178")),
             field_value_type::one())},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         group_value_type(
             field_value_type(integral_type("254155017921606149907129844368549510385368618440139550318910532"
                                            "874259603395336903946742408725761795820224536519988"),
                              integral_type("276843145929673042677916621854414979160158598623313058301150172"
                                            "7704972362141149700714785450629498506208393873593705")),
             field_value_type(integral_type("175533934474433745731856511606202566998475061793772124522071142"
                                            "5551575490663761638802010265668157125441634554205566"),
                              integral_type("560643043433789571968941329642646582974304556331567393300563909"
                                            "451776257854214387388500126524984624222885267024722")),
             field_value_type::one())},
        // {"",
        //  group_value_type(
        //      field_value_type(integral_type(""),
        //                       integral_type("")),
        //      field_value_type(integral_type(""),
        //                       integral_type("")),
        //      field_value_type::one())},
    };

    for (auto &s : samples) {
        check_hash_to_curve<hash_type>(std::get<0>(s), std::get<1>(s));
    }
}

BOOST_AUTO_TEST_SUITE_END()
