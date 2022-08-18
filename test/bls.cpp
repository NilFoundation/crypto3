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

#define BOOST_TEST_MODULE bls_signature_pubkey_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify_single_msg.hpp>

#include <nil/crypto3/pubkey/bls.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <vector>
#include <string>
#include <utility>
#include <random>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<typename curves::bls12<381>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g2_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g2_type<>::value_type const &e) {
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

const std::string BasicSchemeDstMss_str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const std::vector<std::uint8_t> BasicSchemeDstMss(BasicSchemeDstMss_str.begin(), BasicSchemeDstMss_str.end());

const std::string BasicSchemeDstMps_str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const std::vector<std::uint8_t> BasicSchemeDstMps(BasicSchemeDstMps_str.begin(), BasicSchemeDstMps_str.end());

const std::string PopSchemeDstMps_str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const std::vector<std::uint8_t> PopSchemeDstMps(PopSchemeDstMps_str.begin(), PopSchemeDstMps_str.end());

const std::string PopSchemeDstMps_hash_pubkey_to_point_str = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const std::vector<std::uint8_t> PopSchemeDstMps_hash_pubkey_to_point(PopSchemeDstMps_hash_pubkey_to_point_str.begin(),
                                                                     PopSchemeDstMps_hash_pubkey_to_point_str.end());

BOOST_AUTO_TEST_SUITE(bls_serialization)

BOOST_AUTO_TEST_CASE(g1_serialization_test) {
    using nil::marshalling::curve_element_serializer;
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type<>;
    using group_value_type = typename group_type::value_type;
    using integral_type = typename group_value_type::field_type::integral_type;
    using serializer_bls = curve_element_serializer<curve_type>;

    // Affine point
    group_value_type p1 = group_value_type(
        integral_type("3604356284473401589952441283763873345227059496255462321551435982658302670661662992"
                      "473691215983035545839478217804772"),
        integral_type("1327250267123059730920952227120753767562776844810778978087227730380440847250307685"
                      "059082654296549055086001069530253"),
        1);
    BOOST_ASSERT(p1.is_well_formed());
    auto p1_octets = serializer_bls::point_to_octets(p1);
    auto p1_octets_compressed = serializer_bls::point_to_octets_compress(p1);
    group_value_type p1_restored = serializer_bls::octets_to_g1_point(p1_octets);
    group_value_type p1_restored_c = serializer_bls::octets_to_g1_point(p1_octets_compressed);
    BOOST_CHECK_EQUAL(p1, p1_restored);
    BOOST_CHECK_EQUAL(p1, p1_restored_c);

    // Point at infinity
    group_value_type p2;
    BOOST_ASSERT(p2.is_well_formed());
    auto p2_octets = serializer_bls::point_to_octets(p2);
    auto p2_octets_compressed = serializer_bls::point_to_octets_compress(p2);
    group_value_type p2_restored = serializer_bls::octets_to_g1_point(p2_octets);
    group_value_type p2_restored_c = serializer_bls::octets_to_g1_point(p2_octets_compressed);
    BOOST_CHECK_EQUAL(p2, p2_restored);
    BOOST_CHECK_EQUAL(p2, p2_restored_c);

    // Not affine point
    group_value_type p3 =
        group_value_type(integral_type("22084667108196577588735774911639564274189527381579300109027515"
                                       "83108281379986810985262913684437872498514441158400394"),
                         integral_type("12406587907457130429434069344825464684261259614486728581982359"
                                       "85082377053414117332539588331993386548779151154859825"),
                         integral_type("29038518576972662592822044837006359977182512190287782275798717"
                                       "38931918971045982981178959474623545838060738545723395"));
    BOOST_ASSERT(p3.is_well_formed());
    auto p3_octets = serializer_bls::point_to_octets(p3);
    auto p3_octets_compressed = serializer_bls::point_to_octets_compress(p3);
    group_value_type p3_restored = serializer_bls::octets_to_g1_point(p3_octets);
    group_value_type p3_restored_c = serializer_bls::octets_to_g1_point(p3_octets_compressed);
    BOOST_CHECK_EQUAL(p3, p3_restored);
    BOOST_CHECK_EQUAL(p3, p3_restored_c);

    // Generated by blst
    group_value_type p4 = group_value_type(
        integral_type("30311851368840285580047084465003591340796954930450639493358501068943489413531875"
                      "79165196235778982806727098663057122"),
        integral_type("49014011513970003088185148750418624927679653147470313898591903023733897777517111"
                      "6279207970871898981207024969188354"),
        1);
    std::array<std::uint8_t, 96> etalon_serialization = {
        19,  177, 170, 117, 66,  165, 66,  62,  33,  216, 232, 75,  68,  114, 195, 22,  100, 65,  44,  198,
        4,   166, 102, 233, 253, 240, 59,  175, 60,  117, 142, 114, 140, 122, 17,  87,  110, 187, 1,   17,
        10,  195, 154, 13,  249, 86,  54,  226, 3,   47,  59,  177, 79,  209, 127, 104, 230, 130, 164, 206,
        227, 144, 80,  218, 232, 108, 210, 224, 134, 54,  24,  213, 34,  197, 206, 159, 112, 179, 225, 226,
        212, 59,  219, 130, 43,  143, 114, 111, 168, 245, 74,  168, 47,  144, 4,   2};
    std::array<std::uint8_t, 48> etalon_serialization_comp = {
        147, 177, 170, 117, 66,  165, 66,  62,  33,  216, 232, 75,  68,  114, 195, 22,
        100, 65,  44,  198, 4,   166, 102, 233, 253, 240, 59,  175, 60,  117, 142, 114,
        140, 122, 17,  87,  110, 187, 1,   17,  10,  195, 154, 13,  249, 86,  54,  226};

    auto p4_octets = serializer_bls::point_to_octets(p4);
    auto p4_octets_comp = serializer_bls::point_to_octets_compress(p4);

    BOOST_CHECK_EQUAL(std::distance(etalon_serialization.begin(), etalon_serialization.end()),
                      std::distance(p4_octets.begin(), p4_octets.end()));
    BOOST_CHECK_EQUAL(std::distance(etalon_serialization_comp.begin(), etalon_serialization_comp.end()),
                      std::distance(p4_octets_comp.begin(), p4_octets_comp.end()));
    auto p4_octets_it = p4_octets.begin();
    auto p4_octets_comp_it = p4_octets_comp.begin();
    auto etalon_serialization_it = etalon_serialization.begin();
    auto etalon_serialization_comp_it = etalon_serialization_comp.begin();
    while (p4_octets_it != p4_octets.end() && etalon_serialization_it != etalon_serialization.end()) {
        BOOST_CHECK_EQUAL(*p4_octets_it++, *etalon_serialization_it++);
    }
    while (p4_octets_comp_it != p4_octets_comp.end() &&
           etalon_serialization_comp_it != etalon_serialization_comp.end()) {
        BOOST_CHECK_EQUAL(*p4_octets_comp_it++, *etalon_serialization_comp_it++);
    }
}

BOOST_AUTO_TEST_CASE(g2_serialization_test) {
    using nil::marshalling::curve_element_serializer;
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g2_type<>;
    using group_value_type = typename group_type::value_type;
    using integral_type = typename group_value_type::field_type::integral_type;
    using serializer_bls = curve_element_serializer<curve_type>;

    // Affine point
    group_value_type p1 = group_value_type(
        {{integral_type("85911141189038341422217999965810909168006256466381521648082748107372745388299551"
                        "9337819063587669418425211221549283"),
          integral_type("38652946747836373505232449343138682065351453822989118701578533663043001622363102"
                        "79903647373322307985974413380042255")}},
        {{integral_type("11185637828916832078768174243254972746778201844765270288305164561940707627068745"
                        "97608097527159814883098414084023916"),
          integral_type("24808054598506349709552229822047321779605439703657724013272122538247253994600104"
                        "08048001497870419741858246203802842")}},
        {{1, 0}});
    BOOST_ASSERT(p1.is_well_formed());
    auto p1_octets = serializer_bls::point_to_octets(p1);
    auto p1_octets_compressed = serializer_bls::point_to_octets_compress(p1);
    group_value_type p1_restored = serializer_bls::octets_to_g2_point(p1_octets);
    group_value_type p1_restored_c = serializer_bls::octets_to_g2_point(p1_octets_compressed);
    BOOST_CHECK_EQUAL(p1, p1_restored);
    BOOST_CHECK_EQUAL(p1, p1_restored_c);

    // Point at infinity
    group_value_type p2;
    BOOST_ASSERT(p2.is_well_formed());
    auto p2_octets = serializer_bls::point_to_octets(p2);
    auto p2_octets_compressed = serializer_bls::point_to_octets_compress(p2);
    group_value_type p2_restored = serializer_bls::octets_to_g2_point(p2_octets);
    group_value_type p2_restored_c = serializer_bls::octets_to_g2_point(p2_octets_compressed);
    BOOST_CHECK_EQUAL(p2, p2_restored);
    BOOST_CHECK_EQUAL(p2, p2_restored_c);

    // Not affine point
    group_value_type p3 =
        group_value_type({{integral_type("290953753847619202533108629578949989188583860516563349688436"
                                         "1019865954182721618711143316934175637891431477491613012"),
                           integral_type("368137581722696064589677955863335336277512129551843496644195"
                                         "2529453263026919297432456777936746126473663181000071326")}},
                         {{integral_type("380942359543145707855843939767390378902254098363111911764743"
                                         "0337095281824700234046387711064098816968180821028280990"),
                           integral_type("242844158649419580306404578813978370873620848181595711466624"
                                         "627022441036207994945966265054808015025632487127506616")}},
                         {{integral_type("436672409349779794890553748509232825356025978203835354321194"
                                         "85577859579140548640413235169124507251907021664872300"),
                           integral_type("583765897940425051133327959880548965930101581874240474476036"
                                         "503438461199993852443675110705859721269143034948933658")}});
    BOOST_ASSERT(p3.is_well_formed());
    auto p3_octets = serializer_bls::point_to_octets(p3);
    auto p3_octets_compressed = serializer_bls::point_to_octets_compress(p3);
    group_value_type p3_restored = serializer_bls::octets_to_g2_point(p3_octets);
    group_value_type p3_restored_c = serializer_bls::octets_to_g2_point(p3_octets_compressed);
    BOOST_CHECK_EQUAL(p3, p3_restored);
    BOOST_CHECK_EQUAL(p3, p3_restored_c);

    // Generated by blst
    group_value_type p4 =
        group_value_type({{integral_type("986915135914398354429507129337950846494088465187165144608943"
                                         "919532265387278101113414017664528112161554123568767170"),
                           integral_type("240610815317522947303384625207408526547682381889040357486642"
                                         "4879097778273241785181376579099627133390707436080946760")}},
                         {{integral_type("905356155402453036694818402428447875811858561324452962669988"
                                         "634216455237774846815387092699242963228002075684722919"),
                           integral_type("189475011967749777665668577550527779817561737907101306360710"
                                         "7829708998161751301035336528744906948117796249796317894")}},
                         {{1, 0}});
    std::array<std::uint8_t, 4 * 48> etalon_serialization = {
        15,  161, 255, 48,  78,  57,  204, 220, 25,  221, 164, 252, 248, 14,  56,  126, 186, 135, 228, 188, 145, 181,
        52,  200, 97,  99,  213, 46,  0,   199, 193, 89,  187, 88,  29,  135, 173, 244, 86,  36,  83,  54,  67,  164,
        6,   137, 94,  72,  6,   105, 128, 128, 93,  48,  176, 11,  4,   246, 138, 48,  180, 133, 90,  142, 192, 24,
        193, 111, 142, 31,  76,  111, 110, 234, 153, 90,  208, 192, 31,  124, 95,  102, 49,  158, 99,  52,  220, 165,
        94,  251, 68,  69,  121, 16,  224, 194, 12,  79,  120, 253, 220, 93,  66,  103, 2,   14,  45,  152, 92,  38,
        157, 191, 160, 220, 111, 178, 180, 100, 124, 193, 99,  138, 88,  216, 149, 205, 140, 64,  62,  114, 77,  7,
        39,  210, 13,  207, 114, 126, 191, 250, 209, 139, 146, 198, 5,   225, 217, 3,   219, 5,   255, 151, 44,  135,
        176, 253, 38,  170, 35,  218, 150, 221, 234, 64,  32,  144, 147, 122, 96,  34,  55,  118, 246, 163, 226, 254,
        141, 10,  13,  215, 118, 216, 190, 77,  155, 1,   84,  23,  228, 169, 88,  231};
    std::array<std::uint8_t, 2 * 48> etalon_serialization_comp = {
        143, 161, 255, 48,  78,  57,  204, 220, 25,  221, 164, 252, 248, 14,  56,  126, 186, 135, 228, 188,
        145, 181, 52,  200, 97,  99,  213, 46,  0,   199, 193, 89,  187, 88,  29,  135, 173, 244, 86,  36,
        83,  54,  67,  164, 6,   137, 94,  72,  6,   105, 128, 128, 93,  48,  176, 11,  4,   246, 138, 48,
        180, 133, 90,  142, 192, 24,  193, 111, 142, 31,  76,  111, 110, 234, 153, 90,  208, 192, 31,  124,
        95,  102, 49,  158, 99,  52,  220, 165, 94,  251, 68,  69,  121, 16,  224, 194};
    auto p4_octets = serializer_bls::point_to_octets(p4);
    auto p4_octets_comp = serializer_bls::point_to_octets_compress(p4);

    BOOST_CHECK_EQUAL(std::distance(etalon_serialization.begin(), etalon_serialization.end()),
                      std::distance(p4_octets.begin(), p4_octets.end()));
    BOOST_CHECK_EQUAL(std::distance(etalon_serialization_comp.begin(), etalon_serialization_comp.end()),
                      std::distance(p4_octets_comp.begin(), p4_octets_comp.end()));
    auto p4_octets_it = p4_octets.begin();
    auto p4_octets_comp_it = p4_octets_comp.begin();
    auto etalon_serialization_it = etalon_serialization.begin();
    auto etalon_serialization_comp_it = etalon_serialization_comp.begin();
    while (p4_octets_it != p4_octets.end() && etalon_serialization_it != etalon_serialization.end()) {
        BOOST_CHECK_EQUAL(*p4_octets_it++, *etalon_serialization_it++);
    }
    while (p4_octets_comp_it != p4_octets_comp.end() &&
           etalon_serialization_comp_it != etalon_serialization_comp.end()) {
        BOOST_CHECK_EQUAL(*p4_octets_comp_it++, *etalon_serialization_comp_it++);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// TODO: add checks for wrong signatures
template<typename Scheme, typename MsgRange>
void conformity_test(const std::vector<private_key<Scheme>> &sks,
                     const std::vector<MsgRange> &msgs,
                     const std::vector<typename public_key<Scheme>::signature_type> &etalon_sigs) {
    assert(std::distance(std::cbegin(sks), std::cend(sks)) > 1);
    assert(std::distance(std::cbegin(sks), std::cend(sks)) == std::distance(std::cbegin(msgs), std::cend(msgs)) &&
           (std::distance(std::cbegin(sks), std::cend(sks)) + 1) ==
               std::distance(std::cbegin(etalon_sigs), std::cend(etalon_sigs)));

    using scheme_type = Scheme;

    using signing_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;
    using aggregation_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    using aggregate_verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregate_verification_policy<Scheme>>::type;

    using verification_acc_set = verification_accumulator_set<verification_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;
    using signing_acc_set = signing_accumulator_set<signing_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode>;
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set::features_type>::type;
    using aggregate_verification_acc_set = aggregate_verification_accumulator_set<aggregate_verification_mode>;
    using aggregate_verification_acc =
        typename boost::mpl::front<typename aggregate_verification_acc_set::features_type>::type;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;

    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using integral_type = typename _privkey_type::integral_type;

    using msg_type = MsgRange;

    std::random_device rd;
    std::mt19937 gen(rd());

    ///////////////////////////////////////////////////////////////////////////////
    // Sign
    auto sks_iter = sks.begin();
    auto msgs_iter = msgs.begin();
    auto etalon_sigs_iter = etalon_sigs.begin();

    // sign(range, prkey)
    // verify(range, pubkey)
    signature_type sig = ::nil::crypto3::sign(*msgs_iter, *sks_iter);
    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    const pubkey_type &pubkey = *sks_iter;
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sig, pubkey)), true);

    // sign(first, last, prkey)
    // verify(first, last, pubkey)
    sig = ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter);
    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(msgs_iter->begin(), msgs_iter->end(), sig, pubkey)),
                      true);

    // sign(first, last, acc)
    // verify(first, last, acc)
    std::uniform_int_distribution<> distrib(0, msgs_iter->size() - 1);
    signing_acc_set sign_acc0(*sks_iter);
    auto part_msg_iter = msgs_iter->begin() + distrib(gen);
    ::nil::crypto3::sign<scheme_type>(msgs_iter->begin(), part_msg_iter, sign_acc0);
    sign_acc0(part_msg_iter, nil::crypto3::accumulators::iterator_last = msgs_iter->end());
    sig = boost::accumulators::extract_result<signing_acc>(sign_acc0);
    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    verification_acc_set verify_acc0(pubkey, nil::crypto3::accumulators::signature = sig);
    ::nil::crypto3::verify<scheme_type>(msgs_iter->begin(), part_msg_iter, verify_acc0);
    verify_acc0(part_msg_iter, nil::crypto3::accumulators::iterator_last = msgs_iter->end());
    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<verification_acc>(verify_acc0), true);

    // sign(range, acc)
    // verify(range, acc)
    signing_acc_set sign_acc1(*sks_iter);
    msg_type part_msg;
    std::copy(msgs_iter->begin(), part_msg_iter, std::back_inserter(part_msg));
    ::nil::crypto3::sign<scheme_type>(part_msg, sign_acc1);
    part_msg.clear();
    std::copy(part_msg_iter, msgs_iter->end(), std::back_inserter(part_msg));
    sign_acc1(part_msg);
    sig = boost::accumulators::extract_result<signing_acc>(sign_acc1);
    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    verification_acc_set verify_acc1(pubkey, nil::crypto3::accumulators::signature = sig);
    part_msg.clear();
    std::copy(msgs_iter->begin(), part_msg_iter, std::back_inserter(part_msg));
    ::nil::crypto3::verify<scheme_type>(part_msg, verify_acc1);
    part_msg.clear();
    std::copy(part_msg_iter, msgs_iter->end(), std::back_inserter(part_msg));
    verify_acc1(part_msg);
    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<verification_acc>(verify_acc1), true);

    // sign(range, prkey, out)
    // verify(range, pubkey, out)
    std::vector<signature_type> sig_out;
    ::nil::crypto3::sign(*msgs_iter, *sks_iter, std::back_inserter(sig_out));
    BOOST_CHECK_EQUAL(sig_out.back(), *etalon_sigs_iter);
    std::vector<bool> bool_out;
    ::nil::crypto3::verify(*msgs_iter, sig_out.back(), pubkey, std::back_inserter(bool_out));
    BOOST_CHECK_EQUAL(bool_out.back(), true);

    // sign(first, last, prkey, out)
    // verify(first, last, pubkey, out)
    ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter, std::back_inserter(sig_out));
    BOOST_CHECK_EQUAL(sig_out.back(), *etalon_sigs_iter);
    ::nil::crypto3::verify(msgs_iter->begin(), msgs_iter->end(), sig_out.back(), pubkey, std::back_inserter(bool_out));
    BOOST_CHECK_EQUAL(bool_out.back(), true);

    sks_iter++;
    msgs_iter++;
    etalon_sigs_iter++;

    ///////////////////////////////////////////////////////////////////////////////
    // Agregate
    std::vector<const pubkey_type *> pks;
    std::vector<signature_type> sigs;

    pks.emplace_back(&*sks_iter);
    sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));

    BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

    // TODO: add aggregate call with iterator output
    auto agg_acc = aggregation_acc_set();
    ::nil::crypto3::aggregate<scheme_type>(sigs, agg_acc);
    // ::nil::crypto3::aggregate<scheme_type>(sigs.end() - 1, sigs.end(), agg_acc);

    auto agg_ver_acc = aggregate_verification_acc_set(etalon_sigs.back());
    ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

    sks_iter++;
    msgs_iter++;
    etalon_sigs_iter++;

    while (sks_iter != sks.end() && msgs_iter != msgs.end() && etalon_sigs_iter != (etalon_sigs.end() - 1)) {
        pks.emplace_back(&*sks_iter);
        sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));

        BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
        BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

        ::nil::crypto3::aggregate<scheme_type>(sigs.end() - 1, sigs.end(), agg_acc);
        ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

        sks_iter++;
        msgs_iter++;
        etalon_sigs_iter++;
    }

    signature_type agg_sig = ::nil::crypto3::aggregate<scheme_type>(sigs);
    std::vector<signature_type> agg_sig_out;
    ::nil::crypto3::aggregate<scheme_type>(sigs, std::back_inserter(agg_sig_out));
    BOOST_CHECK_EQUAL(agg_sig, *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(agg_sig_out.back(), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<aggregation_acc>(agg_acc), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(etalon_sigs.back(), *etalon_sigs_iter);

    // TODO: extend public interface to be able to supply signature into accumulator
    agg_ver_acc(agg_sig);
//    ::nil::crypto3::aggregate_verify<scheme_type>(agg_sig, agg_ver_acc);
    auto res = boost::accumulators::extract_result<aggregate_verification_acc>(agg_ver_acc);
    BOOST_CHECK_EQUAL(res, true);
}

// TODO: add checks for wrong signatures
template<typename Scheme, typename MsgRange>
void self_test(const std::vector<private_key<Scheme>> &sks, const std::vector<MsgRange> &msgs) {
    assert(std::distance(std::cbegin(sks), std::cend(sks)) > 1);
    assert(std::distance(std::cbegin(sks), std::cend(sks)) == std::distance(std::cbegin(msgs), std::cend(msgs)));

    using scheme_type = Scheme;

    using signing_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;
    using aggregation_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    using aggregate_verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregate_verification_policy<Scheme>>::type;

    using verification_acc_set = verification_accumulator_set<verification_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;
    using signing_acc_set = signing_accumulator_set<signing_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode>;
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set::features_type>::type;
    using aggregate_verification_acc_set = aggregate_verification_accumulator_set<aggregate_verification_mode>;
    using aggregate_verification_acc =
        typename boost::mpl::front<typename aggregate_verification_acc_set::features_type>::type;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;

    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using integral_type = typename _privkey_type::integral_type;

    using msg_type = MsgRange;

    auto sks_iter = sks.begin();
    auto msgs_iter = msgs.begin();

    // Sign
    signature_type sig = ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter);
    const pubkey_type &pubkey = *sks_iter;
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sig, pubkey)), true);
    auto wrong_sig = integral_type(2) * sig;
    BOOST_CHECK_EQUAL(!static_cast<bool>(::nil::crypto3::verify(*msgs_iter, wrong_sig, pubkey)), true);

    sks_iter++;
    msgs_iter++;

    ///////////////////////////////////////////////////////////////////////////////
    // Agregate
    std::vector<const pubkey_type *> pks;
    std::vector<signature_type> sigs;

    pks.emplace_back(&*sks_iter);
    sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

    auto agg_ver_acc = aggregate_verification_acc_set();
    ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

    sks_iter++;
    msgs_iter++;

    while (sks_iter != sks.end() && msgs_iter != msgs.end()) {
        pks.emplace_back(&*sks_iter);
        sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));
        BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

        ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

        sks_iter++;
        msgs_iter++;
    }

    signature_type agg_sig = ::nil::crypto3::aggregate<scheme_type>(sigs);

    // TODO: extend public interface to be able to supply signature into accumulator
    agg_ver_acc(agg_sig);
//    ::nil::crypto3::aggregate_verify<scheme_type>(agg_sig, agg_ver_acc);
    auto res = boost::accumulators::extract_result<aggregate_verification_acc>(agg_ver_acc);
    BOOST_CHECK_EQUAL(res, true);
}

template<typename SchemePopSign, typename SchemePopProve>
struct conformity_pop_test_case {
    template<typename Scheme = SchemePopSign>
    using signing_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<Scheme>::template bind<
        ::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    template<typename Scheme = SchemePopSign>
    using verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<Scheme>::template bind<
        ::nil::crypto3::pubkey::verification_policy<Scheme>>::type;
    template<typename Scheme = SchemePopSign>
    using aggregation_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<Scheme>::template bind<
        ::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    template<typename Scheme = SchemePopSign>
    using aggregate_verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<Scheme>::template bind<
        ::nil::crypto3::pubkey::aggregate_verification_policy<Scheme>>::type;
    template<typename Scheme = SchemePopSign>
    using single_msg_aggregate_verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<
        Scheme>::template bind<::nil::crypto3::pubkey::single_msg_aggregate_verification_policy<Scheme>>::type;

    template<typename Scheme = SchemePopSign>
    using verification_acc_set = verification_accumulator_set<verification_mode<Scheme>>;
    template<typename Scheme = SchemePopSign>
    using verification_acc = typename boost::mpl::front<typename verification_acc_set<Scheme>::features_type>::type;
    template<typename Scheme = SchemePopSign>
    using signing_acc_set = signing_accumulator_set<signing_mode<Scheme>>;
    template<typename Scheme = SchemePopSign>
    using signing_acc = typename boost::mpl::front<typename signing_acc_set<Scheme>::features_type>::type;
    template<typename Scheme = SchemePopSign>
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode<Scheme>>;
    template<typename Scheme = SchemePopSign>
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set<Scheme>::features_type>::type;
    template<typename Scheme = SchemePopSign>
    using aggregate_verification_acc_set = aggregate_verification_accumulator_set<aggregate_verification_mode<Scheme>>;
    template<typename Scheme = SchemePopSign>
    using aggregate_verification_acc =
        typename boost::mpl::front<typename aggregate_verification_acc_set<Scheme>::features_type>::type;
    template<typename Scheme = SchemePopSign>
    using single_msg_aggregate_verification_acc_set =
        aggregate_verification_accumulator_set<single_msg_aggregate_verification_mode<Scheme>>;
    template<typename Scheme = SchemePopSign>
    using single_msg_aggregate_verification_acc =
        typename boost::mpl::front<typename single_msg_aggregate_verification_acc_set<Scheme>::features_type>::type;

    template<typename Scheme = SchemePopSign>
    using privkey_type = private_key<Scheme>;
    template<typename Scheme = SchemePopSign>
    using pubkey_type = public_key<Scheme>;

    template<typename Scheme = SchemePopSign>
    using _privkey_type = typename privkey_type<Scheme>::private_key_type;
    template<typename Scheme = SchemePopSign>
    using _pubkey_type = typename pubkey_type<Scheme>::public_key_type;
    template<typename Scheme = SchemePopSign>
    using signature_type = typename pubkey_type<Scheme>::signature_type;
    template<typename Scheme = SchemePopSign>
    using integral_type = typename _privkey_type<Scheme>::integral_type;

    // TODO: add checks for wrong signatures
    template<typename MsgRange>
    static inline void
        process(const std::vector<std::vector<private_key<SchemePopSign>>> &sks_n,
                const std::vector<MsgRange> &msgs,
                const std::vector<std::vector<typename public_key<SchemePopSign>::signature_type>> &etalon_sigs_n,
                const std::vector<typename public_key<SchemePopSign>::signature_type> &etalon_agg_sigs) {

        using msg_type = MsgRange;

        auto sks_it = sks_n.begin();
        auto etalon_sigs_it = etalon_sigs_n.begin();
        auto msgs_it = msgs.begin();
        auto etalon_agg_sigs_it = etalon_agg_sigs.begin();
        while (sks_it != sks_n.end() && etalon_sigs_it != etalon_sigs_n.end() && msgs_it != msgs.end() &&
               etalon_agg_sigs_it != etalon_agg_sigs.end()) {
            auto sk_it = sks_it->begin();
            auto sig_it = etalon_sigs_it->begin();

            std::vector<signature_type<>> my_sigs;
            std::vector<signature_type<>> my_proofs;

            while (sk_it != sks_it->end() && sig_it != etalon_sigs_it->end()) {
                my_sigs.emplace_back(::nil::crypto3::sign(*msgs_it, *sk_it));
                my_proofs.emplace_back(static_cast<signature_type<>>(::nil::crypto3::sign<SchemePopProve>(*sk_it)));

                BOOST_CHECK_EQUAL(my_sigs.back(), *sig_it);
                BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_it, my_sigs.back(), *sk_it)), true);
                BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify<SchemePopProve>(my_proofs.back(), *sk_it)),
                                  true);

                sk_it++;
                sig_it++;
            }
            signature_type<> agg_sig = ::nil::crypto3::aggregate<SchemePopSign>(my_sigs);

            BOOST_CHECK_EQUAL(agg_sig, *etalon_agg_sigs_it);
            BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::aggregate_verify_single_msg<SchemePopSign>(
                                  *msgs_it, *sks_it, agg_sig)),
                              true);

            sks_it++;
            etalon_sigs_it++;
            msgs_it++;
            etalon_agg_sigs_it++;
        }
    }
};

BOOST_AUTO_TEST_SUITE(bls_signature_public_interface_tests)

BOOST_AUTO_TEST_CASE(bls_basic_mps) {
    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_default_public_params<>, bls_mps_ro_version, bls_basic_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using scalar_integral_type = typename _privkey_type::integral_type;
    using base_integral_type = typename curve_type::base_field_type::integral_type;

    privkey_type sk = privkey_type(_privkey_type(
        scalar_integral_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(_privkey_type(
        scalar_integral_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(_privkey_type(
        scalar_integral_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(_privkey_type(
        scalar_integral_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(_privkey_type(
        scalar_integral_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(_privkey_type(
        scalar_integral_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(_privkey_type(
        scalar_integral_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(_privkey_type(
        scalar_integral_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(_privkey_type(
        scalar_integral_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(_privkey_type(
        scalar_integral_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(_privkey_type(
        scalar_integral_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
    std::vector<privkey_type> sks = {sk, sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7, sk8, sk9};

    using msg_type = std::vector<std::uint8_t>;
    const std::string msg_str = "hello foo";
    msg_type msg(msg_str.begin(), msg_str.end());
    msg_type msg0 = {185, 220, 20,  6, 167, 235, 40,  21, 30,  81,  80,  215, 178, 4,   186, 167, 25,
                     212, 240, 145, 2, 18,  23,  219, 92, 241, 181, 200, 76,  79,  167, 26,  135};
    msg_type msg1 = {74,  107, 138, 33, 170, 232, 134, 133, 134, 142, 9,  76, 242, 158, 244, 9,  10,  247, 169, 12,
                     192, 126, 136, 23, 170, 82,  135, 99,  121, 125, 60, 51, 43,  103, 202, 75, 193, 16,  100};
    msg_type msg2 = {66,  216, 95,  16,  226, 168, 203, 24, 195, 183, 51, 95,  38,  232, 195, 154, 18,
                     177, 188, 193, 112, 113, 119, 183, 97, 56,  115, 46, 237, 170, 183, 77,  161, 65};
    msg_type msg3 = {203, 227, 55, 207, 93, 62, 0, 229, 179, 35, 15, 254, 219, 11, 153, 7, 135, 208, 199, 14, 11, 254};
    msg_type msg4 = {236, 45, 249, 129, 243, 27,  239, 225, 83,  248, 29,  23,  22, 23, 132,
                     219, 28, 136, 34,  213, 60,  209, 238, 125, 181, 50,  54,  72, 40, 189,
                     244, 4,  176, 64,  168, 220, 197, 34,  243, 211, 217, 154, 236};
    msg_type msg5 = {196};
    msg_type msg6 = {252, 95,  189, 184, 148, 187, 239, 26,  45,  225, 160, 127,
                     139, 160, 196, 185, 25,  48,  16,  102, 237, 188, 5,   107};
    msg_type msg7 = {187, 88,  157, 157, 165, 182, 117, 166, 114, 62,  21,  46,  94,  99,  164, 206, 3,  78,  158, 131,
                     229, 138, 1,   58,  240, 231, 53,  47,  183, 144, 133, 20,  227, 179, 209, 4,   13, 11,  185, 99,
                     179, 149, 75,  99,  107, 95,  212, 191, 109, 10,  173, 186, 248, 21,  125, 6,   42, 203, 36,  24};
    msg_type msg8 = {246, 33};
    msg_type msg9 = {248, 179, 64,  240, 10,  193, 190, 186, 94,  98,  205, 99,  42,  124,
                     231, 128, 156, 114, 86,  8,   172, 165, 239, 191, 124, 65,  242, 55,
                     100, 63,  6,   192, 153, 114, 7,   23,  29,  232, 103, 249, 214};
    std::vector<msg_type> msgs = {msg, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9};

    signature_type etalon_sig = signature_type(
        {{base_integral_type("85911141189038341422217999965810909168006256466381521648082748107372745388299551"
                             "9337819063587669418425211221549283"),
          base_integral_type("38652946747836373505232449343138682065351453822989118701578533663043001622363102"
                             "79903647373322307985974413380042255")}},
        {{base_integral_type("11185637828916832078768174243254972746778201844765270288305164561940707627068745"
                             "97608097527159814883098414084023916"),
          base_integral_type("24808054598506349709552229822047321779605439703657724013272122538247253994600104"
                             "08048001497870419741858246203802842")}},
        {{1, 0}});
    signature_type etalon_sig0 = signature_type(
        {{base_integral_type("20367499301549630664794509143514612141767176044319343973582778132616836810060515"
                             "3615593024400226467409507465298708"),
          base_integral_type("17417694670444283249273233111740896342493427875890296354555908316449711174493557"
                             "28033568410346657520637304027438607")}},
        {{base_integral_type("13785121595373601972992367437749277919574099148535767401846529956933782527599494"
                             "29259211046717019870365053373909219"),
          base_integral_type("24046199905556805702641548487225288440078118481046409601677592067898992239812184"
                             "87409527866974288173456445634088126")}},
        {{1, 0}});
    signature_type etalon_sig1 = signature_type(
        {{base_integral_type("90710834246453736299315729969237597330519914417987003396017091519825531180139938"
                             "8489961456582868775448915444433006"),
          base_integral_type("25270941636657849141156823835907608851960602446295799011344219835523764041905411"
                             "32043871314989466510719980724197962")}},
        {{base_integral_type("11006537471688222187298795434169534977642750061352332023596150077572000526735174"
                             "82403026939564880349556232012966482"),
          base_integral_type("28970439382737866335805354269095929846361465365892679572353954171141396021759389"
                             "21238430628022984093395902845067862")}},
        {{1, 0}});
    signature_type etalon_sig2 = signature_type(
        {{base_integral_type("33291851192811896392629164391625138665143179943493712663950082658032677190756046"
                             "48006297427089956744281126109600615"),
          base_integral_type("21481784373644589901071764128354006437350755974736558340033332083967391474385784"
                             "74987192401977500510609089259809834")}},
        {{base_integral_type("28395122069875147416798807835672742446913197015626296480737621120106997822476818"
                             "58302101388270155386199540905532875"),
          base_integral_type("22689547301172733805507423021728158677552716845162509921148732522212324530304334"
                             "84032136004952017086008634579671429")}},
        {{1, 0}});
    signature_type etalon_sig3 = signature_type(
        {{base_integral_type("19658093393812310940168117154777513276790821449059154517758807117065395639329295"
                             "39953139284370994990106048975184623"),
          base_integral_type("16510818588919860825223531880780727504525558374417068496521683495180945632742105"
                             "45526361233720214380010050298439748")}},
        {{base_integral_type("21750138894910650225849064109227837448666098189077950706961180628134118614949898"
                             "92773456878984969421207097124583038"),
          base_integral_type("43824315547881612750271376731987427535941811196653478745774872868444671927498152"
                             "8004571647227921826225224384703237")}},
        {{1, 0}});
    signature_type etalon_sig4 = signature_type(
        {{base_integral_type("11173519713766922788448750238567322868508124499013440838782442360886914774999842"
                             "55834853084044097208643416916388801"),
          base_integral_type("18751280988359834793434628393541880844046457411751217408067392066479497490017863"
                             "48339367613442120122601247819752239")}},
        {{base_integral_type("34751815510365790071332195279684682216769530697521411164712269546622434004161955"
                             "67678920567991160867811579468845233"),
          base_integral_type("17655267962137873267480108548396702456330312615506725556513599717843889679852469"
                             "01235970958204895502771211905101565")}},
        {{1, 0}});
    signature_type etalon_sig5 = signature_type(
        {{base_integral_type("35509415272796846251007392883403334095333542231214314921570124143315798203514932"
                             "15113415830260262405373415722354761"),
          base_integral_type("22776837870227705502456214626359335066120633487230168982185531428438127126588172"
                             "03881174280092177111229928738918456")}},
        {{base_integral_type("18856629376754653352757905132316635449916511693652569715482330756216983571716519"
                             "18870253544256368888131980557733622"),
          base_integral_type("25139378885684192706949228554756728040049920012409323377005052759121552208442826"
                             "85831809983947603487923806727602018")}},
        {{1, 0}});
    signature_type etalon_sig6 = signature_type(
        {{base_integral_type("15859470065179161151263091896468958573452927269536698750750510937398772686159831"
                             "80935530279063139523045848929031592"),
          base_integral_type("11586271747255882623037490839044486615393741367490886028434848964384977248132242"
                             "84041438545109439918355332919183341")}},
        {{base_integral_type("28882245733470323496704740066065596308049408813451072846209456764046576330913971"
                             "76850298649809519774537156953947009"),
          base_integral_type("98938928200146064754539531129494984918024470835250157220713160123096536641365436"
                             "238620890954632965275278325341978")}},
        {{1, 0}});
    signature_type etalon_sig7 = signature_type(
        {{base_integral_type("35232470967305977549839898599750205881756536563675290039395816345409254249073128"
                             "50580537335730004667202743592096425"),
          base_integral_type("15510200665437420485604450001353854668739623902697982224648170413523930581075721"
                             "18812748030004587648848192327291754")}},
        {{base_integral_type("24666867106641878529186207252046045371103197872968875759652985236251804283533156"
                             "14150563881497873255199969665107324"),
          base_integral_type("11462332732017724644478094384413507834933490634742044096213067641080214952759845"
                             "55497303897248944055184802696915965")}},
        {{1, 0}});
    signature_type etalon_sig8 = signature_type(
        {{base_integral_type("30914103995211065257110419059711853143764940205795844687784797902894987319935550"
                             "03980679510558612201958296424747853"),
          base_integral_type("12766567504164445624536003209150631222747020520888601239247696937433631165371400"
                             "35698250140459055712038775453880539")}},
        {{base_integral_type("19996572608041414373464196286047987142063183494142464698552697600426028321901507"
                             "59219744773494542657237275449333647"),
          base_integral_type("33631387951308176859060121973790261787165406047259115324166531965237497141377594"
                             "41385539294562054616188492139689844")}},
        {{1, 0}});
    signature_type etalon_sig9 = signature_type(
        {{base_integral_type("58193789210078297088008912986218479562378746744456770966521904903053580769479766"
                             "7123251630641979454111055164270224"),
          base_integral_type("44923182459723592345335966144005466700213239755379004077753607349766040086143928"
                             "770428944139911102466627523503800")}},
        {{base_integral_type("31219623034257049397086584975892649672921216020800619837899616716296192149104612"
                             "71195150365710875841949893181236870"),
          base_integral_type("15245316264031841516784228058567442189765531096216009069579788284961451254290981"
                             "21669836210232968245470706286353809")}},
        {{1, 0}});
    signature_type etalon_agg_sig = signature_type(
        {{base_integral_type("18220404422387103573016815419543106211555329938444713749473054663814783182546339"
                             "92897017937660322039699444351331382"),
          base_integral_type("48174166927593931964514744391068732125381951502159883824583822091521766656550644"
                             "9460448932647300586457580378333213")}},
        {{base_integral_type("73461623680166961089685890352016720588145318970991597855294388137931753210590736"
                             "4694476426293065924488168855791463"),
          base_integral_type("34110737309389519223382510182418054823170371615385370448247187212612775099543648"
                             "82537962124670376518393059481359811")}},
        {{1, 0}});
    std::vector<signature_type> etalon_sigs = {etalon_sig,  etalon_sig0, etalon_sig1, etalon_sig2,
                                               etalon_sig3, etalon_sig4, etalon_sig5, etalon_sig6,
                                               etalon_sig7, etalon_sig8, etalon_sig9, etalon_agg_sig};

    conformity_test<scheme_type>(sks, msgs, etalon_sigs);
    self_test<scheme_type>(sks, msgs);
}

BOOST_AUTO_TEST_CASE(bls_basic_mss) {
    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_default_public_params<>, bls_mss_ro_version, bls_basic_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using scalar_integral_type = typename _privkey_type::integral_type;
    using base_integral_type = typename curve_type::base_field_type::integral_type;

    privkey_type sk = privkey_type(_privkey_type(
        scalar_integral_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(_privkey_type(
        scalar_integral_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(_privkey_type(
        scalar_integral_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(_privkey_type(
        scalar_integral_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(_privkey_type(
        scalar_integral_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(_privkey_type(
        scalar_integral_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(_privkey_type(
        scalar_integral_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(_privkey_type(
        scalar_integral_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(_privkey_type(
        scalar_integral_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(_privkey_type(
        scalar_integral_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(_privkey_type(
        scalar_integral_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
    std::vector<privkey_type> sks = {sk, sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7, sk8, sk9};

    using msg_type = std::vector<std::uint8_t>;
    const std::string msg_str = "hello foo";
    msg_type msg(msg_str.begin(), msg_str.end());
    msg_type msg0 = {185, 220, 20,  6, 167, 235, 40,  21, 30,  81,  80,  215, 178, 4,   186, 167, 25,
                     212, 240, 145, 2, 18,  23,  219, 92, 241, 181, 200, 76,  79,  167, 26,  135};
    msg_type msg1 = {74,  107, 138, 33, 170, 232, 134, 133, 134, 142, 9,  76, 242, 158, 244, 9,  10,  247, 169, 12,
                     192, 126, 136, 23, 170, 82,  135, 99,  121, 125, 60, 51, 43,  103, 202, 75, 193, 16,  100};
    msg_type msg2 = {66,  216, 95,  16,  226, 168, 203, 24, 195, 183, 51, 95,  38,  232, 195, 154, 18,
                     177, 188, 193, 112, 113, 119, 183, 97, 56,  115, 46, 237, 170, 183, 77,  161, 65};
    msg_type msg3 = {203, 227, 55, 207, 93, 62, 0, 229, 179, 35, 15, 254, 219, 11, 153, 7, 135, 208, 199, 14, 11, 254};
    msg_type msg4 = {236, 45, 249, 129, 243, 27,  239, 225, 83,  248, 29,  23,  22, 23, 132,
                     219, 28, 136, 34,  213, 60,  209, 238, 125, 181, 50,  54,  72, 40, 189,
                     244, 4,  176, 64,  168, 220, 197, 34,  243, 211, 217, 154, 236};
    msg_type msg5 = {196};
    msg_type msg6 = {252, 95,  189, 184, 148, 187, 239, 26,  45,  225, 160, 127,
                     139, 160, 196, 185, 25,  48,  16,  102, 237, 188, 5,   107};
    msg_type msg7 = {187, 88,  157, 157, 165, 182, 117, 166, 114, 62,  21,  46,  94,  99,  164, 206, 3,  78,  158, 131,
                     229, 138, 1,   58,  240, 231, 53,  47,  183, 144, 133, 20,  227, 179, 209, 4,   13, 11,  185, 99,
                     179, 149, 75,  99,  107, 95,  212, 191, 109, 10,  173, 186, 248, 21,  125, 6,   42, 203, 36,  24};
    msg_type msg8 = {246, 33};
    msg_type msg9 = {248, 179, 64,  240, 10,  193, 190, 186, 94,  98,  205, 99,  42,  124,
                     231, 128, 156, 114, 86,  8,   172, 165, 239, 191, 124, 65,  242, 55,
                     100, 63,  6,   192, 153, 114, 7,   23,  29,  232, 103, 249, 214};
    std::vector<msg_type> msgs = {msg, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9};

    signature_type etalon_sig = signature_type(
        base_integral_type("3604356284473401589952441283763873345227059496255462321551435982658302670661662992"
                           "473691215983035545839478217804772"),
        base_integral_type("1327250267123059730920952227120753767562776844810778978087227730380440847250307685"
                           "059082654296549055086001069530253"),
        1);
    signature_type etalon_sig0 = signature_type(
        base_integral_type("2247162578336307790300117844468947468720835189503626092261065265284788376322645855"
                           "042715828480095761644405233051874"),
        base_integral_type("2364572828575432059598629809133542306991756251639507754172391827473214632094272480"
                           "555900473658825424155647109058525"),
        1);
    signature_type etalon_sig1 = signature_type(
        base_integral_type("2682490444660789877583886321905960114902652442803495723367958666787384702397472500"
                           "408964001575304343327434901684937"),
        base_integral_type("3398673792460996127293687423416160321937175398276743121920178467641743757351954952"
                           "279078317569019542910531025540079"),
        1);
    signature_type etalon_sig2 = signature_type(
        base_integral_type("1347303293479541648493710888035421086742953254639266802540953946092800132955184336"
                           "716227000453492775693763388470068"),
        base_integral_type("2965751007554715065372323902481143005042153195426686124681928170781042466524036725"
                           "847121383628910851875335237214272"),
        1);
    signature_type etalon_sig3 = signature_type(
        base_integral_type("2020949567874524893692715355826059781955246225639797156337485897884183875627253029"
                           "365572606211660046200987584949456"),
        base_integral_type("2661978344164434777390106369216008969721648470464214705732248531209245223745264716"
                           "886907615841230548334496241701927"),
        1);
    signature_type etalon_sig4 = signature_type(
        base_integral_type("1295596529614126583854964959745974248071654423082591508292706821891679592140820811"
                           "396472710582327962844827798010388"),
        base_integral_type("1865574367401637027504196197496274442235818138639872868577213850882124237777371942"
                           "665705835112837456264197462580733"),
        1);
    signature_type etalon_sig5 = signature_type(
        base_integral_type("1627965373156489515967985946405293206164735458728684682603510522409622661001980600"
                           "479982118109972776117618805451903"),
        base_integral_type("3347085207755333216062507889510622277277671295604347342681432996333029865646962813"
                           "581951496121063765853643101887807"),
        1);
    signature_type etalon_sig6 = signature_type(
        base_integral_type("4697484206696710341086846751327637572827266392821125551281410267480625651167377160"
                           "72109460414767295782271090737846"),
        base_integral_type("2003782050609382358969270839371734101515648206407234705691771583997491646831068109"
                           "318844271307118633165374562376373"),
        1);
    signature_type etalon_sig7 = signature_type(
        base_integral_type("1429356597467588284789702427471826678158367528549605776421800852181350217528192766"
                           "331071794605809732247519561410608"),
        base_integral_type("1009789117757634469832549285515513621721452504555200122530087853526471782604838398"
                           "116162362023899952757025992887377"),
        1);
    signature_type etalon_sig8 = signature_type(
        base_integral_type("3916623792497751856153624596012574665373813712805049268942596247414374347154130300"
                           "506294967498612792476202518285634"),
        base_integral_type("3461812416940437175833935990973121464623855248471044862632385305842713912388437755"
                           "200235625788441209769016660305140"),
        1);
    signature_type etalon_sig9 = signature_type(
        base_integral_type("8317990943748298317593571478484202006039024526832236336059033273053025211139978683"
                           "2129089397979316684601678620304"),
        base_integral_type("3666516296905512856019726406051933303243313687988121908994579574714110113701386717"
                           "232936250509350140704196795339498"),
        1);
    signature_type etalon_agg_sig = signature_type(
        base_integral_type("1347890076939912845745386708815835780163588356335929090894089616427726245503639652"
                           "126316979340877114260832647740757"),
        base_integral_type("3055112058004854338590166655340093414620546693806824954758338468746323342336631148"
                           "81983910742368460029728081685283"),
        1);
    std::vector<signature_type> etalon_sigs = {etalon_sig,  etalon_sig0, etalon_sig1, etalon_sig2,
                                               etalon_sig3, etalon_sig4, etalon_sig5, etalon_sig6,
                                               etalon_sig7, etalon_sig8, etalon_sig9, etalon_agg_sig};

    conformity_test<scheme_type>(sks, msgs, etalon_sigs);
    self_test<scheme_type>(sks, msgs);
}

BOOST_AUTO_TEST_CASE(bls_aug_mss) {
    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_default_public_params<>, bls_mss_ro_version, bls_aug_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using scalar_integral_type = typename _privkey_type::integral_type;
    using base_integral_type = typename curve_type::base_field_type::integral_type;

    privkey_type sk = privkey_type(_privkey_type(
        scalar_integral_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(_privkey_type(
        scalar_integral_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(_privkey_type(
        scalar_integral_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(_privkey_type(
        scalar_integral_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(_privkey_type(
        scalar_integral_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(_privkey_type(
        scalar_integral_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(_privkey_type(
        scalar_integral_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(_privkey_type(
        scalar_integral_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(_privkey_type(
        scalar_integral_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(_privkey_type(
        scalar_integral_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(_privkey_type(
        scalar_integral_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
    std::vector<privkey_type> sks = {sk, sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7, sk8, sk9};

    using msg_type = std::vector<std::uint8_t>;
    const std::string msg_str = "hello foo";
    msg_type msg(msg_str.begin(), msg_str.end());
    msg_type msg0 = {185, 220, 20,  6, 167, 235, 40,  21, 30,  81,  80,  215, 178, 4,   186, 167, 25,
                     212, 240, 145, 2, 18,  23,  219, 92, 241, 181, 200, 76,  79,  167, 26,  135};
    msg_type msg1 = {74,  107, 138, 33, 170, 232, 134, 133, 134, 142, 9,  76, 242, 158, 244, 9,  10,  247, 169, 12,
                     192, 126, 136, 23, 170, 82,  135, 99,  121, 125, 60, 51, 43,  103, 202, 75, 193, 16,  100};
    msg_type msg2 = {66,  216, 95,  16,  226, 168, 203, 24, 195, 183, 51, 95,  38,  232, 195, 154, 18,
                     177, 188, 193, 112, 113, 119, 183, 97, 56,  115, 46, 237, 170, 183, 77,  161, 65};
    msg_type msg3 = {203, 227, 55, 207, 93, 62, 0, 229, 179, 35, 15, 254, 219, 11, 153, 7, 135, 208, 199, 14, 11, 254};
    msg_type msg4 = {236, 45, 249, 129, 243, 27,  239, 225, 83,  248, 29,  23,  22, 23, 132,
                     219, 28, 136, 34,  213, 60,  209, 238, 125, 181, 50,  54,  72, 40, 189,
                     244, 4,  176, 64,  168, 220, 197, 34,  243, 211, 217, 154, 236};
    msg_type msg5 = {196};
    msg_type msg6 = {252, 95,  189, 184, 148, 187, 239, 26,  45,  225, 160, 127,
                     139, 160, 196, 185, 25,  48,  16,  102, 237, 188, 5,   107};
    msg_type msg7 = {187, 88,  157, 157, 165, 182, 117, 166, 114, 62,  21,  46,  94,  99,  164, 206, 3,  78,  158, 131,
                     229, 138, 1,   58,  240, 231, 53,  47,  183, 144, 133, 20,  227, 179, 209, 4,   13, 11,  185, 99,
                     179, 149, 75,  99,  107, 95,  212, 191, 109, 10,  173, 186, 248, 21,  125, 6,   42, 203, 36,  24};
    msg_type msg8 = {246, 33};
    msg_type msg9 = {248, 179, 64,  240, 10,  193, 190, 186, 94,  98,  205, 99,  42,  124,
                     231, 128, 156, 114, 86,  8,   172, 165, 239, 191, 124, 65,  242, 55,
                     100, 63,  6,   192, 153, 114, 7,   23,  29,  232, 103, 249, 214};
    std::vector<msg_type> msgs = {msg, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9};

    self_test<scheme_type>(sks, msgs);
}

// BOOST_AUTO_TEST_CASE(bls_aug_mps) {
//     // TODO: add test
// }

BOOST_AUTO_TEST_CASE(bls_pop_mss) {
    using curve_type = curves::bls12_381;
    using scheme_type = bls<bls_pop_sign_default_public_params<>, bls_mss_ro_version, bls_pop_scheme, curve_type>;
    using scheme_pop_prove_type =
        bls<bls_pop_prove_default_public_params<>, bls_mss_ro_version, bls_pop_scheme, curve_type>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using scalar_integral_type = typename _privkey_type::integral_type;
    using base_integral_type = typename curve_type::base_field_type::integral_type;

    std::vector<privkey_type> sks_0 = {
        privkey_type(
            scalar_integral_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")),
        privkey_type(
            scalar_integral_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")),
        privkey_type(
            scalar_integral_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")),
        privkey_type(
            scalar_integral_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")),
        privkey_type(
            scalar_integral_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")),
        privkey_type(
            scalar_integral_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")),
        privkey_type(
            scalar_integral_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")),
        privkey_type(
            scalar_integral_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")),
        privkey_type(
            scalar_integral_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")),
        privkey_type(
            scalar_integral_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")),
    };
    std::vector<privkey_type> sks_1 = {
        privkey_type(
            scalar_integral_type("2369504379624793579280006665574483344747601607445519063189631339703232443856")),
        privkey_type(
            scalar_integral_type("26871155931427555174449046914648624385219647251239028268944298662101320495545")),
        privkey_type(
            scalar_integral_type("28557033433071297165575355485758538098044359326430208338829921448041625494102")),
        privkey_type(
            scalar_integral_type("50207756579056080743427775554510920463002505646935699384775921010660882070083")),
        privkey_type(
            scalar_integral_type("4489814086703605856270857521235304813261914907164988789613159665246884038151")),
        privkey_type(
            scalar_integral_type("27999114484157470992294589518823692599033177781647483138012576021476400179333")),
        privkey_type(
            scalar_integral_type("42567019084926239122712818032193175076567424719134478834872414023296796320357")),
        privkey_type(
            scalar_integral_type("35298624111423141056388101307435062870108221684361714529106750723274377872863")),
        privkey_type(
            scalar_integral_type("6579153998468513419786359934020246770600406824170889850803198217728618698226")),
        privkey_type(
            scalar_integral_type("6539350955118550946575217625093029917954692652855633801961789114651890998661")),
    };
    std::vector<privkey_type> sks_2 = {
        privkey_type(
            scalar_integral_type("35957171001594694088720487987136287724516371500148041118758676624782950541343")),
        privkey_type(
            scalar_integral_type("22758694265525713398795984411245001581510004886536999679669107705015603678875")),
        privkey_type(
            scalar_integral_type("45144179501096972603440498362227784062141899540924159942809113340040390662877")),
        privkey_type(
            scalar_integral_type("1840469417843895170012914915960969486629325593345767920212426720811340372749")),
        privkey_type(
            scalar_integral_type("25604584184868343745303218004818491639807915381067307058328198626860270377388")),
        privkey_type(
            scalar_integral_type("47826508191159869425572828684997830703928546945691419236357419849825709340438")),
        privkey_type(
            scalar_integral_type("46752758778614664955976577481842353264403261116012689540942194703931606267073")),
        privkey_type(
            scalar_integral_type("1353045885643404754277593144812444225931415980755674844687045201544927533478")),
        privkey_type(
            scalar_integral_type("15234919244624245069026516906725720858085709457777593189146428458132347567163")),
        privkey_type(
            scalar_integral_type("35216920335569339620126246410692007502040656594756514612601109719761533811375")),
    };
    std::vector<privkey_type> sks_3 = {
        privkey_type(
            scalar_integral_type("44846790857179378636182807875786327214993897162360637724968697705025794642333")),
        privkey_type(
            scalar_integral_type("23870613015465401266444558440262015653740663903791315414716868119752738441220")),
        privkey_type(
            scalar_integral_type("23439173523683741500798160304221604560434765737708417109534517586766344880634")),
        privkey_type(
            scalar_integral_type("21288803441811270583623370562387713070152626197672433531200345326421712287533")),
        privkey_type(
            scalar_integral_type("32503256233997741173480644308025972731833278744104127493516486219753213387018")),
        privkey_type(
            scalar_integral_type("46811868463263528350462227616426434771578809045297619166691855405945470150361")),
        privkey_type(
            scalar_integral_type("6293628395975428984357543682843187494765636412012017794600244158401723471918")),
        privkey_type(
            scalar_integral_type("43895544712345759646206304247940760355319317187574944382914306227652374928961")),
        privkey_type(
            scalar_integral_type("48179455399056012869086846076571600159323457437342490463984270900442759634040")),
        privkey_type(
            scalar_integral_type("15244614054442559267920524022105573071383429957358030776946994041743591866706")),
    };
    std::vector<privkey_type> sks_4 = {
        privkey_type(
            scalar_integral_type("24671480881034555668621958391531162804947981507242463478650268716538708853016")),
        privkey_type(
            scalar_integral_type("35156860692258266859714933944184502459108001875120924441959754569840594064117")),
        privkey_type(
            scalar_integral_type("10009799081777253087427127013887456678691115252901131568711175816521662803996")),
        privkey_type(
            scalar_integral_type("26725745523140978681632350855299902164508999036874348590285573200318010911758")),
        privkey_type(
            scalar_integral_type("47369557198254831037546011708076336436882374536558104107399747848690464800093")),
        privkey_type(
            scalar_integral_type("18192560042083570853921100083230193051649804688722122954533392841165441419428")),
        privkey_type(
            scalar_integral_type("29409956613647379467023640788415265145553681481170181038736615819022702247736")),
        privkey_type(
            scalar_integral_type("23355486751239950547671156404592102200180636821914272620083087747398616652941")),
        privkey_type(
            scalar_integral_type("6190957438783997636927425558563693845765391731669345057514374198814430571383")),
        privkey_type(
            scalar_integral_type("18315077413398251993817593998878564091948630821724239467337386703960158955398")),
    };
    std::vector<privkey_type> sks_5 = {
        privkey_type(
            scalar_integral_type("43879387577444284867225374895412957121478660348999120715937378069682700264647")),
        privkey_type(
            scalar_integral_type("9365189757817316199500199904632334272336220006252986395633337300438822249536")),
        privkey_type(
            scalar_integral_type("16664568455936926898228475380796343651808382373568284937681967155518200670090")),
        privkey_type(
            scalar_integral_type("48512375444401302464882679853012371770681841086602238641703559283734980911072")),
        privkey_type(
            scalar_integral_type("47325847886939383467423719688864080013772927690427857050549502629497273469647")),
        privkey_type(
            scalar_integral_type("10944219016283652928750954331783106947798895292633751709762909351672457430933")),
        privkey_type(
            scalar_integral_type("12992404648299778389108195161446721984361718313799114280528673879344789372757")),
        privkey_type(
            scalar_integral_type("33957893568936936840281082256470251755882221502729648047853109120614137135512")),
        privkey_type(
            scalar_integral_type("37458692876367357108749299380400281720068573587532297343991292086984426369015")),
        privkey_type(
            scalar_integral_type("51166611183057827374512246291190133958554265767470596674109803397025983146067")),
    };
    std::vector<privkey_type> sks_6 = {
        privkey_type(
            scalar_integral_type("12725661857107102441780983287384238808278563198861104608788098082933381882746")),
        privkey_type(
            scalar_integral_type("44188672626552435485431094556632789464209692254273419678899723355398680884823")),
        privkey_type(
            scalar_integral_type("36299726244033767605886693744973562676839637466938488301971956775013048617049")),
        privkey_type(
            scalar_integral_type("24791239752789558856008694734770776950416505036747482257593301403756285906174")),
        privkey_type(
            scalar_integral_type("11248844888476761728957175688844865609115133744313063162359128615242399306476")),
        privkey_type(
            scalar_integral_type("29165656643790880221400020534001587571273105802552812484490664913996533881997")),
        privkey_type(
            scalar_integral_type("22725405117690258564083766734873051038927391979883011238345108964175939904139")),
        privkey_type(
            scalar_integral_type("3170544880906710447974347630412235304341948536772446892465032646567868631471")),
        privkey_type(
            scalar_integral_type("47684329279925942167853794985231439878227271636671029249162013670754139447039")),
        privkey_type(
            scalar_integral_type("44065288211512777303732797123407949920673752161085989729445186683764585835831")),
    };
    std::vector<privkey_type> sks_7 = {
        privkey_type(
            scalar_integral_type("46761622771097458983966977536111330884524778692941345889849364099197024282993")),
        privkey_type(
            scalar_integral_type("33508015279120063381285338995352668704730427122273333328622962453368104710804")),
        privkey_type(
            scalar_integral_type("44725039460708817115344423417052256045568291985638013980251525067997866857029")),
        privkey_type(
            scalar_integral_type("46833135132882600382154798661263761027158499201120613389419448951547141158407")),
        privkey_type(
            scalar_integral_type("20880673796762049924851435742171324131459080912134183778950724982881501083067")),
        privkey_type(
            scalar_integral_type("45394142255690604204714572257416332831892472888869385324878761977830621612343")),
        privkey_type(
            scalar_integral_type("51984015576088397996956284141615708947725329768364829309875758815228333196075")),
        privkey_type(
            scalar_integral_type("48293144431428700872268676964556096022212054327427228163098783485196515529202")),
        privkey_type(
            scalar_integral_type("36222815212116149677418064146507233881718761668382989691025766670825645985075")),
        privkey_type(
            scalar_integral_type("50759280419860417802055275065687093297038790247990902467795244595907892506092")),
    };
    std::vector<privkey_type> sks_8 = {
        privkey_type(
            scalar_integral_type("18746656845646859750561258867056424653369118452181987362435158421729226076698")),
        privkey_type(
            scalar_integral_type("31031560450659879786932526067256771604615387756442671123866002549871606679599")),
        privkey_type(
            scalar_integral_type("42494955329311697249572246104019625483038664646322441879590721841201771335870")),
        privkey_type(
            scalar_integral_type("43782052753664520569471160529173897961207108821566825393268891447596146054616")),
        privkey_type(
            scalar_integral_type("26363562248624265009458273612928610241976727325183610252378574293171777607284")),
        privkey_type(
            scalar_integral_type("8330605458902223354655609230515256436651802889371700166429602300903172948508")),
        privkey_type(
            scalar_integral_type("33631523381804483667922029118359379550752079336584633907397563557091336056406")),
        privkey_type(
            scalar_integral_type("38902873125533844275467523940118290304821263142325046482935001018436033904609")),
        privkey_type(
            scalar_integral_type("21186732187481406240755327814169836126584542394151303448634680901921963427400")),
        privkey_type(
            scalar_integral_type("7414415982747742360299276276780362021924698250402910656023926061967429270589")),
    };
    std::vector<privkey_type> sks_9 = {
        privkey_type(
            scalar_integral_type("9002517108680634148912198663388287630298040868446423873959280357965384444644")),
        privkey_type(
            scalar_integral_type("20769509770088624697168035266555805504367557410835986579877801358530423431840")),
        privkey_type(
            scalar_integral_type("10471598158849283370466963664073078956391340575269597786040249259208941155163")),
        privkey_type(
            scalar_integral_type("38298179342103490265542894264723183683640300774068241662807160748046234447335")),
        privkey_type(
            scalar_integral_type("38002822806114311455746644612018021287228960046070496107872097107976550634160")),
        privkey_type(
            scalar_integral_type("9717059311017176101883301475874953395225713545443461257602337754443483280802")),
        privkey_type(
            scalar_integral_type("33475308610895441921585083068864950299191740111413597957557228910270689634240")),
        privkey_type(
            scalar_integral_type("8905194960900233962941853200031185599184174289112152214189292652244170740907")),
        privkey_type(
            scalar_integral_type("52243467421328849929566262215650804220328323015916662092647174158778452994708")),
        privkey_type(
            scalar_integral_type("9092304683956881416251913178222695577348165263602981029776877633501622925022")),
    };
    std::vector<std::vector<privkey_type>> sks_n = {sks_0, sks_1, sks_2, sks_3, sks_4,
                                                    sks_5, sks_6, sks_7, sks_8, sks_9};

    std::vector<signature_type> sigs_0 = {
        signature_type(
            base_integral_type("2547146713482947039916893893068651683951139814726379827811800938009362708982078565"
                               "053195613225684082094032804982792"),
            base_integral_type("1837311166270744251444798206250478284977604394235484837169682717319945007757809079"
                               "368167322913524080770329187111872"),
            1),
        signature_type(
            base_integral_type("1010867827897947169097432198378450207519599111114814425532967991850836777968783031"
                               "880639423745125611882304895259667"),
            base_integral_type("3291444832807228096594534931551973002970667437958588449098310818647312230306746122"
                               "090262191224531104092964358520071"),
            1),
        signature_type(
            base_integral_type("2950207063301346386722837650633362137539715787120059249304252307480520351082199490"
                               "260651463874170982816214005285183"),
            base_integral_type("6466926560316411032759912390546726048613664988207309871860356384978112780321466878"
                               "18141152216982368009066181005804"),
            1),
        signature_type(
            base_integral_type("3460837294344853645952044576710721693646116997440386386619678385233685623897960839"
                               "145881274192437104194519381931933"),
            base_integral_type("6770858332384348159790511229519022135990138182888426020603710253440119052980890434"
                               "74208852514052907552325098423475"),
            1),
        signature_type(
            base_integral_type("1458245955189140365824557160920255687554215611565855516662542132238133282955650880"
                               "17658911314934711184510783620792"),
            base_integral_type("2519241143021779968266865629807328473384574675200698799454451133872115551178082267"
                               "149820541868871989644650447770278"),
            1),
        signature_type(
            base_integral_type("4715017534494436179381736884357727632497530550556889900985170870201869961554031817"
                               "16139442386573851891323129641595"),
            base_integral_type("3054230963154698015152846425982150226660456315167995101599639285345742396511543386"
                               "75185592200974040567102170662681"),
            1),
        signature_type(
            base_integral_type("1629015209442926753786771999675171747758454116545954533650863471792540587074642266"
                               "535393551208513382231517839307616"),
            base_integral_type("1794357822831171310100671989623184006250670856271801648596131286083349849633310690"
                               "515662671375843172565180528075766"),
            1),
        signature_type(
            base_integral_type("2040884477569369288523806125266390978058238133952306014163495740380429522199215907"
                               "108222894058828849354648417903216"),
            base_integral_type("3112517302690088767848459157746720300429203418699400995436684658112790086635008621"
                               "687150473962812795609880140692449"),
            1),
        signature_type(
            base_integral_type("3533328943456568480504184164672000600221679122390409074615265247807510688328845871"
                               "83687278067185700449914789458705"),
            base_integral_type("4320296960905316765219999278657860862589277783925247891468037314971455126971799221"
                               "08511738962065878641318469092836"),
            1),
        signature_type(
            base_integral_type("1355729387207465779270829710432638229015135180037028179505382192469414418587717078"
                               "439069714140184522156850561908485"),
            base_integral_type("1061162334530112847501648007204970188549317043317961561346181373243674770960235770"
                               "328054871925984056646714808265834"),
            1),
    };
    std::vector<signature_type> sigs_1 = {
        signature_type(
            base_integral_type("8927582583782023134263037760078923403624659578954531404269249766593369184665777300"
                               "96673295957414271056926897764745"),
            base_integral_type("1828576277144799754731103968231060695422856686479361709273635430833667847624697813"
                               "92957815117533654197031882182107"),
            1),
        signature_type(
            base_integral_type("5144354492728215020454643105583699539913524880241558462855810176812722818240727544"
                               "00324230347402946484659666727267"),
            base_integral_type("1251606356441000370934031362160869120737346129648189400902045233646188134164608119"
                               "296830691454376395993655981155440"),
            1),
        signature_type(
            base_integral_type("3118646307632408137420541317537008078351896283318477169288908703913783999331244149"
                               "63127172704899183712434629549835"),
            base_integral_type("3597393466831372348394529874057136542985529147725888953727336659007534986098374146"
                               "062084911925830577430664269705602"),
            1),
        signature_type(
            base_integral_type("7604698138225325528976350236644737884986080735106903448723685753886517082843547180"
                               "55940734553907528835909052690401"),
            base_integral_type("1494928579927125368227143636054629231507516311704402396325984637686386176478061417"
                               "233950750174259537624847192247912"),
            1),
        signature_type(
            base_integral_type("5042598354225754301793366287244447537661382164896692771876259431701789549454276589"
                               "66516990437057248463272563425903"),
            base_integral_type("6844479552105811037232292163779293867723292840510239871580098747018341832979373317"
                               "6398977108124782106913265291328"),
            1),
        signature_type(
            base_integral_type("3890062605503399428282829128441384596606314903815139669332135251972730732953369940"
                               "733164472246001696352317740953025"),
            base_integral_type("1345548421387422764152561045707440723992680373149083008394891423235404055579812619"
                               "917649519745488988525857671521695"),
            1),
        signature_type(
            base_integral_type("3264503130598638432965707615350490418449432300721310883896875667624396979838133171"
                               "743227462501616169653342315397380"),
            base_integral_type("1265014985588087965826802033564362550183947121442501567498886590037602833879269563"
                               "897632218056986232055375349874895"),
            1),
        signature_type(
            base_integral_type("2447348956485304338778002758651514341202640206119867769800031365951047317145492088"
                               "54783001327287612944703606006488"),
            base_integral_type("3689812036927950302447137570997786126812172597394790269928635813344902137113131559"
                               "728777203775628188918770573126175"),
            1),
        signature_type(
            base_integral_type("8698890930960684337740197742905608686587528111075968471492806802419694672110239454"
                               "21528868515582276167826554972946"),
            base_integral_type("2970633580527025347321357973617256413887902893275295449640830008406665171348095357"
                               "274412985660328007691064865282462"),
            1),
        signature_type(
            base_integral_type("4518542647477250349745916437438056619916298139241096746484650952975150940328290748"
                               "97630183453128656708808440176048"),
            base_integral_type("2898309105262984361006430712214625918620250363970508696071130865972117134030371674"
                               "648770986448297464173812802469870"),
            1),
    };
    std::vector<signature_type> sigs_2 = {
        signature_type(
            base_integral_type("3073415590818201520514803103984865610750543089370418811597050969569963445164408158"
                               "698857767228639218345918562466945"),
            base_integral_type("3775161657977032960497526371311293258751626435010603081163996018058840090813628940"
                               "960455887576623088813747686044376"),
            1),
        signature_type(
            base_integral_type("2251655673997594907206611824884081617267064660063400059065702941026880428919863427"
                               "012178114265865689823971807810908"),
            base_integral_type("2992421862669483131951316412266456735613528374873183818305532687765757862461920543"
                               "415781594276564098930955494562035"),
            1),
        signature_type(
            base_integral_type("3550219231603704593751451114256070341919519570077067865083329816155585259981733165"
                               "876538809677149458008472280404826"),
            base_integral_type("1239681602592857318156498767988117906112208379793887571487465253441702838050956621"
                               "530486663766203269344564659912804"),
            1),
        signature_type(
            base_integral_type("2922053209467030168685916041481392117176843676671179487587219940210712721430346453"
                               "039207210027636615968804801850666"),
            base_integral_type("9777936661319500762459295516850953757467253756975105466742108070022895336038525904"
                               "90789729502709168209024159068282"),
            1),
        signature_type(
            base_integral_type("1726146848933405198993865142485519423158661288561289520898924456319858125160934556"
                               "96565587453694114056270665517125"),
            base_integral_type("2792679660445417909168515651657019773119245251754424394873665834266716108103243918"
                               "120555054216586592045727046372269"),
            1),
        signature_type(
            base_integral_type("7852816550976698879538246621845247912787708510911915330640373072951642129005264068"
                               "67317823415965849429234290612840"),
            base_integral_type("1118892953174556533981060214310031284997234511264520436856800766700137433886215312"
                               "619263099564687221105155589548092"),
            1),
        signature_type(
            base_integral_type("2987827765930226744324160709234188039067993275312184930598027173694547318685295400"
                               "59082047229965091041360305033460"),
            base_integral_type("9457419959439992125717707807669497747672787830657744590413070193319663119508322422"
                               "45002599112075197038185391906968"),
            1),
        signature_type(
            base_integral_type("4876156085391007995965987129155621226188309464845224701791483308822870529308939536"
                               "09364876332301591008313684293136"),
            base_integral_type("3167655052930268032876438391824013119285068210960742308294704963610650770047916254"
                               "623805722585761060437258975606416"),
            1),
        signature_type(
            base_integral_type("3128681693470196532099754978203645328231078954072621313122446380697903278783935593"
                               "400901439442893052399103954711491"),
            base_integral_type("2096028726813768751656827159283251995818316712356559097257800184536015794348727381"
                               "236400950013189303310638777463007"),
            1),
        signature_type(
            base_integral_type("2910315279306811586346619288101461775968174273741226074933978173693981320794155169"
                               "005060013725639632089550579908036"),
            base_integral_type("3321812041197837928786780184652869275224234638764149038739428412537925791631849520"
                               "355318752771690648243694239494949"),
            1),
    };
    std::vector<signature_type> sigs_3 = {
        signature_type(
            base_integral_type("6310048338751151565354028998638485383012255413280542986468604145705896760073281477"
                               "44847178970164992631333480909403"),
            base_integral_type("3283015965234153100318039871147257714178755795525904246157714035865311415325603656"
                               "111218434033869778210046150069035"),
            1),
        signature_type(
            base_integral_type("3375018252152840483670739804066561916743697534301401819374134490570937793100458542"
                               "627467268496752993244163287080024"),
            base_integral_type("1166508995233965103981768800835003537190357467054297564634798284145476658741110726"
                               "46293507796545724728211718948100"),
            1),
        signature_type(
            base_integral_type("2165951107553224916040725192849120214272974886592315310025513602956264969117067782"
                               "291921371619032816091918239061444"),
            base_integral_type("3515213406517840982379699904275116130342248746480482601414380809775903960439387799"
                               "022126459005911335374040311747168"),
            1),
        signature_type(
            base_integral_type("2422424954037224387690023672341772993023350122258796012851054887990905319967822292"
                               "312876357073175618026163032365503"),
            base_integral_type("1686142189399731307825868917016483859423889913490134095777304701101927678087035759"
                               "097803983044600758086796261771633"),
            1),
        signature_type(
            base_integral_type("1922037110596973421849118266115803165788944984087299467351258158231898786508402468"
                               "659543788260823954815547130540721"),
            base_integral_type("2711751198126164379880940292752880675444254162005255403403891824446429437773154900"
                               "087029379892356526347758495344310"),
            1),
        signature_type(
            base_integral_type("1027577908944414794562345795366374279668364641283992140960483489136601290949237038"
                               "685526901560368339443908378914309"),
            base_integral_type("3713339954866241208806307605171594541440448264635917911871507884771108726420552539"
                               "509852506445025567704602153075386"),
            1),
        signature_type(
            base_integral_type("2831407188578763034043951066748728434501331110719233762764376164515818225395469541"
                               "71843800057097296511038126615363"),
            base_integral_type("1936100242858540591208117640929521199237068676340628428004042031767592713344996267"
                               "686143382734410955206720497563392"),
            1),
        signature_type(
            base_integral_type("6436789433815690158582156666446345031141561343304065274373910226016024147007640094"
                               "52442038634030631257017098008703"),
            base_integral_type("8233109182943107761977539615103041179260558624608427770229546659921026553383049809"
                               "49433797918045837393765302508864"),
            1),
        signature_type(
            base_integral_type("3540151563642218155534482026567473609246958490528539705155502748310238291757049436"
                               "073237751975440454317423064461912"),
            base_integral_type("2876247411770081889823739466854221855791452718539911658203911304138117748770784359"
                               "154899155698729648064572055822233"),
            1),
        signature_type(
            base_integral_type("3827670697754023229674690887274106490816736966172305740849847603849386628058341478"
                               "951157088334186940078279561696933"),
            base_integral_type("2244170619089108552354063879281432511581796568578251856271461325670010115543329384"
                               "742218861706178837590431939850753"),
            1),
    };
    std::vector<signature_type> sigs_4 = {
        signature_type(
            base_integral_type("5884672248768665838447976445291377248171371755191353702740412326853512248315250636"
                               "7732384300273043926206770691641"),
            base_integral_type("8637514742063852915692910788853920161605398418183572028362377800638129451318482212"
                               "44296311363704542619086815894597"),
            1),
        signature_type(
            base_integral_type("2741097311365095359895280436388859345127892200153729569120718872468001627017283079"
                               "645096880067020372678886781502237"),
            base_integral_type("1859074400532225340477459622936635995761539054839399251034357710000662449193141146"
                               "352659040513191834623289856154563"),
            1),
        signature_type(
            base_integral_type("9513656215051999740332400399407909848853563936399801399448254674363817835174131972"
                               "77272162962604104114567873419071"),
            base_integral_type("1955344218005362161774222713802980890815857957941712222566472654956639958646432856"
                               "552251361525591629858087050906600"),
            1),
        signature_type(
            base_integral_type("2637852349241191786250178856280685602822507375281257902813222583302291226646714453"
                               "268050018376327122958505594437464"),
            base_integral_type("1607111695747663042420530166306406591035055208722886757095981982923872512169019390"
                               "549103889013179330227592139345111"),
            1),
        signature_type(
            base_integral_type("3897100813895028914322560995854748747437091758218943699238207481445047789014314537"
                               "657953846741109890488534771737025"),
            base_integral_type("2077102326876940174051612399631267294136506639276376163603428145424184671531243846"
                               "144732173247387689471082721410554"),
            1),
        signature_type(
            base_integral_type("2881323095740416343105234694066856584860737900692080051790764890552137581148067203"
                               "001568760317432817426586986486538"),
            base_integral_type("4326498745371816319160179982472842229095758104965717858868727528309336199365693897"
                               "807270379761586242933142628893"),
            1),
        signature_type(
            base_integral_type("5957148522672285702615760842283342247932771997918155373063840765572399804471572177"
                               "37544975188522059040060650471950"),
            base_integral_type("3206569086454443498572408165252930823424436807111821683110446055166513547533331435"
                               "970396926947499507670578163388756"),
            1),
        signature_type(
            base_integral_type("2294740212496360056613172207129572207416659673157285799577329797890458736863230723"
                               "474490135750982035929296943458679"),
            base_integral_type("1746941429333732224736152599969133959903470259906693647160976333082119998778628296"
                               "822428326650786673716187947015221"),
            1),
        signature_type(
            base_integral_type("3203928604956218904380327800564935367343160082300860305705181034445774863124230065"
                               "975789885550849231117463032992024"),
            base_integral_type("3259905440480308210851123502251029941749083160876161156324307350158271545551052050"
                               "760469246918357752717192019180016"),
            1),
        signature_type(
            base_integral_type("3232305984222600364220379445979381561229545351529484379451097040094318174114825345"
                               "759852965428134612315691025154662"),
            base_integral_type("5274493986742024550650899294884802110909365273764009894884026532198815740817142660"
                               "61691667343045533578979785180614"),
            1),
    };
    std::vector<signature_type> sigs_5 = {
        signature_type(
            base_integral_type("1624980802471599693239080604031361774353428937533833997557968153331312229044144389"
                               "304527649113999198909746153920633"),
            base_integral_type("2767132940881224383154269602791219083509141937230253577557151348591993254924560161"
                               "073165104084023867765858248764848"),
            1),
        signature_type(
            base_integral_type("1446932322636169179392773164240655537436474339997242956591418544013277120427717247"
                               "856550698069133432634160096835621"),
            base_integral_type("3843090659205917613326369073847909359996127324010616409767737393955198026095416042"
                               "606978356807145807602659116829420"),
            1),
        signature_type(
            base_integral_type("3261351094965584362455105362965807735216212939737040281190961388946399845380046954"
                               "784145154451289565314821232281910"),
            base_integral_type("3293013734832178396174899451231429356738329228401794909317571490818343872587883599"
                               "447158454480964496042043962237038"),
            1),
        signature_type(
            base_integral_type("2156599883740101912396266639195793760208158483411117602313682092745981201774337977"
                               "170051462268617931771454495097949"),
            base_integral_type("6474580618768551435350174624791764360987253636113859574989194625674188673651506614"
                               "15155470658319955395876659419428"),
            1),
        signature_type(
            base_integral_type("3146586922283822151422758625050058325404183941019166745163485201518919966624555186"
                               "13299723779814639130184663388685"),
            base_integral_type("2143895093292562907547963666739911796802741558621299241479593574983318337651670764"
                               "996649347876218831467788171005566"),
            1),
        signature_type(
            base_integral_type("2043953950901207029935221043397552024073712877406913494810274716789754546243369244"
                               "276601613962162023005126888373682"),
            base_integral_type("4558700736061952233852207364977628234085528927177825166948969766488436036277241199"
                               "65505490222006254436611593372945"),
            1),
        signature_type(
            base_integral_type("1317456700940754031234408860019504581571635940011379972051907070542094505018746579"
                               "970018944128200402386421138262005"),
            base_integral_type("6193093990074004808718661098092047084503694081699777495021858986927136332479300467"
                               "85255222025827519158922855983232"),
            1),
        signature_type(
            base_integral_type("1975205547332108136697807964243044979675315129586082313570152299462861679159751811"
                               "913235849139637018466870872010868"),
            base_integral_type("2425545016366955409659158635188160781678158190857516071736240769603759138990904858"
                               "526788106743213387002621389392568"),
            1),
        signature_type(
            base_integral_type("2068776786022736271877218031769853195781024461596577190749938697831553939363679897"
                               "628637043773600247511273410105570"),
            base_integral_type("3837743299548170261962554187116587046804876287570441625285114645962378070767416674"
                               "070243436958340071120605358131957"),
            1),
        signature_type(
            base_integral_type("2155177881171244016481372629654764607095694422759658484031913239763089673061540621"
                               "278575883679228277930490825973721"),
            base_integral_type("4378435833884719447117190734118720568398854926502298794333363728916763425874677568"
                               "97337818602005012267586853803287"),
            1),
    };
    std::vector<signature_type> sigs_6 = {
        signature_type(
            base_integral_type("3255434475449552613370797574808893070866078650279159365915656942680237884011412055"
                               "836898499690388729943673909287315"),
            base_integral_type("4142059600905711524551433549509610143850101057406713385140651360079544837103743287"
                               "87557080812013422151768976251128"),
            1),
        signature_type(
            base_integral_type("1654240530116266051126183920610105138461968838667698886749025273863484400048033378"
                               "38986727932954568592893191096866"),
            base_integral_type("1021407893780456087005727755192817136790997296283452142814744853214399680577110345"
                               "015853276273182836258858186776949"),
            1),
        signature_type(
            base_integral_type("1613409969576133727840496825560357228456846293953766077673431326772851408363987072"
                               "540940938118505910131854679450852"),
            base_integral_type("2149717309162637042678417713878976532839945009794624969481954005421080260923271843"
                               "469587949467270500170121627106328"),
            1),
        signature_type(
            base_integral_type("1603816970152102519017718778408138882132547627143353055930192168403701049674969010"
                               "527764291124757098853584299801838"),
            base_integral_type("3557390238300117847593137946942098336657176808123461427026174112534242561176408358"
                               "800161726146856881016714127400137"),
            1),
        signature_type(
            base_integral_type("9244581670514817375277307446119142152338984816952816918989103999926405491282470510"
                               "89610633772396220668387714436428"),
            base_integral_type("8734929087708619804450435991471497214076106706561043675084512700314342951465940618"
                               "70632882872337036158984518630650"),
            1),
        signature_type(
            base_integral_type("2445041831146265426239250785890565703036313031400170415942615011874577858532009696"
                               "974310770975655226489801041658571"),
            base_integral_type("5512072826800374348492205244747802242777233761901561769625108364421878006386043154"
                               "21209714362997473292812455613880"),
            1),
        signature_type(
            base_integral_type("3506638768689499941634583114869094536083655531283988182220118108750630742526843236"
                               "382635286564506336111909370443066"),
            base_integral_type("2577776815196911857582710253252630526740298939464520185201437744049019876444799245"
                               "80012865633593242708144125952361"),
            1),
        signature_type(
            base_integral_type("1892190486275862743845721061372915227188352596381582382145758404285827112500751962"
                               "028390729736749385403653271245445"),
            base_integral_type("3296014034102811188040144598920562444803441403342133179687535122721422578551270038"
                               "720431963458627938370318978783126"),
            1),
        signature_type(
            base_integral_type("2745860126051790194714375972721391679480460754297119032151752092043491325128519698"
                               "195659829754819985136159113840963"),
            base_integral_type("2641902869242288348442903861551653277735078099612820308995467241753259823665056863"
                               "517245556702486692790020263728658"),
            1),
        signature_type(
            base_integral_type("1959372996471406452967311272413710243756668859351431041179640895242978805345383367"
                               "515657665978963430972925164926744"),
            base_integral_type("3360527811182000135278196179787363192032056380532166708309864435081048000087749416"
                               "445030554993075062495425857556101"),
            1),
    };
    std::vector<signature_type> sigs_7 = {
        signature_type(
            base_integral_type("2714645068492986981937317001061887269878226520905343218015139477715422259876927843"
                               "062098815932414778862077273533208"),
            base_integral_type("2943751645876776926624913737890060064122342911785057074115233881587077484923157790"
                               "268914962210704754358539112741249"),
            1),
        signature_type(
            base_integral_type("1872354537403656188164647231172727202009845951538893319747209357182774646765456505"
                               "764840721724197965016178012446409"),
            base_integral_type("2325827147262697698272031344226291837060418467386383087891101512387386225360641606"
                               "766681985836305936176277029362475"),
            1),
        signature_type(
            base_integral_type("3614166952606795429135646371115661735484217637660535414483684344770366411565212364"
                               "66066240740844473210596468696501"),
            base_integral_type("2603922876360263618559023765013698744514791298904943225857488825954475439185824320"
                               "331425804755362739073540424940031"),
            1),
        signature_type(
            base_integral_type("2871441357866235207412785242675272629179212875833101049583986921340551764687190907"
                               "929878151870191411689005709841946"),
            base_integral_type("2267597700902301544193554554217677414164756199520207287969373341593300924393743534"
                               "304579202566418702490258294915964"),
            1),
        signature_type(
            base_integral_type("1305332397067385841432802373421809028193955206788746652617527594607526028021586089"
                               "19364825106217818598191640883554"),
            base_integral_type("1963466956471531542443925487039413160958580369599617849257526629359035232511677776"
                               "400562705255825184056004215549669"),
            1),
        signature_type(
            base_integral_type("2566388299860777785985307070000982244384960731003980130731096972245131464702782421"
                               "934216393470029795042630654239794"),
            base_integral_type("5233673022526490183979853985023840198086968470095254733457281773720454143188987874"
                               "53142097819338242588865507564019"),
            1),
        signature_type(
            base_integral_type("1990225925163235803022407992912049836951129275877371273931425065115495353382018706"
                               "201967714055127733332371842808442"),
            base_integral_type("1519166378281180024901689127468771078101432373357612846672487394073495156002366983"
                               "768282023863238837252781912635709"),
            1),
        signature_type(
            base_integral_type("3200625396228613925508787978234849325833493087869912299416903565265792261043978166"
                               "268128271198921649867206111744093"),
            base_integral_type("3453297856893744972774705960485954995210897737358227269301852562082765907883937340"
                               "100949684722187768262450362277012"),
            1),
        signature_type(
            base_integral_type("3111171508045265895098917790506971202325704787220861581838886842527336389063481686"
                               "999426589473048454266661105060597"),
            base_integral_type("9563721349515934885574268225391354722454867848826429054472987288459790144799418413"
                               "31461362867412528947158945391017"),
            1),
        signature_type(
            base_integral_type("3820554594120294281492671047077755840725257790596625362457563540223453950818392591"
                               "170267099168156562932183720563554"),
            base_integral_type("1468232896136903865325266974484405794106096656198775402531086440310811950924983720"
                               "044838323134938099256321336155863"),
            1),
    };
    std::vector<signature_type> sigs_8 = {
        signature_type(
            base_integral_type("2821021631577065901420875031391460148941053911552361201165188961941834883227818289"
                               "381777988186782643800523522609693"),
            base_integral_type("2632293170696056542333892967280709916705622641650329247062694369599676143397746994"
                               "261554387573180162640019376757904"),
            1),
        signature_type(
            base_integral_type("5152429385048653245817093726718324190753820949783600825121013132697362339905493128"
                               "32178072764427962961728891469210"),
            base_integral_type("2445239057795842242228509997856338117206427430153004311425540152624277758636413407"
                               "809574586442608105951807804671071"),
            1),
        signature_type(
            base_integral_type("2839573097780069495370345713286265991759182375649877133328365960820825677660686600"
                               "420931645675465236322393990913417"),
            base_integral_type("3710946382885302657003443430679125175565099147647543169112102376834027682145571364"
                               "951855803025666130357208636216685"),
            1),
        signature_type(
            base_integral_type("1030397847263468446146339297821391784651697305655528828104869809960456379381965366"
                               "943364512951451847699579664821694"),
            base_integral_type("3001384274920418089203076308242048806687270796208387472388817775117452179970368884"
                               "987391084723528884592498229405248"),
            1),
        signature_type(
            base_integral_type("1994889288942240977253752512542997155284532514461634278543861300388339162032131190"
                               "281546176198968260449280865769007"),
            base_integral_type("1454342724354291351065426036338386574456921248206381127567496650542568323430762323"
                               "780659404480016443533443215375228"),
            1),
        signature_type(
            base_integral_type("4340257081572947127087361303148515285465091997743101368600299103860475550066682416"
                               "73130756486884266288922881085820"),
            base_integral_type("1164242790756046405933411010384237700216752635805943757061087484378058366114254951"
                               "900416189435660612167703397136292"),
            1),
        signature_type(
            base_integral_type("2447687993387838629767620519855329368115321127313059179901541513691618140144165251"
                               "779500019952692464330799993003235"),
            base_integral_type("3016535482385980109868983383411103613564155029435342234368799451743746443344597754"
                               "217012707182142199203961050069854"),
            1),
        signature_type(
            base_integral_type("9581258510963490577470518130049464656386242589069269808643208920650686599725668977"
                               "87875025010056927698756330898448"),
            base_integral_type("1922992107182576563563605987326712516709770411667771568104221817348269448086397602"
                               "967230840022921212735834667140995"),
            1),
        signature_type(
            base_integral_type("3684157182598355953984998059643952884799724774800935231418454519807563605375702827"
                               "69067089512841389133316489051561"),
            base_integral_type("2187103878253682473517477146428057255331389657820377470548866502052224698592921585"
                               "184092173745939416794981531706644"),
            1),
        signature_type(
            base_integral_type("3118929716927244707511405024709604047254128010235580841529986449039529112673696280"
                               "909193332280375160708532033402481"),
            base_integral_type("3417204373191715758647434869115349018977086210131909585967961096507128379563331676"
                               "918338940342722146741486290327714"),
            1),
    };
    std::vector<signature_type> sigs_9 = {
        signature_type(
            base_integral_type("3614191833619916771937923987471512697198222744507162350081951746328319780589900395"
                               "458912858002735051573879504563188"),
            base_integral_type("2957612112486862210580976612133903676085833054084162722154150038348055712519316088"
                               "998898753172665720495306658672303"),
            1),
        signature_type(
            base_integral_type("6943726045689118618096222349611532353884748204807953488478078405659721537975643728"
                               "18627626696107469225671507869448"),
            base_integral_type("3701297390156900680166476208723918861443941599901993776076227831303940373573517168"
                               "321269059197013651971358807451287"),
            1),
        signature_type(
            base_integral_type("2650479071999526992848542758364042760665513628631461254833862626415964485607296374"
                               "943740358238008517365126876269927"),
            base_integral_type("3591326866535656465313023764156507060720853300097670836551055205398935326270960441"
                               "078893859264013022247331095073450"),
            1),
        signature_type(
            base_integral_type("5160875849399631716879951871550446159357028147334627435376863508027637616730996272"
                               "40258149684123873011698587975132"),
            base_integral_type("2823239863847831444644387989234316681234527900150968908150474194417114881530396298"
                               "092505917622537716356276275023746"),
            1),
        signature_type(
            base_integral_type("2918724263140600644481002525779585398458601069205571861837827766299355378348192912"
                               "731999196812695016913809235140951"),
            base_integral_type("3580485954157131403971288202213620346843301369336526865759352040483915832892052494"
                               "86141319735544452022012196399455"),
            1),
        signature_type(
            base_integral_type("3398668435467482221330323377751204544476092841722944400779540654086089647027552765"
                               "952114342045606573166385606159390"),
            base_integral_type("3417009627450676516330431396768755613489120795842394123236986318972601991037550949"
                               "677929891267097226142451271572226"),
            1),
        signature_type(
            base_integral_type("3224820196462308014799966623517180452347678187615617464201165996281448855866083852"
                               "333669567212637085945103105564616"),
            base_integral_type("1381045428590297970041200208175636790105449136197177168238371249429929758505009282"
                               "380858551471970071793568824051174"),
            1),
        signature_type(
            base_integral_type("5515051754749126429573633829949935874026885124379607647399047220913948552357077639"
                               "51850093224860259219896233079837"),
            base_integral_type("1484882883889370710316213210462488753797517138959255741994012931293992163755424855"
                               "5477534951337172364507581305546"),
            1),
        signature_type(
            base_integral_type("1340378099469131217180864853371541239192743188962932860918801683642272204411306184"
                               "982865159406328539849190784726569"),
            base_integral_type("3988401522626426059515269685282046124317669750996005926241417738911838337373376167"
                               "420168107673194398275253194898459"),
            1),
        signature_type(
            base_integral_type("8425952664946501071739621016260311336618386468939924822353201445286604816918057719"
                               "71421729740779857703450491072675"),
            base_integral_type("2013128275611530836001289486095460793869288589729680474062638143008108329049490569"
                               "037790962530078741015159323192067"),
            1),
    };
    std::vector<std::vector<signature_type>> sigs_n = {sigs_0, sigs_1, sigs_2, sigs_3, sigs_4,
                                                       sigs_5, sigs_6, sigs_7, sigs_8, sigs_9};

    std::vector<std::uint8_t> msg_0 = {185, 220, 20,  6, 167, 235, 40,  21, 30,  81,  80,  215, 178, 4,   186, 167, 25,
                                       212, 240, 145, 2, 18,  23,  219, 92, 241, 181, 200, 76,  79,  167, 26,  135};
    std::vector<std::uint8_t> msg_1 = {100, 63,  6,  192, 153, 114, 7,   23,  29,  232, 103, 249, 214, 151, 191,
                                       94,  166, 1,  26,  188, 206, 108, 140, 219, 33,  19,  148, 210, 192, 45,
                                       208, 251, 96, 219, 90,  44,  23,  172, 61,  200, 88,  120, 169, 11,  237};
    std::vector<std::uint8_t> msg_2 = {42,  173, 25, 200, 18,  12, 164, 20, 47, 182, 1,   159, 204, 236, 249,
                                       250, 219, 4,  173, 224, 59, 52,  30, 63, 199, 114, 1,   179, 220, 149};
    std::vector<std::uint8_t> msg_3 = {159, 14, 88, 112, 57, 19, 127};
    std::vector<std::uint8_t> msg_4 = {79,  155, 160, 153, 141, 34,  25,  179, 186, 202, 17,
                                       25,  64,  213, 36,  183, 207, 148, 103, 125, 108, 85,
                                       119, 80,  250, 77,  185, 225, 7,   126, 237, 181, 186};
    std::vector<std::uint8_t> msg_5 = {112, 63,  158, 165, 214, 184, 246, 124, 233, 224, 96,  247, 101, 83,
                                       44,  50,  61,  176, 52,  236, 112, 13,  184, 25,  147, 111, 190, 111,
                                       116, 159, 211, 124, 233, 39,  102, 63,  67,  148, 152, 201, 140, 81};
    std::vector<std::uint8_t> msg_6 = {39, 116, 163, 178};
    std::vector<std::uint8_t> msg_7 = {39,  99,  171, 210, 33,  237, 133, 216, 63,  145, 135, 175, 139, 158, 146,
                                       143, 0,   222, 255, 66,  63,  255, 218, 219, 120, 110, 102, 120, 165, 154,
                                       243, 5,   205, 192, 37,  70,  208, 248, 171, 70,  129, 172, 193, 240, 0,
                                       105, 176, 196, 123, 188, 159, 19,  209, 47,  217, 65,  31,  141, 245, 50};
    std::vector<std::uint8_t> msg_8 = {233};
    std::vector<std::uint8_t> msg_9 = {43, 216, 54,  153, 246, 7,   65,  36,  72,  210, 2,   217, 72,  187, 17,
                                       27, 173, 212, 86,  214, 128, 134, 255, 154, 89,  6,   234, 59,  44,  218,
                                       65, 17,  211, 99,  131, 145, 247, 167, 177, 83,  238, 167, 122, 180, 114,
                                       21, 214, 254, 19,  179, 80,  245, 159, 136, 76,  110, 49,  172, 8};
    std::vector<std::vector<std::uint8_t>> msgs = {msg_0, msg_1, msg_2, msg_3, msg_4,
                                                   msg_5, msg_6, msg_7, msg_8, msg_9};

    std::vector<signature_type> agg_sigs = {
        signature_type(
            base_integral_type("1084917570002802763999237510539725659994871357035449444385093811995915316976445281"
                               "292130656008639155395730412291658"),
            base_integral_type("3886306453024106962210618574822438002507742324781378798145177640914851427480607773"
                               "80324526627818863422254675106741"),
            1),
        signature_type(
            base_integral_type("1334273933295198506579506466388518399757868713595298851455511991726529865559956852"
                               "139535647293288864109223486269501"),
            base_integral_type("2915143050271976741474346244282955959370160202462730084655401743968720393681037796"
                               "212282376238149776988779619385728"),
            1),
        signature_type(
            base_integral_type("1992226813233186161892841053730955713413330718396654770930615161245446330886348808"
                               "375149142136621699710166186529599"),
            base_integral_type("3792853260901743204349364966800584618293678374436330555441521901126225913302996074"
                               "787985368120014089424818764350034"),
            1),
        signature_type(
            base_integral_type("2273714389694683929793672845667364981885257753454257270925422420590663263362283897"
                               "559197709998858963248068940797693"),
            base_integral_type("7507214413513007609692689436408309286989826371582864950226511743165197870277975060"
                               "2498390191538725175882329115209"),
            1),
        signature_type(
            base_integral_type("3629662317305453527945814569531241916308551910395591700586345516594171820438063817"
                               "619360333835424710455112141718887"),
            base_integral_type("3977694355992175752758017157256345335610558907805754302645841748408524019079246693"
                               "516486369282313108381864169850447"),
            1),
        signature_type(
            base_integral_type("2743066008141784332448636417850442533444376990969234272262103820239974897235349447"
                               "940848232836245269355081404970989"),
            base_integral_type("1003768812584312775171898292160717609356818331948530343149025924229312799065943734"
                               "731919710505333711189358653656122"),
            1),
        signature_type(
            base_integral_type("1120060595279201597292489863360350939390846549261297899755461307631388272858656494"
                               "70363583760043719107241961383627"),
            base_integral_type("3032999153532165991682551028625187876282753540066198123454340275579278219322558692"
                               "791110643868420991799030300916720"),
            1),
        signature_type(
            base_integral_type("1827631294354850244539090463908521035964141492169605349156917800494545990061799040"
                               "142059677171367430783523947795508"),
            base_integral_type("1461596941678182387988133247119487583922045995621434700589940645198051782085659556"
                               "164556176218490298266521640001681"),
            1),
        signature_type(
            base_integral_type("4279615515140370040311679974410757722905208857087413242574315353971587570075791975"
                               "16042030611508597429044635860148"),
            base_integral_type("1483169406161183521857518773785313836760796098376071625472725178754507210694402765"
                               "17299367081698862501290292015162"),
            1),
        signature_type(
            base_integral_type("3897131325847469827104109262324942155320575380077985344861872795926599212115111988"
                               "01911682524047046070189254233304"),
            base_integral_type("1066950327548057040635477728785400668202524036698616416794176843313107716420767020"
                               "768360276092814627500088544460485"),
            1),
    };

    conformity_pop_test_case<scheme_type, scheme_pop_prove_type>::process(sks_n, msgs, sigs_n, agg_sigs);
}

// BOOST_AUTO_TEST_CASE(bls_pop_mps) {
//     // TODO: add test
// }

BOOST_AUTO_TEST_SUITE_END()
