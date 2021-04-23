//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/pubkey/bls.hpp>
#include <nil/crypto3/pubkey/detail/bls/serialization.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

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
    using nil::crypto3::pubkey::detail::serializer;
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g1_type;
    using group_value_type = typename group_type::value_type;
    using modulus_type = typename group_value_type::g1_field_type_value::modulus_type;
    using serializer_bls = serializer<curve_type>;

    // Affine point
    group_value_type p1 = group_value_type(
        modulus_type("3604356284473401589952441283763873345227059496255462321551435982658302670661662992"
                     "473691215983035545839478217804772"),
        modulus_type("1327250267123059730920952227120753767562776844810778978087227730380440847250307685"
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
    group_value_type p3 = group_value_type(modulus_type("22084667108196577588735774911639564274189527381579300109027515"
                                                        "83108281379986810985262913684437872498514441158400394"),
                                           modulus_type("12406587907457130429434069344825464684261259614486728581982359"
                                                        "85082377053414117332539588331993386548779151154859825"),
                                           modulus_type("29038518576972662592822044837006359977182512190287782275798717"
                                                        "38931918971045982981178959474623545838060738545723395"));
    BOOST_ASSERT(p3.is_well_formed());
    auto p3_octets = serializer_bls::point_to_octets(p3);
    auto p3_octets_compressed = serializer_bls::point_to_octets_compress(p3);
    group_value_type p3_restored = serializer_bls::octets_to_g1_point(p3_octets);
    group_value_type p3_restored_c = serializer_bls::octets_to_g1_point(p3_octets_compressed);
    BOOST_CHECK_EQUAL(p3, p3_restored);
    BOOST_CHECK_EQUAL(p3, p3_restored_c);

    // Generated by blst
    group_value_type p4 =
        group_value_type(modulus_type("30311851368840285580047084465003591340796954930450639493358501068943489413531875"
                                      "79165196235778982806727098663057122"),
                         modulus_type("49014011513970003088185148750418624927679653147470313898591903023733897777517111"
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
    using nil::crypto3::pubkey::detail::serializer;
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g2_type;
    using group_value_type = typename group_type::value_type;
    using modulus_type = typename group_value_type::g1_field_type_value::modulus_type;
    using serializer_bls = serializer<curve_type>;

    // Affine point
    group_value_type p1 = group_value_type(
        {{modulus_type("85911141189038341422217999965810909168006256466381521648082748107372745388299551"
                       "9337819063587669418425211221549283"),
          modulus_type("38652946747836373505232449343138682065351453822989118701578533663043001622363102"
                       "79903647373322307985974413380042255")}},
        {{modulus_type("11185637828916832078768174243254972746778201844765270288305164561940707627068745"
                       "97608097527159814883098414084023916"),
          modulus_type("24808054598506349709552229822047321779605439703657724013272122538247253994600104"
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
    group_value_type p3 = group_value_type({{modulus_type("290953753847619202533108629578949989188583860516563349688436"
                                                          "1019865954182721618711143316934175637891431477491613012"),
                                             modulus_type("368137581722696064589677955863335336277512129551843496644195"
                                                          "2529453263026919297432456777936746126473663181000071326")}},
                                           {{modulus_type("380942359543145707855843939767390378902254098363111911764743"
                                                          "0337095281824700234046387711064098816968180821028280990"),
                                             modulus_type("242844158649419580306404578813978370873620848181595711466624"
                                                          "627022441036207994945966265054808015025632487127506616")}},
                                           {{modulus_type("436672409349779794890553748509232825356025978203835354321194"
                                                          "85577859579140548640413235169124507251907021664872300"),
                                             modulus_type("583765897940425051133327959880548965930101581874240474476036"
                                                          "503438461199993852443675110705859721269143034948933658")}});
    BOOST_ASSERT(p3.is_well_formed());
    auto p3_octets = serializer_bls::point_to_octets(p3);
    auto p3_octets_compressed = serializer_bls::point_to_octets_compress(p3);
    group_value_type p3_restored = serializer_bls::octets_to_g2_point(p3_octets);
    group_value_type p3_restored_c = serializer_bls::octets_to_g2_point(p3_octets_compressed);
    BOOST_CHECK_EQUAL(p3, p3_restored);
    BOOST_CHECK_EQUAL(p3, p3_restored_c);

    // Generated by blst
    group_value_type p4 = group_value_type({{modulus_type("986915135914398354429507129337950846494088465187165144608943"
                                                          "919532265387278101113414017664528112161554123568767170"),
                                             modulus_type("240610815317522947303384625207408526547682381889040357486642"
                                                          "4879097778273241785181376579099627133390707436080946760")}},
                                           {{modulus_type("905356155402453036694818402428447875811858561324452962669988"
                                                          "634216455237774846815387092699242963228002075684722919"),
                                             modulus_type("189475011967749777665668577550527779817561737907101306360710"
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

// BOOST_AUTO_TEST_SUITE(bls_signature_private_interface_tests)
//
// BOOST_AUTO_TEST_CASE(bls_pop_mss_private_interface_manual_test) {
//     using curve_type = curves::bls12_381;
//     using hash_type = sha2<256>;
//
//     using signature_variant = bls_signature_mss_ro_variant<curve_type, hash_type>;
//     using scheme_type = bls_pop_scheme<signature_variant>;
//
//     using private_key_type = typename scheme_type::private_key_type;
//     using public_key_type = typename scheme_type::public_key_type;
//     using signature_type = typename scheme_type::signature_type;
//     using modulus_type = typename scheme_type::policy_type::modulus_type;
//
//     std::vector<private_key_type> sks_0 = {
//         private_key_type(modulus_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")),
//         private_key_type(modulus_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")),
//         private_key_type(modulus_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")),
//         private_key_type(modulus_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")),
//         private_key_type(modulus_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")),
//         private_key_type(modulus_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")),
//         private_key_type(modulus_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")),
//         private_key_type(modulus_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")),
//         private_key_type(modulus_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")),
//         private_key_type(modulus_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")),
//     };
//     std::vector<private_key_type> sks_1 = {
//         private_key_type(modulus_type("2369504379624793579280006665574483344747601607445519063189631339703232443856")),
//         private_key_type(modulus_type("26871155931427555174449046914648624385219647251239028268944298662101320495545")),
//         private_key_type(modulus_type("28557033433071297165575355485758538098044359326430208338829921448041625494102")),
//         private_key_type(modulus_type("50207756579056080743427775554510920463002505646935699384775921010660882070083")),
//         private_key_type(modulus_type("4489814086703605856270857521235304813261914907164988789613159665246884038151")),
//         private_key_type(modulus_type("27999114484157470992294589518823692599033177781647483138012576021476400179333")),
//         private_key_type(modulus_type("42567019084926239122712818032193175076567424719134478834872414023296796320357")),
//         private_key_type(modulus_type("35298624111423141056388101307435062870108221684361714529106750723274377872863")),
//         private_key_type(modulus_type("6579153998468513419786359934020246770600406824170889850803198217728618698226")),
//         private_key_type(modulus_type("6539350955118550946575217625093029917954692652855633801961789114651890998661")),
//     };
//     std::vector<private_key_type> sks_2 = {
//         private_key_type(modulus_type("35957171001594694088720487987136287724516371500148041118758676624782950541343")),
//         private_key_type(modulus_type("22758694265525713398795984411245001581510004886536999679669107705015603678875")),
//         private_key_type(modulus_type("45144179501096972603440498362227784062141899540924159942809113340040390662877")),
//         private_key_type(modulus_type("1840469417843895170012914915960969486629325593345767920212426720811340372749")),
//         private_key_type(modulus_type("25604584184868343745303218004818491639807915381067307058328198626860270377388")),
//         private_key_type(modulus_type("47826508191159869425572828684997830703928546945691419236357419849825709340438")),
//         private_key_type(modulus_type("46752758778614664955976577481842353264403261116012689540942194703931606267073")),
//         private_key_type(modulus_type("1353045885643404754277593144812444225931415980755674844687045201544927533478")),
//         private_key_type(modulus_type("15234919244624245069026516906725720858085709457777593189146428458132347567163")),
//         private_key_type(modulus_type("35216920335569339620126246410692007502040656594756514612601109719761533811375")),
//     };
//     std::vector<private_key_type> sks_3 = {
//         private_key_type(modulus_type("44846790857179378636182807875786327214993897162360637724968697705025794642333")),
//         private_key_type(modulus_type("23870613015465401266444558440262015653740663903791315414716868119752738441220")),
//         private_key_type(modulus_type("23439173523683741500798160304221604560434765737708417109534517586766344880634")),
//         private_key_type(modulus_type("21288803441811270583623370562387713070152626197672433531200345326421712287533")),
//         private_key_type(modulus_type("32503256233997741173480644308025972731833278744104127493516486219753213387018")),
//         private_key_type(modulus_type("46811868463263528350462227616426434771578809045297619166691855405945470150361")),
//         private_key_type(modulus_type("6293628395975428984357543682843187494765636412012017794600244158401723471918")),
//         private_key_type(modulus_type("43895544712345759646206304247940760355319317187574944382914306227652374928961")),
//         private_key_type(modulus_type("48179455399056012869086846076571600159323457437342490463984270900442759634040")),
//         private_key_type(modulus_type("15244614054442559267920524022105573071383429957358030776946994041743591866706")),
//     };
//     std::vector<private_key_type> sks_4 = {
//         private_key_type(modulus_type("24671480881034555668621958391531162804947981507242463478650268716538708853016")),
//         private_key_type(modulus_type("35156860692258266859714933944184502459108001875120924441959754569840594064117")),
//         private_key_type(modulus_type("10009799081777253087427127013887456678691115252901131568711175816521662803996")),
//         private_key_type(modulus_type("26725745523140978681632350855299902164508999036874348590285573200318010911758")),
//         private_key_type(modulus_type("47369557198254831037546011708076336436882374536558104107399747848690464800093")),
//         private_key_type(modulus_type("18192560042083570853921100083230193051649804688722122954533392841165441419428")),
//         private_key_type(modulus_type("29409956613647379467023640788415265145553681481170181038736615819022702247736")),
//         private_key_type(modulus_type("23355486751239950547671156404592102200180636821914272620083087747398616652941")),
//         private_key_type(modulus_type("6190957438783997636927425558563693845765391731669345057514374198814430571383")),
//         private_key_type(modulus_type("18315077413398251993817593998878564091948630821724239467337386703960158955398")),
//     };
//     std::vector<private_key_type> sks_5 = {
//         private_key_type(modulus_type("43879387577444284867225374895412957121478660348999120715937378069682700264647")),
//         private_key_type(modulus_type("9365189757817316199500199904632334272336220006252986395633337300438822249536")),
//         private_key_type(modulus_type("16664568455936926898228475380796343651808382373568284937681967155518200670090")),
//         private_key_type(modulus_type("48512375444401302464882679853012371770681841086602238641703559283734980911072")),
//         private_key_type(modulus_type("47325847886939383467423719688864080013772927690427857050549502629497273469647")),
//         private_key_type(modulus_type("10944219016283652928750954331783106947798895292633751709762909351672457430933")),
//         private_key_type(modulus_type("12992404648299778389108195161446721984361718313799114280528673879344789372757")),
//         private_key_type(modulus_type("33957893568936936840281082256470251755882221502729648047853109120614137135512")),
//         private_key_type(modulus_type("37458692876367357108749299380400281720068573587532297343991292086984426369015")),
//         private_key_type(modulus_type("51166611183057827374512246291190133958554265767470596674109803397025983146067")),
//     };
//     std::vector<private_key_type> sks_6 = {
//         private_key_type(modulus_type("12725661857107102441780983287384238808278563198861104608788098082933381882746")),
//         private_key_type(modulus_type("44188672626552435485431094556632789464209692254273419678899723355398680884823")),
//         private_key_type(modulus_type("36299726244033767605886693744973562676839637466938488301971956775013048617049")),
//         private_key_type(modulus_type("24791239752789558856008694734770776950416505036747482257593301403756285906174")),
//         private_key_type(modulus_type("11248844888476761728957175688844865609115133744313063162359128615242399306476")),
//         private_key_type(modulus_type("29165656643790880221400020534001587571273105802552812484490664913996533881997")),
//         private_key_type(modulus_type("22725405117690258564083766734873051038927391979883011238345108964175939904139")),
//         private_key_type(modulus_type("3170544880906710447974347630412235304341948536772446892465032646567868631471")),
//         private_key_type(modulus_type("47684329279925942167853794985231439878227271636671029249162013670754139447039")),
//         private_key_type(modulus_type("44065288211512777303732797123407949920673752161085989729445186683764585835831")),
//     };
//     std::vector<private_key_type> sks_7 = {
//         private_key_type(modulus_type("46761622771097458983966977536111330884524778692941345889849364099197024282993")),
//         private_key_type(modulus_type("33508015279120063381285338995352668704730427122273333328622962453368104710804")),
//         private_key_type(modulus_type("44725039460708817115344423417052256045568291985638013980251525067997866857029")),
//         private_key_type(modulus_type("46833135132882600382154798661263761027158499201120613389419448951547141158407")),
//         private_key_type(modulus_type("20880673796762049924851435742171324131459080912134183778950724982881501083067")),
//         private_key_type(modulus_type("45394142255690604204714572257416332831892472888869385324878761977830621612343")),
//         private_key_type(modulus_type("51984015576088397996956284141615708947725329768364829309875758815228333196075")),
//         private_key_type(modulus_type("48293144431428700872268676964556096022212054327427228163098783485196515529202")),
//         private_key_type(modulus_type("36222815212116149677418064146507233881718761668382989691025766670825645985075")),
//         private_key_type(modulus_type("50759280419860417802055275065687093297038790247990902467795244595907892506092")),
//     };
//     std::vector<private_key_type> sks_8 = {
//         private_key_type(modulus_type("18746656845646859750561258867056424653369118452181987362435158421729226076698")),
//         private_key_type(modulus_type("31031560450659879786932526067256771604615387756442671123866002549871606679599")),
//         private_key_type(modulus_type("42494955329311697249572246104019625483038664646322441879590721841201771335870")),
//         private_key_type(modulus_type("43782052753664520569471160529173897961207108821566825393268891447596146054616")),
//         private_key_type(modulus_type("26363562248624265009458273612928610241976727325183610252378574293171777607284")),
//         private_key_type(modulus_type("8330605458902223354655609230515256436651802889371700166429602300903172948508")),
//         private_key_type(modulus_type("33631523381804483667922029118359379550752079336584633907397563557091336056406")),
//         private_key_type(modulus_type("38902873125533844275467523940118290304821263142325046482935001018436033904609")),
//         private_key_type(modulus_type("21186732187481406240755327814169836126584542394151303448634680901921963427400")),
//         private_key_type(modulus_type("7414415982747742360299276276780362021924698250402910656023926061967429270589")),
//     };
//     std::vector<private_key_type> sks_9 = {
//         private_key_type(modulus_type("9002517108680634148912198663388287630298040868446423873959280357965384444644")),
//         private_key_type(modulus_type("20769509770088624697168035266555805504367557410835986579877801358530423431840")),
//         private_key_type(modulus_type("10471598158849283370466963664073078956391340575269597786040249259208941155163")),
//         private_key_type(modulus_type("38298179342103490265542894264723183683640300774068241662807160748046234447335")),
//         private_key_type(modulus_type("38002822806114311455746644612018021287228960046070496107872097107976550634160")),
//         private_key_type(modulus_type("9717059311017176101883301475874953395225713545443461257602337754443483280802")),
//         private_key_type(modulus_type("33475308610895441921585083068864950299191740111413597957557228910270689634240")),
//         private_key_type(modulus_type("8905194960900233962941853200031185599184174289112152214189292652244170740907")),
//         private_key_type(modulus_type("52243467421328849929566262215650804220328323015916662092647174158778452994708")),
//         private_key_type(modulus_type("9092304683956881416251913178222695577348165263602981029776877633501622925022")),
//     };
//     std::vector<std::vector<private_key_type>> sks_n = {sks_0, sks_1, sks_2, sks_3, sks_4,
//                                                         sks_5, sks_6, sks_7, sks_8, sks_9};
//
//     std::vector<public_key_type> pks_0 = {
//         public_key_type({{modulus_type("9869151359143983544295071293379508464940884651871651446089439195322653872781011"
//                                        "13414017664528112161554123568767170"),
//                           modulus_type("2406108153175229473033846252074085265476823818890403574866424879097778273241785"
//                                        "181376579099627133390707436080946760")}},
//                         {{modulus_type("9053561554024530366948184024284478758118585613244529626699886342164552377748468"
//                                        "15387092699242963228002075684722919"),
//                           modulus_type("1894750119677497776656685775505277798175617379071013063607107829708998161751301"
//                                        "035336528744906948117796249796317894")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2141614175260072836365331584208124170660059813246260190466358608483797394615928"
//                                        "40211939855336381517891051741276368"),
//                           modulus_type("2650619473364051082040689109251944368467495160205955763005297718175019210501079"
//                                        "116654401782146365657120078395681345")}},
//                         {{modulus_type("3634052120567270983639569473620425049276040377515902417475261962424349731850994"
//                                        "658659854425679451400599222607934082"),
//                           modulus_type("5099038293131657781704779726947888810975069790540182085053715093027259825646089"
//                                        "25089294045504828329481326551710648")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3417640715409776374066027267857601883094944217675426960018014426889645307918629"
//                                        "372724054413390347155681924840391558"),
//                           modulus_type("3473414583298623206380837902916659193577790963010337436263707184311224847816247"
//                                        "847844467185359177108372192975159311")}},
//                         {{modulus_type("1420508027927212530897776417509347281293169110422739533230859578787700513487235"
//                                        "616180228112866538492064471595509473"),
//                           modulus_type("1161795262458323343284112677204493783305261981886995263485940035679004019777947"
//                                        "869551000129358733559575974970347842")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("9739516260296219980235017056652935770613733255984411484024196528260104936073073"
//                                        "42568824924391088442518128029319037"),
//                           modulus_type("1501498247001046893024022693897765917023368834465272103650279081322905070709985"
//                                        "500511539514448756123396746343783604")}},
//                         {{modulus_type("3450556017386160388759685672252065570196438932086685137790044023926271831096102"
//                                        "68771463852959783918183538812988066"),
//                           modulus_type("2949304854676622327823521342079041967630546163494131565314601294002237398611311"
//                                        "234703984548859532724690550634771240")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1761498699861007023538715213459076829024517250654921437540629028929812836585200"
//                                        "732413579236103091551430482586718368"),
//                           modulus_type("3587827333847943084113852532778458967703496477878945438333497881936158379298463"
//                                        "477899033388949929156704108627430588")}},
//                         {{modulus_type("3335811555671333926568533840643212284212320230429524137510487921414461258323422"
//                                        "859433880249728361421382964584716658"),
//                           modulus_type("3847242806349041610471314575292200690452420208465664378435435875182493153887873"
//                                        "431227746695067634531650322041945095")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1605456820625062757937335728013199017848887567201428398159195285203661469913384"
//                                        "895017880782971393426256728305465113"),
//                           modulus_type("2513002797287711325676931851586045982484033198219618503940260236411064151842325"
//                                        "369898994549305781759266806023687389")}},
//                         {{modulus_type("1851326620227664962713767835874531446103275869103542921304860933552852160648435"
//                                        "646934700542255063174200846986840445"),
//                           modulus_type("3182993233466663731229585238265623832867154463215015243501893214900152947852655"
//                                        "020748142571795041714726379310914959")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1201978768113982344259111896753994712530115952531357367661907612247006218408532"
//                                        "425938223656157937985377659010848127"),
//                           modulus_type("2964962018574208324235921795619164456195606701901358054709684427150846775686866"
//                                        "042558844870239125382073080943796873")}},
//                         {{modulus_type("3715073098968853891604230804986167353634495127574986144088970025361288465118764"
//                                        "166016280995329658820017636671766937"),
//                           modulus_type("2001491594618861872073297833137240235143746017486499127363966629981371313691029"
//                                        "204970033978857371631692412274006674")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1492342709301925320264030406283796129052711821283103876981942497523517107031705"
//                                        "526363472168733809506691060000443125"),
//                           modulus_type("1152812372053952042553346892092530021693187851968732905766184814826494418864706"
//                                        "552076914862222037595871580694821550")}},
//                         {{modulus_type("4762249313853867412135533728553596362014042904955932397548438691313499174986942"
//                                        "37974383793866227124212019078203466"),
//                           modulus_type("7478318495178126415939141344807441015399664267492602548835606577743737692055986"
//                                        "99588296157423667823197136053946651")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2231127024428675179498036526961207009928146637687715175730712017742175374631495"
//                                        "840514067537470902013716749605354252"),
//                           modulus_type("7099995769750371752721880583461488451063267758833613788992746242727953768727747"
//                                        "62050654913872828047763484011636957")}},
//                         {{modulus_type("2460804578391158870831876239076295971331046775638053881976858791550134834173998"
//                                        "10163088870142034968396718604155118"),
//                           modulus_type("3682353022914254836793011233998324742437147427943666955141184940323076224008860"
//                                        "471696184585218555086617820626834881")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("7398004350882736937676821858603794160012365558756881375250444415536549483810635"
//                                        "65223413764397583702416387368419944"),
//                           modulus_type("1750679754639328137511638686703618938090014793486421323713036658294431277116191"
//                                        "29909646953512777606686786202005958")}},
//                         {{modulus_type("7965911485287093407389658754437797317989120567930015282401034516483601684229473"
//                                        "91354202902673455688323829845185549"),
//                           modulus_type("3438674710890738902269417118274782723680996183719023918833993695881818178204283"
//                                        "292640462665125472587629287737450344")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_1 = {
//         public_key_type({{modulus_type("2967893484120472085706310586726380205588067460993304376371133159706832592529207"
//                                        "903193353344797457425490690505804909"),
//                           modulus_type("3405844751338522226265223837114196683152110169644012981732888063138915739633192"
//                                        "948284339940435157566750403074265830")}},
//                         {{modulus_type("3026098750941490110584151939841721507246659458518181703213617461466417960538222"
//                                        "976131619510854550516715600964983064"),
//                           modulus_type("1978296346371944977837091846701481486924755517352071628160541010822182118115005"
//                                        "454570130945741267189050339762477190")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3571634861294138545670333304600352348888757389144590504543271885970519594730387"
//                                        "37285112633649320251413759150854054"),
//                           modulus_type("3651431981169032094820657193981164171655288969641691966856431770158075765466284"
//                                        "30199903919978307489282143625150326")}},
//                         {{modulus_type("1568549861499884720264284094858340295945044973983201490800018790082999211952529"
//                                        "230137834529595523193971374591042760"),
//                           modulus_type("3193026882437744736301254551134569126564592462913398038033035402065997608527471"
//                                        "396835805849840991200697632398835071")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2273344451661289160830901995217746886278310187308493038301582062926401507943178"
//                                        "381062831353843479155461748657629653"),
//                           modulus_type("1709146448561070089007234901903329114855698723988028311596729967761227143193118"
//                                        "001670452668441390666417830484618365")}},
//                         {{modulus_type("2006128690869605493919810922436713376944559997714463405784520741716002393887794"
//                                        "187140134359938326756411995930546889"),
//                           modulus_type("4610154950988712598564060601491156763472183007358574311994129954977587780941900"
//                                        "09743321472103048723739534717773859")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2798843997582204232012436096657008450859498675802462239618174575462599297499172"
//                                        "715860777988865093776680193590636335"),
//                           modulus_type("2000671088852307920792059286647113050252612464868813327567177774050139878411373"
//                                        "87934883330558595912005273290417442")}},
//                         {{modulus_type("1328039517461147133666949614194428505829303934894910686190214361126318475239075"
//                                        "388217095197926158246702136273590280"),
//                           modulus_type("3776154024130455449923985887269306830821301727059716822589220682670560964038683"
//                                        "273347873897198615694019421998268831")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3337193906786309259787822134433441333009159784786092293338361779596022046219803"
//                                        "231394475714048124520554021012632326"),
//                           modulus_type("2652245537210355617056194801038132274676415862217468006852761372836718750469452"
//                                        "711376059398259169555180548680914368")}},
//                         {{modulus_type("2193527529083989723976626674361736321358217309134669345072350727963715273262033"
//                                        "094761025634310569210433065069554473"),
//                           modulus_type("1823058954198039729855143162352553072190330337503386039309383779739970070487777"
//                                        "256561583132618262471725038661178237")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3024240424596096267506244081679675770011776108544214811397212285780240433920344"
//                                        "271960846682980490355538141154375000"),
//                           modulus_type("1627153267453462890113063008088421576594572751501094780433083979767799364315761"
//                                        "211905089261742516416555902684166022")}},
//                         {{modulus_type("2749503790242499007400100234242129392850592033098196690389086589472136663613160"
//                                        "478402468130263956530753265128551723"),
//                           modulus_type("2452779556199647770117072065620755763513868491972451098940854468050629122219226"
//                                        "301297125798438375863642548592752749")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("7769655755071013597612775475082592716841034695778017914510036659130783801337106"
//                                        "91227442604001318758753529918704690"),
//                           modulus_type("8704573108781580321415254717120203950309288645288196208389412490355502974691332"
//                                        "15533158641770740457497236401082411")}},
//                         {{modulus_type("3428731368517744006303922001165405128323559375780956926920186254289006885821169"
//                                        "425315910208415283448811472538160309"),
//                           modulus_type("2371031440173804931102572397328041163404426288018783243446309926542923696772721"
//                                        "719663391956461992257976093122629541")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("4761541837854307784954889673003695745851072589360026825494493305479228046905264"
//                                        "4284241073006167336942014404755475"),
//                           modulus_type("2831070056756767315407792006657829859642381600444400206646261414701522192569954"
//                                        "400820115780477101691930159942501892")}},
//                         {{modulus_type("1395876534701770204799352177553775367022955978384847127843862310926331189265521"
//                                        "385126904282656669782405795817301457"),
//                           modulus_type("1720313943084915754272415111070819396952007234331046851354848568337800383989101"
//                                        "47232822157671281689749784737726193")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2412475730207947991936471716669713131714503349940336181777022838620542066000471"
//                                        "659811781202510142050431589381279468"),
//                           modulus_type("1166043005756772246655475855813011208446223317701745421600160636314061007698609"
//                                        "105359657860531462594425642688372123")}},
//                         {{modulus_type("3624041011977100317171364891227281019252695440765864955383954592877895505000889"
//                                        "249441945322522862929648091115534498"),
//                           modulus_type("3025786843535270217448198308957738875842395491720095260766483542013301232892109"
//                                        "279333420513300352745612535828141334")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2148050544010812433700757880009014935328166321969731052902453769233173295232465"
//                                        "952257560896455182106560234865704874"),
//                           modulus_type("1799715334783536149448892309190564168853720402011947593710579023337456900924591"
//                                        "543219640045998648772132374622994323")}},
//                         {{modulus_type("1466926306734669550890221489649647448412872811000506298246203876426366001517021"
//                                        "464480923054507512022000405685751080"),
//                           modulus_type("3282385565584602906496355002998529249336771647828856884904796084803872202663428"
//                                        "912575155899722401254023476602629449")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_2 = {
//         public_key_type({{modulus_type("2832078100775080974310490004524808332834100214470327836720469792664572440152061"
//                                        "183990009632964534179825224630097545"),
//                           modulus_type("2422648896117916210998596995130938814685055600385797309906740859762378680367502"
//                                        "177425546664140479704486567393377777")}},
//                         {{modulus_type("1612194286783970204099289905771381610351734587625190180622801960479622691652325"
//                                        "277577837678570607785932552817549398"),
//                           modulus_type("3320662949158051060143305752369293629989890454507263067533182841861198878338457"
//                                        "669634092526282087198700591469626285")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1384852825356390954824626037025516018083224521263029102885180981138037884204080"
//                                        "776317002325652910023065973943879440"),
//                           modulus_type("3952686027050855535747118981471036356465649592724807400849172517041817180092227"
//                                        "267851079151469044514111996779396305")}},
//                         {{modulus_type("1571762855168345026268140808094077383390653457868455514307633189404966989041283"
//                                        "036806597279769079180519174541972833"),
//                           modulus_type("2584071621476416921681006616188726389371713439370162712575432739519880638039967"
//                                        "503648682282511599982567009514566832")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1701708719568752244687538584537275038362073556584714843061968233732588384028247"
//                                        "69968822408913792192946779054911527"),
//                           modulus_type("1139226923438222162512047495531791457452612290476832798959801912356161208824599"
//                                        "812465521049120109988916503563107425")}},
//                         {{modulus_type("2993723778949816023784732040478921196862744506285582584525494489271944793426468"
//                                        "677065130959206525835367786046368396"),
//                           modulus_type("3693027947101032904395971756052096627516356143914333209894773322390981502754796"
//                                        "00068419637720784847480902154323386")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1505197779878880997743636792124105830344147385542508492602426365277539739306308"
//                                        "30129828905582088979796539913060989"),
//                           modulus_type("1540273520540483660301720050002816561362230638212105591416815792337265191093403"
//                                        "935701172589565405796366688412014078")}},
//                         {{modulus_type("1458395851257909091847044103600542320642680271575103260243287590916343012547571"
//                                        "602987330730814084744968403421356973"),
//                           modulus_type("1425292607345705485417425471219656672789696416733993840794547070086325797124229"
//                                        "565167224369031854138310109156488745")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("4140298853992099613693525502610566133331208360669425308232838316834105730006872"
//                                        "15148264911366765795780362789850559"),
//                           modulus_type("3352464995025013934291272122411832087371046208309365126606690199190557061625428"
//                                        "347504793139677207474337931545344631")}},
//                         {{modulus_type("2405622249244184200698653552616578248897349043111861487574433824848073910974262"
//                                        "555706993187683590271900488371894423"),
//                           modulus_type("3820550869586127786420454613765120024852041776690765788889863905171366602100172"
//                                        "506556646152744818422845076048417474")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1136395953916925631195415236708776430798187399498690229419552341546278297277024"
//                                        "305724449351917400021193156259035167"),
//                           modulus_type("3473929204604723312054335714665510074934424724345009626685864554862970097524682"
//                                        "257545987577671220082700799284107017")}},
//                         {{modulus_type("3237430533010648929556552307375280098134515115941856060052250928870911892694780"
//                                        "909410478811110872632578728668578121"),
//                           modulus_type("1352805443602458594980247676600530793963516389134586412511363376154920149740027"
//                                        "141298559267559348465718353841449944")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3508745778904752146517503698103225140087066470251120601493138889334235045807969"
//                                        "41536864000297066866432306136096041"),
//                           modulus_type("2224472183817374366342837613217960764417455113224170846999201473459872932181134"
//                                        "58524276577235649506161669822850606")}},
//                         {{modulus_type("3978565864721029819058028782500187562933320329904540988589610345062226128551882"
//                                        "139347370503584873154314979062342424"),
//                           modulus_type("5914711105060790305858068098029425870074328950447226216655648070647112104363535"
//                                        "16515329924973683821126697706035195")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2720767296339211633441586217807469612605962635490752562822361485177303446941698"
//                                        "723614492206329823841299773686164573"),
//                           modulus_type("1256301540248323344065352733777080858298380965386864677934044181667918083969940"
//                                        "51845574498552237661578641412941369")}},
//                         {{modulus_type("1303169260990018818792526029826836611582243336222925131926590220066519088795203"
//                                        "070256295975212096267725606867946718"),
//                           modulus_type("3965323147581332581833338430675037524678079991929384017523525459013479510350681"
//                                        "498391838532247586250043734076787674")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2985043713082553899826038909039675888927443744069001655242536162547192700389692"
//                                        "53833328653979535804307632789345899"),
//                           modulus_type("8608336199601660069046386628409470829699216942403982125895847314618258942113446"
//                                        "01908873221585955995355363172214700")}},
//                         {{modulus_type("3351091942488333149947114711481737134469463790298903334089401393769139791583362"
//                                        "971935000063902002608533468748442261"),
//                           modulus_type("2573129246928087992431033913771381614380390809309701881896102522599561277397776"
//                                        "681131074533464463871500359160876988")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1352390059896703703438052805409346514302102947751161120308235693955300616966483"
//                                        "015921517642448167430538195409011368"),
//                           modulus_type("2474271360977435442667556643185106775184317967254640290759930467020116920468028"
//                                        "752132322684828199471324647355126355")}},
//                         {{modulus_type("3095166020930958362116859998686541622588267155090621838851125029239072539882688"
//                                        "555348544582090086685841946091347613"),
//                           modulus_type("7605116961991070299747617282884054465774831443713547895141838048119717977585044"
//                                        "55081055120494247551896849232514935")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_3 = {
//         public_key_type({{modulus_type("1911223755516953037452162543711974001498189311902095094772939571459715501941143"
//                                        "575856551425718269403585267630068503"),
//                           modulus_type("3938345717919878340188579505557003155343198137806750922468732248581520629181510"
//                                        "722637905339800541177508678886461215")}},
//                         {{modulus_type("1988271167246206827018898054166998654371420064049877186176669350291320560475701"
//                                        "961998276038106702793246167246843862"),
//                           modulus_type("2585152835118531732046038827732678155884963592068459750444634373926117444532290"
//                                        "645363203176971539975969312610739203")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3007694898468979691625067006902997818667709226948458323141229171971857461508702"
//                                        "822028890059287473396355690481035163"),
//                           modulus_type("1834569338036768554863560249278632231029393470624783600721621072582583233101471"
//                                        "38078350867254411768563006228240746")}},
//                         {{modulus_type("7493068344709950127612191537098074997985794745468049458709941697406470402860284"
//                                        "33660581263105762830465245593607058"),
//                           modulus_type("2921527244594166634843508880070314139110416522231532660444276339894765112085696"
//                                        "218051787627364293389075148595068214")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1778015285779197564607134174889516981941734012709131288448645454907277904740997"
//                                        "479299293586034393596236525019267299"),
//                           modulus_type("8647875063488552751182609521145192500701077762040358135811362777863357134593794"
//                                        "65574928233806586114471150573798776")}},
//                         {{modulus_type("2510891407066812765941688879563080885021678990818430245316510892772050113446752"
//                                        "103295053494287713745538531157621843"),
//                           modulus_type("1090002720681204145449894192593820597923816754063982301795512894568794323772106"
//                                        "098486731207069847388743271486465053")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3450443149793269753920958841767933601076173377998149673199101480792518833416976"
//                                        "580020891626654131011791102652212775"),
//                           modulus_type("2959140514702276464476359452653378568351183334897694958873517761596658870202882"
//                                        "312180500195220305469648056535883215")}},
//                         {{modulus_type("5044658011852577824255581390349535200750580846940218319425690650853568927720536"
//                                        "25628183416830732890092463255675572"),
//                           modulus_type("3447051516325997715056779648586810718442338386252853373388346861178186197464701"
//                                        "115604058510431361341497118224026735")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1992419914758267906418992131584135616529910480741508857988536571928439812889798"
//                                        "541364112680703689454537443661993081"),
//                           modulus_type("2852198598949988498026324678552371112323277767379501733765794946915805361520294"
//                                        "859223258405131207985437187805143840")}},
//                         {{modulus_type("2572068574675195898880118908719004569927435708267495152587720326284712812090185"
//                                        "233871639095279022195006055898997299"),
//                           modulus_type("3797718308823065026356610819128539285987287101851884269689487449769884992904444"
//                                        "596059733406485149306507240555738724")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2095144811736098087133691391398327262368883892483096504839561114518202997601533"
//                                        "619063911122956026848212292063737836"),
//                           modulus_type("3032232544762905855267301363147550225284445221689018905596009758559334482089800"
//                                        "007866275826010655883444510638248902")}},
//                         {{modulus_type("7796227171712553738688150293729133099999605506575061111008373995586996333693199"
//                                        "35671414514006899617197816396034979"),
//                           modulus_type("1390162276148159390791197422979250421887687401760102314238536966671781512797355"
//                                        "132834162447170552630163706223088606")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3693920190812618472363498872538722489555891371425115015414970539264017661410194"
//                                        "356696353306128842163029479665843918"),
//                           modulus_type("2243616577405432017401803078246300804232661895848183786524464995561622171299106"
//                                        "840597719444602701562226163950700592")}},
//                         {{modulus_type("2353593119788806399713028797602714912453078568468238790031422933351799698675961"
//                                        "434772807045824117781102668043113033"),
//                           modulus_type("2588556805675958210792361480140477925003315630451990879735671523144668203063637"
//                                        "777968294816045378729699296444151717")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1034262660890223899935027007961692712569401424473061053046504781835436345240215"
//                                        "152159131231468223127449322541410405"),
//                           modulus_type("3487959427704325797553033231959095381077838470796734653334929292535538365470900"
//                                        "0698502240250049638072353188876286")}},
//                         {{modulus_type("4912413774013737930236728515714777253820924006365729920275959796434491980930093"
//                                        "44478102440319669603548874609030355"),
//                           modulus_type("5731474122941242896354167045180957262186782444818717446761333460242159195922874"
//                                        "28614519250488487674076323638791629")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1716295591255303459389756455896972844624523200052419531969544222993784193321317"
//                                        "808936055833722473842990399081627194"),
//                           modulus_type("2765713334112904037952194828317197185223076581019043798001076950444046630004592"
//                                        "726978034716201761340460845083361938")}},
//                         {{modulus_type("5276349113571372028013180160436404899461031619246214984304499040723838876892536"
//                                        "741531158144720802145772436178147"),
//                           modulus_type("1932476419045546377426186705656718411926060293489885327857787271603592354626946"
//                                        "631337337604415172856637625716161500")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("7250404275759521076365458094022146575056028007575526029105370174442286726948844"
//                                        "54599456575456005733528127522933700"),
//                           modulus_type("1364561183887324316666173887404407272598019781228177833008781115064112192978494"
//                                        "427680496029744547328399634772754477")}},
//                         {{modulus_type("4559139077086022852469068650823343667925771831077279845064406410357206086056052"
//                                        "76639684342991137290292945977028631"),
//                           modulus_type("3573950093112161313787492397795521079539868632300023870495619807687813551201730"
//                                        "814857452574939978913105815368230847")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_4 = {
//         public_key_type({{modulus_type("3401451992126268393749075263647857315981271508063847238997456289470766261655467"
//                                        "572043976383887941144956530910770736"),
//                           modulus_type("3481712036093348598436683379872042116925894749504876038243097183860515319973495"
//                                        "568603766393973294117079199796415561")}},
//                         {{modulus_type("1838036200766189266903247181374381543570687110205339191621033663102267539302692"
//                                        "942824757877938887820330592868347100"),
//                           modulus_type("2989716069899107794875721573507577996388813192123061855344764367227217618484754"
//                                        "219105269324310948213831182595196090")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2426363871559715863189289467550417004196783135175334999019863589705863279797041"
//                                        "423320230912550659012451444081950862"),
//                           modulus_type("3978072677094121584456973215999671120956081446287030337853050070541841552185883"
//                                        "218739143076969031693494183554745167")}},
//                         {{modulus_type("2676102110964494696933566554763675348063283460050628767878199734777303456480919"
//                                        "439526475058375761656951848622504983"),
//                           modulus_type("3204292712487295728141763399929681613478316945700588018123158038400843755641021"
//                                        "858859186319065426087746867883859872")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3041105577866931992588405169436530627769665462346302148158218153620169686242346"
//                                        "190484415874934070285579662576117846"),
//                           modulus_type("1185557669619997087913370632268850104337279337297984496569837564894962712477895"
//                                        "281220267569135928328162664213953355")}},
//                         {{modulus_type("2976282594964204646114144563243284642604477623591329186927310971570273743256684"
//                                        "26287696714745342481573366101128598"),
//                           modulus_type("2818412692938763328519352593697928023537459569464998870461465035423623857143344"
//                                        "632464321620558897231743549429629866")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1016159901798264394397631616207937086988438841445069737905333170081645041745473"
//                                        "676053038618064088505809304675961800"),
//                           modulus_type("2102848650155255504007844506593413444486674114076084035467423948788388653167304"
//                                        "3458030969938511826372836599326136")}},
//                         {{modulus_type("3130706097864418310878473477263149353960285747296511586677424826443720228655873"
//                                        "67174427570814893997089181582197729"),
//                           modulus_type("2435674753013464912073418254336733392608484847192718951993429102710187440976728"
//                                        "231715157912855778779600052103230547")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1332551317125642591899577311839584875292134203992817400853841762399394943113845"
//                                        "427948861182222651415587920565931551"),
//                           modulus_type("3422540097329845700308429395717235475598306080730559614500333514593959140882631"
//                                        "315442397431428857501678438184285830")}},
//                         {{modulus_type("1720382210347750198637352882313582169927729296969273792941693076407876732807644"
//                                        "812738982468378099796839215983544294"),
//                           modulus_type("1530563508419857185432596259780365865252587466455110755373210225260732203390636"
//                                        "861093801530537538303973715852458773")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("5175652838557897280412389041681204751531001793306865094976772939226459477570874"
//                                        "39616011461356913191366030227406630"),
//                           modulus_type("2375949955582592512420111964304728655049453355649789629417921056702830523143470"
//                                        "287709306842658448700592461297473267")}},
//                         {{modulus_type("2400341935805915629175962939205908742386284572028586234127093447347654290002853"
//                                        "586870285948153712083035375182479598"),
//                           modulus_type("7586657726352993867475884651482350151149507593571266275647917366094838799202093"
//                                        "43080206630344095274497429809580904")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2670560576605680864287148223409789128594739954137360983344432780121709720088870"
//                                        "460457891430676256605372211325116253"),
//                           modulus_type("2308229867641923530613702710949560382477118960187647749837846085705036474727704"
//                                        "299872629469759973033208632912457556")}},
//                         {{modulus_type("3924667138956679794437532054321769833353983368209860563045809996684922774061155"
//                                        "182299328897436914954010264160408884"),
//                           modulus_type("8105269244653969052434561077367641419029344083935254539119835922573841853666122"
//                                        "30204743264421004044160654963838443")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2452212048683561743838619728088217060938270326349721441397265832435063413923291"
//                                        "415107865411543829147192601832789589"),
//                           modulus_type("2869429474329587239049382870311777627134278967201335025102928339807417144480476"
//                                        "156642273723836685021789614461687989")}},
//                         {{modulus_type("7195718048583089711187234117947835552298799237770300590469427739697078568267254"
//                                        "7195149306620524588711792839773352"),
//                           modulus_type("1961603985673816574366223788985922694848138797469137408902513378094708562988798"
//                                        "83458219834631684862750872904040436")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2951025148766504614572498763638972076740786741982612128527799191032888698657033"
//                                        "278258363056080729168490887451906100"),
//                           modulus_type("2620008385703061952275550025900424820659773827857255891263609529595497483677286"
//                                        "888991459533846268070044906665602464")}},
//                         {{modulus_type("7496770058366906373996700637615972990339473229554950569672702359123162986813991"
//                                        "4428777470573222127298179915822375"),
//                           modulus_type("2713026295902247568928928478084537430255033232545883729837033309960189210421122"
//                                        "251143474538739320448357962058221745")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("9134460212107451213069968417971390662267947580444044363815820341276698313757904"
//                                        "46687522222824596614177405400022386"),
//                           modulus_type("1820110434849533508411193722781210889884685318179555189765095245901981066673169"
//                                        "965017222334088360953087250285815200")}},
//                         {{modulus_type("2794200894281324136175157382033306716762402367162212246668700745489493277259791"
//                                        "256960453607684699845522080646336480"),
//                           modulus_type("2987643432095158293762743397228864319843033903504153305271703458428477990313960"
//                                        "255944832930723748038705194395688671")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_5 = {
//         public_key_type({{modulus_type("1707675722692633113384936589042377459473073287197671555197811175010393940993631"
//                                        "974811579642074862541337870336893977"),
//                           modulus_type("3904553444701892915897516271596326218821395681709333746626751573478316038838655"
//                                        "972850251323519754780758813898827133")}},
//                         {{modulus_type("1768729316828733753946044850080047104504361010308534002316366890313392627963283"
//                                        "858549929720589508854668895752711108"),
//                           modulus_type("2092594738581707672967082564521625300894161120302987881205013709041911782650579"
//                                        "19278430366902282571491004790853024")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1488923609161222756870529068053768531643304372686055126630665930467610719052293"
//                                        "084537183041948320393111295156047704"),
//                           modulus_type("4668248631257673076061888942909555538829213201239634761925091250631524876236519"
//                                        "27359872873776299897726539765793322")}},
//                         {{modulus_type("2975511047467246041653822307922038023926126743250252329059348366305825900380703"
//                                        "562848936217563468682435418598651494"),
//                           modulus_type("1641856606917713491223361120876233060120034811111944104036040518331172822277160"
//                                        "069723946932725335936473629952472431")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2128995207835853092723871982985247676316623554524066985633576937323747592472223"
//                                        "150584778056808822352476960157184628"),
//                           modulus_type("2506307302157636218233022465027574192145157455439295324810349321618070595873321"
//                                        "845098116417189073079691021546566290")}},
//                         {{modulus_type("2610169691586011107308980002912999308604184864226316813897973369281463619512452"
//                                        "297991495415229342583777968743188177"),
//                           modulus_type("1076899795440530295475039919902730239746975879347380038082478524107395669281900"
//                                        "463521850243549256961853255776893212")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3448372449858270676726500749307464466024950409778848450241646185227394326010525"
//                                        "047752133452190011562508724150242263"),
//                           modulus_type("3497254553277255707323686133816366550312248363335762510176874796000313884792018"
//                                        "686079190364218424124249445960192849")}},
//                         {{modulus_type("4263748814397593062619923333424424598924209609305263078813803461513394593034147"
//                                        "77266571473914655701637425083026635"),
//                           modulus_type("1134112862502794390572218714987323156312140025681218367585334413116114600213893"
//                                        "522838348962060684656384215145118256")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2825770176619382475640171294916460854441400839885538311908491328451168771125212"
//                                        "991729195925461696644635432810288366"),
//                           modulus_type("3135973363941896236026684501331808257820793035249450318612625971592190799211015"
//                                        "529739083571121701810296280160500325")}},
//                         {{modulus_type("3724680111693033535878551318268426075528811472394395397491593125945344494640076"
//                                        "370156446645715395018842169837465511"),
//                           modulus_type("2075534261769931266311268452867238661472130517314042467915903035411869259945102"
//                                        "144695300640605361759732114908147900")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("7933725844330892133584118729309995850583642259187749483691969002125740046725519"
//                                        "83417397671665524765483091821700002"),
//                           modulus_type("6500664091147891029436497838299608966702964045849701206768592811034471940644722"
//                                        "22840838804568405518763393040846934")}},
//                         {{modulus_type("1050968900238649797313935929307679614425899080178137747138626237788951506213762"
//                                        "358137864896556292122140822075311215"),
//                           modulus_type("5062375125858581905252812021844327106408653494167316463382966778566470553107546"
//                                        "53255350875423106864411858391161424")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2762793795262580250422864832714949661534331986235572113455894559066732028921281"
//                                        "059466442292522740286052459900517084"),
//                           modulus_type("1294505011522492641507544208063160989128055237356911051122573925514929754943338"
//                                        "702630712574977669125957210694480403")}},
//                         {{modulus_type("2303133101491107280648670462724598618210115609210076521182002840018761398959977"
//                                        "636210727360587037985290005769216146"),
//                           modulus_type("2720020776907996027740941333695186614783945044514197510229426597551029020883132"
//                                        "505798332176483776684330799661892382")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("6004935932032926927488262559969977041158935741746586427716548602176127443408695"
//                                        "20495237588568283028259073016359204"),
//                           modulus_type("1952495648153681807716723904905831842149786042278414976749720573656504809130023"
//                                        "205294283108832846346129769870361201")}},
//                         {{modulus_type("1976466935754887961361537768259822917905838776135025772300440883578030641621173"
//                                        "561188497222128398536620471888552935"),
//                           modulus_type("3193612360098162597050791663107291337199092491323019835528069450571334726692109"
//                                        "183909588620155635757844051216024620")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2983187227455636818732476448882870131549569868026669218247697746303112907981095"
//                                        "899484568034604389080176756444490661"),
//                           modulus_type("3664551705815670186045725324539281164269213122324447599778700597784114477211532"
//                                        "21014905660589398030659039148624251")}},
//                         {{modulus_type("3904732078981804898049420181937022048320129723488971821371969854680123926574538"
//                                        "210643695118217582228741474624672169"),
//                           modulus_type("2141038243052726581500470991345582872819180053884888485543150677673017977868691"
//                                        "985084945448965800359249869885827463")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2174924559149132509403249752050802595202902924744008787065933237358954402597952"
//                                        "889617593798303991171946743810348975"),
//                           modulus_type("1252778305625511343533940535408559383317839184554081171698971179649856080819714"
//                                        "063568293795790775383538700394289843")}},
//                         {{modulus_type("3054752545315473268277000637531389220759269885038430445178354031676213055140951"
//                                        "392591983369992165106909163659626723"),
//                           modulus_type("3557828601568948303303260368231559803681115123264560728734913049330201007941071"
//                                        "890519533916424653606677654070207296")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_6 = {
//         public_key_type({{modulus_type("5965531760465405342066821633393490077077001510042207621386740828054424652137364"
//                                        "00936783031372734291354661543108854"),
//                           modulus_type("2736364730136692922494681844694079482877788882634295671794209129677259195597241"
//                                        "565604069471398928177919615616054909")}},
//                         {{modulus_type("6512106949683380583850585638344775666901779103528055240314456682546294149862259"
//                                        "68370426464362203059272469401193646"),
//                           modulus_type("2258443336003119658749353558906728810171541810467727157947097381371569800692246"
//                                        "131918546172919165103909514711668241")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3470373160864650451405248329455313654895689268827077154098441868765846608727252"
//                                        "120443036630435267033219944526851881"),
//                           modulus_type("8466301910013549771492884772557035849721128094532928191332297830563591611340071"
//                                        "70887987529761206110645216720397497")}},
//                         {{modulus_type("1047147218061002995019132946332826105854172906548937115865757805353250277366486"
//                                        "543343081602149346793367039159496098"),
//                           modulus_type("1490616810211518513055325641843438514633138611360085399656444806051571419543544"
//                                        "618624479850685072103613749201796067")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2492873583699729773749066010827499233926129772394776391838573927178576714562853"
//                                        "016689172240040831700483420159662466"),
//                           modulus_type("6064894950618103587834670081736693045869003062439735351571536556579759377145223"
//                                        "23477874512778986025040655403160419")}},
//                         {{modulus_type("2726089736286133254425949700916126487146343079401547740740957349031694581700764"
//                                        "186729001698105618480128803761688144"),
//                           modulus_type("2174659199221923633267959038201750940793864530204834957963663293947373587902069"
//                                        "48032623642629331764421228784210395")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2385997926250150055424209831539323343307639414207095625577853427369996695873433"
//                                        "040659625426437373596567586158647388"),
//                           modulus_type("4732750897155771143497593484904528859391033578982832062404642027886672540824482"
//                                        "96010788112584735176653814335968710")}},
//                         {{modulus_type("1470891135704376795974351097615056060127722740242899118524812820133928855281725"
//                                        "136221151362278503953525418790142739"),
//                           modulus_type("1730356464593538151922948867194512586407811965380521216865364513790997761871420"
//                                        "983880282408494427692908622006417451")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1152888676426977774173838391298675519413848861644734013026293537138432023489912"
//                                        "428890293140353666203235126444659397"),
//                           modulus_type("1255853070910805051750878697275670726283321962568691398134406302295270536626450"
//                                        "81130476320842252571746063652023710")}},
//                         {{modulus_type("3914114917273821912588168664413128144107570800273906392701693400438762082408543"
//                                        "6552960500226281220911347225191424"),
//                           modulus_type("2244184281982537920259915217021202913290113146587613451904304569732920694370458"
//                                        "255873761448836034785923819745984865")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("9074399844168159891719968492233349058759838278300616675326115706549121386516877"
//                                        "95734199328920405812809672504094424"),
//                           modulus_type("2444683318453665734599447313963959662502652668908729725068900239286325374170018"
//                                        "209555402089924248857672576438090105")}},
//                         {{modulus_type("3046697907851014463821460919256931938049091109849306516343111113411442394470824"
//                                        "380867112670315085691884382753897195"),
//                           modulus_type("1336337891664165393305907376063433688729112970110780536971729881726824542678910"
//                                        "255390960186314793114563872201364502")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3474118919729433471405607362878899726715230788576858011718481145791899773513052"
//                                        "026880936016864883374245128151666046"),
//                           modulus_type("3305585753087500789395210083263493852610480635881766460203264325397714086404710"
//                                        "510542948903265757615167867273156185")}},
//                         {{modulus_type("2032953906562283930512330189993096391370678274174814746479441130308295130503001"
//                                        "891737892181610681728526754003033028"),
//                           modulus_type("1579503450406316787702702117803440331019234245691318101389900274079981035106340"
//                                        "029863528993808627820814118631416641")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2546760665640114380200564230609151571522181385090384133989012751369075449338159"
//                                        "431347558812785076471598863288120975"),
//                           modulus_type("1387279319816623962816255072940465780866741366241051887954834202316937378784075"
//                                        "034693778573820042899599140809822749")}},
//                         {{modulus_type("3704139056525759915737205715007418865722623244408806319210409337051249187222336"
//                                        "947134911462044230960442159575716676"),
//                           modulus_type("3198081175411941723406279910626737370465324136387012270080476664999911131925817"
//                                        "68969180890539455272134824560122806")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2699648079544144659429382216523176373677503239823435770544023586439646557089723"
//                                        "995501548040264051679857055948473181"),
//                           modulus_type("1406007432531877150887882623473662071810433735131522530918189476425609736087312"
//                                        "755522889287816809586640948043362429")}},
//                         {{modulus_type("1012821053473148406103310720248300727360419830049802977332413386461810187060550"
//                                        "327275611643056659532489574856404750"),
//                           modulus_type("1461057344914125247268000228452597602316524555599873738329062131004953471727505"
//                                        "190305370472519350566536569501339959")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1916660895759630680218591084826847455187921602496209311339960616996408826473113"
//                                        "767394750958814954781129121750081787"),
//                           modulus_type("3678120194620103480458679465092568994456510487726923597648588790481279445134416"
//                                        "314363267175249934296365936514170881")}},
//                         {{modulus_type("5415793902918555148223409483697249458802062547210118986595128589661955474982113"
//                                        "88642396522243716579532476658113835"),
//                           modulus_type("2142292653207546350668413339210655933206919613984779583036921592953928833385404"
//                                        "576891437893146326545066377886412569")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_7 = {
//         public_key_type({{modulus_type("3538998610874879318207373580846941900256791114104562354508918570939637884318408"
//                                        "331595623869555278720029294033440563"),
//                           modulus_type("6970919383608166902441649382567690235768926698729604493806834841190076314063110"
//                                        "59698020459178093117450162331516964")}},
//                         {{modulus_type("1365656041367348255403957817735382471123514287643659455194793576924790126542353"
//                                        "791039278034791480870463447946871645"),
//                           modulus_type("9266489224966251643819986209611488745876699631641605209488196513008476403489247"
//                                        "23726971182745994643468713004028977")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1912628557662892285113070170271087973392892132277626578815679564079573690492329"
//                                        "778242481259390675083911778605329371"),
//                           modulus_type("3801447732564489387421653668505131182709063229956730752614675071006342807826022"
//                                        "125445064471727173818088147148646232")}},
//                         {{modulus_type("1147832093749387408147585188461607540983547528576213019457563991676580634888733"
//                                        "186947175697384484600791980117923514"),
//                           modulus_type("6613747835786505901553958329151702344565332012867567722178558671369507174006573"
//                                        "44541848718008402622858485953052659")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1011284943471594207610595433038474201980505916720475138874081042404744637534531"
//                                        "680566880162761883263411495065433095"),
//                           modulus_type("3504998486737386808500748440791192097748776678191752597441453829495369412507530"
//                                        "488425088960666382476596659972595663")}},
//                         {{modulus_type("1682037564494803431932036721681901042459022379316614139745064851650496038014364"
//                                        "90750231930711396135746419920770601"),
//                           modulus_type("2132415955076439320330121216279696126321865575918843005163969648514744214583903"
//                                        "669712594593118263081003736703628707")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("9807339210468552078858264945621875740915728945765334970800590417184933155150168"
//                                        "34296328512849971799817584193502541"),
//                           modulus_type("2849345207480197979073681076677589928747477232138049696752854487013067819504766"
//                                        "118297501465608652781800789329463659")}},
//                         {{modulus_type("3901818698686608629799267046299149312011899550147135464430409300099233387899583"
//                                        "474129937769716841253209753148132118"),
//                           modulus_type("3201047803180144273144043062612449962960033330010165333036936865286872599649571"
//                                        "487790757999371098289521734570406513")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3270381076384676792594661955754084462300145152833942560154789656867864846117664"
//                                        "610317664334974153069757965429303087"),
//                           modulus_type("3451884756649221296469427864952382782312652482794952923838134090717262347196312"
//                                        "284005372149654872105274820234802412")}},
//                         {{modulus_type("2154474091963312804047395586797938981880635900224457678977651941704597731829213"
//                                        "700170802162156205276780892721675632"),
//                           modulus_type("5847479671513837053231717287137579380083725309702338743706917559397740756701142"
//                                        "10955042961505404448678504656535022")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3518751397896723092539054145967579031931188403970741493950437257519179751412076"
//                                        "308851558877587953474918043347919657"),
//                           modulus_type("3895343341732729979367452815904147675937813524431230977451110938832683118108746"
//                                        "760922964903822774092221319952806061")}},
//                         {{modulus_type("1448307386896393843479335542293471704412703372009294788547434517570049371435705"
//                                        "236860254559954682667128957671998156"),
//                           modulus_type("5613891662077950244981598155925449460557550932732052634676341212971010968068697"
//                                        "87327291093842707682164621455829566")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("9907299526288982106637923035842885475286548607460852618064971718013123103976543"
//                                        "57984017638488484134156402593404906"),
//                           modulus_type("2260286538989246671212052323519037168425909314537807288787958153008451516366190"
//                                        "123851700139703318585385226607712718")}},
//                         {{modulus_type("3613429067489462640499842519145955432478008948501469735180199247495104585696964"
//                                        "556327855544754005069759798225786543"),
//                           modulus_type("3814042321367003784436881955722254363642301578842767273608213505050796633732972"
//                                        "779456971038006897752407128201888180")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2841157213701756061658023508923937027646322583680867044538317711145293957899295"
//                                        "317136475608325946460023072639815278"),
//                           modulus_type("2911221452402903916464263454085156923167990990887001678511045220092014401323330"
//                                        "95127319870395404626679733660279525")}},
//                         {{modulus_type("8285700369384090393439646097529321438841351363038396326496765097989147108613982"
//                                        "66826202366347954223438990693975240"),
//                           modulus_type("6469046586804353766969518855429728140672899604198381709531157014334206481826223"
//                                        "13375935049582692710551001177225969")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1187020552979532527811401834495915482432077139481800604892107440488197132963082"
//                                        "175202561327169424555509258022407369"),
//                           modulus_type("3983001947646193526439387372824745693300140236109337197353961375292993883789538"
//                                        "717012858917626792865976221246306779")}},
//                         {{modulus_type("3379012044230087090218963532572146554443942462365075888862138266543023022624884"
//                                        "625163375535536937546745710107991467"),
//                           modulus_type("3008470273039708521678139455197368548315198091858852721553761530957324342302500"
//                                        "683415297908494656177370996899777851")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3836597690278935214221775896221699785061400146078588110165904881119348820402402"
//                                        "489193659851107950479029753945283211"),
//                           modulus_type("3827488122485489061148338096997438057494265422362105180904668488248981478953163"
//                                        "995327402930305799689687415834817909")}},
//                         {{modulus_type("2162389623663440957882964028706906720605877814599317191982004628244494617126441"
//                                        "948118560194210432396885612699081137"),
//                           modulus_type("3021964042420867282942895646474497157285413409947947110051234017209612578950683"
//                                        "729910799773814685370204108433825805")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_8 = {
//         public_key_type({{modulus_type("1022433248791358199590263461676901724136917085657153802353659780259697582489304"
//                                        "738712708519714624050802135061497111"),
//                           modulus_type("3333448737160918148782539953501069698041080705651958194242906208564543354633442"
//                                        "46936346616297864805240097279488856")}},
//                         {{modulus_type("9235926847635774142784152547782407901501684826882812074937153323782532817466113"
//                                        "80070608602145988823124320313219115"),
//                           modulus_type("1506040875690749408851834976267117482653315961119968804963215273842320079546171"
//                                        "388902087060482071220103811527440181")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2102201559046463954831030297364638601938718356164131586201632880811975169500646"
//                                        "422923915933597051387402792626046129"),
//                           modulus_type("1186010830759055477217346076000343894067949583297453934153494780554523189110855"
//                                        "6493948474469286026792761920625519")}},
//                         {{modulus_type("2454873816330618718569738737080460280144879835718247475072070341874018634652155"
//                                        "911095848583812472699593321802747834"),
//                           modulus_type("1606516470445645925401346034151616001406821829406320656216756477208633732771667"
//                                        "388587354456822154261533838646003151")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("4857222246837636341155541902546924422143688133600032556215341812695763694195382"
//                                        "13940586504957427207032236199194614"),
//                           modulus_type("1820310090961738386504802938295504954518098055990879827280332736051839825388709"
//                                        "597590346965266895851359330083736824")}},
//                         {{modulus_type("1866590448413031736177677525267208718890865543216332130814608252875542647584746"
//                                        "857284254314233053527507429316311336"),
//                           modulus_type("5879957048529291639914768953658881384035633326809785525887174543322909544853812"
//                                        "9212153163801244992802504377682015")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1171554251611009724186676159758070599455421165331573657491134388932630771519731"
//                                        "254343355268120994377065072051787051"),
//                           modulus_type("3312663155053985660127447973230408809346818930751873946182654958494782602917228"
//                                        "736041286640178512948685830842358875")}},
//                         {{modulus_type("6789789487674726601035064399175233437848775062840604201968163526300698682647021"
//                                        "87365200003187616613069593234108202"),
//                           modulus_type("3401463800596261886850617206635660828800461112285997635121398061089011566189402"
//                                        "089149934692537750263031148860414946")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2315519186848878846022936834016737440236834989379398004655552240678500083738579"
//                                        "933917023781770325133535692481525131"),
//                           modulus_type("1523436563692896491977293421296100891294146587827575644271533111660949776947850"
//                                        "183314148116802940161968997439828278")}},
//                         {{modulus_type("7669277777186437372962236323689005425417213922576206082399596268918560227689142"
//                                        "30720419396994944781564737103004720"),
//                           modulus_type("3624258690993407177132019195981554939089303905807102945354699912182007923401688"
//                                        "448110092938088751877226580063363135")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3043769693383994930003081658761742052134129528094252991028880472258939664182013"
//                                        "631093062936178564772576454972847769"),
//                           modulus_type("3712643793069624651025476671125159581679499327522328165857880608838532338014632"
//                                        "515848881590898090893266128055246599")}},
//                         {{modulus_type("1076349503114819986985395712345106842324346526052613547461850353075413778334875"
//                                        "344179212454731311213683237158311341"),
//                           modulus_type("1008100657912541257961010341598782879076594464564616795304822772740015225570811"
//                                        "792101424349018606069330003747669580")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1490140571982521410224045538506984056730531320277521191241739768418930986909845"
//                                        "464618732620106385244122167889807797"),
//                           modulus_type("1736260370437725785690532508650159406880801746987618334258837050960510958793728"
//                                        "922074153341244994181738486379765035")}},
//                         {{modulus_type("2203400276064257188473710708290845408996566691764859562886520048232395377437360"
//                                        "892306937180391574981551388679394699"),
//                           modulus_type("1911200354410206618546416662524383974022284859581237205226086520640877005078341"
//                                        "69622076834099843296488120111618286")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3346444340939973928448083402211761703662340061596657669752501870669097130123847"
//                                        "621787542718929564631140618480307396"),
//                           modulus_type("1581057498869319722304316413441753366815449804693281755999285332069004804571269"
//                                        "769757134820423852794234864842828782")}},
//                         {{modulus_type("3672908632783746398470427510433082238602313906294215917060323750244193877809416"
//                                        "459826121811440401989313885237036014"),
//                           modulus_type("3054569251991074191242751424700660778951459602743124897036156386782967221159743"
//                                        "568552084182537294529982085984290066")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1209177150932301730021056557437014802354589719335343950143005292616247591490817"
//                                        "191675267139121262916607133627695992"),
//                           modulus_type("6692636346048696842680319292325044979359428750053139827244453843439879482413503"
//                                        "64675138540416308197435535623310728")}},
//                         {{modulus_type("6743154979383603016564101834752802043510040635795056609810160389690706274443544"
//                                        "72290350021720565172767044343081070"),
//                           modulus_type("3990240350699077576196136222684440100905963099746077574390750621802698445831893"
//                                        "094988737022539874008431745681179190")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1196190828994156858831223933037472367668056382602781118903115277704467026637344"
//                                        "754328466589942810929254322002658112"),
//                           modulus_type("8877928932844595838166108713532465965651839540925941969788890791512976747833568"
//                                        "18177972977630587744336741987613449")}},
//                         {{modulus_type("6440071357759196684500873984098033364143507511248007075388101159839736852135071"
//                                        "58183821591155894141704405398058986"),
//                           modulus_type("2483322212668122309850883595440093066392742188203446626145177168790369000018762"
//                                        "724236524472224718489870195226663024")}},
//                         {{1, 0}}),
//     };
//     std::vector<public_key_type> pks_9 = {
//         public_key_type({{modulus_type("4908400167821450013408784075044818895657570539310714529315275114665135412160260"
//                                        "54284835008083563605608450699936807"),
//                           modulus_type("5778682727851638583908529851383113050359167925167948712373181381985121196731386"
//                                        "94251378636831224149969110737142278")}},
//                         {{modulus_type("2505953117241766648050291006150313205367238756914401094251910860245544967432600"
//                                        "566103888278849695240520408179613536"),
//                           modulus_type("7246854931410700463323577038430052664108878823416542389459330243094884114217399"
//                                        "42522367418825142196169335370247570")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("1576785882524177441239739895422585908623225413608943308592488329771827096801833"
//                                        "883622182270987273278830562662608790"),
//                           modulus_type("2075638744615740301495349498662560085355463724582557607743386621420066414776579"
//                                        "306142101084265121023009327551052624")}},
//                         {{modulus_type("8496946335964280725618718004604399084071709331630782453878528834269532147123535"
//                                        "41302344614310943565052828377427558"),
//                           modulus_type("2203922973827680472212150249319685481742728182498242239183216448306842743323176"
//                                        "921871034323959162174474181787145663")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("8773118769946870104504383666866570007396239964692035693299273305183795098157831"
//                                        "03533397895027420289934881969971445"),
//                           modulus_type("2075077640946087585094555918779690756640022531766353283838613763777773234132490"
//                                        "241340146878892318038857464543972055")}},
//                         {{modulus_type("3025193107901860560388898600123259876578854367060891628475640203532979654804933"
//                                        "792593524890231553651403511860703253"),
//                           modulus_type("3434223112964953481910914857438400163730553335816902583325055259053217490554475"
//                                        "619475257214777035084243695813110974")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3320533061835315708699005614590922398695377879772486888195426607533947016889370"
//                                        "411752611508631503648833918472145114"),
//                           modulus_type("3650025477956323827530377460850294409073187922476687041625919333644924941481265"
//                                        "586895844982565401437459131145721397")}},
//                         {{modulus_type("1565293404851117661090266757972892026578795410687715437462085172056991785074759"
//                                        "380363900082775480843569696728296215"),
//                           modulus_type("3768215393729065424063289797614097065777654073476175832756717467789256400119148"
//                                        "500950091902101017269978740518355999")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("4943959215099448019007997599752023760564958382035694783139663210027890630832999"
//                                        "63084825371381748115909530476604712"),
//                           modulus_type("7044370435205132354697578536396901821106156570498307511482138896633325778929381"
//                                        "67055064424059240612233524977365085")}},
//                         {{modulus_type("3672695291429396095567586170989201550375927213195119527946756592138070784723939"
//                                        "770771944243679504729646396206779503"),
//                           modulus_type("1417946959261335480956626756683336183129608529815045577392486677394872139297118"
//                                        "531198462889472846490326183655026580")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2889821288574740441309705359774059702935329029405623380253976052624803517706029"
//                                        "145564524138037542952862102057201776"),
//                           modulus_type("2324554817945264642838650683471238961910632609298373783080007492695709031515483"
//                                        "939792892539038253880202195073064615")}},
//                         {{modulus_type("2308158631752856577776563093338628301115300171319333105866616438131667854178727"
//                                        "914198116465351242635603325857502042"),
//                           modulus_type("1567930199634650806064407382657504036503315493956432833113560139589605935428546"
//                                        "168378658735983914873799980020407878")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("2910394025946712481408039109073179725436335855484691486307313732469227350196014"
//                                        "517131709750404365735396498524217410"),
//                           modulus_type("8685432495122868021973323280473698346323322986004980330798875251470800883529747"
//                                        "3274826366986798087714774421803081")}},
//                         {{modulus_type("3860869173082287734254805595522428827079739401207733409399492367840539196914353"
//                                        "510041051477005683047832813426705557"),
//                           modulus_type("3511902346584904718374206822643995170179603597550720272576456197411537799378250"
//                                        "515549207423371895847783832391195293")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("4290397061030253100048826285906239336923067395446874000723739656548598732750606"
//                                        "67982403257955231032364162219259984"),
//                           modulus_type("2331522647066861631021431037581626414322223381517425850010073541548609020240157"
//                                        "486265866099666663970225892515075253")}},
//                         {{modulus_type("3026098363487308418402314805522926716408358400958235593908472058308985595734634"
//                                        "955048981337726464981191223699694808"),
//                           modulus_type("3468428970469574139827397983358255471799963067831370575967292180667912023991905"
//                                        "30590146594545196110684737699135228")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3664500303182650319080079816136934602032739534651917942026699707758383777883653"
//                                        "695476570903904230739634736505057949"),
//                           modulus_type("3409881328760338594232008237236033711558618469982868282250779453360809918240022"
//                                        "598275127923873013479769415190330422")}},
//                         {{modulus_type("4613566753721819919786139907371888557499812194783372901062620310038680928621734"
//                                        "41330042515801074609290423891968614"),
//                           modulus_type("1574506493698673256710466253326351206979456056759922554034356488061299249989153"
//                                        "263430587322251750923946800071726928")}},
//                         {{1, 0}}),
//         public_key_type({{modulus_type("3225803246639739815178399866025930816263861239763221206518397509666950191670557"
//                                        "489893445514347534735847965478532035"),
//                           modulus_type("1902703311141223494491037536242154350695559184658641582506325009964751823161883"
//                                        "147887391210707351389322021924296170")}},
//                         {{modulus_type("1632656963408605319975637759837425378468620525642236254270030946553957580602388"
//                                        "052451530419213314213342187247552019"),
//                           modulus_type("2628510888994427606051011188502608119883573422431835163969193231476014067198582"
//                                        "008272287023150280736289632873990063")}},
//                         {{1, 0}}),
//     };
//     std::vector<std::vector<public_key_type>> pks_n = {pks_0, pks_1, pks_2, pks_3, pks_4,
//                                                        pks_5, pks_6, pks_7, pks_8, pks_9};
//
//     std::vector<signature_type> sigs_0 = {
//         signature_type(modulus_type("2547146713482947039916893893068651683951139814726379827811800938009362708982078565"
//                                     "053195613225684082094032804982792"),
//                        modulus_type("1837311166270744251444798206250478284977604394235484837169682717319945007757809079"
//                                     "368167322913524080770329187111872"),
//                        1),
//         signature_type(modulus_type("1010867827897947169097432198378450207519599111114814425532967991850836777968783031"
//                                     "880639423745125611882304895259667"),
//                        modulus_type("3291444832807228096594534931551973002970667437958588449098310818647312230306746122"
//                                     "090262191224531104092964358520071"),
//                        1),
//         signature_type(modulus_type("2950207063301346386722837650633362137539715787120059249304252307480520351082199490"
//                                     "260651463874170982816214005285183"),
//                        modulus_type("6466926560316411032759912390546726048613664988207309871860356384978112780321466878"
//                                     "18141152216982368009066181005804"),
//                        1),
//         signature_type(modulus_type("3460837294344853645952044576710721693646116997440386386619678385233685623897960839"
//                                     "145881274192437104194519381931933"),
//                        modulus_type("6770858332384348159790511229519022135990138182888426020603710253440119052980890434"
//                                     "74208852514052907552325098423475"),
//                        1),
//         signature_type(modulus_type("1458245955189140365824557160920255687554215611565855516662542132238133282955650880"
//                                     "17658911314934711184510783620792"),
//                        modulus_type("2519241143021779968266865629807328473384574675200698799454451133872115551178082267"
//                                     "149820541868871989644650447770278"),
//                        1),
//         signature_type(modulus_type("4715017534494436179381736884357727632497530550556889900985170870201869961554031817"
//                                     "16139442386573851891323129641595"),
//                        modulus_type("3054230963154698015152846425982150226660456315167995101599639285345742396511543386"
//                                     "75185592200974040567102170662681"),
//                        1),
//         signature_type(modulus_type("1629015209442926753786771999675171747758454116545954533650863471792540587074642266"
//                                     "535393551208513382231517839307616"),
//                        modulus_type("1794357822831171310100671989623184006250670856271801648596131286083349849633310690"
//                                     "515662671375843172565180528075766"),
//                        1),
//         signature_type(modulus_type("2040884477569369288523806125266390978058238133952306014163495740380429522199215907"
//                                     "108222894058828849354648417903216"),
//                        modulus_type("3112517302690088767848459157746720300429203418699400995436684658112790086635008621"
//                                     "687150473962812795609880140692449"),
//                        1),
//         signature_type(modulus_type("3533328943456568480504184164672000600221679122390409074615265247807510688328845871"
//                                     "83687278067185700449914789458705"),
//                        modulus_type("4320296960905316765219999278657860862589277783925247891468037314971455126971799221"
//                                     "08511738962065878641318469092836"),
//                        1),
//         signature_type(modulus_type("1355729387207465779270829710432638229015135180037028179505382192469414418587717078"
//                                     "439069714140184522156850561908485"),
//                        modulus_type("1061162334530112847501648007204970188549317043317961561346181373243674770960235770"
//                                     "328054871925984056646714808265834"),
//                        1),
//     };
//     std::vector<signature_type> sigs_1 = {
//         signature_type(modulus_type("8927582583782023134263037760078923403624659578954531404269249766593369184665777300"
//                                     "96673295957414271056926897764745"),
//                        modulus_type("1828576277144799754731103968231060695422856686479361709273635430833667847624697813"
//                                     "92957815117533654197031882182107"),
//                        1),
//         signature_type(modulus_type("5144354492728215020454643105583699539913524880241558462855810176812722818240727544"
//                                     "00324230347402946484659666727267"),
//                        modulus_type("1251606356441000370934031362160869120737346129648189400902045233646188134164608119"
//                                     "296830691454376395993655981155440"),
//                        1),
//         signature_type(modulus_type("3118646307632408137420541317537008078351896283318477169288908703913783999331244149"
//                                     "63127172704899183712434629549835"),
//                        modulus_type("3597393466831372348394529874057136542985529147725888953727336659007534986098374146"
//                                     "062084911925830577430664269705602"),
//                        1),
//         signature_type(modulus_type("7604698138225325528976350236644737884986080735106903448723685753886517082843547180"
//                                     "55940734553907528835909052690401"),
//                        modulus_type("1494928579927125368227143636054629231507516311704402396325984637686386176478061417"
//                                     "233950750174259537624847192247912"),
//                        1),
//         signature_type(modulus_type("5042598354225754301793366287244447537661382164896692771876259431701789549454276589"
//                                     "66516990437057248463272563425903"),
//                        modulus_type("6844479552105811037232292163779293867723292840510239871580098747018341832979373317"
//                                     "6398977108124782106913265291328"),
//                        1),
//         signature_type(modulus_type("3890062605503399428282829128441384596606314903815139669332135251972730732953369940"
//                                     "733164472246001696352317740953025"),
//                        modulus_type("1345548421387422764152561045707440723992680373149083008394891423235404055579812619"
//                                     "917649519745488988525857671521695"),
//                        1),
//         signature_type(modulus_type("3264503130598638432965707615350490418449432300721310883896875667624396979838133171"
//                                     "743227462501616169653342315397380"),
//                        modulus_type("1265014985588087965826802033564362550183947121442501567498886590037602833879269563"
//                                     "897632218056986232055375349874895"),
//                        1),
//         signature_type(modulus_type("2447348956485304338778002758651514341202640206119867769800031365951047317145492088"
//                                     "54783001327287612944703606006488"),
//                        modulus_type("3689812036927950302447137570997786126812172597394790269928635813344902137113131559"
//                                     "728777203775628188918770573126175"),
//                        1),
//         signature_type(modulus_type("8698890930960684337740197742905608686587528111075968471492806802419694672110239454"
//                                     "21528868515582276167826554972946"),
//                        modulus_type("2970633580527025347321357973617256413887902893275295449640830008406665171348095357"
//                                     "274412985660328007691064865282462"),
//                        1),
//         signature_type(modulus_type("4518542647477250349745916437438056619916298139241096746484650952975150940328290748"
//                                     "97630183453128656708808440176048"),
//                        modulus_type("2898309105262984361006430712214625918620250363970508696071130865972117134030371674"
//                                     "648770986448297464173812802469870"),
//                        1),
//     };
//     std::vector<signature_type> sigs_2 = {
//         signature_type(modulus_type("3073415590818201520514803103984865610750543089370418811597050969569963445164408158"
//                                     "698857767228639218345918562466945"),
//                        modulus_type("3775161657977032960497526371311293258751626435010603081163996018058840090813628940"
//                                     "960455887576623088813747686044376"),
//                        1),
//         signature_type(modulus_type("2251655673997594907206611824884081617267064660063400059065702941026880428919863427"
//                                     "012178114265865689823971807810908"),
//                        modulus_type("2992421862669483131951316412266456735613528374873183818305532687765757862461920543"
//                                     "415781594276564098930955494562035"),
//                        1),
//         signature_type(modulus_type("3550219231603704593751451114256070341919519570077067865083329816155585259981733165"
//                                     "876538809677149458008472280404826"),
//                        modulus_type("1239681602592857318156498767988117906112208379793887571487465253441702838050956621"
//                                     "530486663766203269344564659912804"),
//                        1),
//         signature_type(modulus_type("2922053209467030168685916041481392117176843676671179487587219940210712721430346453"
//                                     "039207210027636615968804801850666"),
//                        modulus_type("9777936661319500762459295516850953757467253756975105466742108070022895336038525904"
//                                     "90789729502709168209024159068282"),
//                        1),
//         signature_type(modulus_type("1726146848933405198993865142485519423158661288561289520898924456319858125160934556"
//                                     "96565587453694114056270665517125"),
//                        modulus_type("2792679660445417909168515651657019773119245251754424394873665834266716108103243918"
//                                     "120555054216586592045727046372269"),
//                        1),
//         signature_type(modulus_type("7852816550976698879538246621845247912787708510911915330640373072951642129005264068"
//                                     "67317823415965849429234290612840"),
//                        modulus_type("1118892953174556533981060214310031284997234511264520436856800766700137433886215312"
//                                     "619263099564687221105155589548092"),
//                        1),
//         signature_type(modulus_type("2987827765930226744324160709234188039067993275312184930598027173694547318685295400"
//                                     "59082047229965091041360305033460"),
//                        modulus_type("9457419959439992125717707807669497747672787830657744590413070193319663119508322422"
//                                     "45002599112075197038185391906968"),
//                        1),
//         signature_type(modulus_type("4876156085391007995965987129155621226188309464845224701791483308822870529308939536"
//                                     "09364876332301591008313684293136"),
//                        modulus_type("3167655052930268032876438391824013119285068210960742308294704963610650770047916254"
//                                     "623805722585761060437258975606416"),
//                        1),
//         signature_type(modulus_type("3128681693470196532099754978203645328231078954072621313122446380697903278783935593"
//                                     "400901439442893052399103954711491"),
//                        modulus_type("2096028726813768751656827159283251995818316712356559097257800184536015794348727381"
//                                     "236400950013189303310638777463007"),
//                        1),
//         signature_type(modulus_type("2910315279306811586346619288101461775968174273741226074933978173693981320794155169"
//                                     "005060013725639632089550579908036"),
//                        modulus_type("3321812041197837928786780184652869275224234638764149038739428412537925791631849520"
//                                     "355318752771690648243694239494949"),
//                        1),
//     };
//     std::vector<signature_type> sigs_3 = {
//         signature_type(modulus_type("6310048338751151565354028998638485383012255413280542986468604145705896760073281477"
//                                     "44847178970164992631333480909403"),
//                        modulus_type("3283015965234153100318039871147257714178755795525904246157714035865311415325603656"
//                                     "111218434033869778210046150069035"),
//                        1),
//         signature_type(modulus_type("3375018252152840483670739804066561916743697534301401819374134490570937793100458542"
//                                     "627467268496752993244163287080024"),
//                        modulus_type("1166508995233965103981768800835003537190357467054297564634798284145476658741110726"
//                                     "46293507796545724728211718948100"),
//                        1),
//         signature_type(modulus_type("2165951107553224916040725192849120214272974886592315310025513602956264969117067782"
//                                     "291921371619032816091918239061444"),
//                        modulus_type("3515213406517840982379699904275116130342248746480482601414380809775903960439387799"
//                                     "022126459005911335374040311747168"),
//                        1),
//         signature_type(modulus_type("2422424954037224387690023672341772993023350122258796012851054887990905319967822292"
//                                     "312876357073175618026163032365503"),
//                        modulus_type("1686142189399731307825868917016483859423889913490134095777304701101927678087035759"
//                                     "097803983044600758086796261771633"),
//                        1),
//         signature_type(modulus_type("1922037110596973421849118266115803165788944984087299467351258158231898786508402468"
//                                     "659543788260823954815547130540721"),
//                        modulus_type("2711751198126164379880940292752880675444254162005255403403891824446429437773154900"
//                                     "087029379892356526347758495344310"),
//                        1),
//         signature_type(modulus_type("1027577908944414794562345795366374279668364641283992140960483489136601290949237038"
//                                     "685526901560368339443908378914309"),
//                        modulus_type("3713339954866241208806307605171594541440448264635917911871507884771108726420552539"
//                                     "509852506445025567704602153075386"),
//                        1),
//         signature_type(modulus_type("2831407188578763034043951066748728434501331110719233762764376164515818225395469541"
//                                     "71843800057097296511038126615363"),
//                        modulus_type("1936100242858540591208117640929521199237068676340628428004042031767592713344996267"
//                                     "686143382734410955206720497563392"),
//                        1),
//         signature_type(modulus_type("6436789433815690158582156666446345031141561343304065274373910226016024147007640094"
//                                     "52442038634030631257017098008703"),
//                        modulus_type("8233109182943107761977539615103041179260558624608427770229546659921026553383049809"
//                                     "49433797918045837393765302508864"),
//                        1),
//         signature_type(modulus_type("3540151563642218155534482026567473609246958490528539705155502748310238291757049436"
//                                     "073237751975440454317423064461912"),
//                        modulus_type("2876247411770081889823739466854221855791452718539911658203911304138117748770784359"
//                                     "154899155698729648064572055822233"),
//                        1),
//         signature_type(modulus_type("3827670697754023229674690887274106490816736966172305740849847603849386628058341478"
//                                     "951157088334186940078279561696933"),
//                        modulus_type("2244170619089108552354063879281432511581796568578251856271461325670010115543329384"
//                                     "742218861706178837590431939850753"),
//                        1),
//     };
//     std::vector<signature_type> sigs_4 = {
//         signature_type(modulus_type("5884672248768665838447976445291377248171371755191353702740412326853512248315250636"
//                                     "7732384300273043926206770691641"),
//                        modulus_type("8637514742063852915692910788853920161605398418183572028362377800638129451318482212"
//                                     "44296311363704542619086815894597"),
//                        1),
//         signature_type(modulus_type("2741097311365095359895280436388859345127892200153729569120718872468001627017283079"
//                                     "645096880067020372678886781502237"),
//                        modulus_type("1859074400532225340477459622936635995761539054839399251034357710000662449193141146"
//                                     "352659040513191834623289856154563"),
//                        1),
//         signature_type(modulus_type("9513656215051999740332400399407909848853563936399801399448254674363817835174131972"
//                                     "77272162962604104114567873419071"),
//                        modulus_type("1955344218005362161774222713802980890815857957941712222566472654956639958646432856"
//                                     "552251361525591629858087050906600"),
//                        1),
//         signature_type(modulus_type("2637852349241191786250178856280685602822507375281257902813222583302291226646714453"
//                                     "268050018376327122958505594437464"),
//                        modulus_type("1607111695747663042420530166306406591035055208722886757095981982923872512169019390"
//                                     "549103889013179330227592139345111"),
//                        1),
//         signature_type(modulus_type("3897100813895028914322560995854748747437091758218943699238207481445047789014314537"
//                                     "657953846741109890488534771737025"),
//                        modulus_type("2077102326876940174051612399631267294136506639276376163603428145424184671531243846"
//                                     "144732173247387689471082721410554"),
//                        1),
//         signature_type(modulus_type("2881323095740416343105234694066856584860737900692080051790764890552137581148067203"
//                                     "001568760317432817426586986486538"),
//                        modulus_type("4326498745371816319160179982472842229095758104965717858868727528309336199365693897"
//                                     "807270379761586242933142628893"),
//                        1),
//         signature_type(modulus_type("5957148522672285702615760842283342247932771997918155373063840765572399804471572177"
//                                     "37544975188522059040060650471950"),
//                        modulus_type("3206569086454443498572408165252930823424436807111821683110446055166513547533331435"
//                                     "970396926947499507670578163388756"),
//                        1),
//         signature_type(modulus_type("2294740212496360056613172207129572207416659673157285799577329797890458736863230723"
//                                     "474490135750982035929296943458679"),
//                        modulus_type("1746941429333732224736152599969133959903470259906693647160976333082119998778628296"
//                                     "822428326650786673716187947015221"),
//                        1),
//         signature_type(modulus_type("3203928604956218904380327800564935367343160082300860305705181034445774863124230065"
//                                     "975789885550849231117463032992024"),
//                        modulus_type("3259905440480308210851123502251029941749083160876161156324307350158271545551052050"
//                                     "760469246918357752717192019180016"),
//                        1),
//         signature_type(modulus_type("3232305984222600364220379445979381561229545351529484379451097040094318174114825345"
//                                     "759852965428134612315691025154662"),
//                        modulus_type("5274493986742024550650899294884802110909365273764009894884026532198815740817142660"
//                                     "61691667343045533578979785180614"),
//                        1),
//     };
//     std::vector<signature_type> sigs_5 = {
//         signature_type(modulus_type("1624980802471599693239080604031361774353428937533833997557968153331312229044144389"
//                                     "304527649113999198909746153920633"),
//                        modulus_type("2767132940881224383154269602791219083509141937230253577557151348591993254924560161"
//                                     "073165104084023867765858248764848"),
//                        1),
//         signature_type(modulus_type("1446932322636169179392773164240655537436474339997242956591418544013277120427717247"
//                                     "856550698069133432634160096835621"),
//                        modulus_type("3843090659205917613326369073847909359996127324010616409767737393955198026095416042"
//                                     "606978356807145807602659116829420"),
//                        1),
//         signature_type(modulus_type("3261351094965584362455105362965807735216212939737040281190961388946399845380046954"
//                                     "784145154451289565314821232281910"),
//                        modulus_type("3293013734832178396174899451231429356738329228401794909317571490818343872587883599"
//                                     "447158454480964496042043962237038"),
//                        1),
//         signature_type(modulus_type("2156599883740101912396266639195793760208158483411117602313682092745981201774337977"
//                                     "170051462268617931771454495097949"),
//                        modulus_type("6474580618768551435350174624791764360987253636113859574989194625674188673651506614"
//                                     "15155470658319955395876659419428"),
//                        1),
//         signature_type(modulus_type("3146586922283822151422758625050058325404183941019166745163485201518919966624555186"
//                                     "13299723779814639130184663388685"),
//                        modulus_type("2143895093292562907547963666739911796802741558621299241479593574983318337651670764"
//                                     "996649347876218831467788171005566"),
//                        1),
//         signature_type(modulus_type("2043953950901207029935221043397552024073712877406913494810274716789754546243369244"
//                                     "276601613962162023005126888373682"),
//                        modulus_type("4558700736061952233852207364977628234085528927177825166948969766488436036277241199"
//                                     "65505490222006254436611593372945"),
//                        1),
//         signature_type(modulus_type("1317456700940754031234408860019504581571635940011379972051907070542094505018746579"
//                                     "970018944128200402386421138262005"),
//                        modulus_type("6193093990074004808718661098092047084503694081699777495021858986927136332479300467"
//                                     "85255222025827519158922855983232"),
//                        1),
//         signature_type(modulus_type("1975205547332108136697807964243044979675315129586082313570152299462861679159751811"
//                                     "913235849139637018466870872010868"),
//                        modulus_type("2425545016366955409659158635188160781678158190857516071736240769603759138990904858"
//                                     "526788106743213387002621389392568"),
//                        1),
//         signature_type(modulus_type("2068776786022736271877218031769853195781024461596577190749938697831553939363679897"
//                                     "628637043773600247511273410105570"),
//                        modulus_type("3837743299548170261962554187116587046804876287570441625285114645962378070767416674"
//                                     "070243436958340071120605358131957"),
//                        1),
//         signature_type(modulus_type("2155177881171244016481372629654764607095694422759658484031913239763089673061540621"
//                                     "278575883679228277930490825973721"),
//                        modulus_type("4378435833884719447117190734118720568398854926502298794333363728916763425874677568"
//                                     "97337818602005012267586853803287"),
//                        1),
//     };
//     std::vector<signature_type> sigs_6 = {
//         signature_type(modulus_type("3255434475449552613370797574808893070866078650279159365915656942680237884011412055"
//                                     "836898499690388729943673909287315"),
//                        modulus_type("4142059600905711524551433549509610143850101057406713385140651360079544837103743287"
//                                     "87557080812013422151768976251128"),
//                        1),
//         signature_type(modulus_type("1654240530116266051126183920610105138461968838667698886749025273863484400048033378"
//                                     "38986727932954568592893191096866"),
//                        modulus_type("1021407893780456087005727755192817136790997296283452142814744853214399680577110345"
//                                     "015853276273182836258858186776949"),
//                        1),
//         signature_type(modulus_type("1613409969576133727840496825560357228456846293953766077673431326772851408363987072"
//                                     "540940938118505910131854679450852"),
//                        modulus_type("2149717309162637042678417713878976532839945009794624969481954005421080260923271843"
//                                     "469587949467270500170121627106328"),
//                        1),
//         signature_type(modulus_type("1603816970152102519017718778408138882132547627143353055930192168403701049674969010"
//                                     "527764291124757098853584299801838"),
//                        modulus_type("3557390238300117847593137946942098336657176808123461427026174112534242561176408358"
//                                     "800161726146856881016714127400137"),
//                        1),
//         signature_type(modulus_type("9244581670514817375277307446119142152338984816952816918989103999926405491282470510"
//                                     "89610633772396220668387714436428"),
//                        modulus_type("8734929087708619804450435991471497214076106706561043675084512700314342951465940618"
//                                     "70632882872337036158984518630650"),
//                        1),
//         signature_type(modulus_type("2445041831146265426239250785890565703036313031400170415942615011874577858532009696"
//                                     "974310770975655226489801041658571"),
//                        modulus_type("5512072826800374348492205244747802242777233761901561769625108364421878006386043154"
//                                     "21209714362997473292812455613880"),
//                        1),
//         signature_type(modulus_type("3506638768689499941634583114869094536083655531283988182220118108750630742526843236"
//                                     "382635286564506336111909370443066"),
//                        modulus_type("2577776815196911857582710253252630526740298939464520185201437744049019876444799245"
//                                     "80012865633593242708144125952361"),
//                        1),
//         signature_type(modulus_type("1892190486275862743845721061372915227188352596381582382145758404285827112500751962"
//                                     "028390729736749385403653271245445"),
//                        modulus_type("3296014034102811188040144598920562444803441403342133179687535122721422578551270038"
//                                     "720431963458627938370318978783126"),
//                        1),
//         signature_type(modulus_type("2745860126051790194714375972721391679480460754297119032151752092043491325128519698"
//                                     "195659829754819985136159113840963"),
//                        modulus_type("2641902869242288348442903861551653277735078099612820308995467241753259823665056863"
//                                     "517245556702486692790020263728658"),
//                        1),
//         signature_type(modulus_type("1959372996471406452967311272413710243756668859351431041179640895242978805345383367"
//                                     "515657665978963430972925164926744"),
//                        modulus_type("3360527811182000135278196179787363192032056380532166708309864435081048000087749416"
//                                     "445030554993075062495425857556101"),
//                        1),
//     };
//     std::vector<signature_type> sigs_7 = {
//         signature_type(modulus_type("2714645068492986981937317001061887269878226520905343218015139477715422259876927843"
//                                     "062098815932414778862077273533208"),
//                        modulus_type("2943751645876776926624913737890060064122342911785057074115233881587077484923157790"
//                                     "268914962210704754358539112741249"),
//                        1),
//         signature_type(modulus_type("1872354537403656188164647231172727202009845951538893319747209357182774646765456505"
//                                     "764840721724197965016178012446409"),
//                        modulus_type("2325827147262697698272031344226291837060418467386383087891101512387386225360641606"
//                                     "766681985836305936176277029362475"),
//                        1),
//         signature_type(modulus_type("3614166952606795429135646371115661735484217637660535414483684344770366411565212364"
//                                     "66066240740844473210596468696501"),
//                        modulus_type("2603922876360263618559023765013698744514791298904943225857488825954475439185824320"
//                                     "331425804755362739073540424940031"),
//                        1),
//         signature_type(modulus_type("2871441357866235207412785242675272629179212875833101049583986921340551764687190907"
//                                     "929878151870191411689005709841946"),
//                        modulus_type("2267597700902301544193554554217677414164756199520207287969373341593300924393743534"
//                                     "304579202566418702490258294915964"),
//                        1),
//         signature_type(modulus_type("1305332397067385841432802373421809028193955206788746652617527594607526028021586089"
//                                     "19364825106217818598191640883554"),
//                        modulus_type("1963466956471531542443925487039413160958580369599617849257526629359035232511677776"
//                                     "400562705255825184056004215549669"),
//                        1),
//         signature_type(modulus_type("2566388299860777785985307070000982244384960731003980130731096972245131464702782421"
//                                     "934216393470029795042630654239794"),
//                        modulus_type("5233673022526490183979853985023840198086968470095254733457281773720454143188987874"
//                                     "53142097819338242588865507564019"),
//                        1),
//         signature_type(modulus_type("1990225925163235803022407992912049836951129275877371273931425065115495353382018706"
//                                     "201967714055127733332371842808442"),
//                        modulus_type("1519166378281180024901689127468771078101432373357612846672487394073495156002366983"
//                                     "768282023863238837252781912635709"),
//                        1),
//         signature_type(modulus_type("3200625396228613925508787978234849325833493087869912299416903565265792261043978166"
//                                     "268128271198921649867206111744093"),
//                        modulus_type("3453297856893744972774705960485954995210897737358227269301852562082765907883937340"
//                                     "100949684722187768262450362277012"),
//                        1),
//         signature_type(modulus_type("3111171508045265895098917790506971202325704787220861581838886842527336389063481686"
//                                     "999426589473048454266661105060597"),
//                        modulus_type("9563721349515934885574268225391354722454867848826429054472987288459790144799418413"
//                                     "31461362867412528947158945391017"),
//                        1),
//         signature_type(modulus_type("3820554594120294281492671047077755840725257790596625362457563540223453950818392591"
//                                     "170267099168156562932183720563554"),
//                        modulus_type("1468232896136903865325266974484405794106096656198775402531086440310811950924983720"
//                                     "044838323134938099256321336155863"),
//                        1),
//     };
//     std::vector<signature_type> sigs_8 = {
//         signature_type(modulus_type("2821021631577065901420875031391460148941053911552361201165188961941834883227818289"
//                                     "381777988186782643800523522609693"),
//                        modulus_type("2632293170696056542333892967280709916705622641650329247062694369599676143397746994"
//                                     "261554387573180162640019376757904"),
//                        1),
//         signature_type(modulus_type("5152429385048653245817093726718324190753820949783600825121013132697362339905493128"
//                                     "32178072764427962961728891469210"),
//                        modulus_type("2445239057795842242228509997856338117206427430153004311425540152624277758636413407"
//                                     "809574586442608105951807804671071"),
//                        1),
//         signature_type(modulus_type("2839573097780069495370345713286265991759182375649877133328365960820825677660686600"
//                                     "420931645675465236322393990913417"),
//                        modulus_type("3710946382885302657003443430679125175565099147647543169112102376834027682145571364"
//                                     "951855803025666130357208636216685"),
//                        1),
//         signature_type(modulus_type("1030397847263468446146339297821391784651697305655528828104869809960456379381965366"
//                                     "943364512951451847699579664821694"),
//                        modulus_type("3001384274920418089203076308242048806687270796208387472388817775117452179970368884"
//                                     "987391084723528884592498229405248"),
//                        1),
//         signature_type(modulus_type("1994889288942240977253752512542997155284532514461634278543861300388339162032131190"
//                                     "281546176198968260449280865769007"),
//                        modulus_type("1454342724354291351065426036338386574456921248206381127567496650542568323430762323"
//                                     "780659404480016443533443215375228"),
//                        1),
//         signature_type(modulus_type("4340257081572947127087361303148515285465091997743101368600299103860475550066682416"
//                                     "73130756486884266288922881085820"),
//                        modulus_type("1164242790756046405933411010384237700216752635805943757061087484378058366114254951"
//                                     "900416189435660612167703397136292"),
//                        1),
//         signature_type(modulus_type("2447687993387838629767620519855329368115321127313059179901541513691618140144165251"
//                                     "779500019952692464330799993003235"),
//                        modulus_type("3016535482385980109868983383411103613564155029435342234368799451743746443344597754"
//                                     "217012707182142199203961050069854"),
//                        1),
//         signature_type(modulus_type("9581258510963490577470518130049464656386242589069269808643208920650686599725668977"
//                                     "87875025010056927698756330898448"),
//                        modulus_type("1922992107182576563563605987326712516709770411667771568104221817348269448086397602"
//                                     "967230840022921212735834667140995"),
//                        1),
//         signature_type(modulus_type("3684157182598355953984998059643952884799724774800935231418454519807563605375702827"
//                                     "69067089512841389133316489051561"),
//                        modulus_type("2187103878253682473517477146428057255331389657820377470548866502052224698592921585"
//                                     "184092173745939416794981531706644"),
//                        1),
//         signature_type(modulus_type("3118929716927244707511405024709604047254128010235580841529986449039529112673696280"
//                                     "909193332280375160708532033402481"),
//                        modulus_type("3417204373191715758647434869115349018977086210131909585967961096507128379563331676"
//                                     "918338940342722146741486290327714"),
//                        1),
//     };
//     std::vector<signature_type> sigs_9 = {
//         signature_type(modulus_type("3614191833619916771937923987471512697198222744507162350081951746328319780589900395"
//                                     "458912858002735051573879504563188"),
//                        modulus_type("2957612112486862210580976612133903676085833054084162722154150038348055712519316088"
//                                     "998898753172665720495306658672303"),
//                        1),
//         signature_type(modulus_type("6943726045689118618096222349611532353884748204807953488478078405659721537975643728"
//                                     "18627626696107469225671507869448"),
//                        modulus_type("3701297390156900680166476208723918861443941599901993776076227831303940373573517168"
//                                     "321269059197013651971358807451287"),
//                        1),
//         signature_type(modulus_type("2650479071999526992848542758364042760665513628631461254833862626415964485607296374"
//                                     "943740358238008517365126876269927"),
//                        modulus_type("3591326866535656465313023764156507060720853300097670836551055205398935326270960441"
//                                     "078893859264013022247331095073450"),
//                        1),
//         signature_type(modulus_type("5160875849399631716879951871550446159357028147334627435376863508027637616730996272"
//                                     "40258149684123873011698587975132"),
//                        modulus_type("2823239863847831444644387989234316681234527900150968908150474194417114881530396298"
//                                     "092505917622537716356276275023746"),
//                        1),
//         signature_type(modulus_type("2918724263140600644481002525779585398458601069205571861837827766299355378348192912"
//                                     "731999196812695016913809235140951"),
//                        modulus_type("3580485954157131403971288202213620346843301369336526865759352040483915832892052494"
//                                     "86141319735544452022012196399455"),
//                        1),
//         signature_type(modulus_type("3398668435467482221330323377751204544476092841722944400779540654086089647027552765"
//                                     "952114342045606573166385606159390"),
//                        modulus_type("3417009627450676516330431396768755613489120795842394123236986318972601991037550949"
//                                     "677929891267097226142451271572226"),
//                        1),
//         signature_type(modulus_type("3224820196462308014799966623517180452347678187615617464201165996281448855866083852"
//                                     "333669567212637085945103105564616"),
//                        modulus_type("1381045428590297970041200208175636790105449136197177168238371249429929758505009282"
//                                     "380858551471970071793568824051174"),
//                        1),
//         signature_type(modulus_type("5515051754749126429573633829949935874026885124379607647399047220913948552357077639"
//                                     "51850093224860259219896233079837"),
//                        modulus_type("1484882883889370710316213210462488753797517138959255741994012931293992163755424855"
//                                     "5477534951337172364507581305546"),
//                        1),
//         signature_type(modulus_type("1340378099469131217180864853371541239192743188962932860918801683642272204411306184"
//                                     "982865159406328539849190784726569"),
//                        modulus_type("3988401522626426059515269685282046124317669750996005926241417738911838337373376167"
//                                     "420168107673194398275253194898459"),
//                        1),
//         signature_type(modulus_type("8425952664946501071739621016260311336618386468939924822353201445286604816918057719"
//                                     "71421729740779857703450491072675"),
//                        modulus_type("2013128275611530836001289486095460793869288589729680474062638143008108329049490569"
//                                     "037790962530078741015159323192067"),
//                        1),
//     };
//     std::vector<std::vector<signature_type>> sigs_n = {sigs_0, sigs_1, sigs_2, sigs_3, sigs_4,
//                                                        sigs_5, sigs_6, sigs_7, sigs_8, sigs_9};
//
//     std::vector<std::uint8_t> msg_0 = {185, 220, 20,  6, 167, 235, 40,  21, 30,  81,  80,  215, 178, 4,   186, 167,
//     25,
//                                        212, 240, 145, 2, 18,  23,  219, 92, 241, 181, 200, 76,  79,  167, 26,  135};
//     std::vector<std::uint8_t> msg_1 = {100, 63,  6,  192, 153, 114, 7,   23,  29,  232, 103, 249, 214, 151, 191,
//                                        94,  166, 1,  26,  188, 206, 108, 140, 219, 33,  19,  148, 210, 192, 45,
//                                        208, 251, 96, 219, 90,  44,  23,  172, 61,  200, 88,  120, 169, 11,  237};
//     std::vector<std::uint8_t> msg_2 = {42,  173, 25, 200, 18,  12, 164, 20, 47, 182, 1,   159, 204, 236, 249,
//                                        250, 219, 4,  173, 224, 59, 52,  30, 63, 199, 114, 1,   179, 220, 149};
//     std::vector<std::uint8_t> msg_3 = {159, 14, 88, 112, 57, 19, 127};
//     std::vector<std::uint8_t> msg_4 = {79,  155, 160, 153, 141, 34,  25,  179, 186, 202, 17,
//                                        25,  64,  213, 36,  183, 207, 148, 103, 125, 108, 85,
//                                        119, 80,  250, 77,  185, 225, 7,   126, 237, 181, 186};
//     std::vector<std::uint8_t> msg_5 = {112, 63,  158, 165, 214, 184, 246, 124, 233, 224, 96,  247, 101, 83,
//                                        44,  50,  61,  176, 52,  236, 112, 13,  184, 25,  147, 111, 190, 111,
//                                        116, 159, 211, 124, 233, 39,  102, 63,  67,  148, 152, 201, 140, 81};
//     std::vector<std::uint8_t> msg_6 = {39, 116, 163, 178};
//     std::vector<std::uint8_t> msg_7 = {39,  99,  171, 210, 33,  237, 133, 216, 63,  145, 135, 175, 139, 158, 146,
//                                        143, 0,   222, 255, 66,  63,  255, 218, 219, 120, 110, 102, 120, 165, 154,
//                                        243, 5,   205, 192, 37,  70,  208, 248, 171, 70,  129, 172, 193, 240, 0,
//                                        105, 176, 196, 123, 188, 159, 19,  209, 47,  217, 65,  31,  141, 245, 50};
//     std::vector<std::uint8_t> msg_8 = {233};
//     std::vector<std::uint8_t> msg_9 = {43, 216, 54,  153, 246, 7,   65,  36,  72,  210, 2,   217, 72,  187, 17,
//                                        27, 173, 212, 86,  214, 128, 134, 255, 154, 89,  6,   234, 59,  44,  218,
//                                        65, 17,  211, 99,  131, 145, 247, 167, 177, 83,  238, 167, 122, 180, 114,
//                                        21, 214, 254, 19,  179, 80,  245, 159, 136, 76,  110, 49,  172, 8};
//     std::vector<std::vector<std::uint8_t>> msgs = {msg_0, msg_1, msg_2, msg_3, msg_4,
//                                                    msg_5, msg_6, msg_7, msg_8, msg_9};
//
//     std::vector<signature_type> agg_sigs = {
//         signature_type(modulus_type("1084917570002802763999237510539725659994871357035449444385093811995915316976445281"
//                                     "292130656008639155395730412291658"),
//                        modulus_type("3886306453024106962210618574822438002507742324781378798145177640914851427480607773"
//                                     "80324526627818863422254675106741"),
//                        1),
//         signature_type(modulus_type("1334273933295198506579506466388518399757868713595298851455511991726529865559956852"
//                                     "139535647293288864109223486269501"),
//                        modulus_type("2915143050271976741474346244282955959370160202462730084655401743968720393681037796"
//                                     "212282376238149776988779619385728"),
//                        1),
//         signature_type(modulus_type("1992226813233186161892841053730955713413330718396654770930615161245446330886348808"
//                                     "375149142136621699710166186529599"),
//                        modulus_type("3792853260901743204349364966800584618293678374436330555441521901126225913302996074"
//                                     "787985368120014089424818764350034"),
//                        1),
//         signature_type(modulus_type("2273714389694683929793672845667364981885257753454257270925422420590663263362283897"
//                                     "559197709998858963248068940797693"),
//                        modulus_type("7507214413513007609692689436408309286989826371582864950226511743165197870277975060"
//                                     "2498390191538725175882329115209"),
//                        1),
//         signature_type(modulus_type("3629662317305453527945814569531241916308551910395591700586345516594171820438063817"
//                                     "619360333835424710455112141718887"),
//                        modulus_type("3977694355992175752758017157256345335610558907805754302645841748408524019079246693"
//                                     "516486369282313108381864169850447"),
//                        1),
//         signature_type(modulus_type("2743066008141784332448636417850442533444376990969234272262103820239974897235349447"
//                                     "940848232836245269355081404970989"),
//                        modulus_type("1003768812584312775171898292160717609356818331948530343149025924229312799065943734"
//                                     "731919710505333711189358653656122"),
//                        1),
//         signature_type(modulus_type("1120060595279201597292489863360350939390846549261297899755461307631388272858656494"
//                                     "70363583760043719107241961383627"),
//                        modulus_type("3032999153532165991682551028625187876282753540066198123454340275579278219322558692"
//                                     "791110643868420991799030300916720"),
//                        1),
//         signature_type(modulus_type("1827631294354850244539090463908521035964141492169605349156917800494545990061799040"
//                                     "142059677171367430783523947795508"),
//                        modulus_type("1461596941678182387988133247119487583922045995621434700589940645198051782085659556"
//                                     "164556176218490298266521640001681"),
//                        1),
//         signature_type(modulus_type("4279615515140370040311679974410757722905208857087413242574315353971587570075791975"
//                                     "16042030611508597429044635860148"),
//                        modulus_type("1483169406161183521857518773785313836760796098376071625472725178754507210694402765"
//                                     "17299367081698862501290292015162"),
//                        1),
//         signature_type(modulus_type("3897131325847469827104109262324942155320575380077985344861872795926599212115111988"
//                                     "01911682524047046070189254233304"),
//                        modulus_type("1066950327548057040635477728785400668202524036698616416794176843313107716420767020"
//                                     "768360276092814627500088544460485"),
//                        1),
//     };
//
//     auto sks_it = sks_n.begin();
//     auto pks_it = pks_n.begin();
//     auto sigs_it = sigs_n.begin();
//     auto msgs_it = msgs.begin();
//     auto agg_sigs_it = agg_sigs.begin();
//     while (sks_it != sks_n.end() && pks_it != pks_n.end() && sigs_it != sigs_n.end() && msgs_it != msgs.end() &&
//            agg_sigs_it != agg_sigs.end()) {
//         auto sk_it = sks_it->begin();
//         auto pk_it = pks_it->begin();
//         auto sig_it = sigs_it->begin();
//
//         std::vector<signature_type> my_sigs;
//         std::vector<public_key_type> my_pks;
//         std::vector<signature_type> my_proofs;
//
//         while (sk_it != sks_it->end() && pk_it != pks_it->end() && sig_it != sigs_it->end()) {
//             my_sigs.emplace_back(scheme_type::sign(*sk_it, *msgs_it, PopSchemeDstMps));
//             my_pks.emplace_back(scheme_type::generate_public_key(*sk_it));
//             my_proofs.emplace_back(scheme_type::pop_prove(*sk_it, PopSchemeDstMps_hash_pubkey_to_point));
//
//             BOOST_CHECK_EQUAL(my_pks.back(), *pk_it);
//             BOOST_CHECK_EQUAL(my_sigs.back(), *sig_it);
//             BOOST_CHECK_EQUAL(scheme_type::verify(my_pks.back(), *msgs_it, PopSchemeDstMps, my_sigs.back()), true);
//             BOOST_CHECK_EQUAL(scheme_type::pop_verify(*pk_it, PopSchemeDstMps_hash_pubkey_to_point,
//             my_proofs.back()),
//                               true);
//
//             sk_it++;
//             pk_it++;
//             sig_it++;
//         }
//         signature_type agg_sig = scheme_type::aggregate(my_sigs);
//
//         BOOST_CHECK_EQUAL(agg_sig.to_affine(), *agg_sigs_it);
//         BOOST_CHECK_EQUAL(scheme_type::fast_aggregate_verify(my_pks, *msgs_it, PopSchemeDstMps, agg_sig), true);
//
//         sks_it++;
//         pks_it++;
//         sigs_it++;
//         msgs_it++;
//         agg_sigs_it++;
//     }
// }
//
// BOOST_AUTO_TEST_CASE(bls_pop_mps_private_interface_manual_test) {
//     // TODO: add test
// }
//
// BOOST_AUTO_TEST_SUITE_END()

template<typename Scheme, typename MsgRange>
void conformity_test(std::vector<private_key<Scheme>> &sks,
                     const std::vector<MsgRange> &msgs,
                     const std::vector<typename private_key<Scheme>::signature_type> &etalon_sigs) {
    using scheme_type = Scheme;

    using signing_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;
    using aggregation_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    using aggregated_verification_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::aggregated_verification_policy<Scheme>>::type;

    using verification_acc_set = verification_accumulator_set<verification_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;
    using signing_acc_set = signing_accumulator_set<signing_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode>;
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set::features_type>::type;
    using aggregated_verification_acc_set = aggregated_verification_accumulator_set<aggregated_verification_mode>;
    using aggregated_verification_acc =
        typename boost::mpl::front<typename aggregated_verification_acc_set::features_type>::type;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_ops_type = no_key_ops<scheme_type>;

    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename privkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    using msg_type = MsgRange;

    std::random_device rd;
    std::mt19937 gen(rd());

    ///////////////////////////////////////////////////////////////////////////////
    // Sign
    auto sks_iter = sks.begin();
    auto msgs_iter = msgs.begin();
    auto etalon_sigs_iter = etalon_sigs.begin();

    // sign(range, privkey)
    // verify(range, pubkey)
    signature_type sig = ::nil::crypto3::sign(*msgs_iter, *sks_iter);
    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    pubkey_type &pubkey = *sks_iter;
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sig, pubkey)), true);

    // sign(first, last, privkey)
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

    // sign(range, privkey, out)
    // verify(range, pubkey, out)
    std::vector<signature_type> sig_out;
    ::nil::crypto3::sign(*msgs_iter, *sks_iter, std::back_inserter(sig_out));
    BOOST_CHECK_EQUAL(sig_out.back(), *etalon_sigs_iter);
    std::vector<bool> bool_out;
    ::nil::crypto3::verify(*msgs_iter, sig_out.back(), pubkey, std::back_inserter(bool_out));
    BOOST_CHECK_EQUAL(bool_out.back(), true);

    // sign(first, last, privkey, out)
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
    std::vector<pubkey_type *> pks;
    std::vector<signature_type> sigs;

    pks.emplace_back(&*sks_iter);
    sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));

    BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

    auto agg_ver_acc = aggregated_verification_acc_set(sigs.back());
    ::nil::crypto3::verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

    // TODO: add aggregate call with iterator output
    auto agg_acc = aggregation_acc_set();
    ::nil::crypto3::aggregate<scheme_type>(sigs, agg_acc);
    // ::nil::crypto3::aggregate<scheme_type>(sigs.end() - 1, sigs.end(), agg_acc);

    sks_iter++;
    msgs_iter++;
    etalon_sigs_iter++;

    while (sks_iter != sks.end() && msgs_iter != msgs.end() && etalon_sigs_iter != (etalon_sigs.end() - 1)) {
        pks.emplace_back(&*sks_iter);
        sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));
        BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
        BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

        agg_ver_acc(*msgs_iter, nil::crypto3::accumulators::key = *pks.back());
        agg_acc(sigs.end() - 1, nil::crypto3::accumulators::iterator_last = sigs.end());

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

    agg_ver_acc(agg_sig);
    // TODO: fix aggregated verification
    // auto res = boost::accumulators::extract_result<aggregated_verification_acc>(agg_ver_acc);
    // BOOST_CHECK_EQUAL(res, true);
}

template<typename Scheme, typename MsgRange>
void self_test(std::vector<private_key<Scheme>> &sks, const std::vector<MsgRange> &msgs) {
    using scheme_type = Scheme;

    using signing_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;
    using aggregation_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    using aggregated_verification_mode =
        typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type, ::nil::crypto3::pubkey::nop_padding>::
            template bind<::nil::crypto3::pubkey::aggregated_verification_policy<Scheme>>::type;

    using verification_acc_set = verification_accumulator_set<verification_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;
    using signing_acc_set = signing_accumulator_set<signing_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode>;
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set::features_type>::type;
    using aggregated_verification_acc_set = aggregated_verification_accumulator_set<aggregated_verification_mode>;
    using aggregated_verification_acc =
        typename boost::mpl::front<typename aggregated_verification_acc_set::features_type>::type;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using no_key_ops_type = no_key_ops<scheme_type>;

    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    using msg_type = MsgRange;

    auto sks_iter = sks.begin();
    auto msgs_iter = msgs.begin();

    // Sign
    signature_type sig = ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter);
    pubkey_type &pubkey = *sks_iter;
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sig, pubkey)), true);

    sks_iter++;
    msgs_iter++;

    // Agregate
    std::vector<pubkey_type *> pks;
    std::vector<signature_type> sigs;

    pks.emplace_back(&*sks_iter);
    sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));
    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

    // auto acc = verification_acc_set(*pks.back());
    // ::nil::crypto3::verify<scheme_type>(*msgs_iter, acc);

    auto agg_ver_acc = aggregated_verification_acc_set(sigs.back());
    ::nil::crypto3::verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

    sks_iter++;
    msgs_iter++;

    while (sks_iter != sks.end() && msgs_iter != msgs.end()) {
        pks.emplace_back(&*sks_iter);
        sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));
        BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

        agg_ver_acc(*msgs_iter, nil::crypto3::accumulators::key = *pks.back());

        sks_iter++;
        msgs_iter++;
    }

    signature_type agg_sig = ::nil::crypto3::aggregate<scheme_type>(sigs);

    agg_ver_acc(agg_sig);
    // TODO: fix aggregated verification
    // auto res = boost::accumulators::extract_result<verification_acc>(acc);
    // BOOST_CHECK_EQUAL(res, true);
}

BOOST_AUTO_TEST_SUITE(bls_signature_public_interface_tests)

BOOST_AUTO_TEST_CASE(bls_basic_mps) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mps_ro_variant<curve_type, hash_type>;
    using scheme_type = bls<bls_variant, bls_basic_scheme>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    privkey_type sk = privkey_type(
        _privkey_type(modulus_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(
        _privkey_type(modulus_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(
        _privkey_type(modulus_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(
        _privkey_type(modulus_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(
        _privkey_type(modulus_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(
        _privkey_type(modulus_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(
        _privkey_type(modulus_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(
        _privkey_type(modulus_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(
        _privkey_type(modulus_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(
        _privkey_type(modulus_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(
        _privkey_type(modulus_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
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

    signature_type etalon_sig =
        signature_type({{modulus_type("85911141189038341422217999965810909168006256466381521648082748107372745388299551"
                                      "9337819063587669418425211221549283"),
                         modulus_type("38652946747836373505232449343138682065351453822989118701578533663043001622363102"
                                      "79903647373322307985974413380042255")}},
                       {{modulus_type("11185637828916832078768174243254972746778201844765270288305164561940707627068745"
                                      "97608097527159814883098414084023916"),
                         modulus_type("24808054598506349709552229822047321779605439703657724013272122538247253994600104"
                                      "08048001497870419741858246203802842")}},
                       {{1, 0}});
    signature_type etalon_sig0 =
        signature_type({{modulus_type("20367499301549630664794509143514612141767176044319343973582778132616836810060515"
                                      "3615593024400226467409507465298708"),
                         modulus_type("17417694670444283249273233111740896342493427875890296354555908316449711174493557"
                                      "28033568410346657520637304027438607")}},
                       {{modulus_type("13785121595373601972992367437749277919574099148535767401846529956933782527599494"
                                      "29259211046717019870365053373909219"),
                         modulus_type("24046199905556805702641548487225288440078118481046409601677592067898992239812184"
                                      "87409527866974288173456445634088126")}},
                       {{1, 0}});
    signature_type etalon_sig1 =
        signature_type({{modulus_type("90710834246453736299315729969237597330519914417987003396017091519825531180139938"
                                      "8489961456582868775448915444433006"),
                         modulus_type("25270941636657849141156823835907608851960602446295799011344219835523764041905411"
                                      "32043871314989466510719980724197962")}},
                       {{modulus_type("11006537471688222187298795434169534977642750061352332023596150077572000526735174"
                                      "82403026939564880349556232012966482"),
                         modulus_type("28970439382737866335805354269095929846361465365892679572353954171141396021759389"
                                      "21238430628022984093395902845067862")}},
                       {{1, 0}});
    signature_type etalon_sig2 =
        signature_type({{modulus_type("33291851192811896392629164391625138665143179943493712663950082658032677190756046"
                                      "48006297427089956744281126109600615"),
                         modulus_type("21481784373644589901071764128354006437350755974736558340033332083967391474385784"
                                      "74987192401977500510609089259809834")}},
                       {{modulus_type("28395122069875147416798807835672742446913197015626296480737621120106997822476818"
                                      "58302101388270155386199540905532875"),
                         modulus_type("22689547301172733805507423021728158677552716845162509921148732522212324530304334"
                                      "84032136004952017086008634579671429")}},
                       {{1, 0}});
    signature_type etalon_sig3 =
        signature_type({{modulus_type("19658093393812310940168117154777513276790821449059154517758807117065395639329295"
                                      "39953139284370994990106048975184623"),
                         modulus_type("16510818588919860825223531880780727504525558374417068496521683495180945632742105"
                                      "45526361233720214380010050298439748")}},
                       {{modulus_type("21750138894910650225849064109227837448666098189077950706961180628134118614949898"
                                      "92773456878984969421207097124583038"),
                         modulus_type("43824315547881612750271376731987427535941811196653478745774872868444671927498152"
                                      "8004571647227921826225224384703237")}},
                       {{1, 0}});
    signature_type etalon_sig4 =
        signature_type({{modulus_type("11173519713766922788448750238567322868508124499013440838782442360886914774999842"
                                      "55834853084044097208643416916388801"),
                         modulus_type("18751280988359834793434628393541880844046457411751217408067392066479497490017863"
                                      "48339367613442120122601247819752239")}},
                       {{modulus_type("34751815510365790071332195279684682216769530697521411164712269546622434004161955"
                                      "67678920567991160867811579468845233"),
                         modulus_type("17655267962137873267480108548396702456330312615506725556513599717843889679852469"
                                      "01235970958204895502771211905101565")}},
                       {{1, 0}});
    signature_type etalon_sig5 =
        signature_type({{modulus_type("35509415272796846251007392883403334095333542231214314921570124143315798203514932"
                                      "15113415830260262405373415722354761"),
                         modulus_type("22776837870227705502456214626359335066120633487230168982185531428438127126588172"
                                      "03881174280092177111229928738918456")}},
                       {{modulus_type("18856629376754653352757905132316635449916511693652569715482330756216983571716519"
                                      "18870253544256368888131980557733622"),
                         modulus_type("25139378885684192706949228554756728040049920012409323377005052759121552208442826"
                                      "85831809983947603487923806727602018")}},
                       {{1, 0}});
    signature_type etalon_sig6 =
        signature_type({{modulus_type("15859470065179161151263091896468958573452927269536698750750510937398772686159831"
                                      "80935530279063139523045848929031592"),
                         modulus_type("11586271747255882623037490839044486615393741367490886028434848964384977248132242"
                                      "84041438545109439918355332919183341")}},
                       {{modulus_type("28882245733470323496704740066065596308049408813451072846209456764046576330913971"
                                      "76850298649809519774537156953947009"),
                         modulus_type("98938928200146064754539531129494984918024470835250157220713160123096536641365436"
                                      "238620890954632965275278325341978")}},
                       {{1, 0}});
    signature_type etalon_sig7 =
        signature_type({{modulus_type("35232470967305977549839898599750205881756536563675290039395816345409254249073128"
                                      "50580537335730004667202743592096425"),
                         modulus_type("15510200665437420485604450001353854668739623902697982224648170413523930581075721"
                                      "18812748030004587648848192327291754")}},
                       {{modulus_type("24666867106641878529186207252046045371103197872968875759652985236251804283533156"
                                      "14150563881497873255199969665107324"),
                         modulus_type("11462332732017724644478094384413507834933490634742044096213067641080214952759845"
                                      "55497303897248944055184802696915965")}},
                       {{1, 0}});
    signature_type etalon_sig8 =
        signature_type({{modulus_type("30914103995211065257110419059711853143764940205795844687784797902894987319935550"
                                      "03980679510558612201958296424747853"),
                         modulus_type("12766567504164445624536003209150631222747020520888601239247696937433631165371400"
                                      "35698250140459055712038775453880539")}},
                       {{modulus_type("19996572608041414373464196286047987142063183494142464698552697600426028321901507"
                                      "59219744773494542657237275449333647"),
                         modulus_type("33631387951308176859060121973790261787165406047259115324166531965237497141377594"
                                      "41385539294562054616188492139689844")}},
                       {{1, 0}});
    signature_type etalon_sig9 =
        signature_type({{modulus_type("58193789210078297088008912986218479562378746744456770966521904903053580769479766"
                                      "7123251630641979454111055164270224"),
                         modulus_type("44923182459723592345335966144005466700213239755379004077753607349766040086143928"
                                      "770428944139911102466627523503800")}},
                       {{modulus_type("31219623034257049397086584975892649672921216020800619837899616716296192149104612"
                                      "71195150365710875841949893181236870"),
                         modulus_type("15245316264031841516784228058567442189765531096216009069579788284961451254290981"
                                      "21669836210232968245470706286353809")}},
                       {{1, 0}});
    signature_type etalon_agg_sig =
        signature_type({{modulus_type("18220404422387103573016815419543106211555329938444713749473054663814783182546339"
                                      "92897017937660322039699444351331382"),
                         modulus_type("48174166927593931964514744391068732125381951502159883824583822091521766656550644"
                                      "9460448932647300586457580378333213")}},
                       {{modulus_type("73461623680166961089685890352016720588145318970991597855294388137931753210590736"
                                      "4694476426293065924488168855791463"),
                         modulus_type("34110737309389519223382510182418054823170371615385370448247187212612775099543648"
                                      "82537962124670376518393059481359811")}},
                       {{1, 0}});
    std::vector<signature_type> etalon_sigs = {etalon_sig,  etalon_sig0, etalon_sig1, etalon_sig2,
                                               etalon_sig3, etalon_sig4, etalon_sig5, etalon_sig6,
                                               etalon_sig7, etalon_sig8, etalon_sig9, etalon_agg_sig};

    conformity_test<scheme_type>(sks, msgs, etalon_sigs);
}

BOOST_AUTO_TEST_CASE(bls_basic_mss) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mss_ro_variant<curve_type, hash_type>;
    using scheme_type = bls<bls_variant, bls_basic_scheme>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    privkey_type sk = privkey_type(
        _privkey_type(modulus_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(
        _privkey_type(modulus_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(
        _privkey_type(modulus_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(
        _privkey_type(modulus_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(
        _privkey_type(modulus_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(
        _privkey_type(modulus_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(
        _privkey_type(modulus_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(
        _privkey_type(modulus_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(
        _privkey_type(modulus_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(
        _privkey_type(modulus_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(
        _privkey_type(modulus_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
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

    signature_type etalon_sig =
        signature_type(modulus_type("3604356284473401589952441283763873345227059496255462321551435982658302670661662992"
                                    "473691215983035545839478217804772"),
                       modulus_type("1327250267123059730920952227120753767562776844810778978087227730380440847250307685"
                                    "059082654296549055086001069530253"),
                       1);
    signature_type etalon_sig0 =
        signature_type(modulus_type("2247162578336307790300117844468947468720835189503626092261065265284788376322645855"
                                    "042715828480095761644405233051874"),
                       modulus_type("2364572828575432059598629809133542306991756251639507754172391827473214632094272480"
                                    "555900473658825424155647109058525"),
                       1);
    signature_type etalon_sig1 =
        signature_type(modulus_type("2682490444660789877583886321905960114902652442803495723367958666787384702397472500"
                                    "408964001575304343327434901684937"),
                       modulus_type("3398673792460996127293687423416160321937175398276743121920178467641743757351954952"
                                    "279078317569019542910531025540079"),
                       1);
    signature_type etalon_sig2 =
        signature_type(modulus_type("1347303293479541648493710888035421086742953254639266802540953946092800132955184336"
                                    "716227000453492775693763388470068"),
                       modulus_type("2965751007554715065372323902481143005042153195426686124681928170781042466524036725"
                                    "847121383628910851875335237214272"),
                       1);
    signature_type etalon_sig3 =
        signature_type(modulus_type("2020949567874524893692715355826059781955246225639797156337485897884183875627253029"
                                    "365572606211660046200987584949456"),
                       modulus_type("2661978344164434777390106369216008969721648470464214705732248531209245223745264716"
                                    "886907615841230548334496241701927"),
                       1);
    signature_type etalon_sig4 =
        signature_type(modulus_type("1295596529614126583854964959745974248071654423082591508292706821891679592140820811"
                                    "396472710582327962844827798010388"),
                       modulus_type("1865574367401637027504196197496274442235818138639872868577213850882124237777371942"
                                    "665705835112837456264197462580733"),
                       1);
    signature_type etalon_sig5 =
        signature_type(modulus_type("1627965373156489515967985946405293206164735458728684682603510522409622661001980600"
                                    "479982118109972776117618805451903"),
                       modulus_type("3347085207755333216062507889510622277277671295604347342681432996333029865646962813"
                                    "581951496121063765853643101887807"),
                       1);
    signature_type etalon_sig6 =
        signature_type(modulus_type("4697484206696710341086846751327637572827266392821125551281410267480625651167377160"
                                    "72109460414767295782271090737846"),
                       modulus_type("2003782050609382358969270839371734101515648206407234705691771583997491646831068109"
                                    "318844271307118633165374562376373"),
                       1);
    signature_type etalon_sig7 =
        signature_type(modulus_type("1429356597467588284789702427471826678158367528549605776421800852181350217528192766"
                                    "331071794605809732247519561410608"),
                       modulus_type("1009789117757634469832549285515513621721452504555200122530087853526471782604838398"
                                    "116162362023899952757025992887377"),
                       1);
    signature_type etalon_sig8 =
        signature_type(modulus_type("3916623792497751856153624596012574665373813712805049268942596247414374347154130300"
                                    "506294967498612792476202518285634"),
                       modulus_type("3461812416940437175833935990973121464623855248471044862632385305842713912388437755"
                                    "200235625788441209769016660305140"),
                       1);
    signature_type etalon_sig9 =
        signature_type(modulus_type("8317990943748298317593571478484202006039024526832236336059033273053025211139978683"
                                    "2129089397979316684601678620304"),
                       modulus_type("3666516296905512856019726406051933303243313687988121908994579574714110113701386717"
                                    "232936250509350140704196795339498"),
                       1);
    signature_type etalon_agg_sig =
        signature_type(modulus_type("1347890076939912845745386708815835780163588356335929090894089616427726245503639652"
                                    "126316979340877114260832647740757"),
                       modulus_type("3055112058004854338590166655340093414620546693806824954758338468746323342336631148"
                                    "81983910742368460029728081685283"),
                       1);
    std::vector<signature_type> etalon_sigs = {etalon_sig,  etalon_sig0, etalon_sig1, etalon_sig2,
                                               etalon_sig3, etalon_sig4, etalon_sig5, etalon_sig6,
                                               etalon_sig7, etalon_sig8, etalon_sig9, etalon_agg_sig};

    conformity_test<scheme_type>(sks, msgs, etalon_sigs);
}

BOOST_AUTO_TEST_CASE(bls_aug_mss) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;
    using bls_variant = bls_mss_ro_variant<curve_type, hash_type>;
    using scheme_type = bls<bls_variant, bls_aug_scheme>;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;
    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using modulus_type = typename _privkey_type::modulus_type;

    privkey_type sk = privkey_type(
        _privkey_type(modulus_type("40584678435858019826189226852568167523058602168344608386410664029843289288788")));
    privkey_type sk0 = privkey_type(
        _privkey_type(modulus_type("29176549297713285193980476492654453090922895038084043429400975439145351443151")));
    privkey_type sk1 = privkey_type(
        _privkey_type(modulus_type("40585117271250146059877388118684336732873186494264946880060291896577224725335")));
    privkey_type sk2 = privkey_type(
        _privkey_type(modulus_type("45886370217672527532777721877838391538229570137587047321202212328953149902472")));
    privkey_type sk3 = privkey_type(
        _privkey_type(modulus_type("19762266376499491078172889092632042203022319834135186210032537313920486879651")));
    privkey_type sk4 = privkey_type(
        _privkey_type(modulus_type("15724682387466220754989576158075623370205964683114512175646555875294878270040")));
    privkey_type sk5 = privkey_type(
        _privkey_type(modulus_type("33226416337304547706725914366309537312728030661591208707654637961767252809198")));
    privkey_type sk6 = privkey_type(
        _privkey_type(modulus_type("49982478890296611858471805110495423014777307019988548142462625941529678935904")));
    privkey_type sk7 = privkey_type(
        _privkey_type(modulus_type("39173047464264140957945480253099882536542601616650590859685482789716806668270")));
    privkey_type sk8 = privkey_type(
        _privkey_type(modulus_type("1736704745325545561810873045053838863182155822833148229111251876717780819270")));
    privkey_type sk9 = privkey_type(
        _privkey_type(modulus_type("28618215464539410203567768833379175107560454883328823227879971748180101456411")));
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

BOOST_AUTO_TEST_CASE(bls_aug_mps) {
    // TODO: add test
}

BOOST_AUTO_TEST_CASE(bls_pop_mss) {
}

BOOST_AUTO_TEST_CASE(bls_pop_mps) {
    // TODO: add test
}

BOOST_AUTO_TEST_SUITE_END()
