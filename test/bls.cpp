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

#include <boost/multiprecision/cpp_int.hpp>

// #include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
// #include <nil/crypto3/pubkey/detail/bls/bls_core_functions.hpp>
#include <nil/crypto3/pubkey/bls.hpp>
#include <nil/crypto3/pubkey/detail/bls/serialization.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <vector>
#include <string>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace boost::multiprecision;

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
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(bls_signature_manual_tests)

BOOST_AUTO_TEST_CASE(bls_basic_mps_private_interface_manual_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;

    using policy_type = bls_signature_mps_ro_policy<curve_type, hash_type>;
    using basic_scheme = modes::bls_basic_scheme<policy_type>;

    using private_key_type = typename policy_type::policy_type::private_key_type;
    using public_key_type = typename policy_type::policy_type::public_key_type;
    using signature_type = typename policy_type::policy_type::signature_type;
    using modulus_type = typename policy_type::policy_type::modulus_type;

    // Sign
    private_key_type sk =
        private_key_type(modulus_type("40584678435858019826189226852568167523058602168344608386410664029843289288788"));
    const std::string msg_str = "hello foo";
    const std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());

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

    signature_type sig = basic_scheme::sign(sk, msg, BasicSchemeDstMps);
    BOOST_CHECK_EQUAL(sig.to_affine_coordinates(), etalon_sig);

    // Agregate...
}

BOOST_AUTO_TEST_CASE(bls_basic_mss_private_interface_manual_test) {
    using curve_type = curves::bls12_381;
    using hash_type = sha2<256>;

    using policy_type = bls_signature_mss_ro_policy<curve_type, hash_type>;
    using basic_scheme = modes::bls_basic_scheme<policy_type>;

    using private_key_type = typename policy_type::policy_type::private_key_type;
    using public_key_type = typename policy_type::policy_type::public_key_type;
    using signature_type = typename policy_type::policy_type::signature_type;
    using modulus_type = typename policy_type::policy_type::modulus_type;

    // Sign
    private_key_type sk =
        private_key_type(modulus_type("40584678435858019826189226852568167523058602168344608386410664029843289288788"));
    public_key_type pk = policy_type::public_key_policy_type::key_gen(sk);

    const std::string msg_str = "hello foo";
    const std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());

    signature_type etalon_sig =
        signature_type(modulus_type("3604356284473401589952441283763873345227059496255462321551435982658302670661662992"
                                    "473691215983035545839478217804772"),
                       modulus_type("1327250267123059730920952227120753767562776844810778978087227730380440847250307685"
                                    "059082654296549055086001069530253"),
                       1);

    signature_type sig = basic_scheme::sign(sk, msg, BasicSchemeDstMps);
    BOOST_CHECK_EQUAL(sig.to_affine_coordinates(), etalon_sig);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk, msg, BasicSchemeDstMps, sig), true);

    // Agregate
    private_key_type sk0 =
        private_key_type(modulus_type("29176549297713285193980476492654453090922895038084043429400975439145351443151"));
    private_key_type sk1 =
        private_key_type(modulus_type("40585117271250146059877388118684336732873186494264946880060291896577224725335"));
    private_key_type sk2 =
        private_key_type(modulus_type("45886370217672527532777721877838391538229570137587047321202212328953149902472"));
    private_key_type sk3 =
        private_key_type(modulus_type("19762266376499491078172889092632042203022319834135186210032537313920486879651"));
    private_key_type sk4 =
        private_key_type(modulus_type("15724682387466220754989576158075623370205964683114512175646555875294878270040"));
    private_key_type sk5 =
        private_key_type(modulus_type("33226416337304547706725914366309537312728030661591208707654637961767252809198"));
    private_key_type sk6 =
        private_key_type(modulus_type("49982478890296611858471805110495423014777307019988548142462625941529678935904"));
    private_key_type sk7 =
        private_key_type(modulus_type("39173047464264140957945480253099882536542601616650590859685482789716806668270"));
    private_key_type sk8 =
        private_key_type(modulus_type("1736704745325545561810873045053838863182155822833148229111251876717780819270"));
    private_key_type sk9 =
        private_key_type(modulus_type("28618215464539410203567768833379175107560454883328823227879971748180101456411"));

    public_key_type pk0 = policy_type::public_key_policy_type::key_gen(sk0);
    public_key_type pk1 = policy_type::public_key_policy_type::key_gen(sk1);
    public_key_type pk2 = policy_type::public_key_policy_type::key_gen(sk2);
    public_key_type pk3 = policy_type::public_key_policy_type::key_gen(sk3);
    public_key_type pk4 = policy_type::public_key_policy_type::key_gen(sk4);
    public_key_type pk5 = policy_type::public_key_policy_type::key_gen(sk5);
    public_key_type pk6 = policy_type::public_key_policy_type::key_gen(sk6);
    public_key_type pk7 = policy_type::public_key_policy_type::key_gen(sk7);
    public_key_type pk8 = policy_type::public_key_policy_type::key_gen(sk8);
    public_key_type pk9 = policy_type::public_key_policy_type::key_gen(sk9);

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

    using msg_type = std::vector<std::uint8_t>;
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

    signature_type sig0 = basic_scheme::sign(sk0, msg0, BasicSchemeDstMps);
    signature_type sig1 = basic_scheme::sign(sk1, msg1, BasicSchemeDstMps);
    signature_type sig2 = basic_scheme::sign(sk2, msg2, BasicSchemeDstMps);
    signature_type sig3 = basic_scheme::sign(sk3, msg3, BasicSchemeDstMps);
    signature_type sig4 = basic_scheme::sign(sk4, msg4, BasicSchemeDstMps);
    signature_type sig5 = basic_scheme::sign(sk5, msg5, BasicSchemeDstMps);
    signature_type sig6 = basic_scheme::sign(sk6, msg6, BasicSchemeDstMps);
    signature_type sig7 = basic_scheme::sign(sk7, msg7, BasicSchemeDstMps);
    signature_type sig8 = basic_scheme::sign(sk8, msg8, BasicSchemeDstMps);
    signature_type sig9 = basic_scheme::sign(sk9, msg9, BasicSchemeDstMps);

    BOOST_CHECK_EQUAL(sig0.to_affine_coordinates(), etalon_sig0);
    BOOST_CHECK_EQUAL(sig1.to_affine_coordinates(), etalon_sig1);
    BOOST_CHECK_EQUAL(sig2.to_affine_coordinates(), etalon_sig2);
    BOOST_CHECK_EQUAL(sig3.to_affine_coordinates(), etalon_sig3);
    BOOST_CHECK_EQUAL(sig4.to_affine_coordinates(), etalon_sig4);
    BOOST_CHECK_EQUAL(sig5.to_affine_coordinates(), etalon_sig5);
    BOOST_CHECK_EQUAL(sig6.to_affine_coordinates(), etalon_sig6);
    BOOST_CHECK_EQUAL(sig7.to_affine_coordinates(), etalon_sig7);
    BOOST_CHECK_EQUAL(sig8.to_affine_coordinates(), etalon_sig8);
    BOOST_CHECK_EQUAL(sig9.to_affine_coordinates(), etalon_sig9);

    BOOST_CHECK_EQUAL(basic_scheme::verify(pk0, msg0, BasicSchemeDstMps, sig0), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk1, msg1, BasicSchemeDstMps, sig1), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk2, msg2, BasicSchemeDstMps, sig2), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk3, msg3, BasicSchemeDstMps, sig3), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk4, msg4, BasicSchemeDstMps, sig4), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk5, msg5, BasicSchemeDstMps, sig5), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk6, msg6, BasicSchemeDstMps, sig6), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk7, msg7, BasicSchemeDstMps, sig7), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk8, msg8, BasicSchemeDstMps, sig8), true);
    BOOST_CHECK_EQUAL(basic_scheme::verify(pk9, msg9, BasicSchemeDstMps, sig9), true);

    signature_type etalon_agg_sig =
        signature_type(modulus_type("1347890076939912845745386708815835780163588356335929090894089616427726245503639652"
                                    "126316979340877114260832647740757"),
                       modulus_type("3055112058004854338590166655340093414620546693806824954758338468746323342336631148"
                                    "81983910742368460029728081685283"),
                       1);
    signature_type agg_sig = basic_scheme::aggregate(
        std::array<signature_type, 10>({sig0, sig1, sig2, sig3, sig4, sig5, sig6, sig7, sig8, sig9}));
    BOOST_CHECK_EQUAL(agg_sig.to_affine_coordinates(), etalon_agg_sig);
    BOOST_CHECK_EQUAL(basic_scheme::aggregate_verify(
                          std::array<public_key_type, 10>({pk0, pk1, pk2, pk3, pk4, pk5, pk6, pk7, pk8, pk9}),
                          std::array<msg_type, 10>({msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8, msg9}),
                          BasicSchemeDstMps, agg_sig),
                      true);
}

BOOST_AUTO_TEST_SUITE_END()
