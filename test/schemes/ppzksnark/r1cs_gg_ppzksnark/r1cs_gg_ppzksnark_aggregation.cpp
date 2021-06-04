//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE r1cs_gg_ppzksnark_aggregation_test

#include <vector>
#include <tuple>
#include <string>
#include <utility>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/assert.hpp>

#include <boost/iterator/zip_iterator.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/commitment.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/prove.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::snark;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << std::hex << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << std::hex << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_3over2<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << std::hex << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]" << std::endl;
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
            struct print_log_value<typename fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_3over2<FieldParams> const &e) {
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

using curve_type = curves::bls12_381;
using scheme_type = r1cs_gg_ppzksnark<curve_type>;

using g1_type = typename curve_type::g1_type;
using g2_type = typename curve_type::g2_type;
using G1_value_type = typename g1_type::value_type;
using G2_value_type = typename g2_type::value_type;

using scalar_field_type = typename curve_type::scalar_field_type;
using scalar_field_value_type = typename scalar_field_type::value_type;

using fq_type = typename curve_type::base_field_type;
using fq_value_type = typename fq_type::value_type;

using fq2_type = typename G2_value_type::underlying_field_type;
using fq2_value_type = typename fq2_type::value_type;

using fq12_type = typename curve_type::gt_type;
using fq12_value_type = typename fq12_type::value_type;

using fq6_value_type = typename fq12_value_type::underlying_type;

using scalar_modular_type = typename scalar_field_type::number_type;
using base_modular_type = typename curve_type::base_field_type::number_type;

BOOST_AUTO_TEST_SUITE(aggregation_functions)

// Test data generated by bellperson
BOOST_AUTO_TEST_CASE(bls381_commitment_test) {
    std::size_t n = 10;
    scalar_field_value_type u(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    scalar_field_value_type v(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);

    auto w1 = structured_generators_scalar_power<g1_type>(n, u);
    auto w2 = structured_generators_scalar_power<g1_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_wkey<curve_type> wkey {w1, w2};

    auto v1 = structured_generators_scalar_power<g2_type>(n, u);
    auto v2 = structured_generators_scalar_power<g2_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_vkey<curve_type> vkey {v1, v2};

    std::vector<G1_value_type> a = {{
        G1_value_type {
            0x0f8a94d761852712cc9408e3b2802aadfac6ae8840e33dc0b02c3df6bf3c139bd9390f10bd7e1942d0a4ee1e2bce3c4c_cppui381,
            0x1243524a748ca8f359697c46e29af5e331be8059628a9dca0d9bf7deb4924360754400222e13f1cfc75606d6695422eb_cppui381,
            1},
        G1_value_type {
            0x04c1a1c869d164044f09f9a42a10e4488a99adf06a5a689fabfd76890a137a884adf415d516615758b2cb3fb68e8e601_cppui381,
            0x09846e9776d3eeace43f1b26a71cffc0f84d021168ac96bbf32b0037dad49449a3259df6dc4a9542daec9d18d6ad2078_cppui381,
            1},
        G1_value_type {
            0x014c6d39bcffbe12ae7af62ac383efe538910888b3fdfff45f7789364f09282bb5ae2dba49f5ffb2fe1f0f36318c9d40_cppui381,
            0x19046eac6839db3f1c57c77965eddee9fb4a542acaa83293fc1ed8a9789a11927ed00ea00dd8a99138ebefab2e0a65f3_cppui381,
            1},
        G1_value_type {
            0x069e0585b1949fe6224f54542589d3f6afcd2064ec9d7cd90ab941c82bd0ee6f9099a327faf71f8b3b1f3fed9655a948_cppui381,
            0x1255d5100e698b3c118cb4f1f6361575c5b227fb1aa16b357e2a8cfabafc003857d288c6d2fbc34b0298510b0c1742e6_cppui381,
            1},
        G1_value_type {
            0x18ec551102d9902a3e89c67bb4081451ca67933040da61ede139c0d3df4e703dff22c283870a47865fed8e971ea41a0a_cppui381,
            0x14198bf26269a123d6802c3da3e95df666e839ea0be10da952d52942e1114834b83f816bf351ebb89c040e447183fd19_cppui381,
            1},
        G1_value_type {
            0x1818d8fd8dc994dfba13703ba296b251b58bfd129f8b3265f73a94bc5a424b854cad79cc75321d2161a72f513fe463f5_cppui381,
            0x0165b7d5a5d585709921fde377032bddef937d3a061776ff43b8f6a0d3c2b7fdc61bdc9dc052707da2a6c492a4696f60_cppui381,
            1},
        G1_value_type {
            0x1101a14b720e8e4b35dc2115304af9a4ebb1a0193b4d82379b8c3943363319d4859e1f0ca76aef7bbbd9d4db6becbc14_cppui381,
            0x0c92c3e46da264c431dac023f654e5c5540fe34471c7946dd32d5f25f6bf3529a041f9965206bf3416216fa7e251c5f4_cppui381,
            1},
        G1_value_type {
            0x0c772ec090d90944627d4ce86f7f9dbc5bb8b3114ace872532d02de88bbef7709314257775dd41b506325a5f567c1289_cppui381,
            0x0e3a498329f47387340451a0984b19be5a8eac672704ebb295f85321cd19aaf5d56952b29bd3d0a6e478c010bbc16ea7_cppui381,
            1},
        G1_value_type {
            0x0f30a9e7a22fad589a2cb9a5f1e7af8b70c98479f9bceda75af8770d5fa04fc60e009433f12712fd8a05b2fbc8d8bd6b_cppui381,
            0x0b4447c7af450fcf8f638ce3c6723e151fd9636cec84ba35f278d25d331cd726eb685c1cbaa48bbbb92523c9204dcae5_cppui381,
            1},
        G1_value_type {
            0x0e26525b8fd932191628e29a2f62939d3f7e387646d48bb33a873331b89dbe007877703c6599291970c320274cfaa1f4_cppui381,
            0x089f59a37dbb4f9fc9a7349ecc0222216b6cb38370c5019e80fdc7c953c33fdd9b2da8966954b594097bf8cf7db6e2c2_cppui381,
            1},
    }};

    typename r1cs_gg_ppzksnark_ipp2_commitment<curve_type>::output_type c1 =
        r1cs_gg_ppzksnark_ipp2_commitment<curve_type>::single(vkey, a.begin(), a.end());

    fq12_value_type etalon_c1_first = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x140bfee03fbe747bbdfbfad4577ea2af7175c5c601772f2d8f3c1751b32bf7177dff399967040a77606991e53df2d8bd_cppui381,
                0x01204263fc7f73813a0ac121e8e98d0b825b30a54eee57e9ea1b1618a7984212206e204fe51341a237c29861b27c68c7_cppui381),
            fq2_value_type(
                0x09ba91ba4f1c1bf8a657a5c946b652f0ca034efe9bdefa7235191c653673d09956c2ca0cf57c1983f525a9112c0f0fd1_cppui381,
                0x059b47fb6a66bd8a99a8a7ec56dddd183b6d1bbc534ff00eaab928a0f10e404fa4fa9ff5cc9eb9a5054eb4dfb3aca030_cppui381),
            fq2_value_type(
                0x16cd370184ae0c5c7fddef3dac1f272c0723d1f2e8f5ed93f8996e83970ee546f500e18a69d81538216156e22ef64f93_cppui381,
                0x199a09c8d60f9246e0d895cc230df9ca3e334b846539b20465e1e420ccadf654c02d90244724d241000b342c2461b878_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0798b3616ff94070745cabcaa00627006153cc656cf159747eccc17a423df95905edf7db7da023a06f609c0c0c4ed808_cppui381,
                0x0bb15ba186dfdbd6c60c277bee3b29e4b51ebcfdd060cafa265a065d63cf8c72df03be62b31ea8f3b116a6643d8aadda_cppui381),
            fq2_value_type(
                0x179b1fd8d7d72a856dcf12c48c3b91db3930a18afd17660f9047d030a79b494844ff3901fbe1d1fd2933cb76681c68e9_cppui381,
                0x1679d14bcf02ea246f8486419ef20d5384a5d11ef1ade7b7c68f95b27d6bf8e1670a4ea192c8d8e53999ef359b9949da_cppui381),
            fq2_value_type(
                0x03f46c37e53e33257aecb46bd3cabf6f6019a2ea481ac567c8badf8250a27425e425d36614ec8f0bf87ea75df4443bdd_cppui381,
                0x00332853a0ed64dc0e7277fe792432644b9acc0955863ce982dbe3f3b6798fc4a9f56c98293c79e8eceb9e76d579714f_cppui381)));
    fq12_value_type etalon_c1_second = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x044df213be87f69e1ec7d16f831f3651c88d9c933bd005e390d5654043c94135e45b558b7f2ecf6ead89208261de1e97_cppui381,
                0x113daabcd8e117c7799008110783afdbaf320c623c13e1db4cb79e014f9cb825161ddbc05c7777aabd31513c7fc1cace_cppui381),
            fq2_value_type(
                0x19080dd8b95ec5b5e59c29db031a430c940c26559945c7db463737e778aa2fef9d1287196644e0b9fecd671f30ee6019_cppui381,
                0x0487279eec345a6b8230e476eab49bbd28b85082994f3085002c79fcc1c893aa54a46ac2e1b28327b2f21a679428e9d9_cppui381),
            fq2_value_type(
                0x0c9c0377cb585dd7422c3348d3d8ce89befbed472c2570411b15caf6a6bf4c69dc6e7db6092f7d0bd2c8670de5e3ca96_cppui381,
                0x100ae902f195d41ff489e9fd3d58b1684c1c8f81d05f5b99d0c0ab6f0399a893515137edb4c93e59130ad4cfe99f9b37_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x195985fab083b606700086a5abf53c873a03b2e6df0af1ce26430d3412c79958133d26af8e7a5b9a4d353920019a3e7a_cppui381,
                0x0300204c07b1559a6a9ee972e4130960fe286f50bbe4abbf5a3c392d8f1c78673e224a5c0f290c6a273dc4083cbe36c9_cppui381),
            fq2_value_type(
                0x14111077e1ff7677b532ed54e204c82c8c03b0ed963e44d2b9fd615ac4fbdb876f8e0f6f52e11448ea4ab3cd26616200_cppui381,
                0x0d46ee9f57f33c3d6216de22f24f697cbc3ede24da2207c8fc27d76153a0d39ad4198ed01b68f24f9357680183f0a1cf_cppui381),
            fq2_value_type(
                0x0c9ecea9b38974348515e5362a0f1215a6f03d844db50e539d5a1d50999f0cdfdfdd72c9fc6b6f29c42120cc7cc77e63_cppui381,
                0x0e24169cd073d7a84f4bf841f4fc2a223389cc55b3e002d8c8f586183b2aa269909dce414377f17145e1a69918cfd155_cppui381)));

    BOOST_CHECK_EQUAL(c1.first, etalon_c1_first);
    BOOST_CHECK_EQUAL(c1.second, etalon_c1_second);

    std::vector<G2_value_type> b = {
        G2_value_type(
            fq2_value_type(
                0x09e690df81211b6fd71977ace7b7f9907822ae7404c41e08f3a2d7b86daa17b09288c958dbf89527b1afcd50b59ee4c7_cppui381,
                0x00f8c7df5151249b79742ff5ce80660c13ccea63fa2469c48e41671e7a9b693ee2f2c09cd27954bc9532bed9f6d0bb41_cppui381),
            fq2_value_type(
                0x0f959ae56e18cd4185c44ef8b9d0c4930edede16b47963a4871b65fa06cdb5ff69c62f657b348bf189cdb0e3d6493272_cppui381,
                0x03c8015d3a153613d2f2419c911cf6fb6e9428ae23b98d4f19b81e3a57c8c5459f8063a2501aa89fd5ea940add2d6e66_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0c5e0f7fdfbf77ee7d140464ba731db9b99f37df0a06be3123447db3a46bab379b9bf7f16e9e4429de5abb2e9648c8c6_cppui381,
                0x0cb520b8e96560957114ad6d7e67dfdadb1bd88358b2ce482e8879a8ada324f60872ead531b9cb46b1de16041a7e5819_cppui381),
            fq2_value_type(
                0x087b07e6f10e365c78650a766590842a4b3b9072276e16ec58751707724e57261f7102020fb1190f5a730217244157a3_cppui381,
                0x16189daed8628a98dcc5c3982df12242107a2776939a0e23e96ec3a98242ebfedf3aa0ba6faecede760d133e4f8b3b60_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x15e0fd0a87b807e6390a7e72f57d8f47b8c46602939ffdc91407e08d169e036d8e39fd9f114cf4319153d18053fa1201_cppui381,
                0x021ae075bed23c5c04a58196e20d9a9819eaea4b28cdf2c144f3884cce2b3cee1c2ca67edcdb0c81c7629f43b913671f_cppui381),
            fq2_value_type(
                0x0f55034f53bfd3465b0374b7abe44fdb831080ce799f6ae2316df35abe8cae11e8c3c36f347ddc6cc46cb6ba78888b47_cppui381,
                0x022e87bee60c1ac9cdb051cd9d3c7c579cbb77f9ef8572cd42d312a38ec87a432dbe24ee21a165a951f2954efa161fe8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0c26999b288ac57eaa399e65e1d849e186f304c0474f1c5c70acafe1177cbbba719327d0680e30f5a6ceb11feab39c6f_cppui381,
                0x04cc7745b53e41b642a70002f5f7b4515e81b6d1e7fd7de01d5c827c8a5ee8960f32fa4dc17173625d85a44ec7699f28_cppui381),
            fq2_value_type(
                0x10301cb9b9846330b836cc9d2b21b837f5e954f1d4618525c52c2dd0b734f1f06bcdf9b669285f437723a59df92340cb_cppui381,
                0x0fea154121f26e7bb8d997bba9c1ae7564d08cd51da04e770fec34886004acf78351fa19618b9f815c35acbe8db8bb6c_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x080785a6c856b3beabd7cd4b6bda1e28b06d971d835f7ba537423b267ee5acc809b96f71898b54b34115f9e06d0cb2f9_cppui381,
                0x0433029a8c5dbc20513065c874be1eabfe92b21ce79ecded24ff73687478997f08659cab60eec74a9e896f7d937d94f5_cppui381),
            fq2_value_type(
                0x0d11a2bbd1f8d571f9857353e11822341d24fd51b50155fdf002e41d22eebdfea4b883a2f426332a596edb650cbabcf5_cppui381,
                0x110051f9782ce55f721be563faee85618f262ed52e6c22cea74495647d4a80c07bacbd6db09c5420abc30159b2980819_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x08cb3db1ed554c7f3f8ee249a2bed141e753d37635257b243e9b74add03a91271e9f16da0caafc4193c11d3df5618091_cppui381,
                0x0b817c56f7db7387f7dd9df93a320796a9e1a1365c1f309a82c0e8d711cbbcc394350c8a791ca81ab19eade7f73c72d3_cppui381),
            fq2_value_type(
                0x00a00d84ce31283066883f0bcf1fe487904c2372b6a531978d83dcd901c7a7056055245425d76008c87fd4ea36039b5d_cppui381,
                0x00429080cd40357e275b478e75564af9435ba0480caa56c2bed13c5a5ba5743939645a8334ed0990c3e16fc558e4ff46_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x03df0e71b764fe8ee41af3cf3aa581c5134f7f0fa21d12398b623f3e7862a677b810e6152353cfe9cbffde603ddf258a_cppui381,
                0x00eb2582ffd4e5a26175cb6b8087fded84dd8fe45f386c13225ab17c8b95e211401652cc1edf70d8635c58d76569e8d3_cppui381),
            fq2_value_type(
                0x12dc4daa59ff9794847c54f3953f20228239e02d96cab9f22b8dc050cb4ce01ea2776273a07bd1e0b4813e3d06b9cf3e_cppui381,
                0x16e45e6a31e4f58f71c3f949d477a4035ff5d4611c8f13df495e7c4190f87190d74dc1545df8704d2611f209c221ac92_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x05606487ad598cd53d5ceeebb6572978a0cae7a181a6264429bd8eec68afc0b9e791f8a4190adf807e4390090082aa87_cppui381,
                0x0ce0c26551fe1fbb9cac5cd681b45715352a8e2961da3b616232285c08f42f652b5858a4619368f5bd55900e66ca2910_cppui381),
            fq2_value_type(
                0x174277032ded436b2941e6ffbeea4afd3fc7644754a6eb8838fc605459c13d2f1d8c3479040a0ec9ea345d7412709ae5_cppui381,
                0x0d35ad13fa98efa1d9f665a9212ae2acc8a6a2bcd1d78806c848d0b47a4e084f5491b3c5e2cdc537375bad926ebb47c8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x103f4048259e2498b3235cf5f8c147c9fe5536f736be621a13c7cd2db960c304bb23c5f9554642acad89420b3802b75f_cppui381,
                0x1214f068b41c5302ed0ff42db19414c9f36821ee1df5d19842e87ccdb2eeb2450c17254195ebc6471c0bb2d4a1a5d76b_cppui381),
            fq2_value_type(
                0x07f58e4bc4bc0d6b1b55f0a1f2676234ad49d7e5f0fd942aaa296e582aff1a614b3183e622f0069fca3fd91b0e74e790_cppui381,
                0x108460a7cc77970d261962fe10933316dfc1b1012b5fb6fa7c3f1d03cb48953564e7c044b93d0f760176740bb2cdf6c3_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x11879877c76cc96ecf44b0fdd92626e2b701907461426955cb363d54f18bb627220988ee2a2568cc1db7a2504be96499_cppui381,
                0x125028b5a85cd28547ece1d1d47ffee83b5540225c8b3538c724608343df38a1b91c99a6e027f6f6c262f1785248e527_cppui381),
            fq2_value_type(
                0x01cbdd7aab1a1be51e6dc92798b94fca2aacda25cf13ecae179e7aedca028adbb5f79ac8bf6a9f5604f9605f0df4663d_cppui381,
                0x0d7b93debfcaca8662889c1f02c6051dea6b6901f17b6bb3c3143d1fccf437e1bef597c7d4d80453f464c874149e51b4_cppui381),
            fq2_value_type::one()),
    };

    typename r1cs_gg_ppzksnark_ipp2_commitment<curve_type>::output_type c2 =
        r1cs_gg_ppzksnark_ipp2_commitment<curve_type>::pair(vkey, wkey, a.begin(), a.end(), b.begin(), b.end());

    fq12_value_type etalon_c2_first = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x06374258f33742cf76fe64480b8ad2a86974a883987baf7e2f49b787ca7c3bb51054a38ac44adb31c7489e9c8d49e57c_cppui381,
                0x19ea09aac0b3eabd46e1d0941468d6d1d2e2b91adc32f789a099202112bd67091fa1ad6607dde1fdeac668b65f292bb6_cppui381),
            fq2_value_type(
                0x198f67a348fc61989b62bd222ebf556898544ae0a1ecc812c50641ea56f7bb3345631bcaceba13e150e4729278f924a7_cppui381,
                0x129dc8dbe59bf05522cfebaad81d6f7d8e7d3d66f1d90ab054a4598b50ba594e30ed41679b3ad1fbbf2ade87b5430ed9_cppui381),
            fq2_value_type(
                0x12498e9b54216dc229a1005aec0eaaa9b7103ab28feeee6545e316b96b697dc487081a6637ffb77ceb28ada75586d3a8_cppui381,
                0x07fcaf4b1e618d02843eabd0e62a70eaff57d30b6148de786f0a8b582c070ae132555197e92f6f2a3c19873e09c09eea_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x01c30d135188a98243ab65fa03710752698c00ec8dbc0cea0451d8889a6a71a3ad64b22c926e37e4b13fb374642b6ea8_cppui381,
                0x12d513a82eb3c5885a140b572e6871de735417a08273291337ef0c41781eee1856d415a3d4f8e9d7f0a6b52b02935f4d_cppui381),
            fq2_value_type(
                0x03b5a7efdab63732332d570bca0420cda704ca14ae354dd71978e61945520204aff412ce01b96b57751903fdd0f8ff60_cppui381,
                0x14f1eecb185e456af66d744ce71c9a97948f615fe28abc1118525b8fde195fc35ee1391c9d17c456690eaf7412aaa34f_cppui381),
            fq2_value_type(
                0x12247d032fe95b80cca3eb325c377f4d9bff75ced2d2218b46ea3425e0dff032cccb8915f57160ef3156e1f3de32570c_cppui381,
                0x0786d9e022313cc63f2f9019ad0c20fae5ce649ad6f65a15a41c46d1133896be4d584c481116ec988cc621fee980c423_cppui381)));
    fq12_value_type etalon_c2_second = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x05d3e965b1ddf572f81453a80474f013bdcbcbe76091bccad474829803926286c83b30be9b50eb810669e3583b0ace6d_cppui381,
                0x04a9171487ec6caccef97664499065f53a64a2b06dd0a5fea4cbc23bbf793f2cd91cef8c27a49750b2725016f2708a02_cppui381),
            fq2_value_type(
                0x0468d7a42d2338bff7ddffaaeda808496dd2526ff36ee861d9d2fff332997146a5e3309a705b649854f1a5728928a2d2_cppui381,
                0x0c98328b0db9e53e51592c3272ca21acb93f4975ca3f94419b6b2a46c75c5f879a83dedf9d4443cce15339e7ab593534_cppui381),
            fq2_value_type(
                0x04c526ce7891dd2e1efc326860147829bc55586cef46fd4190a574069b2cf59c48cbbe6017dc11a38670d0e1fdc02bc4_cppui381,
                0x0f380eba055ede7d6c14931bee8b094e1e67c4a6b526895cea679cda1fdf0f298bb71f69c867ab00d3573d682154ee34_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x03c63b40ca07dd457d85a76166eab0acdd212bd07969b87e37d62bae6c5a207d42d1d652ddd1ddbca31978f45077c5be_cppui381,
                0x07ea58d0dceb0457cfc50ae675d41b8d67b686a0013d0eff44b7497f420fb61717cf298bde3b9a84ae6741af069db641_cppui381),
            fq2_value_type(
                0x06b7e4d967b9a9debd338c044993a45f18dea0ac2a94ae075a7be650d47d2f28495d0115b5a1b944d3c420664ff8374a_cppui381,
                0x07e9dc11f7bad4aecf09ec07f4d158996f51c9c6d2784f670551d6786f3c0f44b974b6fcd1b508165e43d7fbae297bc8_cppui381),
            fq2_value_type(
                0x0768f0ac2cee937c8ad88372e16e9aeea5186fa1a65ca7f1290e0c361d2f2028e9dd35da7d4d32922610190b9a7cd39c_cppui381,
                0x047a4eaa8daef463a886a6483e9544a810e613fba4eec17b8b9308454c742cc0607671ac4007145152368fa0562a7c2d_cppui381)));

    BOOST_CHECK_EQUAL(c2.first, etalon_c2_first);
    BOOST_CHECK_EQUAL(c2.second, etalon_c2_second);

    scalar_field_value_type c(0x72629fcfc3205536b36d285f185f874593443f8ceab231d81ef8178d2958d4c3_cppui255);
    auto [vkey_left, vkey_right] = vkey.split(n / 2);
    r1cs_gg_ppzksnark_ipp2_commitment_key<g2_type> vkey_compressed = vkey_left.compress(vkey_right, c);
    auto [wkey_left, wkey_right] = wkey.split(n / 2);
    r1cs_gg_ppzksnark_ipp2_commitment_key<g1_type> wkey_compressed = wkey_left.compress(wkey_right, c);

    std::vector<G2_value_type> et_v1_compressed = {{
        G2_value_type(
            fq2_value_type(
                0x0b74b7f8348ef6806367449678620c0943454fb99a4c35db90f2effabf1222b8b0d45175f812eaf687ac8eb8fdcd35e4_cppui381,
                0x101b4827b17e42992ec9cbfd7f942fe15b950bae7e44dbc004c6c6c7242bb7df4b02e54e2b2dd586e05e706236f53148_cppui381),
            fq2_value_type(
                0x1430aa96637e61f55af1ab05b1e3fb0c7d74fc922c0308d964c639103d15816cb3a8b97cf6e43b8bbccb1fb0bcf3c813_cppui381,
                0x195f9a7b105c1ac10b22a5c548fffa142eda073f91c1d867e63c86f1dea2633fc209481d22dd15d6f5de4ce8ff8c52fd_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x00c8044bd8548f5ae0c3a19fc8b3980fc94adbd9e7953c3715b49c25d2ffbb0ccdd1c7dba056a44d0696a0d9f907870f_cppui381,
                0x09bec35b32da6f260bfdabda7f42f6d0b364f9d0527f3ee85019286898776877ed491967f833431a50e9d26943b7e965_cppui381),
            fq2_value_type(
                0x183f644129e79748ea3bdffe2e8f401928ddb814525c229ecef3c181c24fea8e8f814a3da08ad7916af21f5263c86ea0_cppui381,
                0x04703ffe02768a0ffed187e084283db046e8c5d8a871e1cd4f1294c27f0729ade6e60706f5d78943296a0800882a17dc_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0a049b5bb3922ded25acbed4fe6fc260524c4d39af5f6820c0f25f76c87a5de587224fc4ab4ee0fb8e51ca5b354ef034_cppui381,
                0x0089ae4a8fe593660b04d3679e496747347ec7a0091dc4a02cc51cb074c0fa88426acfb5690ed6cfad1e0db3d7a3686d_cppui381),
            fq2_value_type(
                0x0761e2abbb49a3b011dbdb7f904a28dd8316497f0c16bcc06e6f2640443dbad8f1876188102850854c9b82a082e1bb80_cppui381,
                0x02fbb2d1918807d74d16514e1943f393f130fb2d7d6cde1860ce1f5cbe7693bc0eb1e1a84c129cdd063d3b4f121f81e5_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x11556de064ace780a8d6bd92fe9c32f903d65ffa039a596385bb865d61518d3916b319bfb44da815c46352deaff6498b_cppui381,
                0x01eee0a3f808f727bf741a2d036415e3dfcd9abf7a3445c4f0c4b87d5629e5013d3980a1e170c9d170c33d6fdb4d7252_cppui381),
            fq2_value_type(
                0x05b816fcd58e57c58211991f38f1a64ad6be94bc7b1f0a9844f6438f3dd80d3cc51c131e797a0c49bb3a41de4e145615_cppui381,
                0x15e109abc824df3600fabd8f186798187f39c6fa1c751602882bc551c19007012003f061f3e6820a36dd7c3884b0a9ee_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x15293a0e5372631bc3aa71a40cc067bd7eabd9a273bb2e4fbb0e33ec09c6c610bbe473f4c2fc0e276d0fdf3d80ffdae9_cppui381,
                0x1725efdd89c30b2d7665e250e4f0bdde8f97c75ef28c1cc277617756cc4364396ee709aadccbef3dcf2739fbe6e672fe_cppui381),
            fq2_value_type(
                0x05a0d144964762de0be4ce7fe354f3d9156c4316c8affe4ce305d0ab10e684317d9d77a32f306d2e57ed9eb7db8a3c9d_cppui381,
                0x067332db95199c7a9cac48cbbb4d172fbdb368693995cb9e6df88bb3c920a49ea329f6cf52528c8e1289f5189db2b347_cppui381),
            fq2_value_type::one()),
    }};
    std::vector<G2_value_type> et_v2_compressed = {{
        G2_value_type(
            fq2_value_type(
                0x186a7e15d408fa91dd9e7566d188fe02f7baa045fd16951d35b9d21acfd8005f95301d22fce8441c81c61b955e4589c6_cppui381,
                0x01209911f0abd559c390384a373b2d8e76bf5ac5675d3a5920e80453a8a9c2b648b993c4ba7fb401436e0406f6d8ec31_cppui381),
            fq2_value_type(
                0x0d25f34ceeff50e5502fddf943cfd36a628d119cd5f2d905617928743e71e77201547e433a407eed7f214f26c6e98424_cppui381,
                0x0ac2daac37505f408299340e30438444e5a9952a42d388966ceb504cab2a5498c38c318f1dfc5ad8055cd147ed8734c7_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x06b57042e4849b92a4e81346f8ba0114340c47d468096a46cddc32cfdd719a62137456eeaf56d1d28e0235cc806885c7_cppui381,
                0x063ca8f71db63973e371d8bbd76eee8fa490e59a7529b181c278b67b7a2b415440ccdda92a8834f4da915fe0383d43bd_cppui381),
            fq2_value_type(
                0x055dc89a8b6d8dc2027b1536f7e5ee25d6d1c3652860f2749bc97d17f91ad1655566b224339a8bcc2969783258716529_cppui381,
                0x0ce40dca881a8a4e995ebd12c10ce9f5081bce504e97f4e9f6ade1340c800d399a5fe3d669f44666d340663345e675e4_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x092dcde789e5a67dc5614d0b2462c550e7aa9be6d66d3492706f1454aaa2818609bb8dd1b850aa82d92d0f64c33d0435_cppui381,
                0x170f8e4565aa5ba8187714ffe7baa3a4917fe07475acc3cbd8fa429e034fa4f3ac53b06723eb5696f15d6e27393d888b_cppui381),
            fq2_value_type(
                0x07cbeb5679bad39efe161160a9f858ee129d82c0df28865a96dd23057ca9827c3606f3c2162cb76ac762f336e6bbb871_cppui381,
                0x19034ae5fcd14ab1ef3e1d979fd14ee274e61a1c64992f052c620f0c91a9a103f5a7bcb2bf5ce3056f4bd593d26f4a52_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x109b9b9fbf16c6fff2cf1f276ad1b09aff3ef976611cdc825f78e0f7ca76a271829e694b7f23a9ecb525427cdab92ed2_cppui381,
                0x150d3c3a996cb5713d597b4451e41b34b1b55b722784e951665fb1d07ee3c2ad5630ea3a35466c6dd8d96b105e5195bf_cppui381),
            fq2_value_type(
                0x0f93626288c013dffd087a341de791d5bd0c6cf04f1d0daa47232fd2705042c6a7627d902905bdfdbaa599672708a020_cppui381,
                0x0114d3a70ba03f3991a8c09294f3272e5143a84317494cfc4877f4d22eecb80be7fec0d6d80f6f0efb1b8c678f27f5ac_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x048f8757d41ff0940208039356e5ea7f8014761dea150eb67ef174d406fca8b3ebebac9f8872107ed155d43bbedfaea8_cppui381,
                0x14120aea46096abc03bb60ba301ec921f631dac868d95c2b2a863a74357b4f83ef1f5f5ccb056689abf4a3d6efb37398_cppui381),
            fq2_value_type(
                0x1184c3a34c160c7368114e39f29e949692b45527a4db659f278f3d36761d6906295dc9b7535df62d439c1cac004bb808_cppui381,
                0x197a4921a2fc88f5309e37a21931233b54606f90ecaa91fc0eb44f4431cb76615567acd63b588e8d78e76ee922a653db_cppui381),
            fq2_value_type::one()),
    }};
    std::vector<G1_value_type> et_w1_compressed = {{
        G1_value_type(
            0x0cc4f23befb077b70594e4727b515a99a71e37a2aba3676f06d92ad8607515b17d396a41c44fb6223d09c38b9609144a_cppui381,
            0x016d54a871a0c361b7b529277fbe4f1c60ccd683a7e2a9858605fec8cf06d485ca88c29b42ed0422a7b227e6f31e0378_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x105a1d84e85d2fbb65419dc25289eea9c6161740ffa7b1480bb9c9c55ec8a5c6e23bbea43ef9e8f1b3f4ad50de0f010a_cppui381,
            0x14c7e1997b89959300bc4d6f26ab37a08426980d2f1776d573ee3d43e44afffe4979ff4690c1e8e189b9e659cfb54302_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x03c866a31a613ccfdab2848521c14a42e232493f3f0799095c21e3f08d04b5fb2a1570df09a9005d1990bff956e2b8ec_cppui381,
            0x0b036658a0a7c475779b17f180a4335e24391f547eb4aa078c9532aeb9613acefc2b97e83356034bd6c9cc6a2f3566fb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x043d40d8cd4633e48bbfe4aa0032517cd43696465e30269363ab61a3ae9a37be615a36ca3088e3524ad19b3cb1bb2ec8_cppui381,
            0x03595a48c66399f7a07e9753e37cb2419bf288fb247907bccd67f481f184f12d8c3528485d1dca17a7c69ecbae23dae8_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0c47c20a3997052ec6ad1b217c1adfdcf17bb25998222bfd231e69f67cdc8008042cbf1fda89a3bb36715de890c0833c_cppui381,
            0x18438fa4cd0ef23b24bfb959eacc54edae6ccd3870fe55d7fba589c628d5db98cfc0851b231477fa62ac161f0fb882b5_cppui381,
            fq_value_type::one()),
    }};
    std::vector<G1_value_type> et_w2_compressed = {{
        G1_value_type(
            0x1670abfc0df68a21a2c7cb3bd1c62f8a48fbfd4799d83d484c996ef3d82a3dbdf5fd0175da7abe3d2ba96f059e1881f7_cppui381,
            0x0197a0b5a87ba59fd2c0a9c4de2ce5f773960c4cb59f6d1ef0657cbba79f0f499a7f58d09897716a676edd0a8ca3008f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x026b17c7a93778cdafc553746420a4d3689de8ec7920233bfd5d0abce2e1cfa29845ad7da2f3e36dc7934e476268284b_cppui381,
            0x0ffe95d7d5b842f8d8227f6e84a728b7a8cf7dbd933d80b2d90a17658dff5e61d2a54b54c575624b74d9b322f7fe2a01_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x13041e72558e8360e2b6adfddeddbd4f86a325245556097bcfa3fd6beb8eeeec6ae8a116545e89438b2f93f9dcf12250_cppui381,
            0x17698d73a7969cbc92b884f01d86c8034f7e764ee8f8f3476b557eb558156bd678706ff636575501a394d91f28314531_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x133030a621342bc3b57541336a5cc1e389fe746d27904be1bbb948abfd281cbe9bb90d746343e8e4481496d3202015e8_cppui381,
            0x0cc3f51d219fa568723c86c71cc6c11160d00a3b3031268a5f6eabe6672e33d147de99d69f4e7dece907f1b954134b5f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16f1afdc3b42de247b9278a284ef853e613bb90cf9342b8ae7a6a9cec7f7d26d669d010c69443384d41555943b04de43_cppui381,
            0x0d138e4715989d4c70c92613b10103c17ce187a5f135a7d07ffec540c6101a24c8fd36f9713c25627e8db62a2a35baa4_cppui381,
            fq_value_type::one()),
    }};

    BOOST_CHECK_EQUAL(vkey_compressed.a, et_v1_compressed);
    BOOST_CHECK_EQUAL(vkey_compressed.b, et_v2_compressed);
    BOOST_CHECK_EQUAL(wkey_compressed.a, et_w1_compressed);
    BOOST_CHECK_EQUAL(wkey_compressed.b, et_w2_compressed);
}

BOOST_AUTO_TEST_CASE(bls381_polynomial_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type r_shift(
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255);
    constexpr std::array<scalar_field_value_type, n> tr = {{
        0x3540c82ee6a14e5d87232db54031a151c313b02c2e5fb8097c98a22b5b1e248a_cppui255,
        0x3cdb7300a2167608f0b4371abde5bbeb0134d0a10c684e15942b9ade19be06b2_cppui255,
        0x1932db8eab26bffd30801c82338662329a83e9cd9e69f8547efee3b971c45333_cppui255,
        0x28a5a5846b8ef1151e23d7dac18b31b6f79ad9762d93a5ab7a09ec367fa15379_cppui255,
        0x32fc439e07ce9f303a50fdcebdede1b4aa3295a7ea84e5dd746466ce09edfadd_cppui255,
        0x17a55ff8ad252c1506c91301bf374301c2ec773f996598c10ec5b8518ab97910_cppui255,
        0x1c8ea45a048d71ca0dfb90deac07c6aba0c661e44b89e40af2ddfc02ddf4a35f_cppui255,
        0x1ba576908f3a792ffba1b1f2f427514cbd2fe9caf194037a178d47b2067547cd_cppui255,
    }};
    std::vector<scalar_field_value_type> et_poly_coeffs = {{
        0x0000000000000000000000000000000000000000000000000000000000000001_cppui255,
        0x480d5d9990c007e523111f13a4e4061ab69d113818dec59d1273f49f52296162_cppui255,
        0x1c0abb58c4a3de0c94bbde371db6475242fc6123f3e68e3022882416866a0971_cppui255,
        0x3eefdb325408c8ed044d2d8a245821eb03313482868f0776d5db0b6b304de06f_cppui255,
        0x03441b4883df6096879ef162eddeb395ab9a80ca1a2403a61f9bc5d7b66d61a0_cppui255,
        0x6ac136f24de0910a56a8c00eeab93f4e08c4754b0af8d77d45040c23483a3601_cppui255,
        0x595796f3711a982dc195fdc294444fd4127b3bf4fb57ef1fe73ba786e2cd8b3b_cppui255,
        0x68242a724d539dcde318352368080fe13ca7e75638953bee46cebb2aae451d63_cppui255,
        0x1cd6f4493f342dfe8fba32ee030dac4c002ed16c84c9fbbcddf4a510a72d63d9_cppui255,
        0x28ed796d756ceaa877742c2229c7a2249fc6511eaa85f82d51f555c3aa60623c_cppui255,
        0x6013627cbd87199375925d96bb505c1e2c2fac69d0072927a3d62ed8214990ed_cppui255,
        0x1d3c7275c9e6e11e2a4c960edd8c7fd67843a0c59a024bf44fd5314c838e199c_cppui255,
        0x2d9e8b3eb9c9f4ffc6901f6bdc89ec2d6dae92fc0fc19260532723bc3821dd96_cppui255,
        0x584dace948f5c058c571fab6b534749a83f02cbf95c964155c2c221d586dd67f_cppui255,
        0x3c1dc72ea7a79bd9a7fd76ee22484cc48c0bd7ad5d66c2a102862ec7221a88e0_cppui255,
        0x53afeb3f2a7f9cfd5be3ecf160a0316d75be4650158ee59f1960a17ce7e0cb57_cppui255,
        0x3ec8e839758da1f92f47a8777c38cc67a9e243f0a34da25f07df0e976f99cd8c_cppui255,
        0x3943ba6edcade9f65c9f22a154f1b9ca45f1a23b058c9c0e0c6c3c0f4543f491_cppui255,
        0x15aef80fdad1d60ee81fc555b4f8c8f3cb5ad1f0ce2a40e3fba710043dacc1a7_cppui255,
        0x142197f4144a72cb8e25cf5c976b06f9ca9b1aa1c7268be77a870dd3542f6a12_cppui255,
        0x7385a85b56d429a29542d4cb9f41dcd1adf8268c5c560568ccd6b907869722b5_cppui255,
        0x16883f376358bb8b5fcbaa95c203bde08fd98efd6a00de6d286452ba5acaefb9_cppui255,
        0x24f6e1eba0f8bda6c7bba6f678825efda1de9437c37054d68e6dc26d162c616e_cppui255,
        0x18649997a5f6eaafbd0c770811456c1123e1c5fa7aa7d07da777c6548fdfb0a0_cppui255,
        0x5ed4c557c48b3cffc1f462abdf8f4d9c1f2b0019b09d4e83561961bef7be3ecb_cppui255,
        0x0d1916a0935c0f8a5e1d06404fc6a96ed931d082ed1187619ade67cf1892f41f_cppui255,
        0x15437e1083ee249424c4e9a49e7a3724d4d960d13606a76a192bb7012b5f8df6_cppui255,
        0x4f8d6caeb51340c7e7d6341dcc19f4eb7dec5e6f02cc910cd5ff8bf200c9c8e5_cppui255,
        0x70267178abd9a15e624f537d5716e68281fbf95d045cb3a9943cdc26b5bcfe44_cppui255,
        0x2fc5d00aa95d2e97f24d20d29ad4c8307d3b0a6c615429b62f93ecbaaa5fe09d_cppui255,
        0x1a4ba280ba66e01758596ff10ced5f871938cc63228445048f8d18482ef48c6d_cppui255,
        0x1ad39de6f72da86c7730db7491c6dae910b3528d6c5013bbf9adb62c215efdd2_cppui255,
        0x6932ec74d018d36c376c29c5bd0d52c3a526c0fdb34d0136dd9fc87bba6cf45d_cppui255,
        0x44eae134e384252e2ea7bc1b33283bd04edbe1417a22799b1793f2ab0a29a7fb_cppui255,
        0x0db00937710081215915ac1e7dc70b3a4b49352f9a1813aba087629874eeb341_cppui255,
        0x207e89c0c4084f21abd035037ec66165348909e8f2e03808ac3a099372cf927c_cppui255,
        0x105c4d40813de99b80d86ce5e92f8e1f3caaef348644f0f9942a514ade360be0_cppui255,
        0x31e97c20fbc80c8c05758a8530156f2566c1a3d1095df49f4e7f2d3f82e25876_cppui255,
        0x476154855d5fbbb0683806fc9e2f9a6068afd35595a8c51a332bdddae043307a_cppui255,
        0x031874d3c0a6b1324366b64039c4fabf94b0243c39e77a633b6ccd69cb0c8c95_cppui255,
        0x70cc56d291248c13b1341d1964b6837dba9cb47ad37d1c5d95b24406e5a7783c_cppui255,
        0x2ad3e32cceeddbca5a4b04f2aaf2df0726dd4e701e4d2548764a8c0a4647a407_cppui255,
        0x1e3770a820da575dd692bb5bacba9d672093c3247af5b37488fd40e590905048_cppui255,
        0x6ea451815ae5fd07d6b203c600592fbf67f7f71cdac9ad505093cc16a71b5f58_cppui255,
        0x6931fd34b6eb5e501455a274713ecbbaed12c116fbf10585edb00aad5c9225ca_cppui255,
        0x391772c1990b157a9c080afe9e5fa2688565483deb4313d9b3a2398b94a54531_cppui255,
        0x6fd11da108d634967c28d706e1d238952532e938c3a43d2f4c80427ee5e41465_cppui255,
        0x4340a1cdfc5337b60859988391a22c5b74df5fc06064b69c351b0d227f437e78_cppui255,
        0x4a8490fe693187c8cc205c7dedcdbc4708964da51775ac88b298465bf23c1bb4_cppui255,
        0x3e136d819aa9dcb7cb78c693b9feb213e51e79c23df7b3a4aaa64357c459cc09_cppui255,
        0x0096de691391f1e4896e9d17d690f5cb948965349174fc5f488285125362a2db_cppui255,
        0x643df8ad7ba980771b96936fa67a63e485def3d8f9ea4bb82d350949fb092a71_cppui255,
        0x379dc3dcf086eac6f2532596d5f9670b25f5d752d3d3990e5cd64875deb30458_cppui255,
        0x63211c52065d6c71d6d1a8c77a9000896b9588e801f911b13f97f9803ceb9bad_cppui255,
        0x37ac58c5f5826a91c8b182464a083a04aacc5177e4b88d25ca49136efcfef93f_cppui255,
        0x66ba00908a3ba13d2a04457f2094627992685524b6798128e36b633853433526_cppui255,
        0x717311b6e53630e6bebf9443d93a796518c9c8751858deb57f1282c42bc67de3_cppui255,
        0x6b755dff197f12e46d8339ff46bfdf24f805d36f46ba9d42735e8f73bb1bf95d_cppui255,
        0x096cf8eb82f7b46a4e28653634c1750dd2c15bfcbbc082622e980e9826657c8b_cppui255,
        0x486806919560cff5feb7c7824f28a13fac252cdc0e9fef3dfe52486fb73c5d3e_cppui255,
        0x63e53e13aa74972b352467b517dbe8af338d966a5d3aa694b882e2c84e44380c_cppui255,
        0x11063433cc63c9174012cc17458f183539dc4cf386dcf3226213c2179ec5619f_cppui255,
        0x690111ad5e36e656daef3951a67d6610f73bbc301bb42bd3dbd13f8c80abe930_cppui255,
        0x72d25810142fefb4dd10f7f228dde90a73fc0906c77f571471e4af5aa0bfcdb6_cppui255,
        0x0229058f25696cea3fa1f50a6da95c74e5c4386ede7de3b3f505a0e638389bc0_cppui255,
        0x262df7daa19ca683206206a485552a0e431666659494b259ff769bc6fe0fb619_cppui255,
        0x3b25332af4ace3e424f8e355a19e9d428719db4bbbd5edf2b92ac980ef6b908a_cppui255,
        0x3cc2b194b50c7b9826ce8666be7f9cd062e92f77d98d59afabe2283ea14a2698_cppui255,
        0x0696ec6bbb951f3b12895e7f8b05257b1e744c2707e472d2b9db78a79eaf1175_cppui255,
        0x47c69add0279970e4272b8792df7b97098055505bea91ed0935be1b871af8ea2_cppui255,
        0x051638844fe262b56f2c6c3accee9fd55108cbf8ecd667096b3cfc16b7dadaca_cppui255,
        0x12bd689671b16e03368447f220d3e4c5e9e13b457e48ecf410ebecad2f53ed8e_cppui255,
        0x70e67fef8f8d90648ad9cd68d0aaae2b4f6adafdcbee0c16f8566d162b2d9547_cppui255,
        0x4914c12c22604660e3725cecefa32e3b3a84c559aeaada25170faaf10ace6d32_cppui255,
        0x412fc9ba9c6e0b797d1a03f767cca6c80bae5776906d40a67197f4fde5dd2da0_cppui255,
        0x2156733411bce77b968698d04662da57ed3bc79367399b49014a4f2ea03afdfd_cppui255,
        0x425cf78d6d13261cc329ab61755bb4c211b009c483ec62fa216511611aae2464_cppui255,
        0x6a967e87cfa5d5a9c135a78d1e92edc0b4e2528ddfe88efc32c63090b819f196_cppui255,
        0x1ad2bbdfa528b202ffc3c62134ab5a53b60be156f707bae7a10c5489a7ea7e6f_cppui255,
        0x4942e35742a4915a9c891a92aaaa477f4017e7c82d6ac1d3eece75a508fb1572_cppui255,
        0x65f6ca3ebf4c6111057c03ed0cd1127a100710fcca53bf44d7247c0de176260d_cppui255,
        0x0f6d4e5dd7ace3540c4eafb4bd779c86ee12f0ba5c92fa9e3565e52c06c9a881_cppui255,
        0x5b730bfb15839de0ead3db78edcccdcc80f8481ca4203d526aea37a129bc6179_cppui255,
        0x5c412c415597256e2b9159bf612760007a6c109d287634e1690b7dd2a3cb9a40_cppui255,
        0x0534aa0edd228f305dc8ae5a322b9e09d4ff3b82b45d559d935572c106daeea1_cppui255,
        0x43042bdd06fb35f6a553002098576a1d7594ec3297d4935382cde01edbf3b2a4_cppui255,
        0x02df631cc1de108e3b21cb1e19e27e794625bbbcbebb6b1021a8f490a4d26ad3_cppui255,
        0x1404628368af0c392030080227b4f2a3cfe1aa258357428959f5eef2154455a5_cppui255,
        0x2c93e7c0cf251568c29205a7864c9851dd595e5823332c1e13a110a7bb0a57fd_cppui255,
        0x27a90e636f9d9a35b378a1e1af3973d0c39cc941ebefa9f2fa13ef6a1e2fb8a2_cppui255,
        0x1ce47dc601ee5db8e7f2913c33484ad46476a2e1a34428fd14c7a8e822c52fc7_cppui255,
        0x71c6aef4c005a4c1c5f4801f866bc0a6bd5952b7f5e4865feb4940b3177fabe4_cppui255,
        0x040d465c49ca0315130efa3046e049a687e798ce732567d6ee84727b3fa226f8_cppui255,
        0x71706d9bd063ca170cb9f8c41ec32ccaed394a1a876a8302a45484159907ec50_cppui255,
        0x44c08e331896853c9ac99e97242d8808fdfffcd18f1c2701af2270aded40330a_cppui255,
        0x4a48fd884cfa214545860746f43495ede0aa14cb3693899352f42ac3ac523315_cppui255,
        0x3874018552b8014999bde467bd8c36e792fda187de468dc586a1b81ad4800d5f_cppui255,
        0x13221842137b41f2358c2ac97d79157f0cc560f342507259075acd2c783544da_cppui255,
        0x60ba123f92573c8841afed0951bee188f137ca4f04f918222bff7a8fd6526c04_cppui255,
        0x389f821fb8cacfb59d4589c9b13a4ecf379f701df2b9469ceb934256bbb6d776_cppui255,
        0x16754b4e1c0f1233c649c4e21d780128edac4c4c2b2439cf449088dc671fc348_cppui255,
        0x15efb0852b2230ed66cd64c55233ba16f66f5c5b05a6ca71f180cad01c8ed71a_cppui255,
        0x3781f551e85953156a09b638e94f690902f1ca91014f08979d1834c0ead682a5_cppui255,
        0x011d64455f427c0bd0577131f9ef48d47bad44c152029e59bea541a7a7dc98a8_cppui255,
        0x4ecb58e8f31f80905a95f962b9bec0538d53f8664b314684dcc8d04beccde8f2_cppui255,
        0x024d233a1e662788e529a405dcc3f25fa16cf5b574109ae1f2289d5d2193feb7_cppui255,
        0x0d0503ed7e91397bc92a73e4692ca6babfec93c725b55cd69a14879f22fd6ff2_cppui255,
        0x39811338758bd4b1d2bcb9890ba2e2313cec6e9f54db2fe82f0d95e0b359840e_cppui255,
        0x2a4e01fa966e5e1c8f7823d5ec3c708f56c9306af2d0321583613df9a2888209_cppui255,
        0x3665f93bb2da394bdd953a883d4c5fe04e176ae7be88e9ecbbf591703c192e5d_cppui255,
        0x0081b49e88f0b930bfcd84492407c730ea10772b809818c83ab95c36f3aa8de9_cppui255,
        0x22339eb7e2c232be0b60f86b7bfaf1025ccdc145b11d6bfa346f1a066cac2918_cppui255,
        0x0f7e1106cf189bd87a972286b151aca5e929777269b968551f00fa0381ffd891_cppui255,
        0x59841df41488a266e2f227dcaf4da41cde578cbfaba8115859becc20b488fd69_cppui255,
        0x6c8f58a4907e2a0b56434db41d3b1e69f9b360f2039d9856c188ab4deaceabfa_cppui255,
        0x41b6ff2188b920cdd099df98164b3d61696eacaec64aeb839024c7500eb8bcaf_cppui255,
        0x59cb1fcd4cffd255f98f5c64c84ea70651b1bed981e99d72cb4c1044952e098d_cppui255,
        0x4dd9da29ce23a3e5c0349517e283e54808855eb60d8b99e223762d9fd98af51f_cppui255,
        0x652fdc9b3a08078583b7e65b9459f42685acd2e1a61830cdfac7506574f5dd06_cppui255,
        0x6ed64a74f8d017974f6fe87fca5ad3d6433462054cece7622fd4a02f8465287a_cppui255,
        0x7314d4441d6e85dbb7c11797760dfc5f004659aee51e7299c7ecace82cadb00a_cppui255,
        0x03ce7f6f76589dcc32e08c0a0642606ce9af3d4f5d7bed76aa270cd50b3e6cfa_cppui255,
        0x3d497c195db408c4eb1f1c34256a6522c20e27192125c8a07370876deb01241c_cppui255,
        0x107a83d4a1d8c489bb1271df2eb9eb0f8acdabaf583fc97c12f2adc5abbe6c04_cppui255,
        0x6fa391c27c905ea55845cac5bb5cf33d0704173e4c32092326ba7e8bb93fb092_cppui255,
        0x252b7b7d7513e0811d293a194bef93f6e19a06ba180d87015bff1f78bff20116_cppui255,
        0x0bfdd6a008dcdfc40ca9b774424f557d4634cef3a8550914ff98fee3ed22d7e1_cppui255,
        0x5d220bbc372737ee19c02511f9c5aabc872d5a167b95c22bf35005de5aeec55d_cppui255,
        0x3d02fd9bd2224c0c5a062fb2f82a288db5db9f749d9eb0ddbd9dc26b205d344e_cppui255,
        0x684eaecbc3d13fa30cc7ea0c3393724de868b8a34dac4580c9fe3dbfdb4a9eea_cppui255,
        0x43e81faa6b9c5e3ccfb5841e8ff60cda8c5a0a71399bba912d99f63343372d60_cppui255,
        0x13b1ecc701b0566bb8cbf4f186104424a2840d7910d75e10a5c3e30ab4d8abc1_cppui255,
        0x2d1c2e7c193745f6d8f5f7aa63665349b399db387e2c838d9b4306d7a385de62_cppui255,
        0x5ba7d9570ac38ef02c5873c5bd9f655632782b1966b119c6f8b47687a229ae96_cppui255,
        0x1f04a0ef594a5bdc826aee7721c288de4c9fc260b012d0b2b6addbd4814a9668_cppui255,
        0x63e5967f5900365a832334f6b52a51c0390f4925761a2dd074c7fafac149afd6_cppui255,
        0x43ca0adc50da6246f4b1ba6c821bef6873d88541a3a27808a3ebfe6c27a7bd4b_cppui255,
        0x29c75f5d0e2331d4cd60d6654eaf1c22deb629837e53e0b723fdb27f0ab6a99a_cppui255,
        0x643189efbd2fd5099df3539df621a8a60af26e404e098f66c369e207a6e22e5e_cppui255,
        0x5bd13b92659428d50ccefca53a52c697e106fcf7b4ebbbd62bbad9e79638bc13_cppui255,
        0x3b9fffa05fb179e966b7081f0f9622d2f9f077cea9b6f02373d3f424ee146189_cppui255,
        0x3c9a59e0725fc1b24b3e79c7bdd37707ed9784c83fab9f4b8b285f4fad637c24_cppui255,
        0x414377c1398bb503f0174a07e8ee6d95783e74b54bb3066df7e16b75f21dcd3a_cppui255,
        0x2dc29d17bfb8103f6d6d48dcebf383e637ef29fab8f801573a58fb18362d1b8e_cppui255,
        0x67031c1c085c8f8cfffac4e0fbbdbe7214c5dcd0a91685f3fbe6c67160e627bd_cppui255,
        0x724b962b45e2adf79b4dad3a9ed82d6df3a1e385dc031d45f854d8dbfa01943d_cppui255,
        0x271417c390b9c3e27ca918f272fe54cfbe540e300115c96eac8520a5dbaa4d69_cppui255,
        0x011690ae897e8a9face5b0a51cff976734b6cf006a81a4153882bcd51194eec1_cppui255,
        0x33dda0320753586276ccadcb5f4e35f8602718f6d8ddddc5f1db1f376616b442_cppui255,
        0x01ade8747e0ffbc898a5467cac783aa96143266853b44ab6c61cd982ee79ea43_cppui255,
        0x363b2ae933e2c5a5d0e91bb5b24d10f48260c2f053101e6f0198b7a06412ec71_cppui255,
        0x5abe59a863d75729a56a033d105228bf4cf5192eae821ae32189e065844f5a48_cppui255,
        0x570507c4c602d257a873aca3d9c023b6c133e73909aad6687099e104c36ed8e2_cppui255,
        0x4a86a84ee21029642a1595c4f1a645e99ef41c411f7c0dade14b2c4e8bc09933_cppui255,
        0x69a18746efa0393beb7702fe0e7643274f1c7da904beb60b42014d5967ca4b34_cppui255,
        0x570470137359d4b2526f2f489d278e7340b33ae8eb2d9bdb64140067e784abae_cppui255,
        0x653274fd83f5249fbe2e778835c93a23ab783c17b5bd2e85d6dc5648673a6f04_cppui255,
        0x27a2d4099898b0f9f2d1c7f2bb7f70bb1ca1f56f5eab19909400881451434a31_cppui255,
        0x00d8fa1404342a92e90006cba8c13879c90d4c575181b1453c5b790f5465a16e_cppui255,
        0x14435f925aa0f45627bc67436e1b5cf50f003df76037f87b94b4204b21985099_cppui255,
        0x6c066f3f9d9e5d5147456c07203b4283e19298347018292c57a88c1a984268e2_cppui255,
        0x5b515f3be19fb374258075bdd0f16780a3028197c7a278dac6beacaa31ef9ed9_cppui255,
        0x4c09d00fa5ed074637b7c471f9574367ab7e96006bb5dd976e6ce0fb8c510bf8_cppui255,
        0x20d127b6078a21ef7e54391932c085e7f4654df49e8f103e25892c8c20244b5f_cppui255,
        0x580475a5b814e0d82b701ad59f33719fd2653a513dfe376feb6797c9177eba7a_cppui255,
        0x63cf6d747ce233351c5d5df3dfdf5b327baba26df40f08935a22946d55841a0d_cppui255,
        0x351d8afe67168f60d78f4654096232279b729ac581817d19eceb83c5bd92b447_cppui255,
        0x35440021e1f004525bdb52188b514ed08c4f920fa53988b98029b8dcd0eb11fe_cppui255,
        0x08096cabc485ca9da3f9c356d76f274299908e574d76ac054ae85fba5681fce7_cppui255,
        0x53d7a804607db92e9c398510b590021bab8e1480c8e5397c40ca31cc8ef38888_cppui255,
        0x522f728820091af6ca285f126623378f7a2ac3933d31d2065aa855c67c024162_cppui255,
        0x5234437802afc9769d9301cf53c2804f514b6dbac5e2fe4268a62066796acd4e_cppui255,
        0x1dd3ae12d0c460f223e9dabdd4d4049c023f588cf8aef3fe5f9742416b3daea0_cppui255,
        0x33879fb8eb95c5b0e8dd3189324d24a0c09914611e693eedcfccd4cfdbc833aa_cppui255,
        0x658e4fb9c73f946ab5278a26e4a9c0502d980f74e8f0315e4b0643056c862717_cppui255,
        0x1a122193c5f5f0c9e34e5eddb380afa5962e040b546c628d7b54b62bf8faa358_cppui255,
        0x4e51e99c866e7c59ebe92a359141b7ea603c71626c5b04b468515fe943ed5e51_cppui255,
        0x604918f13a0b91ff8980b42934a14fa80c5f95c16d22379943460c62d0050059_cppui255,
        0x64b52e08d3afb19c2d66c375d41d0b50f9d43350e695f972490d4167b4dad706_cppui255,
        0x6448724b222c98f72de1a942bcb7316f6db646eb2a93a1e1ddb73dde6f7630cd_cppui255,
        0x42e9f2d7e03795995872c8e14831757493854f07fd03e28ea5e481fa2e6e5d00_cppui255,
        0x11c5580567cff78b9a3efb5400a17a1b5f22954b775154dd0a98fc5c133fdffe_cppui255,
        0x4739f93374d06c312798481a586955248e0bcb41b01c584e13de06c4f1976cf7_cppui255,
        0x581364822399de7648f346b78c65ed7e6095c5775d122221199486be6aae02a3_cppui255,
        0x3024a680a2d674f96c6841b936d429a5f20762304d2a29532d65f9743369df75_cppui255,
        0x23bd923a227adfdee0cb10ea11d598897c7c0f906b645f887d292817ee66759e_cppui255,
        0x0fe864f291829c40460bf08ef4f593be2739efe8f361fc08047a4be94ae6dd35_cppui255,
        0x630d0f774643cd197aba40e27bf94b45a7310194fc81f904db1b5eec7c35e193_cppui255,
        0x566c33ddae001788c433c1e1566446c991554c37e67c96904d647503856ce4f2_cppui255,
        0x0549ea7a86d6304311e53674d3de0d7c7a8c4e1651e69fe7dd9eb1caf5ad9857_cppui255,
        0x487304c054c8124adb27e5d3079b3dafefd6b69db2d0605fd4506d3aaa5607db_cppui255,
        0x143e742dd25ce947adda8b6d3dc26e683db77101211384cad7eedc12a047b804_cppui255,
        0x41ef40c96879a56b2190dc10f23525865660b629ccb30a4761b779e0628ab857_cppui255,
        0x134d2d53a84ad41e5cfcfe75bf49c8de1e69b615738401bc31287826763faece_cppui255,
        0x1f5120857962996f095ad78e5ddd8258b08be174a7c369744372278cf98a2676_cppui255,
        0x5ea93fbbec339f9554eefc2f87087781a2880127f3dae033264025993654dfca_cppui255,
        0x2e183d894ab20b49f0b937aaf3d65a02ba29d08c89ca69576d53282827e2560f_cppui255,
        0x142e79bfca24b129f8e24be07bdba8f646a98093699013c149b7e90a4867bd97_cppui255,
        0x61a5b1c2f741290bb64a6182d97d6c6734816eb5e909f5e44d2ead92717dc3c9_cppui255,
        0x37ff04291d41edff6b6888cf36de141d18a60a6f57b27364f84c8ef07dd35118_cppui255,
        0x6a6125e36eaf98e32ca267a90895fefc0610a874f497a4187d4bcc2f997bb873_cppui255,
        0x095ffe71832abdc79e750eed95a627095fe785b7b1dcc9bfa5d61195c4ae1cd5_cppui255,
        0x2e11cf7c849427744c1a6d940df52aa6d65614a5fe3f274d115fad8a2bb4580b_cppui255,
        0x43e72e049425ed5b337b69e074664177ac10a35c3ab042115e14343b50362001_cppui255,
        0x653ced05189526caf7f0d24927a2a1eb9605eac04d449063ebf5852b0638dcd3_cppui255,
        0x36d5a09ed0e448e0e8031c485f3eeb83352c7f8d8dbe6c32247163e681388db0_cppui255,
        0x6c192143b75fee703d22dc756a24785563263138ada8a80a9654d45cf222cd68_cppui255,
        0x61ac75bd0db91ce314df5cfc3848d892260321de1d880c129474cf7035bc5ca9_cppui255,
        0x6ab4587e850dfc102c4ffb723c49952893065c31002f2a17d92a09b6201f7043_cppui255,
        0x2280ab51bfc0c3d03a61b1ae0cd199adf8cd7d595755bff1bd56848ac9b2addb_cppui255,
        0x6db3abb4d35f2abddfbf8c5ee58be7b104c4387e723433985589b504880260ef_cppui255,
        0x213e130c3c34db9d738af21150ba76382d55bb3b110a2d67f6cbe9c63795da83_cppui255,
        0x5dadd4dc264d9463821290065a2ff738d9f936ccc17382615cd600736ef8f536_cppui255,
        0x1c96d875fe47cfa371656e119d3a9646f67f5be4bb8784b47de10a587166487f_cppui255,
        0x6257cc59864ec4e2485be286144458bc3f4458eadc536ce8c5f5bb2870651193_cppui255,
        0x3c694078e47276d26913242fbba8a6db76a7fbda52977241af03234072ddafd6_cppui255,
        0x6082df0b0ff44fe79bbffe9366113b31f95741bb4f7fa86fec3fb08d925e11f4_cppui255,
        0x68b8926a41350f57bfbf1dcc61fa61c37b438d611a53a41adbfc4be14bf35f99_cppui255,
        0x13e6befe321c5a318a0fb7ab897bfa1d78de4a8c2451a9c838b483eebcc80b09_cppui255,
        0x5553fb737e38a6e413e00f77b115943e48e69d6e4ec131ccc22ce4ed47bdb6d7_cppui255,
        0x36f00a4a2739ed9ba56ea0d136d25a1a9d449c187f94efeb4e7c2d88ae9dea2e_cppui255,
        0x1d790279938a84ddcddf1f25f89f7fef234bb90e2a209fdabccbe03fda68a3a5_cppui255,
        0x0a864c6180e057fb9b20cea35bad5aae97114adcc43ef0fa4e52df1e1cfd9265_cppui255,
        0x177eda2f8aaae07eeb47e206c8d0caececaa26ef4907d98a67ec2257b4bc6db9_cppui255,
        0x4ab7c5d7846a1d8fff53196ca2f21a5c9569ac3a5688a536a8cb0d2e4c666c28_cppui255,
        0x54be7a81a0c2d015c0442e5756773c08c66150b73fbabb3b0b00e390c7848f07_cppui255,
        0x047ee8158528b7337c5ecdeb31522005ff4130adddbabe6c741159a34760da6c_cppui255,
        0x416bc2ac134682d2160769543dc6e426c3289207864e283e67b5861e409e1207_cppui255,
        0x644386d878eddba7ab5c64208012a25632191d0072caad8f20b4a08fc366d489_cppui255,
        0x0583ade3f8f05abb91350e75bc22edb668c3c92c35991f16ea4af45c46ee02f8_cppui255,
        0x49c9c118dc19529b22bd954defcf599a61447b6c3521eda59a0bd625e55dbee4_cppui255,
        0x5d8451e2595474c20f0b172a3e44da56d0ec7c369e6c0a991ae473bcf67fb579_cppui255,
        0x65a7e8cd2471091cad4ec2877d96e60caeb4eeb7c3c1d546a91253380c0466f9_cppui255,
        0x26f90507486b52fa6931e4392a196203b4784547c4d0eb828086acf8679cdaff_cppui255,
        0x6c5a8636cc7a511afc6a28f2386d6eb68c91d4f7e7fe8d26433e3e8128c80ca8_cppui255,
        0x162695cf98ffdf0e50cef20f0df3f8eb1d061303b3d9d6a35847c57dd6b61250_cppui255,
        0x08c0eaa9d94a3dcfbb2532d5bc18235d299769bba449e0b5a7593f5c72bac89b_cppui255,
        0x639030fa3f7dad88ddcbd3d7dda3ed3645c9290362b75681e3b1f2371b67756d_cppui255,
        0x4d7bc37acaf75c2d7bbf0c267383ae88da9311bf70a0191e5c62ea75bd3dd7f7_cppui255,
        0x38cb86c550bf3221ebb2baba61a3c77e449bd1fba63deba6a9c337db2f56c7da_cppui255,
        0x3150e9d8068b2d6b9490c4375bc60c329cf3318f52c4d32cb2d5ace796a1f9b9_cppui255,
        0x54f6038946d1bbf0553ef6e328682f0f2e47ef581218db4e6bbfe85d449625f8_cppui255,
        0x4b99ad7201e92fbab4ef236df467d7c6d0a10bd01de4c6d360ed09f7605fee2b_cppui255,
        0x05a5d1a97f870fc676987bbc4962d76a58b60d414645a92e8b1ea01ba3a89333_cppui255,
        0x71f99c0a53d6b69ff00ba55d627d925a8dbfe8b565a657f0b4fb5964427cc403_cppui255,
        0x5263f0e9812d3d52f221a16f50c036fe0363416f8e74f7c27f0ea0147d0c9621_cppui255,
        0x1d8d7473a2bcd19b69501843ae4754fb77c46920b74b6256afb9d9647943339c_cppui255,
        0x52a6679a95609c26e47ee4318c5a5b2b9cbe50989142ced50b485544ddd6acce_cppui255,
        0x065d2b0719c0bcc1b02037ae08f9a5398feca58936dfbd62b8fce028b01afb7b_cppui255,
        0x520d73bbb1d0970ea53b4e6337b9e353d09c5a856b923344c6d8cedddc238bce_cppui255,
        0x595276f8984d376dc47db0485377b0f95b3234e28ae1cdae168762e83db9de64_cppui255,
        0x663ab3819c59044a9ecfda430332513579c7a5801d369969cf18cdcb241273ef_cppui255,
        0x6bcd48bd3a63cfa11c3e9d52fddcee3112c22dbc68784894a63c605442b1d34a_cppui255,
        0x383c0f2c20c304caac5fe8b0a3013e48b71e33c608420c8e7bd04a5c138a4a01_cppui255,
        0x2ca94a4785a3e19bf06a91acfcfc0b695d432984da488e863ad056bf040890b4_cppui255,
        0x0ea0f213dc3ee2d046abdaf721c410e2cea5896940461e46a96bce4f52880875_cppui255,
    }};
    constexpr scalar_field_value_type kzg_challenge(
        0x73313f808ec41532e12764269b3c8cc1c6d1d01bc4732ebc4c3fba5bbd676376_cppui255);
    constexpr scalar_field_value_type et_eval_val(
        0x256def9d29cdb492f33f938c24ef442857ae93f0bced9e6db5a38de07a948d76_cppui255);
    constexpr scalar_field_value_type alpha(
        0x1f6f2def104ff7f1268b54e99552094728c89bedf9a6ca4b9fb3c117a1ffe631_cppui255);
    constexpr scalar_field_value_type beta(0x058173a1db7dfe76a2f9e03adeaea33127de9160915b10b69f20cf883094a0a7_cppui255);

    std::vector<scalar_field_value_type> poly_coeffs =
        polynomial_coefficients_from_transcript<scalar_field_type>(tr.begin(), tr.end(), r_shift);
    scalar_field_value_type eval_val = polynomial_evaluation_product_form_from_transcript<scalar_field_type>(
        tr.begin(), tr.end(), kzg_challenge, r_shift);

    BOOST_CHECK_EQUAL(poly_coeffs, et_poly_coeffs);
    BOOST_CHECK_EQUAL(eval_val, et_eval_val);
}

BOOST_AUTO_TEST_CASE(bls381_prove_commitment_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type alpha(
        0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    constexpr scalar_field_value_type beta(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);
    constexpr scalar_field_value_type kzg_challenge(
        0x1932db8eab26bffd30801c82338662329a83e9cd9e69f8547efee3b971c45333_cppui255);
    std::vector<scalar_field_value_type> tr = {{
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255,
        0x3540c82ee6a14e5d87232db54031a151c313b02c2e5fb8097c98a22b5b1e248a_cppui255,
        0x3cdb7300a2167608f0b4371abde5bbeb0134d0a10c684e15942b9ade19be06b2_cppui255,
    }};
    kzg_opening<g2_type> et_comm_v(
        G2_value_type(
            fq2_value_type(
                0x130cc68002eab5dd042ad6b44cf05764665429255d243e99ac93df93232efe3ab0690aa049ce7d55975d4468d034cd57_cppui381,
                0x0e9117cdcbca8bdd72d5f002edc2174db28e1db8822faedc36adc87f99a6518871f10c2c05959a112e6bec0108b4d623_cppui381),
            fq2_value_type(
                0x151b4757ffa7a260ca5cd8d3c7dcb380ce0e31cc9a96f7b4e3c0717cd0af0cf62e166d9128fb8a90d3b0afe2e9c77b03_cppui381,
                0x10f62ada6dfa4d1c8fbf7c7f2bafde9f3b9e8896c6432c16707b7ad6da5b5c1797458a154a7268856b5dbdbc9fb4901e_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x12ca1b47637293a935da075572b2fd740a2fbcaa58e2161f61f4fef1982c9f6928d8e3a13a4fe62cf414a34156349502_cppui381,
                0x0384651dd21b50548d96d43ec2ac462c489e3301b20a093ecac9ba24cfd275a2af09c9e699314da975babbf723b4fd7a_cppui381),
            fq2_value_type(
                0x01e201cbc84319db30d383db7411df22609ecf4413dac869ad824024bd46f08a715f2d7eaa79419c869947bcc31b2d38_cppui381,
                0x17dd995635f7e23869a028a2aac730c38edb03b6f30f2db044ac27a4a81963a03c4f2cbc2e9c831403d86a97301f10d3_cppui381),
            fq2_value_type::one()));

    kzg_opening<g1_type> et_comm_w(
        G1_value_type(
            0x085ea66c01bf2544d5cca506b0f230fe3682d7c7f44ba74d70cfc4b0513f7ee658f7e7bad6cb445399e6eb1677a3f6a3_cppui381,
            0x0f7205d63934b7ac8a8416c0e6f1380cf8ef3fe9d74c5b81a4b9c4cdeee3bc10a3a904534ffc542d0c5ba20b3a2f3895_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x003a5a97983e1323251cdb342bd5fe25e9aec95a6beb85e5b608a8859c4b4465e45aca1118bc1c6982732e93ef4a139b_cppui381,
            0x17886e66a7a0b695a242af2a6ee5e872bdc5fcb7f49e2176fb26888464a5cbd6a35d6180a3db4d308fbe2e65c19e2480_cppui381,
            fq_value_type::one()));

    // setup_fake_srs
    r1cs_gg_pp_zksnark_srs<curve_type> srs;
    srs.g_alpha_powers = structured_generators_scalar_power<g1_type>(2 * n, alpha);
    srs.g_beta_powers = structured_generators_scalar_power<g1_type>(2 * n, beta);
    srs.h_alpha_powers = structured_generators_scalar_power<g2_type>(2 * n, alpha);
    srs.h_beta_powers = structured_generators_scalar_power<g2_type>(2 * n, beta);
    auto [pk, vk] = srs.specialize(n);

    kzg_opening<g2_type> comm_v = prove_commitment_v<curve_type>(pk.h_alpha_powers.begin(),
                                                                 pk.h_alpha_powers.end(),
                                                                 pk.h_beta_powers.begin(),
                                                                 pk.h_beta_powers.end(),
                                                                 tr.begin(),
                                                                 tr.end(),
                                                                 kzg_challenge);
    BOOST_CHECK_EQUAL(et_comm_v, comm_v);

    constexpr scalar_field_value_type r_shift(
        0x28a5a5846b8ef1151e23d7dac18b31b6f79ad9762d93a5ab7a09ec367fa15379_cppui255);
    kzg_opening<g1_type> comm_w = prove_commitment_w<curve_type>(pk.g_alpha_powers.begin(),
                                                                 pk.g_alpha_powers.end(),
                                                                 pk.g_beta_powers.begin(),
                                                                 pk.g_beta_powers.end(),
                                                                 tr.begin(),
                                                                 tr.end(),
                                                                 r_shift,
                                                                 kzg_challenge);
    BOOST_CHECK_EQUAL(et_comm_w, comm_w);
}

BOOST_AUTO_TEST_CASE(bls381_transcript_test) {
    scalar_field_value_type a(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    std::vector<std::uint8_t> et_a_ser = {
        93, 227, 44,  5,   215, 179, 179, 161, 188, 47,  202, 226, 198, 224, 235, 229,
        51, 172, 126, 121, 244, 132, 95,  94,  122, 217, 155, 123, 243, 93,  170, 87,
    };
    std::vector<std::uint8_t> a_ser(nil::marshalling::ipp2_aggregation_bincode<curve_type>::fr_octets_num);
    nil::marshalling::ipp2_aggregation_bincode<curve_type>::field_element_to_bytes<scalar_field_type>(
        a, a_ser.begin(), a_ser.end());
    BOOST_CHECK_EQUAL(et_a_ser, a_ser);
    scalar_field_value_type a_deser =
        nil::marshalling::ipp2_aggregation_bincode<curve_type>::field_element_from_bytes<scalar_field_type>(
            a_ser.begin(), a_ser.end());
    BOOST_CHECK_EQUAL(a_deser, a);

    G1_value_type b(
        0x12b8f3abf50782b18f37410b10cf408e88b7749a40e344f562f7cc171612daa1981b9beae698180202993bcdeb42af53_cppui381,
        0x15800fa0ba4aefb8af1a7ca4af19511799fb01492444a070d485c7a3fe9b22bcfabb6bc2007f76a3adc6560ecf990a47_cppui381,
        fq_value_type::one());
    std::vector<std::uint8_t> et_b_ser = {
        178, 184, 243, 171, 245, 7,   130, 177, 143, 55,  65,  11,  16,  207, 64,  142,
        136, 183, 116, 154, 64,  227, 68,  245, 98,  247, 204, 23,  22,  18,  218, 161,
        152, 27,  155, 234, 230, 152, 24,  2,   2,   153, 59,  205, 235, 66,  175, 83,
    };
    std::vector<std::uint8_t> b_ser;
    nil::marshalling::ipp2_aggregation_bincode<curve_type>::point_to_bytes<g1_type>(b, std::back_inserter(b_ser));
    BOOST_CHECK_EQUAL(et_b_ser, b_ser);
    G1_value_type b_deser =
        nil::marshalling::ipp2_aggregation_bincode<curve_type>::g1_point_from_bytes(b_ser.begin(), b_ser.end());
    BOOST_CHECK_EQUAL(b_deser, b);

    G2_value_type c(
        fq2_value_type(
            0x0c23b14b42d3825f16b9e9b2c3a92fe3a82ac2cf8a5635a9d60188b43ef1408627230c5b6e3958d073ebe7c239ea391e_cppui381,
            0x0c45a0c4d7bda23c7e09ac5d43a9d2ea1898c36e7cb164a5cfcb91cb17c9e8d3d6ba5d177f9ab83a6d1ae554fab749f0_cppui381),
        fq2_value_type(
            0x03a257633aa8a4f3d03541ecda1ed72f30af7660891d39c9c24da7560d22fbc145c6817d3c2833e54454e664cf528c36_cppui381,
            0x01856f2127eaf9be53b902ff71a6a9b4dfb597f085fb3a2a35980683e82f1e2169beee9943a0ecbca676b4bc9370282e_cppui381),
        fq2_value_type::one());
    std::vector<std::uint8_t> et_c_ser = {
        140, 69,  160, 196, 215, 189, 162, 60,  126, 9,   172, 93,  67,  169, 210, 234, 24,  152, 195, 110,
        124, 177, 100, 165, 207, 203, 145, 203, 23,  201, 232, 211, 214, 186, 93,  23,  127, 154, 184, 58,
        109, 26,  229, 84,  250, 183, 73,  240, 12,  35,  177, 75,  66,  211, 130, 95,  22,  185, 233, 178,
        195, 169, 47,  227, 168, 42,  194, 207, 138, 86,  53,  169, 214, 1,   136, 180, 62,  241, 64,  134,
        39,  35,  12,  91,  110, 57,  88,  208, 115, 235, 231, 194, 57,  234, 57,  30,
    };
    std::vector<std::uint8_t> c_ser;
    nil::marshalling::ipp2_aggregation_bincode<curve_type>::point_to_bytes<g2_type>(c, std::back_inserter(c_ser));
    BOOST_CHECK_EQUAL(et_c_ser, c_ser);
    G2_value_type c_deser =
        nil::marshalling::ipp2_aggregation_bincode<curve_type>::g2_point_from_bytes(c_ser.begin(), c_ser.end());
    BOOST_CHECK_EQUAL(c_deser, c);

    fq12_value_type d(
        fq6_value_type(
            fq2_value_type(
                0x005db8a7f4d34ee8386fbdd094280f8cab08317945342ae713c2304055ad78397ca6e8174af0752c3757efe813f06a3b_cppui381,
                0x0c3c7febcc53d75eca6b47c27efbcfa8a2f394bcc5087c1308aa768415ad37fa6d7b2778482ec5d10425b2434974f0fa_cppui381),
            fq2_value_type(
                0x0f681a396bb919c9bd0582afcc6d75fe578df8968266082c18129d8ebc769a5b816efb78fdf962d7719a89bc804ea9b4_cppui381,
                0x041e0cc3da511cde05956a4a90ef1d74732ff001d6694d75a35d4546bd9e4f26b8427da499000e0c2bb282713ff23eea_cppui381),
            fq2_value_type(
                0x027423d44d437b22cebc4b79153c0a6f077507c0fdc5aa30a61249faa72ddce8e956a9e489d69a79bee9e16a79ab2022_cppui381,
                0x0958c21e079b0140de7ca150e1d021f065d2f277d78c138048d47f72b4ea0e943ae07bafbd890270cf152facd09aeb8a_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0d96831921809f76a8fb439c4e2ca0266fda8500b2cf4eb31d2281fd352dd9d8fe911fb81a1da00bf52d6e81abfd231a_cppui381,
                0x001cc9dca3d826bce7af86210eda9b0f0df5fc7e951c7904f0eccfc3c07ed4efdb793552757212172a2302e4314155a3_cppui381),
            fq2_value_type(
                0x0624b2b4826178f5eba880e953e8343d1afefe52b47f5c98187fd5361d2a3714bf2b62bf148ae91ab6e24ff4e579976f_cppui381,
                0x00ecad906407071532cf7730a6d3f46515d1a70ca123890fcc313d75100fc835bfe1f7c02c026eeda7221cb2a406ffde_cppui381),
            fq2_value_type(
                0x02d254206dd3c9cbc9c5a99a9b21f4776a7c1bc4745b59b71efa508566f2d97e2da95f19cfaaf702e6efe214f6abe45e_cppui381,
                0x1175ac9f5fd87dc2adecabf2ad3fc65bfe2e4054383e07e201d40dbf4bef2df006a4f8588f93bd872f66ad48982a9fb1_cppui381)));
    std::vector<std::uint8_t> et_d_ser = {
        59,  106, 240, 19,  232, 239, 87,  55,  44,  117, 240, 74,  23,  232, 166, 124, 57,  120, 173, 85,  64,  48,
        194, 19,  231, 42,  52,  69,  121, 49,  8,   171, 140, 15,  40,  148, 208, 189, 111, 56,  232, 78,  211, 244,
        167, 184, 93,  0,   250, 240, 116, 73,  67,  178, 37,  4,   209, 197, 46,  72,  120, 39,  123, 109, 250, 55,
        173, 21,  132, 118, 170, 8,   19,  124, 8,   197, 188, 148, 243, 162, 168, 207, 251, 126, 194, 71,  107, 202,
        94,  215, 83,  204, 235, 127, 60,  12,  180, 169, 78,  128, 188, 137, 154, 113, 215, 98,  249, 253, 120, 251,
        110, 129, 91,  154, 118, 188, 142, 157, 18,  24,  44,  8,   102, 130, 150, 248, 141, 87,  254, 117, 109, 204,
        175, 130, 5,   189, 201, 25,  185, 107, 57,  26,  104, 15,  234, 62,  242, 63,  113, 130, 178, 43,  12,  14,
        0,   153, 164, 125, 66,  184, 38,  79,  158, 189, 70,  69,  93,  163, 117, 77,  105, 214, 1,   240, 47,  115,
        116, 29,  239, 144, 74,  106, 149, 5,   222, 28,  81,  218, 195, 12,  30,  4,   34,  32,  171, 121, 106, 225,
        233, 190, 121, 154, 214, 137, 228, 169, 86,  233, 232, 220, 45,  167, 250, 73,  18,  166, 48,  170, 197, 253,
        192, 7,   117, 7,   111, 10,  60,  21,  121, 75,  188, 206, 34,  123, 67,  77,  212, 35,  116, 2,   138, 235,
        154, 208, 172, 47,  21,  207, 112, 2,   137, 189, 175, 123, 224, 58,  148, 14,  234, 180, 114, 127, 212, 72,
        128, 19,  140, 215, 119, 242, 210, 101, 240, 33,  208, 225, 80,  161, 124, 222, 64,  1,   155, 7,   30,  194,
        88,  9,   26,  35,  253, 171, 129, 110, 45,  245, 11,  160, 29,  26,  184, 31,  145, 254, 216, 217, 45,  53,
        253, 129, 34,  29,  179, 78,  207, 178, 0,   133, 218, 111, 38,  160, 44,  78,  156, 67,  251, 168, 118, 159,
        128, 33,  25,  131, 150, 13,  163, 85,  65,  49,  228, 2,   35,  42,  23,  18,  114, 117, 82,  53,  121, 219,
        239, 212, 126, 192, 195, 207, 236, 240, 4,   121, 28,  149, 126, 252, 245, 13,  15,  155, 218, 14,  33,  134,
        175, 231, 188, 38,  216, 163, 220, 201, 28,  0,   111, 151, 121, 229, 244, 79,  226, 182, 26,  233, 138, 20,
        191, 98,  43,  191, 20,  55,  42,  29,  54,  213, 127, 24,  152, 92,  127, 180, 82,  254, 254, 26,  61,  52,
        232, 83,  233, 128, 168, 235, 245, 120, 97,  130, 180, 178, 36,  6,   222, 255, 6,   164, 178, 28,  34,  167,
        237, 110, 2,   44,  192, 247, 225, 191, 53,  200, 15,  16,  117, 61,  49,  204, 15,  137, 35,  161, 12,  167,
        209, 21,  101, 244, 211, 166, 48,  119, 207, 50,  21,  7,   7,   100, 144, 173, 236, 0,   94,  228, 171, 246,
        20,  226, 239, 230, 2,   247, 170, 207, 25,  95,  169, 45,  126, 217, 242, 102, 133, 80,  250, 30,  183, 89,
        91,  116, 196, 27,  124, 106, 119, 244, 33,  155, 154, 169, 197, 201, 203, 201, 211, 109, 32,  84,  210, 2,
        177, 159, 42,  152, 72,  173, 102, 47,  135, 189, 147, 143, 88,  248, 164, 6,   240, 45,  239, 75,  191, 13,
        212, 1,   226, 7,   62,  56,  84,  64,  46,  254, 91,  198, 63,  173, 242, 171, 236, 173, 194, 125, 216, 95,
        159, 172, 117, 17,
    };
    std::vector<std::uint8_t> d_ser(nil::marshalling::ipp2_aggregation_bincode<curve_type>::gt_octets_num);
    nil::marshalling::ipp2_aggregation_bincode<curve_type>::field_element_to_bytes<fq12_type>(
        d, d_ser.begin(), d_ser.end());
    BOOST_CHECK_EQUAL(et_d_ser, d_ser);
    fq12_value_type d_deser =
        nil::marshalling::ipp2_aggregation_bincode<curve_type>::field_element_from_bytes<fq12_type>(d_ser.begin(),
                                                                                                    d_ser.end());
    BOOST_CHECK_EQUAL(d_deser, d);
}

BOOST_AUTO_TEST_SUITE_END()
