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
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/transcript.hpp>

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
using gt_type = typename curve_type::gt_type;
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

using hash_type = hashes::sha2<256>;

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
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Serialization/deserialization tests

    scalar_field_value_type a(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    std::vector<std::uint8_t> et_a_ser = {
        93, 227, 44,  5,   215, 179, 179, 161, 188, 47,  202, 226, 198, 224, 235, 229,
        51, 172, 126, 121, 244, 132, 95,  94,  122, 217, 155, 123, 243, 93,  170, 87,
    };
    std::vector<std::uint8_t> a_ser(nil::marshalling::algebra_bincode<curve_type>::fr_octets_num);
    nil::marshalling::algebra_bincode<curve_type>::field_element_to_bytes<scalar_field_type>(
        a, a_ser.begin(), a_ser.end());
    BOOST_CHECK_EQUAL(et_a_ser, a_ser);
    scalar_field_value_type a_deser =
        nil::marshalling::algebra_bincode<curve_type>::field_element_from_bytes<scalar_field_type>(
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
    std::vector<std::uint8_t> b_ser(nil::marshalling::algebra_bincode<curve_type>::g1_octets_num);
    nil::marshalling::algebra_bincode<curve_type>::point_to_bytes<g1_type>(b, b_ser.begin(), b_ser.end());
    BOOST_CHECK_EQUAL(et_b_ser, b_ser);
    G1_value_type b_deser =
        nil::marshalling::algebra_bincode<curve_type>::g1_point_from_bytes(b_ser.begin(), b_ser.end());
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
    std::vector<std::uint8_t> c_ser(nil::marshalling::algebra_bincode<curve_type>::g2_octets_num);
    nil::marshalling::algebra_bincode<curve_type>::point_to_bytes<g2_type>(c, c_ser.begin(), c_ser.end());
    BOOST_CHECK_EQUAL(et_c_ser, c_ser);
    G2_value_type c_deser =
        nil::marshalling::algebra_bincode<curve_type>::g2_point_from_bytes(c_ser.begin(), c_ser.end());
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
    std::vector<std::uint8_t> d_ser(nil::marshalling::algebra_bincode<curve_type>::gt_octets_num);
    nil::marshalling::algebra_bincode<curve_type>::field_element_to_bytes<fq12_type>(
        d, d_ser.begin(), d_ser.end());
    BOOST_CHECK_EQUAL(et_d_ser, d_ser);
    fq12_value_type d_deser =
        nil::marshalling::algebra_bincode<curve_type>::field_element_from_bytes<fq12_type>(d_ser.begin(),
                                                                                                    d_ser.end());
    BOOST_CHECK_EQUAL(d_deser, d);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Transcript tests

    scalar_field_value_type et_res = 0x1bff9ec90c94f40fd9360a56a02db6a06be9c09b642d6049eb983bc21fa81fec_cppui255;
    std::string application_tag_str = "snarkpack";
    std::vector<std::uint8_t> application_tag(application_tag_str.begin(), application_tag_str.end());
    std::string domain_separator_str = "random-r";
    std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(), domain_separator_str.end());

    transcript<> tr(application_tag.begin(), application_tag.end());
    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
    tr.write<scalar_field_type>(a);
    tr.write<g1_type>(b);
    tr.write<g2_type>(c);
    tr.write<gt_type>(d);
    BOOST_CHECK_EQUAL(et_res, tr.read_challenge());
}

BOOST_AUTO_TEST_CASE(bls381_gipa_tipp_mipp_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type u(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    constexpr scalar_field_value_type v(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);

    auto w1 = structured_generators_scalar_power<g1_type>(n, u);
    auto w2 = structured_generators_scalar_power<g1_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_wkey<curve_type> wkey {w1, w2};

    auto v1 = structured_generators_scalar_power<g2_type>(n, u);
    auto v2 = structured_generators_scalar_power<g2_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_vkey<curve_type> vkey {v1, v2};

    constexpr scalar_field_value_type foo_in_tr(
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255);

    std::string application_tag_str = "snarkpack";
    std::vector<std::uint8_t> application_tag(application_tag_str.begin(), application_tag_str.end());
    std::string domain_separator_str = "random-r";
    std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(), domain_separator_str.end());

    transcript<> tr(application_tag.begin(), application_tag.end());
    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
    tr.write<scalar_field_type>(foo_in_tr);

    constexpr std::array<G1_value_type, n> a = {{
        G1_value_type(
            0x19382d09ee3fbfb35c5a7784acd3a8b7e26e3c4d2ca1e3b9b954a19961ddf5a04bc3ee1e964b3df3995290247c348ec7_cppui381,
            0x0e1429c57d0b11abeed302fe450ee728b9944a731765408533ea89b81f868ea1086c9d7e62909640641d7c916b19ad33_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d76e41234948369334b432362d0704bd88599200d80645a69ed47acf10464822776a5ba8efaad891d98bf9b104f9d24_cppui381,
            0x08a8c2ae10d589f38a9d983feba2241cbf0d292d44bc082e8fc9ff872f8eb280f6c6cfd1c34928fa81274781a4f4770e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x02e080ea7883f56025b965fe7fa27315af7bf0f532fb031075467cc78dbce6319645e23e8febb6660cc864ba9e985afd_cppui381,
            0x0f25c2c8aaceff02da0d5b85030767c64b3ed2ffd3e3f69e9aee42025c737e95fce00d5269eb151c4d22a5f77ef8c815_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d3541b03376d07cbb7f9f48b3a1cc43cf48160152c20c00c7bad75986839b0f9ef7cc71f1ffb4d254d9ec15ce6bf336_cppui381,
            0x01e48935c827f8ec79129124e8baf1deccf99d8ca0324fae41e037f4854ff4f389a4df3bc9ab2549b6ef949e4acdedb7_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x100462d4d96fcf47dd6f6dd3957f8c2d15cc72fe0f2ab0540813e73a16c74b4bb932722e96a33e2a26ca1ab9bc879e49_cppui381,
            0x0b2d223ea7a3275108aa52b3e4eaba948dc93cb6ae29c3c472a022eab55356e51755a6486e7fa94f3b8b4a06b3ea735c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x1320c3ca0de8f268ff78f461e5b342960432064eec51743c386fe93f2f1ff8d4592d04605092b7302c217a72e6137632_cppui381,
            0x1613b77929282de9c0a3baf3285394260a50660b2f5168c6924973b44f35dc1a236796b3251c5a748039b78d0b377576_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16bfa39559ac6ddfd3c63ef03bfd11ae6de4d08e66f82dc4ec4e2ca4318c266a705134204f2aaf99b91f95610d356bdb_cppui381,
            0x0c2dccca4ef18b3cf50f18ff13de4443eb6f5e6160ae985568fc5557232c892599e27285254360f797e4b59da1c19406_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x09f4ebbbaaaf5d2ea52abcb591412f6851539e1919d34de4f00900e60591438a6668d48070b5fb22c3b59a3cdae45799_cppui381,
            0x0aad9a2d04fbced844ab0811af6deefb18e9d67660073ec96954f2f0edf3a884a4ddcef6d8b7889a9bfbf7e2f151b1b5_cppui381,
            fq_value_type::one()),
    }};
    constexpr std::array<G2_value_type, n> b = {{
        G2_value_type(
            fq2_value_type(
                0x0badfb692a2a7ca4970d2733fc2565afa8e09428453ef5cc916a6d5ab43b8be8b9ef920af378f1823f426bafd1d096c9_cppui381,
                0x0d523776965ea36bab19da0387d38305d628d63fb7da6736f4620b7fce92539fcbaafe7dabd96e98693d9973ecf0544a_cppui381),
            fq2_value_type(
                0x020203c10b37edef960e6921c624ee57a3c2b256385b3c68f8fd611f1deba8ab91cea15d77452639429c74086a322eb7_cppui381,
                0x1498dcc1d84eb92d7e41ee99596e1825901ea430fcb0ff64d346e19375981ba8579d6ebf325c8809f1aee58542bd6c98_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1634b13dec932a66d5b3ea6406bacd702e020970d533c29a3d6fd80a4ce1e8138744eb41b0f1e66e956fbace9af6a151_cppui381,
                0x0a4edb2465192b1b32c84bd6791aa9795b8533df963b1626c8ee548bb5f7430a563d0e662b3053cc12cd256f9e8471a4_cppui381),
            fq2_value_type(
                0x049004fe74f14513aa607d429e78203f86e08100dc70243fef9fe73cf9f04f9c3793b3fbc1d4833f9db371ee94e60bc2_cppui381,
                0x0f2277dafecdf791e560c89086d7abc21e5f0314fabd492a0926e588acf7a34d30c0713ee2cb03054f44a7dae8288694_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0147be5fd09e02e8d64eec3e6737b40d4099ccfdd88651c692c7d4407a2822c35756ba40ca412f61e201b5cb649391a6_cppui381,
                0x165fd26d77e79da63ffbfaa5771426f4fc6c925a92bd593d1075e84ae1db5e9cb0a7dffaea46dd46a44f6cf904cb873a_cppui381),
            fq2_value_type(
                0x1507d32ecb1783a069322547839ffeadd5bc4e04562dc36914686df787f6f82d5a84f32786996fd56ab2ed75e25264cb_cppui381,
                0x0302e3dd0ef0b642fc55af194e4906d57bcbcfa1a3822f078fd7fa1ea0d665ef6f60531068bd7a6834b92618db91ea23_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x04c0d40f727b43aa40d5a66de08182abf5c15f6d3726a9f43085c7a9c8b535ab17bafbc6d90a6677905271c845768ff2_cppui381,
                0x10e288228d368ee8fbfe240e2a0ac3214bc232334d901feb02f41fbb459c11ae6fb381a4022232b66f8a98ec5ed2425e_cppui381),
            fq2_value_type(
                0x0285029f076803949ea0d635d716ddff562a8ba9a652e43da0e1df737978432082cce2435e857a2b78c886fa7a6dce84_cppui381,
                0x0a52fcec1a0fc4ec51022181a0e1e44aee18f8d2cda18c8ce5acc789838b03205919870c83b4ec54cc523d89a40ef62f_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x113b921ff6a06df8c8ee87288df68472b00f7f8dc243c12731f1177ecb8780fbd3765069e0fd5a8c1c7a67649b00d2a0_cppui381,
                0x12d96c166c7292b72c7bb9e0e9e91ffdf7ca3926f67ce4894f0b7ae0d826d397c7fb8bba8e2e29abcb8aa9e7de01c42b_cppui381),
            fq2_value_type(
                0x0b9231a10b1066269677672e76235e7864d7bc0bc99d9de649c1ecca732e887c6c5975c486b44fae713541d130497bf6_cppui381,
                0x011a97bd656717d31c74a17fec650e2a04894d04631792f14183ccacee8db3ddd731f4ced99488a133f66d12a66d2eaa_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x159a7f20fc1f1fe0f794fa735c6ee28b2837aa5d70d70d1f53f1d7cbae31ca04782e9261818ae6bda542076fb61c8bb1_cppui381,
                0x03d48c028b98f10345bd40a59c2bf27229947241472986bbff174ea87d1a1d4721e2a03ccd0af2fad6d014fbc93f55d9_cppui381),
            fq2_value_type(
                0x0c5b2aa2ac824a6a3df42b895d61832e71202b8fa896eb7bd52e4f1360c696385db9fb84783aaea4e8ad86f80e2703a9_cppui381,
                0x07fc3cf1d974627a821f223dac339045ede041850e3b6b542dc66b0d3bfd3a582c68c65ace31bb3986c70b4f59754e62_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0f228b023d7881ed41446c45cbc1fd05aecb0708291131bb189a6d826921780e1c28864cb0d84f68d4d1933d5bb57c15_cppui381,
                0x14292b6aaa6b19596e452bef413171d6fbf68e1d7642dc0e815c8dda280c32d63279dcb9bd16effa5789722dd403c188_cppui381),
            fq2_value_type(
                0x05e1e5b8555c4d238726565fbca0b37042fd10cf5b7f6e0396d71f5660db2aeaa053b0be570f33c1349503829695eb98_cppui381,
                0x0896a44ec87960d640a89fde02f969a079c781ecf6c29f8c3115f6792cdd20eb5046ae8aaedab29b0b6d12728b9863a9_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x108b91795a87e98f1fee29fa53b60f7bd6f397f6e716654e508303a0f5cf9adf44cda4c8698319da3b7f2f417823e127_cppui381,
                0x1389b59456bc26b56b1ec04cd3deb42033519f78255e3569231d551c121bee2b42151c2ef3513c48851519133c7b24be_cppui381),
            fq2_value_type(
                0x13d4e1d3f953e836bdf9602d2fbb7496b8a922638cbca415d171de4a7df0a9ce630c9d14e3804a662ee558d415308993_cppui381,
                0x0b154e4f42109dd3a7857f02cd95c480d205ba5427fd49389051f7fa927ea6e2b6c4373c145349e8cbd9ca1098fba447_cppui381),
            fq2_value_type::one()),
    }};
    constexpr std::array<G1_value_type, n> c = {{
        G1_value_type(
            0x0ae765904fababf7bd5d5edab78752b69917962c150f3b0311446579a083a667412ea18f009817a6051cf852e09e9c40_cppui381,
            0x127fb89d20a2b31725091c033f14986b33878ef4853806987412126bd8135731c09d5222fddf44441eb4e04cee8b9469_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x140e91d114a6dbb835d2ae1ab50729b0553e3e988ca0451b29ac1458caf71b1f1c47ef2255814b4a3ccfb924f57cbe33_cppui381,
            0x0ac830f2ed3435b2b9b3900d0bc0d74407467abdde9f72e922859ae1d2cb094299a7ad467680e7eff331e8a6f92df194_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x186aabfcbe235db4a2dcbacbdd571d0b2e857ada26ee83f0a4121c1bed70ee6609bc0f24b3ffc6ea8af50b1b4de25af5_cppui381,
            0x053ea1258a76b5dc15460676bd2380558bd26cbd98266cb04bbe3d18656f68b8ea11c6db24fdffc28470fa8778e08882_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0642350f1aae9598397a7da3190e07b7b896696682c37641cbbede18f05495bcc822cc8bf34b87709372f3b8cb895a38_cppui381,
            0x140f5cb0dc31c1db82e845f53882f8a7a0679380acb7262411d8f9b7877586192f1d306f5eba7b42fe937c3885542c1e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x04eecaeb1aab1d88696f17a3fb205e7d0bf517c16ccce694f196cf456b45a3983fe40aebbd2c0a5da701c63933d0c388_cppui381,
            0x18dd9108754b69d09b2ad191b8c4f431431030619765f109a0ab1fc9a64e71d483ad96c95a777a0e73aa72703b97f59f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16dd473a6acb01617eb7b690657196e837013062c9a20d0afb16f8604882182b65ab55e112265e510b4a0a95ca2fe1e1_cppui381,
            0x1937d9afd12b5a1334475224f967fae496c1b7ad9277845cfe9acb789d9d207d7bd3c2464b337669c9ffb3d5f643a163_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x19bd07f7ce52c9efe33aa9e93c98c9bc2ddaa4c762c52f988064438ed82dff92c49b5799124116af8ea46d9dab5cd5f6_cppui381,
            0x08f805c413e0a8087b32052148a63dda612c34a988e42e8cd12b3fb3d72942201571bf46298c6dc697c1e51be539295a_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x00352edd966153a5fd28fe8ac333ddc95a4dd00a6ef16f7b59095e705c3bd5d6e8805071f3c8ab2a66f70e7a703233bc_cppui381,
            0x0499e107ae36ceb8da7e1da2b83a8217b428976311420b4281bd428bc18b0db518e125d8a21e92efe1d68bc766ac4ffe_cppui381,
            fq_value_type::one()),
    }};
    constexpr std::array<scalar_field_value_type, n> r = {{
        0x05beb4119e1356ef39f98c7a7115452a3c4c1e2a48975c85d875aae91185fa25_cppui255,
        0x256d4004ff9591bbaeaaf85cac883eed808de37eff2b45c6d05e6670b3cd1fdc_cppui255,
        0x3973e132b07e7b2244f1172a11387054f7c9593b3b258475db005459a0e4bcff_cppui255,
        0x669073a3f8b48ee66412051fc614f73fa8e4e967a81e82562d23bfe430d1e2b4_cppui255,
        0x2d571b235843a47ecc75978a95b3cceb9fb28a6a2919e0304eb79201c4ef0352_cppui255,
        0x622551c093e4773c3e1ffb69e99fcd4a31a1f727369f47b1df49b03b9534a8ad_cppui255,
        0x0b8cb847f81048e85f5843218c1e273b56ce2608d7d9947cd1527a1fca0001f8_cppui255,
        0x3dd77c298708150d79e47bc4afccf78a6e2f32a17bbbcab1ea41e05551c0e96e_cppui255,
    }};

    auto [g_proof, challenges, challenges_inv] = gipa_tipp_mipp<curve_type>(
        tr, a.begin(), a.end(), b.begin(), b.end(), c.begin(), c.end(), vkey, wkey, r.begin(), r.end());

    std::vector<scalar_field_value_type> ch = {
        0x2883b568a12a6dc1561fee01f0090f3ff06a0f7c27f7a40185ac41385a200ded_cppui255,
        0x112b150c55bab0273d64d934d71183dbb256751e8b80d2b0ea87088fcac8e851_cppui255,
        0x055e703e64b31bf0b3bebd815951fe581d97779a3b98620ba1794cd9bc58fbd5_cppui255,
    };
    std::vector<scalar_field_value_type> ch_inv = {
        0x43eecdd051ab2519427d7d76b6f873497e3cdfe31c76d5667e08927b96044bfd_cppui255,
        0x0f9da473894f2bc1c166db82fe51c5d092a281205607879752b816113738d899_cppui255,
        0x662891b8617ed1084a8364b6f5079bfa73f61b837d13a795a411dfb2949aea62_cppui255,
    };

    std::size_t gp_n = 8;
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>, r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>> gp_comms_ab = {
        std::make_pair(
            std::make_pair(
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x1701ba7f0509b7e218885999ff8e0d8fd20879249faf6c907327a354db0620de84726c2ae65f7f7346be4c7b9b2c4367_cppui381,
                            0x03fe09ebb7904bfa095554bdfe698518fb1064b0dc9f122531b9a7182e2ccdb8642b42cd4843eb25a79ed4ff5f71075a_cppui381),
                        fq2_value_type(
                            0x09cb83834ac84dd6b6847b473e767ee9894a1245766a744b6c214bb02531cfb94d13343c9aac3860f3eac1a2de7af470_cppui381,
                            0x095dc64073093a6bf7f9e9dded5df10a42b01711dc9f1dba1b1e0ec84f4472e7d2d2d8519e631705b1f9bbb97be68432_cppui381),
                        fq2_value_type(
                            0x0b510e0d90b29d683baa1822f05ecee708864a37d4ea68a4c4816a81b2cd245ec1545d014f62ed13a03023e52edd1dda_cppui381,
                            0x1689673fc750776551be668c09990aaef7e6b6947f1b0e3f73b38a40beda59108dc9e8ea6fbd5585db728f562795ce06_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x0e99ecab8f6548d90cfe9ae76dddcd4e4c10ad72958b452d553c4dc78ffee512c71fff93f8b085293fe3c02c7b96a6cb_cppui381,
                            0x0cbe80765592e2d2a972471d965dbab09c386796cf2a719446e3bd1f3d7d6524c787e1bb7c20b75351220fc2cc121706_cppui381),
                        fq2_value_type(
                            0x194753dfd2e92783ef2aea297b1c264d59dd9a944bb99fe45ac8b5554b0841470f06f3bc007a8a3414bb9e3334e674d0_cppui381,
                            0x0764b08c7bfbd9e71c5422ccbdebcc3f1cc5beb57f67adf295948fd983f73d9930b688af6a489c36cf9d9288f8d22c49_cppui381),
                        fq2_value_type(
                            0x119cc4751db354af4c481685629eb95d805c55ae53a662fdbd00fe2ff7bffa1861c0540ce45ff4a9197f15c853c7d75d_cppui381,
                            0x040a238800a14a56bfef15ce32fbdb59ba5d76d2aa4af45e17828491f6cafad7643b13f74c368b6d574353a47d535d04_cppui381))),
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x069b17df187719495bb18c016ae7e7c31e8edacaa7aa30e506e70e134b5f1bbb45442a75a1b8b7b206fdc967bcf14514_cppui381,
                            0x0160243efea1efb70087d7450d69c62edff1432c2fb2b8e3f0d9a01902e6515fc24b35bf0ed0c9812e9587424b41971f_cppui381),
                        fq2_value_type(
                            0x034f424496fb477edeb1b23eb85e7c84a64cdee7d331224d70fdbcb209b06e01bc548cf67d8df92dd79e6e7ed2a4cd6f_cppui381,
                            0x03e1f18f3e7264effff7202321de674e2374696f07f68764878b4344223259ef69619126594e1fc0389eb9b8811432a3_cppui381),
                        fq2_value_type(
                            0x0eb7a0b9e959a2c6d83a2d8f5757f48005bf4774d4e554290377798d8675f416c914c67f4e200befbde44139ceeb09a9_cppui381,
                            0x13c675a9f0527e51c4719f6b3b7bfd92da3f206306c8fb9c85c06c286ee45116749135b06ec1495827f1f8bf739304f5_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x03e302298442ff87e6b52fbef013fe0afc3d002a78b8d2d582bc1ccffc8dce383bb4e21d5f549c64f880a1edad5d2790_cppui381,
                            0x0b16d017c1f4c8bd22188a741d1e93b15748aaaa079ba4694d2194583ae81beb9b2361746c7aaeb11f08f71e937bfe88_cppui381),
                        fq2_value_type(
                            0x162a2dafa59534770a715802d107403a1176924870a320f0462ca850397c41c75efcc11b5b6df2b63fab3ca6566f844d_cppui381,
                            0x022629d916cbb06d74e8ecb06fc8f6a78f56f0a93fcceca7448ef647198638010ce1f518ea05552749bf5dce10720ca9_cppui381),
                        fq2_value_type(
                            0x0df9783d2dcf1c4c1c3b97734551c84a7ddab13c5e9b2537ba3506e02a7440cca899ad1564e27dcc807ca1cebf42b13c_cppui381,
                            0x0a3e3e4769f81a94710995948ba1a9f7792d0e22cbb1abe3f479e328a3ad4ed531eade81eab2629fd2280813f75bcba9_cppui381)))),
            std::make_pair(
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x0cb6ca8b6d88b711d02573075e1a40f6f25349a80f88e0b07baf511d8a4baad9b586ff7f9c81445622bcc664dd13a6cc_cppui381,
                            0x0279458add992150b117e6197e5ef3d5c852e1796b449f50cf650cacbb870961629c672ee7b2d9947cdd03bb7b878e3d_cppui381),
                        fq2_value_type(
                            0x1847cf165d4d0f309788dc34d44535872d7a40bae234462e1b9ed09fd5a0f0d1ee26e38d7cca0eb2f660daa83b930b0f_cppui381,
                            0x12080acb367923b739d6d1041f9fbad2c2ee94dda3adb9d1258e63482ef3e435661ff3ee1ee3c84b42976a1cfc934e44_cppui381),
                        fq2_value_type(
                            0x09f8ddf1533933a8d4d6b9b9dbb234924773e13562b9dbeb6875c4001325a67868b782bfc4683c8d49fbd65db65eabfe_cppui381,
                            0x02979b2429f4d35280394b9b5cdb690d15b4a2aaddeac08e1664705ffe909e59bccf4be90c64bf0f34a08e5efd80dcb9_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x11cdeb302303e06fc11452727a8cf6900c6b8f6bc5f503303e41b9f87add0b195d76772d875af36b1877c8da4044b357_cppui381,
                            0x038dc01b2c89d1895bea6c068713259fa1f5d02dfafa4fee9a19a05150ad832a875cb5447379756e45b35e73cfca3749_cppui381),
                        fq2_value_type(
                            0x194c20fe5121f5c1864c5efd03aadb880cd5f6c951d0a7f0a68f53cdfe6aafa5f8d83455ac6883971fca5d743888a579_cppui381,
                            0x14b7cac6044711b4dd19dbf1895ba9c393ae921d8500ce74246e5356b8d894c71caef2b913bed06b62455c3c446ed7af_cppui381),
                        fq2_value_type(
                            0x002e2b2d7ea70d38899115877b6d6ea175f96e59f7d216046f49b7f0e9e22ed7e0c267638448d2285c4cc1289458ff0a_cppui381,
                            0x03966cd64fef5c3ca8e12190400b0ca7da423d329da5270feeeee1ca9f2e8bf52bdb258d5f7ed7a7eaa51bd84852a810_cppui381))),
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x0b6e2795e7fa55531035a61ea6a24052b565a5ef05ce509266cc9ac7059039ba70958b1e4bc2da7353d80f0b699b6774_cppui381,
                            0x1618d8b816e6a34de3e7253178c51b6adadbf2be2f6c4c704fbe40a2c868daa1df8af540c7ab477f27004c5bc3e037b6_cppui381),
                        fq2_value_type(
                            0x052249bc1c46d9914c01e3a69922141f91bd1eafb2ccad0d7186507eda3c97bed89897f4beedc7634985c0e5d0150452_cppui381,
                            0x02ff2b93e282ac16b09951a7f14a5290cfaacb3f9f25b9092b710f7ba2c8c30b285f0e6c62284913e9d0b37a92997306_cppui381),
                        fq2_value_type(
                            0x14bb0012a1d140eff26e210c2f8ef1e29dc4e38aa84c7ab0358313212c2fbd26850b996e82e39f9f65395b4e824dd3ad_cppui381,
                            0x08e1c0a71d4827a4d0708869f4c75d277625daecbe7dfa78aceb94751274c97a4874bd647edea3831f2ebd15c53e3ff5_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x098646703bafe7dd5cb20f895ab856379ebe2795171a2d2d837c3daf319242413836c94235cdd46a14bff333776cb355_cppui381,
                            0x06b75a76e67126a0276a38d56b75c97ac7eed982bf0e6bc0ce850b047a66e3dbc0722657affa8fecf54c153e915ddf34_cppui381),
                        fq2_value_type(
                            0x0febe95b97905efbad801cf2f411b3c42738ddd095c080721dbc0fd8b5b19a1846e88a83903273bfcfe312d4456524c7_cppui381,
                            0x0eee398f5205e62ad1101261d8e611e78eac9f8f8501a6d3948d6d9709600c8e47d213682f3cf059f69c234ff2dccf7f_cppui381),
                        fq2_value_type(
                            0x0dd8d7d5ed516418c10b19f95a374a6e896e30fc1e3d1ad535f9cdbae03abd371ce69d37acaf718544c9380022dc0031_cppui381,
                            0x0fb010c220a47c2abe40a2e2b88aeb11506b9cdb36f9f6e587435be0634c64252126796fae4b841684368b9af64ce00d_cppui381))))),
        std::
            make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x16da8406c72e50852f40308e036b078f3820b71c63131432691fae238e2f8533959a59f3ff7a517230e76da76ea11293_cppui381,
                                0x16df3a44d2a8ebb86dc1ef23adeda663a2f21c68f274b2865df249d892c3d47baefe48aa7637e80d9120ba61e5dc1bfd_cppui381),
                            fq2_value_type(
                                0x0485b9438b3d0ab777df7dffe6240f2e6e4c5bcd5d948973671cf15e4e470dc59652eae43e3979332ce80479e7008b3f_cppui381,
                                0x05c91ce79d3c2d73aba5ddee9f83d201938b90272e620c63fd0987c516a1dcd9633ab470177cb3d51da52b6de9e53cfa_cppui381),
                            fq2_value_type(
                                0x0cda1c363a18c00c3271ff99efb4d016b5b13acca2d801bb7a283b992ae8094e80cadf5e7aa26e7887c183c01aebee0e_cppui381,
                                0x1141bcb428c8989db7a6e7dc2802d589bf49f8140177012fa81bce1ec75479e6c54fccc3486834a1aba2195bfba1ec4c_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x17210c1bb1cc4e8b1379271293a66da66f0ee9541c07b7f4d0924177c5ff01107c543a57e4a6800446573495b8cb7f9f_cppui381,
                                0x0c18658c9e3c0a8129165c8cde1eb4b4b28c50d46ffadef2884b5ec1620b48129a8e65e8fd98a5eace06cc5a51e626c4_cppui381),
                            fq2_value_type(
                                0x0a6e4e70752985d694c8e8f20068ca504aca624f63afcee28a41c8df67b5d24241ccdeac2c2551a1a33c2fee968e9072_cppui381,
                                0x01a9b5dcd330acb681df8be5747d02bfaa016db2c0b1f7b3dfcfcf09f4a25728c00da7aca745afa7a4351e841b089195_cppui381),
                            fq2_value_type(
                                0x164361d654ef2831b88c3fa1aee44c6903a99034cac2d8b7ee03649b29917876da30d16fc03563e32918f0eb41dac3fa_cppui381,
                                0x0c34b80d2414c06736417a5e0602edd1411ff3ccd30557fecd123232d5821916fe6ea4e1f8bee4c72e552f174e70b694_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x01e66d8c34267edee21c19b8bde31acf91564bc8b36a24e9c0b9e5a1956ce63dbdad95fe355ccfbff4ceb2ee8cec79a2_cppui381,
                                0x02ca51dd6351566ee9e231b88a751b93fd78a233a860b8bf6bd8aa5e28085b2040d3e48c05b126e1240027864f98ff3e_cppui381),
                            fq2_value_type(
                                0x0f932f1c62814ba4317a6efc07823ef64fc76d8afe0e0a14f375e74b36720b48d08ced11db0d7a3a0b8c0ef122cb265e_cppui381,
                                0x02870732b2d15ecc4f4af98ac0f5dcf007c47fcf75ca17bfbdb1d559fcb956c7712e73487f638d92d80fe5b35b3289ed_cppui381),
                            fq2_value_type(
                                0x12fb1202408d76d2aadc36a392c7ef2e273d9b835b2a34f42d48e9127437590d07377bf4d56c0088775f687eaa6ac79d_cppui381,
                                0x0f3d1f91c8bfc0aea320f91720ff12d69e3a0e3a80233471a8ddf9fc0dea3c467e84f9c0316fb75f8cc62fd333920544_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x1125252157c328766e2e4b2f158e9b85c425e27f823418173d7a75690ad2d650b8fb9f1d48f1346a67c1efd13d4b6e25_cppui381,
                                0x0c9ce95c2b886c2f826f3eac42f0038aa1ded2f86d263566095ebd78b1a9e2624a1e7f36ffa742dac62f81b419d1cab7_cppui381),
                            fq2_value_type(
                                0x0b3cc7985be98cd4ff44a6ca8fb4fa60049b224d0be10c124611dffc2ed21ab707352b35b746cbc4313b2d7cd0d5b541_cppui381,
                                0x18c534f303bab5e4a5340f2c0e17b0f183b71e28f49f7bfcb93920cf4d5c33a5de2dc83f6d5eed6cb5406254cf4dc82f_cppui381),
                            fq2_value_type(
                                0x074df80972d96ae23b43ef629a8cbe5638e1353e22f51d0df5113a5a262cd3955e3541f73f8714ef4994d7a79432566b_cppui381,
                                0x05d374e795830a7d302915243530cd415f0c18c540b3634c633a2a6739681992cb7daece9674a0491469f260923bc674_cppui381)))),
                std::make_pair(fq12_value_type(fq6_value_type(fq2_value_type(0x132a78e0b00478b3edfc26db906dbf6c2759c7f27c3b98a84011c65b62bf92af8b54ccdbd3c1db8bc9362589e5078f45_cppui381, 0x0168f77a62d1b0e636dbde50e62161a2ed12142c177742aa798dc8dc8b12bd3b9170ebe41020defebca1e5bb20aaad47_cppui381), fq2_value_type(0x11fe2f2b29287ca8a2365bcb07457c284910cc544bb0211101b8ed23c463a1ddaade5a26f1a56ec93cb78659d5d6152e_cppui381, 0x06a641e4fc2750db919dfd1367961cfc265ab7e14f56110c26fa2f6b0366760abe126c5b50a6e9092e6ea61527935f45_cppui381), fq2_value_type(0x04c0aa651f98f36be45309ed33f25884fff4aeb557bebf8f9b75f2286359a1216fd4d8f3a295f812c911f8868159cee4_cppui381, 0x17649067cb9e9d5bcfd3c3bc471e0f769154e7d8722efb664c9ea7ae17dab09daced6ec09bd629f88d9092f6cbd40469_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x1911a9857d93950e3b8b1754d10a44012f88842553804c156f3f8f3516c7696734087e98ed3685c7be16b92e90a945de_cppui381, 0x1489e73b6a540c0e36eb757c0bc1a618f7b6e9be7205292cbdf4361a595e8b7b302434574e7dcb25c1a054903c0e41f7_cppui381),
                                                   fq2_value_type(
                                                       0x17bbc83baed4f6d075d8042261a6cfb22952a2b2e8d5b23a4d526892229d7b03123939d7343a4ada1c5a0b2a76c7bd3d_cppui381,
                                                       0x104cb9d23adba2e984d8ab179f4e433eba61be2aec6229836df5b5b806f612eaf188810f08f2a5ced9580fb489d5c939_cppui381),
                                                   fq2_value_type(
                                                       0x13d5476e4278861e0080218c9b08a75f190512ebe51f993286fab8be19ee2dbb69a8df2e326b4b7522bc58a906ecacbd_cppui381,
                                                       0x05a939f2335e754b28864c96132453330b6abe3eeec760b53a4d774d988c22d5a9c56191401a9d1d7c467149cef95ad8_cppui381))),
                               fq12_value_type(fq6_value_type(
                                                   fq2_value_type(0x11b23e1606ffaab1eb8952f0ba9543f09105aab2d7ac36725ff352a87dfa0b588658b7763b555a1b86aaf933337b59d3_cppui381, 0x14152d1e00b1b620c7f4a3cb377a8e60d576b3455583a01608e94f95f62e1d9b041845f2102e6ac198be8c3d94f68a42_cppui381), fq2_value_type(0x1603b8ca6becaddd01195cae5608d302ca23e14984c70dc7a61455895044ef148d0d8642ba0605aa7d7eb38ba44d9180_cppui381, 0x14e9faa3c12ba3da9e5f7ce9b521b63a8061d21569a21a8ffccc71eb8243c1070c6cb47f1f2363c31659dcb623bfefe9_cppui381), fq2_value_type(0x0fd584caada92f79eaa839320334d5ec141c278c48701997d37c0c51cba8b08e0451bf66000076a85353e7924b30f8b4_cppui381, 0x075e33a667c52690ddef06bd152fd8b06b7c965740a1bf7d23a765e049cb9abfda9f6bd1677033bb2d4731eb3c1b2196_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(
                                                       0x0c1de6523b8ca977f15bd675452a05d4bdf140a83664def3df217691dbc1c7a3edfdaeb49ae7c8ed0c4ed91389131388_cppui381,
                                                       0x1156b0beca8f0bb9bd9716e563b4d776b7a6c9f6f35b6f5003ab392cbb8499a65349bf532573aded001b2e9a76a99cf0_cppui381),
                                                   fq2_value_type(
                                                       0x102268736c645e758dae75f4145d37b032618734391596206c1b925278a3815f1bd6429b1d1112ad1c091777f7fb50e2_cppui381,
                                                       0x0a36bd32a4acc7fa9cea23223cc051bb2a3015d9869acfe90e968127254b240f828430f009c48176242c80a195e8d9be_cppui381),
                                                   fq2_value_type(
                                                       0x13c34a0f16599f0684d7df9688bc41f0cc5bcb0eb2945b2405e00c2ae4b84c6b0e8b9b4d5240edf63cfb0bbeeefb1f3e_cppui381,
                                                       0x04f945294aaee3cad1852fa6dd7b024939483080cf5f561cfe08eea61d8b73cbb0669ad02d9e31f98e5c4ac3401ba2e1_cppui381))))),
        std::
            make_pair(std::make_pair(fq12_value_type(fq6_value_type(fq2_value_type(0x1796a4837667738bda78651ed8a4c65a87632a3ea97c95f51ac06954ec03d8c8ba490c1ea2a9518649d3f71253d684d8_cppui381,
                                                                                   0x10a7292b41a1e5b516f74e9ac0fe19a5adb4186c3c7557cc479ec3b60c38d09b82c6b24045737f9993b5a2329d8bace6_cppui381),
                                                                    fq2_value_type(0x195fd82c2e6fb90c155b2ad618676d49f694d564cb8409b9acab9242a6d0ee80ab7441b5be1c0ae9de004c706b31883b_cppui381,
                                                                                   0x1651f0e415a83964714442c625425dcfb29c22cce70da59b8ec872f5767f3049c4325a2217ce24deefc3caec95a136f4_cppui381),
                                                                    fq2_value_type(0x040bc81b4ef302791f0405a4a6bb36820aecd26d00161a699ede931fd34dbd727ffbd43854b390adb38f180786b3a635_cppui381,
                                                                                   0x06648e5c5fd111450b478256b589ed24746a56a31934ff6b204accba6b007396f5f56f580255728ccbb0faa46e5b1e21_cppui381)),
                                                     fq6_value_type(
                                                         fq2_value_type(0x1297fb8567dc9ae1465edcb4d48b476a0640438ebb32c4028457f0fe2e61c695393585e548144898e78d1d01d36f8bce_cppui381, 0x11c84077dd6ad636c43440cedb146cb1adc6751bc993606df76c6aeb0e531367c7b9dc11a52145fb18fc9708ddbee524_cppui381),
                                                         fq2_value_type(0x15a615bbebc925cbaf49322baaeed4e61a5c4ed3b6d69486f0097571ea22ed8772f015ecec1310179726e2aed0c60efa_cppui381,
                                                                        0x16adf516ab6220a9f9b2d03b48a817221fe288fd431b529b353dd87303f5aaa0634c0feead0cbe424c1eb1c7597b8e67_cppui381),
                                                         fq2_value_type(
                                                             0x092b831b0608cddc79f2931e2a2b5c83915ec6c57e28dac295046c0c233d165e77b1423dfe27b89e23d12fcadd6f5cee_cppui381,
                                                             0x065b4973fe2a9dfebe3961496be7bdd85de4a9c38f6fa2b6012b7cfadbfe50a1e1af8579c12eed88f3f2bf3bbfc9fe17_cppui381))),
                                     fq12_value_type(
                                         fq6_value_type(fq2_value_type(0x03e6a19b59584cebd47c6692aad00d5640cbfef27a9439c4c6a2a1ffb927c72e42121e2aa68fde5c64cd372c662ab090_cppui381,
                                                                       0x08d42616f58f9931a6e197d17f0014d8ac864e1618f2378a1c1bef303e458a3f25fb11ea1de1fbfc12c3f505800b1503_cppui381),
                                                        fq2_value_type(0x04c8fe00bb3d8b84a035b82e6ff867936536ac6f8de6088b43392e6bdf815ef31e3afab0200d2f7c41ee344137751421_cppui381,
                                                                       0x00acba90fefd3fb2d9b2340850f406932a031b5f3a8029dd70ee263f735c2b32826f65f67872dda333be336f6b980ec3_cppui381),
                                                        fq2_value_type(
                                                            0x0ffde25fd0ec8cc2907dba99b10bcd7cfd14aa026a144af21857dc41fabc35bb2c1787cd31b1b1d5ed2c232c475bab2f_cppui381,
                                                            0x164812318daa68df70877bb63c0d8a8001e47c1db8f50d50cb95bc940dffbc7650bc40ea0b24f1595f5226aace718249_cppui381)),
                                         fq6_value_type(
                                             fq2_value_type(
                                                 0x093481d03fef9cc9f271b5d8230d9cb14f3cf98d654b92160336e41e55f6d42fb605a2af905f17b1a459069fefd57c74_cppui381,
                                                 0x11f898ec6152eba558f2cc83c2c7269b9973240c4359a82021f2f4c6553c6f1f21f1b3fe0c5d92a067ef7608509f13eb_cppui381),
                                             fq2_value_type(
                                                 0x088cddbf5faf04086b3e25a0981961c144dd9f2c0ab00992f33dc45e9af3910f91fe60ec07efb7c0826dbb7e0862ccd1_cppui381,
                                                 0x05f8f806e7fb624bde57aadc678423274f5d1693bd9f1ed59ee83c9f76b690e7eb08998e4f8d811e49ca1335a7cc6aac_cppui381),
                                             fq2_value_type(
                                                 0x092a53f720e21ac1602e9670cee8b218a7aab84b5e33f05a0038be28f138e9a7abd348dd361fda6a6af61ee9d5f06173_cppui381,
                                                 0x14deb63656b666b4767eb71188e1c702a23c45d8cf168a1b35dd52e32cffffde0cf78b2185a7cba029a9b5ae24927258_cppui381)))),
                      std::
                          make_pair(
                              fq12_value_type(
                                  fq6_value_type(
                                      fq2_value_type(
                                          0x1710517e71dcc0e44fa6c49b2a6f67c5b3ad99bf27ebb14019d7d76be38a7a9b3d7d7b16b902eab975fef089530c2e76_cppui381,
                                          0x0958e24b6e9472776ecf24d69379d4594d466ba5aeac36ef84a46f8c8d30637674b41982753cd3baf0e44b23a4b45d58_cppui381),
                                      fq2_value_type(
                                          0x11c3a389dc556837541b6744234a7fadd3fa80ce9657dc89ece826ea81e1870d89ef29bb22963c3dc0bbf36f2aba73ba_cppui381,
                                          0x090dd7e0a7c9e256eb6a8fb0e20d5c1fce2d46540b2224b496a6c3c1b638051dcb896bbf7952fe186599471533dbbbdb_cppui381),
                                      fq2_value_type(
                                          0x13b7b8645c9b4053860778a6d0c900697a8eb71803d905bfcb946f06601bace37094d04a9efb482d941723f34b953f46_cppui381,
                                          0x121617dad31fdaf4c08793363fb9da18053ec94f0c0e6451874ff895df9beca02cc139266282b98b8017f3545fca8823_cppui381)),
                                  fq6_value_type(
                                      fq2_value_type(
                                          0x06e9b80e0d58d32189864f7201c765dea9f6396ceed1edebb54f675b64038a4cb8a5d8583dd353bdf7e9070c5fb3662c_cppui381,
                                          0x19fefc64f9dfdc55b956e457e1d7d8df75b72c77514e4d27b53ffe884c9e32a0c0c95f2062006b9f96f25c07dca70886_cppui381),
                                      fq2_value_type(
                                          0x17cbbd1bb6ef16b040f4ee89279425e42fc6747f085c089999f306146faa1cbf5acaacbe6fe64a02699e5e544968c860_cppui381,
                                          0x0a457a90d294ff0d56cb9cfcc91785547e122e5b747c4e6b55f6d7502ac96ffb7628d5c35b8e57e7b4fc9da63c801432_cppui381),
                                      fq2_value_type(
                                          0x068a208adcf654e32af96029dc1002a2806c73cd16d8342b3f041296bbf956a5e2c2e276019df013ed1ab8418f0a519e_cppui381,
                                          0x06f7930f493139b1c1421bd47ab75edc9674f0eb51b73f0caa95dde8fd6a1f76d0c0ceb804bd93291013bc79ae7f5546_cppui381))),
                              fq12_value_type(fq6_value_type(
                                                  fq2_value_type(0x107ddadb37b80b74ad3e2c93d85a56da0fa25be724d07a6d57ec84734a2a4efefa52cda682c81535ee716b9c7aff9a30_cppui381, 0x03a8e006494d27a53ad9324616054a4e25463379078156a24beede1925cc8e390e22004f11737c1d9544d2eece19af79_cppui381), fq2_value_type(0x0664e58fbed899267a597bf36c4c1fd59169881aa246267fcf6ce035f58272d6ca464cc6d7bb40724a76da5dc737c560_cppui381, 0x04a9c751f74a6c4d2a9b6a8fbddcec08aa7093a3ae6fc66e30955a356fabcfe670b030bc04568aa073b404ea6a627a4b_cppui381), fq2_value_type(0x10ebdbeb44f7419d1dcd072c444b833964615580789127e1865719422604b0effa076bc0557ceac7f399113eeee03e9e_cppui381, 0x104172dad68748a62a06f7abd5442d44b62715336070ccbddec71e5f690cce468c4d316748850d32043b19ad9f1725b8_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x042dfcbafa057d992a14412651340136f38bbda1b27d2ab9e7ee65042ebe52d5feed5d135210dfe35660e0cf811c7ff8_cppui381,
                                                      0x00105df46a8c1b1c9e2b3d73c544438ba290cb61336652c136dfbb2fc1a8f2ef94bbb053254c14f6db1564589bf17df9_cppui381),
                                                  fq2_value_type(
                                                      0x1153d7f8cf18508d635a4ab1bcc41bf9ab62648b8114385714616228399f7ef85b38ed94d23f0b8bb0de6711c92f7f25_cppui381,
                                                      0x10e25c5d0cd1c5f0d90771f30a87c500c6797dfcb15397793565586c820fabdfc81de036669e6975df8fefbc7abdb4a2_cppui381),
                                                  fq2_value_type(
                                                      0x02c3df2e0fbefa9f39f2fe5809843332c4b052934d4326de1345bb2d33ffcc474ccac2151298e205344a7a0038e360c9_cppui381,
                                                      0x120a4f8217c9f0dc474a438ffee41b52e46dd2ffb9646a1d3c3f59ae2ba02883c28b9d4d09c003fd65560b0c130f83a6_cppui381))))),
    };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>, r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>> gp_comms_c = {
        std::make_pair(
            std::make_pair(
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x0509c0d0ab554d5c1425bea60c60c7ef90a1959d26a3294c7677fe7f9c1b4ddd8ffba5c06d900bc13a1b317a01a5c7cf_cppui381,
                            0x046d5964c703d200662a0da2054e82bdce73f1a37e8694e9c452dcad42f5d15bdb651c44ff8691022d82cf160800bb53_cppui381),
                        fq2_value_type(
                            0x0ff81c9f18341fa508ae9866e78a755eb1b17bd1233bf1d2854614a6323d9818e2240ddacb4fe659ca0d5588a5df22fe_cppui381,
                            0x0ecc54057b774c2b2da8438a1d26041bb778db87c7a68c70225f3494a268daddee73e8c54fe31f74bbcb5a1ffb312430_cppui381),
                        fq2_value_type(
                            0x138a7fb94a9376c8cdb7d715cd68ce504af6f0cdf2bb09c767585e7083aa572de7c96388252a9d73046b166656ded74c_cppui381,
                            0x1a001a345535ff4333d83392a518c90ee849f00672b652a4c7511bfdcb8cefd7cebffe90e802c05056b94328063b2154_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x0c684748ea5920969bd6cf6023c501f74c238b26ecf79d5bf2d741871bc52ae7ae76f0b06c6b6e348bbc0aed9f35db7c_cppui381,
                            0x1575e1ab44ec2501524ff851a2c973807245fab61bdf976a44cc6eb9f371366c23af378889dec49010baafdea025cbf2_cppui381),
                        fq2_value_type(
                            0x1755614454ce7dc81ffd688002bdbaaeaa62355f676a799d665987a058f283363701d2106c2670a9e3041c3975142b48_cppui381,
                            0x17e77e4d08d89f981f8229862d1a889dd3da1f711dd54a11105072866414f2db55da2d15606391d76e503922a1a252e1_cppui381),
                        fq2_value_type(
                            0x0d938f3bd5bc8b07c20be5fbd4897080700a77d9094a60053defcaae68b7058e63aa4a7d8fa1248764ff0d1bcebae30c_cppui381,
                            0x17aa67c74c3ee3c9a26b3df1971942ad9880ebee53ea153b59628090e88937e74a70527f7e330dfd1c319dff4e4c7661_cppui381))),
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x05a51b0a92a3f0009ad1374af88f9e95c4a7bbf69e8053b33c315d0608f3fa3eb4a6c9f7248f7f94f394bb28f2f106ac_cppui381,
                            0x029d796a6717c6bc82bc4c123621638fd80aa4adf4fbc0cc93defd66ea43c78eac60c99bdede9b1ad550f89d5bc61b66_cppui381),
                        fq2_value_type(
                            0x089283988b3e2d9668594255575288868791a54a37da8c4de2bd9e2f2ccf68b854bd57aaa35cbe6e6072414f07a7ff91_cppui381,
                            0x03c194d6daad3d011314b6c74b6ab60011836b774b308ec19e5dce5d9007dd167da90ca452f88b02c64ad07c19aa6f20_cppui381),
                        fq2_value_type(
                            0x0441a1ae10a79eb27350220350eca05daf096a7fcc2e9f5957396830b8a2fbebbe8ab383bd84453b029df0edd54c7be1_cppui381,
                            0x156818d2d266c0288f1f675c8483c04203afd696f019530138c82c6734604b081af0565bf1039813105806b2562c53b8_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x0389a59bc7ce5d6a9b92c75cc5dccf1292f2c11051dd3cd44deb8d3ae99a3173824ecec5b837a94f80da7b5725a666da_cppui381,
                            0x0ef2b3c46669b8ecc7881b9d5a1091443662b5f568d28f88d02e40146ddd61790a3219a4980cdf732326fd4cde56317a_cppui381),
                        fq2_value_type(
                            0x07e95ceb0f4b806fcd78c6599e30f8cc166a5987647ee081298eaaac7f693df9aa5a8b12e474b7edc91a1fc120ab45a8_cppui381,
                            0x079b811cb3c4a22a320214a66ce62fc97e6d57ebefa1061e68b6c0d5e57ae03ad64a6c8a0e828b57c32d08dd2ce2797f_cppui381),
                        fq2_value_type(
                            0x154f204ceb40f66e6d7308e75e4c4c3ee625cb1c3a49c5c909f830f0eae85e098b4161fd6ddb0e68e0063fdf2718b963_cppui381,
                            0x03efe4a8ebd8413bf8931eb383dcae700b5aca3deecff3e4e4096110dd2fce607d7c57c27170299c953332b0da763f4d_cppui381)))),
            std::make_pair(
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x183ca0a6c9be94ab62147fe8328c5d226edbe6cc8239bc43fb3f385f0c48475d00e24e5d0bdd85f29a2f241af3bbd0ff_cppui381,
                            0x119ef2ed159fcf31d55cceb6bd5ff224f50d1266407fc83d9bc6aa0863eb8cbf90cc023d08039766f70661ac71fdcc80_cppui381),
                        fq2_value_type(
                            0x0703a4ee74872ed2e39926384cf70eb96fe64fe5a6d21e8a57c36d00f15062be299a7717f558743b13920cb957f438e8_cppui381,
                            0x0e683f05d223483f5bc169c7a57256c25e0ee36f44b9e91414a4a4f5b8bce38266f447cc346fcd12a2996237c411db51_cppui381),
                        fq2_value_type(
                            0x0f90ef20a7b4c5c2c118bedf8429d802c9672724339eae4f9d031f78573bfc78596558bf0a872bd3f27c6a70bbb5f3cb_cppui381,
                            0x125f6c17a7fc83f38fe568b40aa7e42e1ff629e7a26811eca4856d6dfa77dc3bde171d7deaf483a43fc7e304f8dea355_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x08748f5f965488602113fc50ca8ab06ca949be2b93e0a9f3bf4e649d9cbb65f4a82748f10672fbd89d17cb4dc0aa5743_cppui381,
                            0x0c01b20eca9eaec6b1f5724d3c0a1d4a9433ca0dc521365a12244439bd7caa391766a9fb87826a1634a8e0c84aab4ca6_cppui381),
                        fq2_value_type(
                            0x0436212511eb8f0360e431d5c986b459379e1e9f7c1b0d366d41ea2d08735c17e76098683d4e5c6c335b83f985893795_cppui381,
                            0x0ac7b1c2859061c8da434968af4cf854dca613cc69a09488b3e21ee0307d1e3f189d4f748fb88a390d031315ea18f54b_cppui381),
                        fq2_value_type(
                            0x08d396a836634af9ceffaa6e80e537d0311fc6a642cbbe1dcc92e2a99a494fb9463183d073c797d87da7ba9376fbd1a1_cppui381,
                            0x191fe239f5a52c76c5c4efe11e206e3ad3236dc233c5d2287ecb32f98bb25407cdff0bf7dbe93924390ce085a8671bc1_cppui381))),
                fq12_value_type(
                    fq6_value_type(
                        fq2_value_type(
                            0x05042fa800bb8f3dfceb80079cda096a8536002c312e208a313522687e8261d03971699821d6a25fa44b8d13e3ee03ec_cppui381,
                            0x00968e82d31d90a794e4676126a9d61a6f20aabec1c144858d618d7eef23d1ac86defb409bd034c78b086bcdd0d9cb4d_cppui381),
                        fq2_value_type(
                            0x0f513a9e86f0775e99974e6b8756f9edfe88535e3d5b5a4fbd22269b914acfd11089447cb34c36b70fcb31ca218e4f00_cppui381,
                            0x1875b65a1ff784750afcae2912309e0dcf3574aa84c41992a5460e167ad6e3db26a5f4c846bd084db0ae2fb558077dd9_cppui381),
                        fq2_value_type(
                            0x185da63fe96c8479b6d8ee4a41f925656c56831a183f1bd089711eccc321b8457b13b787b71f0e3fe97878007bd55d57_cppui381,
                            0x069dcfaae486b11bdb123c41e46a3d641f5b409e8d6dd8eeed5cd35bf08b8bb7864ec81ef89bb052751b9ca109a42d16_cppui381)),
                    fq6_value_type(
                        fq2_value_type(
                            0x18088d899da3cd385300387835a876ae3ed61976586dd4f11bf0d400b57da0bf4eb0e2b92b1c1efb195a5791ccc23ef0_cppui381,
                            0x05b84b60637ed00e55c2bf28b6d5df6dc95081e41bf7abfcf8341b6642245f78076fdcaedd59bf217a1273f022a76c68_cppui381),
                        fq2_value_type(
                            0x1736f5bd56b43f2b728bc9f14284f6eaba42ebea1f9783e346cfbdbfd5af309c9ad03faebfafd0333c7081b16583b450_cppui381,
                            0x0f0894b8caf3ce18c79a42ba2f0bae501512e1e7ea94442f4cc5b264f12f6a6e433eb94b616182d7ec85f8860871fe08_cppui381),
                        fq2_value_type(
                            0x13f46fcb18d43b4edd9a00282666d4041f03d9bd76dbaf5b4cc1717b9d4420b4abb55bb536ff6325a2e1c22a04c15b88_cppui381,
                            0x125251837a3e3df544acb81d9cac435d323f9a3d37e3e7f2473ab37203fc4aa5a8244506add4f4746164c0536aaa854c_cppui381))))),
        std::make_pair(std::make_pair(fq12_value_type(fq6_value_type(fq2_value_type(0x07024c86ba5602ab0e57dcdb4b4501da877d539d4ed4a37dd2745aa9bdb55d0a3cd38347f1df0079dde4e1ef74e9e82d_cppui381,
                                                                                    0x1855fcfb4ad62b22a634e5899594e97501deb42501e6481a3690e4f273b92e57657139c97f789d3912a54a8bde6d9006_cppui381),
                                                                     fq2_value_type(0x0d16ce2260f1fff0d92b6988b2e95cb013a818523b7f1d3b26898ba9ef79e97907d7bfc3b69d8db8ac329393b0ad171a_cppui381,
                                                                                    0x11cf91e2d0999bdeb58a5fececcfb8b514c1373126c185964c5d8cc879036f696522bbcdaae477b8eb88306dcb66c222_cppui381),
                                                                     fq2_value_type(0x15d7b157897b0dd8a5d8947983d5bf42bd417548a1c7810c9c09c4b53990d1c32de45c668dae372ac9f35ecf07993b4b_cppui381,
                                                                                    0x04f0ac9c39b1c302e5882028cc67b5a76ec27dcb2d6d6da17de5715b37da2112c5fbc612a2b6a40a4ae3cd239f2de3ea_cppui381)),
                                                      fq6_value_type(fq2_value_type(0x09beca4a20bfaf28de0b508082d4be151e3ab5c85cf3efbb2b980695361e3b86c41468d7b405ed0f20e47eecd2720983_cppui381,
                                                                                    0x022a2891c36cf2b0ca222a0dba7928cee4523dbc605baf53ab5d111cf095f4c37088190082d0898c73cf82dfe4103811_cppui381),
                                                                     fq2_value_type(0x0b26068b249efddaf8b70903dbd6f816670a596147b0951c4f351516555acb0b720f65b991991043b2ad735d497a0425_cppui381, 0x0fd40b306fab09c4c0def1da79fd2b5b6c2cc7fb517f4e8a721215c4a2d92bdaabe9ea4265db95d621d9407598f9e351_cppui381),
                                                                     fq2_value_type(0x18b8cb7dcaf7d371e6a77c2722792b6829e817c5ec900cebbe081ec7a07c6fa5fd06031dd064995a93d7622b99f7c259_cppui381,
                                                                                    0x15bca171ed3aced3b1ae32ef8153c5dd11e2378791cc0f5fa51907f99c55dde7fd6f507ff4851ba6cb9aa5275cff1a59_cppui381))),
                                      fq12_value_type(fq6_value_type(fq2_value_type(0x02333748cd46d0cc7ec0509c9f68fe93403a60a40643dfc4ab4d98d5c7a16c8287b3f6316839c055b09ba55545c94f27_cppui381,
                                                                                    0x119719edd3b8f58b195bac16996bf2c5fa51226a8ed2251fcb7ac328664dbeb0786fe8a2f570151cd40e73e7939fa2ad_cppui381),
                                                                     fq2_value_type(
                                                                         0x0cb2fbd3de260005c4a913a13d4b41c94684f3ee84c85dc405712663020fb3722714053859d371c599545ad5d9a7ddd8_cppui381,
                                                                         0x114f28852c11052b955444a2826d2a43a0fd82b8813a52f95c62eff10c5671edf9dcf82d8abe8761a7953b3985fbd85c_cppui381),
                                                                     fq2_value_type(
                                                                         0x019863e194fdd97e84bc7c410557a709afcae8fd8b26c8796cdf0b34df6bbf16a65a69a02e2c771d83ac736dfdf5fbcb_cppui381,
                                                                         0x000bca299cf3a818dc9f5a8ec3b58f612abb3a609ffba5ceafca6cacbd4f78e4a212cf098937a2bc4a78fe396351071e_cppui381)),
                                                      fq6_value_type(
                                                          fq2_value_type(0x0ec5930f04cf4e8e0fc40725a12952439bd55786ac78fe098814b7e8821efe802c375342a178f9b590085b6c482b2bd6_cppui381,
                                                                         0x07c47f2380508314a412a9637f8ef1de37a445bbdf9a93b70606be70c752adb9359c488cb0d98699d7e455c9fa514edb_cppui381),
                                                          fq2_value_type(0x0854b125658dd5bf28cc52b1b0c52645c0e180de4f39998136534c71142d24d3c7dac56f534b50fb98b0bae1555bff31_cppui381,
                                                                         0x1519b1727b82f0ccab482a151be1ca2dd744566869c7a7cb4ae0f9a663a60e88441d0c3534f47311330af8afd5bc3e90_cppui381),
                                                          fq2_value_type(0x01ad28d7c45be4f02e5b0f7cc7c520419662339b625b0ec713587c633313e2b412c2d89146a60270365b484d21e27f85_cppui381,
                                                                         0x11806a9c74cc0b5a1f6bc6e143d12468cbb7c853f3fd93f9e55b6121e33f6d191f18394a734c115383b6a941679d2336_cppui381)))),
                       std::make_pair(fq12_value_type(
                                          fq6_value_type(fq2_value_type(0x014b181b2158c0f2ca68b1b4e9873b86fd7b92eb0f4f763c159c4cf3b035eec79b96f35336e0fec34f687b7b6e060113_cppui381, 0x1851e001f259bb85914a2dac6dd45ef416303118875ebb3a9591e7fbb4aa149382e8fe35a0f2ce00e5de6dba1c2655b1_cppui381), fq2_value_type(0x11a167d2b6c687bb3f803077a48803ce99ed74d072c442ede06c8cd121c01782affcfce1e46abff85e39d34230be2e0c_cppui381, 0x0243d0fcce872bcdd60fe16f14be54b914393819901543b8e439934eaa3e619390ed1d6c53597eeceab8d0dc9e8f9879_cppui381), fq2_value_type(0x09ab6d6a7f7a818c7521b34ae94ebc80257f0a55a45d8ed074ed37d4991898f7bd1acb6084bb96ad8c4987a394fbe830_cppui381, 0x0f8d4d57066ddfe290f0607d104a8451b0bbcacba61b8a26cd8529d94c8cf3323278dd843e689ff907edc380f04d7444_cppui381)),
                                          fq6_value_type(
                                              fq2_value_type(0x0f671815379648e914fc13f75f8a28c529b1683ce1ed4d862fb70905b49fd427cb354cd25d941e0b83638a452c5d10ea_cppui381,
                                                             0x194496c918d64e046f43ca0c8c405ffefb377fa71d57077c0548353e7059f61767e82933693ba7683a18c04b60b18528_cppui381),
                                              fq2_value_type(0x16e752db00103bb9540d4e3a27f9a198cc676936712aa498f25a4b0c0e8f9d5ca1999c7b73da4de45fcd9b8b6430cc1a_cppui381,
                                                             0x0ea2e0482a11d07624fb1a7900dd113eed25a6cc943d2a0282f73e6ea6b8c0733772859bfb5fed4cddf70940c7f990eb_cppui381),
                                              fq2_value_type(0x160b5fb68460818eafca5b25758d182d030255fce78a72589377fdd36fec81b29107667c5a30dfc2e3456934dee79370_cppui381,
                                                             0x16137e5b5c153ca9e4d79a8b169ae8342ae597661ba6f48e0e1cb65c0aa359c8b82331acde0b664b3b2d3ba3d1aa27be_cppui381))),
                                      fq12_value_type(
                                          fq6_value_type(
                                              fq2_value_type(0x142d12f21c5fe9a7a09adf2d49d0acbb7ca5b306248bd371437b0899acdb9c60b17cb608197768c2628253966b9df124_cppui381,
                                                             0x01addc2a2195dbfb11ae342651be5f103a8e8304f777766405feef83e5af20d6ec00556bcc0b3c156cb39be11a4002b3_cppui381),
                                              fq2_value_type(
                                                  0x072098acd831acdca2e10e8454e743f7ed660976d521867cf953ed1a48d9d0d51e7ab165084ebb458b1fbd72f03997d0_cppui381,
                                                  0x19b2c06b471fadc502900bcc7698868104e61b2301c06f55b94bf2b795d775b830354206e29491a368c8b384819731a6_cppui381),
                                              fq2_value_type(
                                                  0x041b9548ee21e2042dfcba1ad4f709118b93d3ec63f59d222ba7a88a4e85513b1cdcd82450ca193e74384c1bc8bed15c_cppui381,
                                                  0x0803cafba760215f04328f92d089bd982317d0383158b873fc975f3320bf9c7f9dbe34fa38cdb84deb67e38eed0a0e36_cppui381)),
                                          fq6_value_type(
                                              fq2_value_type(
                                                  0x0c6e7eb98e093c8606221e04b79c88f6cb740ab97174b1a1f82415fc9ad7cadade4bb41adde6e1aa3d5d74b026d90a69_cppui381,
                                                  0x0dd152ce35b3c88c110663260a86a25764f44fb6f824b524df2e60995d7b07a6024b1d40d6578beb147697a060b5717d_cppui381),
                                              fq2_value_type(
                                                  0x025366060878ae527ea6f423947e9d1aa706ded60ba657e22e29e0bbe509812b39b1053b3ab9477d533327b659586258_cppui381,
                                                  0x0e0fd927e4f26b758b6bc2092b8a0f81d58347a6cb2cf4ac88aea4275ae79c9d4411348b94be35734701122226379fcb_cppui381),
                                              fq2_value_type(
                                                  0x0472afc4d6ed38d080d60ce2d0bfa96bf88c101e99aba9e0597d81298a99bfa88e5db8dff60c6dd68807fbd03e235be7_cppui381,
                                                  0x15bf76f0a11dfa35d2e010e631c176776a08cbbbcf26b08ab7d40ca6e04d8a1fb9b62d991614ea90da118993db463abc_cppui381))))),
        std::
            make_pair(std::
                          make_pair(fq12_value_type(
                                        fq6_value_type(fq2_value_type(0x1765ab4c391f7e75c994f3ba27cd1f52b8282fbee1bc361bf83b4aba699ce089789d1700bba237fb38e1d741a65c0e4c_cppui381,
                                                                      0x0da6cd4f3bf4d6bcfabe55c810090e7c1fed3a27136a6820bfe4cb270e05326977998a0c931c82bb1049bd6af3e5c49e_cppui381),
                                                       fq2_value_type(0x0946e44726ea3f7b561ecb5bc4843606afcc7bf7b2e33a9ae6105298bf722403b7c5634fe1c652dae04f404d5c3e11dd_cppui381, 0x15b8fba0861cc717594314eecfc0620d988197eadd59af19cb515ee400d2ecd5f147fbbca0a770e6c630e13b0285a6f4_cppui381),
                                                       fq2_value_type(
                                                           0x18633d791b9748795390333246289615f636dbb3237a1d56ff7fb915773fe9e2d2574c13a126af5cd90a4ff011167c0e_cppui381,
                                                           0x04466903327a93aa62775195cce74fe04f94bb324b4f0be9299b872f9ba1ed2f98a973abfe06c208654fef3296f4fce9_cppui381)),
                                        fq6_value_type(
                                            fq2_value_type(
                                                0x1540066fbc461be90e646e6f6399d2f7c03371d74dd43d2531c39114e11e0bbe4b86f844c5536ce414460dfbc2eb76d0_cppui381,
                                                0x11e9e422b4dc6ba06a1cd24e976ae03bfa616d053582ca633f0214c0ca6af05a7d383a1d509d6cf43f6eb06a97e201fd_cppui381),
                                            fq2_value_type(
                                                0x154f3391f28fd516037a6da6fe3b33257f023d06fdb501951db53a44ccd7306c650cfeb3658cc951fec2c73571a9271b_cppui381,
                                                0x0695d35f6e46c40ca8de1c322a5d21f8ce33eabd85a608a369db39f007292c5d3bf2f340fe67de5b6dc1c980c1c91a63_cppui381),
                                            fq2_value_type(
                                                0x02e7c849c199fb5a675c4eedc7480e431eba542a0c471c3213068aebfa97be71ec61e52a81f1e155eedd6c3acd90eb67_cppui381,
                                                0x00ba921ba55cf5a10b2993145a9c5cb952e919f865f2b07ff07508338c1be221ac51c29d4fdbe1a287256a68d702b2cc_cppui381))),
                                    fq12_value_type(
                                        fq6_value_type(
                                            fq2_value_type(
                                                0x059a65d7f906541fcd4673be639072df8784f2dd35b040aa6bd96feff15d58d321d6258036a4366ced471c86149b5652_cppui381,
                                                0x16872ac23722cdddeb5195fc37246fe97923891918a01b5b03968a57efa7eb21b96347ecafbaf6c8177e366e79a868ba_cppui381),
                                            fq2_value_type(
                                                0x03c04992b14d73caf283ef079c9444feb7bdb5710020c6ac019d6f5794dfb84a4cef52279d607e868383426b8799920f_cppui381,
                                                0x08add72d8e0fca15b272ac9afa602a94712b19c1119b3e22e5ad8ff34695183c13b76a3072614d077c1ee19f0d6e08ad_cppui381),
                                            fq2_value_type(
                                                0x008628667be675f64dbc305f520c37de935fa1a4b309c110d9c0b8e52c9b716c9ceb848d224291d0338b1f712a493b2c_cppui381,
                                                0x170adc98a728b395c890d2b5ed099b20ef8cd86007739c8ffa77fc70f2d5761dc83e2ee89b0b61e15af3583f4c92366d_cppui381)),
                                        fq6_value_type(
                                            fq2_value_type(
                                                0x185df273536c03e5dbeeb2369eb26c2d393f02a3d3ee6f09fab5717e2dae51db2e6cc977ed913a0207a273cdcd903888_cppui381,
                                                0x1761fcc54d4f5847af22af816df687953bd345c329bbaa77bb54830854cde537811ab6adf2e8f824b34d7b0a4020207b_cppui381),
                                            fq2_value_type(
                                                0x141d58115c750b8075dbc36fa11ee7e18e33b743881d485837c8fc646dacff1a90117c8605c491c770f935a043cbdf76_cppui381,
                                                0x0aba5dacb5c48b91c889fa4c7d44a27190dabcb17fa57999b105076a3394056294cd6d2f4630d89c94571e991467f869_cppui381),
                                            fq2_value_type(
                                                0x02adb29e893c00b2a4adac4f0097ed61559a2ed433781fdb1da892c17bf7e3a759f8f55be8c62d09f6ec087e9b0c527e_cppui381,
                                                0x11a08ae7662a9fdbe95c2b4fe958180b8b2e520cd49c4ad4a61c5673c60b657571fc5faafa65b5c57a0f0ca34b742dd0_cppui381)))),
                      std::make_pair(fq12_value_type(
                                         fq6_value_type(fq2_value_type(0x055df495fbdd2cfb95e4886364cab35c39f2f6ee68051e8a75af04b4b7b6bca05fabb58b72031a7d661278effbada5b9_cppui381, 0x011e9e219bbad776d9cf7b71ba5277cdb96a91c6ca1da660c16a1fadc66a5c2b6ef917cffa3f381bbe84a6ed07613319_cppui381), fq2_value_type(0x066c474d42bc3cf8c2383525225633ca04e1c834e1dd6c17626cd54a4b25488769c752f7464a8e942acddfa9fbe199c8_cppui381, 0x0d143a2f40ed551fe6f1495dea8d81a0a185a988d3f84f20a26522663f137981d7960ef1431cc4bc92272b54d361da3d_cppui381), fq2_value_type(0x1158e244ee2d31a82750e2a862dc2897e5e9fc5f3bfa591fdaad46281e52bee48feb202695ceec17793b0fb9dd25164e_cppui381, 0x025c2485998359cbde223524c1619c62035ca1541eebf82b3919e381d79995e35da39f6a8ecda561925a39a4c2ba07bf_cppui381)), fq6_value_type(fq2_value_type(0x0eb4913e820d786e0bbb261e79292062cb817b91b10031ccf7915b0ed971799116ff8d40cdd4578807b75404c9ce581f_cppui381, 0x16ae369f9ea045dd88e5b514189577fea5bbf0221535e86383cb16124692c9ee7454ee1ed1f79b2fcbadd0d0ef04dd6d_cppui381), fq2_value_type(0x0853a2f45d59465598322d9f2e6106abb245dc077db644f20b4f368db07f6a4b55161e63d98f1e3291cc723a87bba803_cppui381, 0x15e42adfe187ebdf6d5a6ce574ffb96503234ddc9bdba8fd047a2b025484d37af85ee239634f217e4f9b449bb524c109_cppui381), fq2_value_type(0x1889b0271c67209a4a0e4243f21f74ab031f03c9d6d8bcdbe649e3a76c8920b6adffaff5ada3870d4de9402e5cb76084_cppui381, 0x11703389221e7e8f9a4e8bde79f4b182d145dd5a6591ddbca888931a17d1c18913ed0fb6edfabdb2ef4677f7236ad50a_cppui381))),
                                     fq12_value_type(fq6_value_type(fq2_value_type(0x1195a6ee7140440abea0622d62939494748606eb7c01579f4fa1958560173bcb73633a09506e47079403fba4b5223edb_cppui381,
                                                                                   0x153e1743c725f821378bc41e04d912db687380ce5f76c43a29ee0aaf8a2f8e715a086dcd03d5cbe7dba8357eda88503d_cppui381),
                                                                    fq2_value_type(0x0913106effaeffecce955a06dd49398c2e09aa81b843779b32b4137ec697540f6396f39dffcb52a1310d2ff80e43c15b_cppui381,
                                                                                   0x13797048a8aa483b1533be4a60fc9453ef8bd27529171431b622e589b7668280a8cda300c0ec2c4af943713d15b20bb4_cppui381),
                                                                    fq2_value_type(0x0d3798c33d6a8f49f389d020cda1e3bb4a18685b56f3e5856b62b6836b0ead3d823dbc1f216255031c61c030b5706b92_cppui381,
                                                                                   0x103a8ba97666b53c25c07888532feaaf3c6093bb25d3a55332ef5546f9507166dd7aa60d826153aaa4aa8616194d83c1_cppui381)),
                                                     fq6_value_type(fq2_value_type(0x1816ea6954386c98bda8236ca5dc16ee746010e92bf98d4d63bea468dc519a121e482c8ea039befb4a372d68cb78a979_cppui381,
                                                                                   0x1133a8de50c397628db1dd3fa00b66071331aac01a6a8ed8b6cf7197ffa08557e31a2a1df5fee1f8704d81eaa095df4b_cppui381),
                                                                    fq2_value_type(
                                                                        0x1970aac58884c46821cdfe774c9a5b34abebc5747dde015f68656fd8eabfbe0084079676acb41ec1bab0a7fe18b97087_cppui381,
                                                                        0x004f38337491be48f6a51ad92348a7b266e0ed66fbe2efbe40b96b07305e291a89ec04c8549d34b14f5dd29c2a832d94_cppui381),
                                                                    fq2_value_type(
                                                                        0x04bd3d054f295242f9f32fc3ad21795542dcd2e92af34e8dbf7550cd45120d9dd9700a744651b091fc286919b79798a2_cppui381,
                                                                        0x0b865cee2e54a6876d88849c5e48b2101e77419f8abac361561a65fb2cf3b25fd43d7344055c17bf11fad4f2518d1b39_cppui381))))),
    };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1788826b397708b027ad4d28d617f2bdcfaa4bdd9e8ed558eb0e2793bbc7ca92e161fedb8d7d4e899928edd018b9c4e1_cppui381,
                        0x0e5ff5ac95f10e80f0d450459608e81cd8790ded433e89b54b148aba9ee51d3b903c0d6e8151fbda77e080ff0e2ded81_cppui381),
                    fq2_value_type(
                        0x15ab6ecce8f643d8040a160b28a88cc354d0f00a0e36f08d8cf9d0be7498d58049d9efd5a6e1500a847e51b953bb5422_cppui381,
                        0x18ace269e554de2b091e1bf93fe6f49943cd8d933a5ff07c44b74a5919b19003096689adfd70d95bb67e76b898e64ded_cppui381),
                    fq2_value_type(
                        0x055d9b8d6422d95ef658133c5c420428757d798ba2a4f3726a966b8f465f1ced397f342835c604b246c1a35f95652ab7_cppui381,
                        0x08d481eb22d5099d849fab89cd08a204ebea62645ea16b00a5b186a85272585e9ddcbd17a97fcfae5723ed9eed3ecb73_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x13f74e51b80987e58a315930ed5c9bc4ec889b658d7fb1346985335c203ab26e45677cd9f0b270aae0f13579f37dbf0e_cppui381,
                        0x154d0f0200afbc37a60263bfaf2113724b5a418ed775d006347fb689f6e1e5bf9994f29525479a8592fe13507bd013a4_cppui381),
                    fq2_value_type(
                        0x0587bcb5d491260467ed5c4b2f61587b4cdcde1f95bd019a44812493a70d43e8973c9f8fe4d3efe5d1357868bbf6a9d3_cppui381,
                        0x0aac99645c6315981ac98aa22fcd9e5b793a98e9ad4a4303e3509b838f105af4b76c29fcd27876413cc8a32125414d3a_cppui381),
                    fq2_value_type(
                        0x0fbafed0658844cd1b17a8256243fd52b59ae0301bc2ac7448ce9995b35326a16d9607ec7c6d6df93a139e3fc9775f0e_cppui381,
                        0x0d25b354fc9056f541dbbb04557c2bd7c798a104b0532d630ca4a51f479bccfcc7145d1a38358dc4f1c715ed93715969_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0ee181afb0aaee4aff5e1f376ea7d439777d256497e6b2f98f4503ed7cd57511425fae9c35b5f79db8e6cb9b38793895_cppui381,
                        0x102537a00e697edaa60b7867d87998739ef9cddfe187457648c0a2be3fd05c92b8ef19329bd7c07c61010965e7bef8a3_cppui381),
                    fq2_value_type(
                        0x15bbf319ef5876460c111365bd6478d7e0c569ebf23a68afc9f877e29760042347e4e4aab02dacc71068b41d8b58910b_cppui381,
                        0x187682bad5baab7ae6bfdfd33ef84a0882cbee0980d5369df1538dd0761ed8dcab020fac9a0a4c5a027ad89f4eea5db7_cppui381),
                    fq2_value_type(
                        0x057142517f230eaa05b21cb517f67b5317ae73ae2944a904f64f888239fe63488fe5c657cbb56f3b5d1f2dc678e49200_cppui381,
                        0x101ad09dcdb181b32a1cd4f24d24dcc01978170243650e64d53b838fd828ef5e8bdbd0a9406323cb14cb29a0b787797f_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x1299f190879a96636bde6755bd4d9f45904273b95637c4188ef3aad491d90561ce2d3d79d0598314f462e46fa0631ab4_cppui381,
                        0x1546ca2af0e225be968677ca9fdfccce7f94f2a235ad79f881da67f8e38ee2b01114c52ed579a69ecde37e7517baee53_cppui381),
                    fq2_value_type(
                        0x10f2b3b749f94880c47b7f1d7025f2309da774aed1ae8a9736867fbb681de22e825e275f242691151018103797399948_cppui381,
                        0x04e5051ccfaff5b87864f3917a92f5ab654d35ed7d2b5834ce01d3854dbb64e627126a0d3ffc56f1a504c41bd8f90d3e_cppui381),
                    fq2_value_type(
                        0x194ceb66c0592dfa69c1dcae1947acd98a2b215c89e66ceb16a20857659e66969e81b1b783e6e55d17d516e331ed22b6_cppui381,
                        0x1063386db2d0ecab4c52fa3a83dcc07afde71e86c78acc6a92c389ca5c0c01b2842e79dfa789ae4e35e5ffa2ae8d07cd_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x16a2a61acf5410a8983fee3e65911fc8ef8bf4280e3ce5174c33be1a5a562a426d3fb20f2082e020eafd309c4996cf92_cppui381,
                        0x0909deb1db74f4786ec60019f5b50a60ae735e62aeb57c2097e0436aad72d13f5d84fef69ae187bd4e8417bc5e079b45_cppui381),
                    fq2_value_type(
                        0x1757ac28a92c04bf2c3d9647b2a06d5eb5d9100f50d5823e8912443c66340483edcf5838c8e17765b07d7195ea2dca32_cppui381,
                        0x082a7c7ca07f53ece7ac269c115aae2f8485d746a9c76b207db11bca692387a9970747ce7be1ecc12f44c1f56f88d13b_cppui381),
                    fq2_value_type(
                        0x1779b373b3a78ad69961e102afbf553ac8081d8aedd1cf702574742073b40623e44d0b29436c25f009fbe58541428993_cppui381,
                        0x029f014ca1e66024f211288e38d2f5eefc1535c43c51da87378189fe2effadc5e389b811be547b0ca7ceeda8ef9d4c78_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x1024e769afa0d5ae54bb42fa474d97f198595a8a7ef36d554131dbbaec0ea8cfa3093a7d52eb2ab0282878a90ec78db0_cppui381,
                        0x021b2e0f6b83ed79f4084a8a3c2b62b60d197ef4e7c7da046b53e759d315f0ae5077e881ad5a3ecb82f09e03e67e8bb0_cppui381),
                    fq2_value_type(
                        0x12056bcd46be6351e6052d5b566a26bd8c9c56fb4bfd17c09e250a70940f0444ddfdf69a189c22a886e5d1acd0269f03_cppui381,
                        0x183ee78969b1b718afd496ec57512a92885858aa424329a03ff278bb1502d0de728bae15d88fd535ae4d6e77868c510d_cppui381),
                    fq2_value_type(
                        0x0586752e90ef08d81e98ae6bfe2379cac34d5ceb58c54e93734ba59379e0b085355a00f371f46e8f8c2ffec44cf127db_cppui381,
                        0x00f211527a6db95d4a43f0634fad06355728bc947311c0fd8fe5876106dda01eadf90d9830653e47e9c4bec57db0dd51_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x04960236d2e304dcdf0f985f3d4cf05b2e97a2aaec262023fe0bd44ac6804c20145c28507953f194d4bafd19f66be7f3_cppui381,
                        0x022c81ba8ca9cd70d8b3e1da607fc00ce738f429760a17b8b2e080e1aecdc42fa150beba7a111891ae4224044129c34a_cppui381),
                    fq2_value_type(
                        0x13503659bca2ff69933dfce8950b044a4cfe36deb9abf21dcdc2c948991d73d8d2df5844586ca787a09f22c242cf870c_cppui381,
                        0x0d3979429426d5fef07934b6051d67b4bc5a0c7bf872f5cff9bfad82d82983ed6c9db23556f8cf572e264206707866d7_cppui381),
                    fq2_value_type(
                        0x029a155db0a5002c85c255e640fdc72db1a2644e068aefd9edd68cab9a5e3774e602cce877ff4ca291bab1cf8563c579_cppui381,
                        0x16f7232f80059cf103b8aa1a4908baa29776200b62f638bbf4c31c8f1dc3a3ef3d7b46f7fc704cc32f6f5a2664a7503d_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x16b54372d94f1571758a6290442b0ce1b56f842d0ac3c7b994c9d863e5b6a9add637ce360d189b8253c096e3141c8f45_cppui381,
                        0x110d7cd8299d438b36752b5e7539cc2b8330c43c09397193bcf643ac76b5f82313dee59cf2e65c1bcba11932323ea251_cppui381),
                    fq2_value_type(
                        0x049209eba43cc8e939832adfbe4c762d3c06a1d48f24a909f161433d4809abe90afb6e0ce5b0638304f05608400969de_cppui381,
                        0x0b9756c54b7d2866da5b9d22a29ca23abfd5bc6946e08dfecd00b0b07f174e4bb08f96913b37d7a7d9f8f60e25c3080e_cppui381),
                    fq2_value_type(
                        0x11e79273751964ab0601d57c7ddd4fdb7c3d32b9cb08ee507ba16b9f00d9f59228dc50c4bd9e10079f3edae149c45218_cppui381,
                        0x098c0ab152f5243075b84c57d0831ab00e6badf052ea517ef07c6cfe8335f938771dbc5f4519f64c805b87369fc836b3_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0578b0ce1c12310c89e78573042b224b55b106826063bce4486c350afebd67f2e5ad11a4d05176cb48258626621ab615_cppui381,
                        0x0dfbe96ed0d2e708dae148e6ddebb0c3b789378af791cf8a6f9a44340e51f0f4ac83dba32db1bfea6e301ba6fbf9d510_cppui381),
                    fq2_value_type(
                        0x13aa0fd7f5b9cea485e7d9d16f7205eec4a533954d4c162a5a67fbd3ce698fced217ff17fc32308a0d5fd4349b581d78_cppui381,
                        0x131d6c897e1cb3acb17c83645ba9ea1fca3fcac9cd45b948b1d7cacca9f31dcadbdac1f6d74ad5bf22754b68b33bb504_cppui381),
                    fq2_value_type(
                        0x0878df44890f4097924d9eda5d1529602e770b75b57cb7560c911d7075f9582d2112034680419197f37efd61efebd8e8_cppui381,
                        0x177e78cb4c7f868dab61eb61a9c8b54daef67d2c8047c33646c0fea9177ee892b5a1a4176a006a131776b468aa5bc45b_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x17e1c7376fcc1d8e890310fbf48d52d0de565de348691120befc7477220908a7ea36d0dd5bbdca517f6cb5912d5c8da4_cppui381,
                        0x0d23f6c5fb259828e09edf873366a390ff4b976616eeb687e656719233bb14850419f238790abbfe173e4ace519cf0db_cppui381),
                    fq2_value_type(
                        0x06bfd2bcd807e8256ddc90d8875cd2b21ebe6a40b2f0291f7a40cd2d4816a200adb790147bbeaeb5da22c8496d12a32b_cppui381,
                        0x0a99ed28de9d13fb6c6b9d2bd17575ba080c97b0902a71a78f5341d12ea46fc08920b724f143e5b9c43c1ceaa136e511_cppui381),
                    fq2_value_type(
                        0x0c30d54ab51c3f63590c9d4b4cdad6e31221675092483a4478ce128448b398640e93a7ec9d3251f844df93a842db2283_cppui381,
                        0x01d4b8b604282d91d98cde7bcfdad4caa7e31d0f203d2a0c776ac775acb698bd4e2bc20993d682b5b3c0f38919afb8f3_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x12320fdcf1a1c2e54dcbe4f0bda294b52931f8a5eed82e6e052927ce75f578719d153b6cb1006dcadd3e22140cc0e6d2_cppui381,
                        0x034ab2124020db9adfcd59020442881ba7856fade5756d30a4c1c289cb6893cfb1d24eb54853dee13d6ed51e528a29f6_cppui381),
                    fq2_value_type(
                        0x17d7210f5dd42c46fbf0e0e9f5543f0ed3dc42fd54acbe28b9ff8ec83861b6e9edae445f7b740f9af0f85a30045afa8d_cppui381,
                        0x113f29ea7afcc1012bbf5ad3c60411231e5e6ab12101ae2e5b0b920b2f0fbdc25555cbe67927844ed3dc58a21523f1bd_cppui381),
                    fq2_value_type(
                        0x053bfd84179beb5028185b23e3b2e0cd1c21047f1ecd79273f1d2f9dff09cd837c7016768ec052c1ce897187db5f4c07_cppui381,
                        0x01262f7bdf84f75f012aa826a120120ba1d094ccac8e6301faa31718af5937ae57215e5566de8e86e193a51e9a2d0e61_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0b11bae91f6b969c364f4365752e15c5309d317d5b6386d59b8da732f23f186b7c7fee3ef0ba2df800f0d96ef8ed917c_cppui381,
                        0x0e94f76116cd2936f91eb7e758fb0ca34127fb135aa60748c4f7a878c964625cc7cccd7f27cd8d72278dd9e1aba48688_cppui381),
                    fq2_value_type(
                        0x0382ac6fb6f360b5f3b76c6c02c4a05fb55213758d8252684cc68b6d50b76866cbe3346e6f8e3b1f956f3413ce7f33b0_cppui381,
                        0x0f3b2651d1142e4794e22d3cad36278839b1bca57a82100e9682a88501ce01bb53e99f26ded23f31fb355061a5899e73_cppui381),
                    fq2_value_type(
                        0x03853cda18ccd9f1a6a27d938c312e7d141b944cd6b38cff562636fcc04009c334f6282ab1341eefe887454e6e65a2c1_cppui381,
                        0x0e9d8bc6e621361814010bfb5baadaa6f6014dffd7c65a4275a0c22378b4c56ab6a0688ef0f3b17bdaa12fd0a98305c3_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x00356ef47a6a688a8832dd47fad2f8b5981a564d3b7dc77b33f13dff52dbb4536b6108510785304da9fbda39bfdc0bb3_cppui381,
                0x110ce13acd56d5f9188faf09684b5e299b848615ad9be48dec0702e42ff794730417d92c7d437ddb1ba82869b5b6fb60_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x11d1f6fa158a0424684bb00c08be8f01c6eb6835a1fbb6ac06606799e517b2752b0b047b70266013b9d932198ced0930_cppui381,
                0x0d6d40a9e4c8aa3f41d50f3204216c78c5959e5d0aaa08fb0276665b50efa7e90749cf7ae48d353c2beb29a7d9703ed1_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x17f33645e50acb5c20888955b496c67bed513e0b844b02628d978b8b37a813e33328f329cd9c0f10eda20cbff4758e1d_cppui381,
                0x106b96a3cfb2fd59f1d171d5d956498c24fbeb6be8ee12e7d6432b8dc3869598e771a56eaf9ab8a0001a1da658df7f09_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x145033766369f79f01c3ae44050c57b90ef20892e9eb73da1efffff9c8257fa82ed55051ea26ef4801268e55f1ae2987_cppui381,
                0x01793eabe34fce514a38b6ed3fdf9dcefc3754caa1efadd577137a1b7182f793374e7040e5cf3d9911f056720c9a0756_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x01bea501f76061a67001ca3c5586aebaafef12130b375d2f12088ef376fe28aacf542d0ce26d01f3cdbc10c5a6b0d6cc_cppui381,
                0x0cb0d723875d30aa8e7c0bd11b30613cc5f40fc0575315171b383ab3508bfb1cf4d764307d32b44c3b74e5ad2bf3f2b8_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x13f158cb09a4dee7c65a345c7f2173e337756c1d286687fa9661c432cae1191927fea54ed47648c38ca1ff52c4d20eed_cppui381,
                0x0d851ce999581e11e4930335dc31241ecf004ac30c1adb4a60424d0d29748c01c4d04be6bea6c26c389c9450139a381e_cppui381,
                fq_value_type::one())),
    };
    G1_value_type gp_final_a = G1_value_type(
        0x0e8fa2b057e92406ee207fb49d5206dc169bca2ed70df83a70c1a14a2813cfc0e3af3505a878479cd76d84c28ccea7cf_cppui381,
        0x15dfc2c8db04ecacf69d7fec04ff641f50064b886bdbe1870ed8fcdb585eb6fe8915bdd29a7fdcf9fcfbaece14d85d33_cppui381,
        fq_value_type::one());
    G2_value_type gp_final_b = G2_value_type(
        fq2_value_type(
            0x00af5b0a0f7004410575e0fa27c27dda035de622ef4bdb0a1132ace3f453be45a68b9c5cfc586caad9901e399a1e9501_cppui381,
            0x0bca883f2a3089607567e2a0adff0a128c4fe32bdb18e9fb10ceccaeb174d67494b36abeab981950b0e864441fe6b9f8_cppui381),
        fq2_value_type(
            0x06889d8d13078eb3f761da2b5cf53736bf8d2e58a4972ca7e58fd50d951689ad6bf1264d9d41c813d1eb9fbf0c7d2389_cppui381,
            0x1399770a311376df72bb55004795c619258767b59ee7fb2a942f8a57806a0bacb0fe1228a6252ec74bb1d59273b5c4c2_cppui381),
        fq2_value_type::one());
    G1_value_type gp_final_c = G1_value_type(
        0x084791edc406a3f22688cbb2b037e1ceb6326b5923f0e0d325166f7aff6a3a49d445bfd9bf7424eaaea21e8aadccb9a2_cppui381,
        0x10b85fa7ea5d2477ea414b7d693df5aeae258f401fe0bc8754c5a06c7182c7b2bba42a4a166a46fb3deb55becc466de6_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x182abf0fec3c7d47f4ce807cb3e1392cf7140591e891b5177a287a9dfbd0260f5dac227621ef6d8a60cc9bcfbdf5fa13_cppui381,
                0x0272aa23725df98efcf4c9e5c3706e91129c5d8ba0a93c528f787db124e90f0d9087a3e610882e03a5cfe7f61dc97dc6_cppui381),
            fq2_value_type(
                0x0c816f6952f4ea048ca681082a9315d2b455874da75f1780f8fdbdf8c135de783b91a633671f92a9c8989c12de1f491e_cppui381,
                0x01bcfeeeb78d21339e7a32406bc15a961d3494cdcba1ad0525a58c1a09908ccff78cfbd33234f23fbe089241fa7a8a9b_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0876f0583fe644557ae2059ee8cdb5f8771e596e98f8daa9ed579371918ef4f52aa4f30bd1f1ff75479c8425f61a320b_cppui381,
                0x0a1b7c06b0c91d35cc69a9d64c5561d5408e73dd040a51762f5853c2cb2873a4c5b994470a54ca45429acef0f92688ba_cppui381),
            fq2_value_type(
                0x04dd9bd93186e54199d3b41a6348d73f516734611390325a478c636659c886c0f88f7ae15ca80b31dc9284b2c1135c8a_cppui381,
                0x00000ff4aa4580802a632b61ce364dfabac4b2e3aac4edff9cb199c2396b36aacd5b2e26ea0f19db2a2e6fd5ff4f13ec_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> gp_final_wkey = std::make_pair(
        G1_value_type(
            0x14006b4350de0de70c5b8b7b35e0103298c7afbab44b4cdc49979f188cdf8c2ac713a8778b7d731b12c41da259819a50_cppui381,
            0x0128fc84e299c6b2965c56e381dc10b3e5b36fc2ed27de8e4bf56aa73f2273b1ff21f8af74f90d64dd21ebe6ef443d07_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x07760bcae08fcaaa51dd8712cbe38ab449198f356399c3ad86b46f69d0373d6c20d2c81054cad4df71c0397375ad8e6b_cppui381,
            0x01dcadbe7a8ea3c463c52f50197a9363fe31a96a8ee4d6e3b06a37270d95ec4ba29ddbc363290da25d25788c29fb4eaa_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(challenges, ch);
    BOOST_CHECK_EQUAL(challenges_inv, ch_inv);
    BOOST_CHECK_EQUAL(g_proof.nproofs, gp_n);
    BOOST_CHECK(g_proof.comms_ab == gp_comms_ab);
    BOOST_CHECK(g_proof.comms_c == gp_comms_c);
    BOOST_CHECK(g_proof.z_ab == gp_z_ab);
    BOOST_CHECK(g_proof.z_c == gp_z_c);
    BOOST_CHECK_EQUAL(g_proof.final_a, gp_final_a);
    BOOST_CHECK_EQUAL(g_proof.final_b, gp_final_b);
    BOOST_CHECK_EQUAL(g_proof.final_c, gp_final_c);
    BOOST_CHECK_EQUAL(g_proof.final_vkey, gp_final_vkey);
    BOOST_CHECK_EQUAL(g_proof.final_wkey, gp_final_wkey);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// prove_tipp_mipp

    // setup_fake_srs
    constexpr scalar_field_value_type alpha =
        0x66d3bcd37b8ce4dbc7efc5bcbb6111f5593c2a173f60a2935bf958efcc099c88_cppui255;
    constexpr scalar_field_value_type beta =
        0x01f39625fe789118b73750642f16a60224a2a86a4d0487a0df75795c3269e3fd_cppui255;
    r1cs_gg_pp_zksnark_srs<curve_type> srs;
    srs.g_alpha_powers = structured_generators_scalar_power<g1_type>(2 * n, alpha);
    srs.g_beta_powers = structured_generators_scalar_power<g1_type>(2 * n, beta);
    srs.h_alpha_powers = structured_generators_scalar_power<g2_type>(2 * n, alpha);
    srs.h_beta_powers = structured_generators_scalar_power<g2_type>(2 * n, beta);
    auto [pk, vk] = srs.specialize(n);

    tipp_mipp_proof<curve_type> tmp =
        prove_tipp_mipp(pk, tr, a.begin(), a.end(), b.begin(), b.end(), c.begin(), c.end(), wkey, r.begin(), r.end());
    G2_value_type tmp_final_vkey_0 = G2_value_type(
        fq2_value_type(
            0x01ae633e5a9d514bb68f5b66ddee78cd8338d3e822e0415e5bc81562f0625ac4c6abd46ddbdff6feec2ccbef9443bb2d_cppui381,
            0x15af49ab8bb885614d5f8a13bab949db6f2a8630ff2b4dd2d9415b206940908b4d2ce98fe0574adb5ed69d71a252b608_cppui381),
        fq2_value_type(
            0x0473b0c84696284dea3086fd79510be839a96847dab5229ea198f5efa594d5668f7f5b02beacab5034164c0585c3c5cd_cppui381,
            0x0a917cdc08a932770f18fcfbfe45a375a80dff31fffebbaa308a7c4dac688927615c2cf7d3342a39499a540c1a96e246_cppui381),
        fq2_value_type::one());
    G2_value_type tmp_final_vkey_1 = G2_value_type(
        fq2_value_type(
            0x09548d215c6b658d4f891613716676a212598b89dbe00105ee6372c46eaa9e1a62f2207fcfe5c5207e5a3c784f4d87e1_cppui381,
            0x10b077547874bfa9336932997f0bd5df7171a929f046059db581c48546334378cb3803e29fba04b72efb4ffadd79e5e1_cppui381),
        fq2_value_type(
            0x1489324494caa6d5db9a9700e9104b904d7d64f966ac3d45be07cc51a4e20129003b3bacd3c8dea021efbd35307daea7_cppui381,
            0x0afc4f38e81fc32dd2d8ca4a7cb34d124f26fc0fa91ac2b32996bd6808cafebe3c17442ca7937c87c235a08e3e04065d_cppui381),
        fq2_value_type::one());
    G1_value_type tmp_final_wkey_0 = G1_value_type(
        0x126d26367b92be54abc4193e795f9ebbff6f2765548938e88ddd873033a4cf45d23e424618d9731e988279aed7f2d1e3_cppui381,
        0x02c95fb68e1802413aae7d9ce21245df5633e8bbfb997636eb0aba5b814a7e14da240a1e918fd08bd2e6d24eed7a6b26_cppui381,
        fq_value_type::one());
    G1_value_type tmp_final_wkey_1 = G1_value_type(
        0x1331116294650b85d5c461fe36d2849dcaf64368e0611368a0a8808c7866f6d4d318898dbb383c4ee769a915993bd1e5_cppui381,
        0x0e2643a986ad17fadfa041f648943ecfa52e452bdb265bc6aa16844ee68f535025b12b5a5e21a45de1f90e116246d814_cppui381,
        fq_value_type::one());

    BOOST_CHECK_EQUAL(tmp_final_vkey_0, tmp.vkey_opening.first);
    BOOST_CHECK_EQUAL(tmp_final_vkey_1, tmp.vkey_opening.second);
    BOOST_CHECK_EQUAL(tmp_final_wkey_0, tmp.wkey_opening.first);
    BOOST_CHECK_EQUAL(tmp_final_wkey_1, tmp.wkey_opening.second);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// aggregate_proofs

    r1cs_gg_ppzksnark_proof<curve_type> proof0 {
        G1_value_type(
            0x13530f80487529a7f80adf52bf9713facde6170e645f90115c02567a9fae89f9c87814ecb557f1dbf34fdf616ea11da4_cppui381,
            0x034fe63c20c60523800edfee5b677f5521afc00c4294b4a8091fa7c2ff8487af03074b5867eb477c493e044dedd337af_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x038620b2afbe168ec751c44f2fef27dbabfa0a77ef93da282e876a0d5295cf00ee9ad42ea675ef435374e4551c6bfb9c_cppui381,
                0x0df3317b77b905ec71d25be269fc13a5e18924efe3bec44d8dce20f61a82b582bc9c9b3cb00352d127512c7961626d36_cppui381),
            fq2_value_type(
                0x0790bc5f62f54e4721d931aee27d93c26758e3d13b036234a8055c175318c51274cd9d79be55b11e9db42c1f3ffa31a0_cppui381,
                0x0eb431b0df5215459c9a129d6e8bfdb354dd44984f05c844b04afff18e942d656f3430b5a5f376036403732bcb0ee85d_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0a2c7090ea4a873ee63836befd899abc05f20928ff5480eb4615d4c7513feb8f82f22a3141a7724c83d01d386a9c6c13_cppui381,
            0x06df9ea9055d7784a4039998d2e890fe7f65b48ff8101ff4b4bd4a446c1c15f58325213ebcfae8caf96f7896426d4218_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof1 {
        G1_value_type(
            0x00e6a6f3ca75feeec83560ee610f5d7a57c92e486a0afc8cd3f2b8dfb445b317ec0c95b48fb19364cbc7d188d982c54b_cppui381,
            0x081b695491ee4f41f69fbcdff9a9cdd02da16a7ea107d7ae62109441e8e1b77c6cd2056a06025dca0c54dccf64eac518_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x089a179c1a5fad95874b28667430f6925f05862070ae8a37a4f6f0319a8c55a09df02200124da0e1e51b30336ee2680b_cppui381,
                0x08a518a8cb77f6af5db38c05635f0040581fc2856a2fcee4565d31669cab3e8e44b0f0cce0f025ba452fbec1b6540453_cppui381),
            fq2_value_type(
                0x13b25c8529a60a1aae50b7db3c792b3f15a8bf18e2d08f5f140cca07c60b45c4f5fc70ba317b62a0c7c06f3520320d53_cppui381,
                0x0e8ddbb275de7ce19d4a30560034b5bfabc80f4b77d2ad7998d16f0c8c3962ff4f12c1cb1a817810451d6234bd6b8746_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x1416d480159b621b06e18fd58ec68fa22e9b4e51878c60cbb3f8713e981138ee1e90032305d7f2cc2d6657b1c353710e_cppui381,
            0x06933ca33b8c7c553c33075f4a2e67ae7a11500479f68b0bb4d7ba05a45b105ab55ceb11b204225abfb0c9cbd0fa973e_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof2 {
        G1_value_type(
            0x0ca547bfabc42f09fa44686c63bb490af48a69622142032ff897fa5937f5753a98dd3da21c72aa506305fd53fe21b4f1_cppui381,
            0x11994c8063bb5e09b9e2d1940aca7a3ebb574ccbc78a0604f0104399a6f7ef32d737b04239ffb1fc0f3a9d552024cba7_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0385bb090211c93f6f401fe6eb3b9e263515409e71225f2f2748613176e8c69f085f60fa7368f9f59e1dea6a626af32b_cppui381,
                0x0539de16f7e1d435d9ff2475ee50d4523efd9b392868d33a9be7f2e2149a29ad46fa89285be341ec944bf441d775a5bd_cppui381),
            fq2_value_type(
                0x13b16d65356526562ef83f5936bd66d33980e904f7d1a24d5b916c746877ba15c37eb98058e8ec4c4e28390c75c83725_cppui381,
                0x0b08a194675c842c6854d103512f778dac00819b56916a3d6124435a0e54812a4a31d8a06da10abb45982aa45a344781_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x143e058ee733cdc1ca6d4b6a96ca0ba521f430742af90017a5a4013037cf97c1c8539d483a86d1436b08bce583fe4efe_cppui381,
            0x0f36e8a80daa5856509cc832ec3e2f63989efebd03d35c1666120840cbb6ab70839b19302c8e30e9388c371e16aa033a_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof3 {
        G1_value_type(
            0x00ee039cbcb7619fe5d623af223605bd709dbe09254fdf31c5da9ac7671dfc3a97bb1832eb705dc3bd9b108d9e2893cc_cppui381,
            0x0cd94728b2f457b1b5faead922e05e8b106da54fde36ef885e76380bf0099c42e3d849cdd784b102cbcd96f3a4c7d87a_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x051672706ad4b43d5f3ba9b0b557cbc75edbd73a9f3a0055a220a664687eeeac48650a2d5f1ca5e597b862b586704356_cppui381,
                0x03e9e20eb749a4453257b3ffea2a275358daec10909e6244d4147e25a92bc5b1148ac74493d5992fb5bea86901337563_cppui381),
            fq2_value_type(
                0x1240d7a95680050f6fbbedfbeaf424ec28377f5287fdcacd5a308d805a2cbbe931f24c18bed02cc99b41e8b2a2b12842_cppui381,
                0x009d875ab92ded1258fb569bde7daa79cecf493acaa09a8a422727cb40d8d7baafaa5dc70a620860f63b9f55c0b6d445_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x19eb502f283b6984de21c1061b468f0570e2b6848b5934e31e7e85924bd360cc4eb736be46d7e14aa5cae36ff7dbfe66_cppui381,
            0x05b07dfb26775922e7b35d11f47af0c4008529569be6d5b5e1ad97d9e03c2bae08d2d9fe5856f27ba30205286055037d_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof4 {
        G1_value_type(
            0x10eb2e95dac6e7186403c59951ef0ff3270702a9aba0be332a59e117ceea9961eb413004905779e3fb9255457835d304_cppui381,
            0x0436cb7592aa022db4b79d953bd972ceb4556b2b4ee877ca354e36c409edbf883d23ee364c11fb377b4f208a460800a8_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0fde87195565d2c046f9b0b61efcf02dae7de56bf1e64cfe8242212535fb1799251ce4c8e3fa4638f5e46a8c78f6b244_cppui381,
                0x032f3f0cd5e3e431a2e7a4fb5fbbeeeeeea1ca6f4af596f105807efa1077d7d90497380cd4050c6d910ef3cfae5f241f_cppui381),
            fq2_value_type(
                0x0ad1c22801d446d44cb7f3eea586e402e3a54203c0dd024a67a74fb7875fc464bd37ce9673d6a572ce979e61350c6233_cppui381,
                0x096847611137e9c0459edca5b30e940079a5084e8402ec84a9d1744d9c98c565cfa30bd0794cdb43edd24c1f3e9a4757_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x130ef743e5c2a1313ff14359419420892632551a65818a94788d3bc3a0b36fdecb32abb0976f61fdd2dec8bc09945a8d_cppui381,
            0x127b5f973e17e2c3911fbd4cacccb90860d867dca43c816e3e873215b7412a3c89ab09c1030964680c751dc839cea92a_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof5 {
        G1_value_type(
            0x0407ea966b72fd73347b64f0612f31aa5d9cc5bd696ff90e828875149d651a3dc085a25ca47ff0578255f39ea40ef033_cppui381,
            0x07a7225782ba9846e3aba16590d89803561ba6406048df61d53110c7b2717de12e01fdc066c42ace26813f55de2842e9_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x19e717983cdabf397ce42f470d8f7f763bd929a1b02c9a9cdbb5fdb3d156e99a100f177e155b1c722c8f2093af8b1c29_cppui381,
                0x075695d6e54dd42ddb9904f6f69b2234c6f0525158ba71f04e5f0d5a4c6f0ebfbea75799a5f9a86bdd0466657d079bfd_cppui381),
            fq2_value_type(
                0x1403744d3a9e2c6a4e2763ad110df33e93cb4c51f7b21445ec3d3befb38ea32ebe46d17f51ad050db9f189860848e49c_cppui381,
                0x179ba3cb4fb78ae762134c64659f82e2d5c1a1d06d5b9100080bee7c59f2f7966411e2320b783feceb87f4174bfb2ad2_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0d9549fba97ff2e5927738ad2390ac0f607a8f2a8ed6004da6f263da02032c833977462e59a62a1293140ad111529d3c_cppui381,
            0x16cfe15b5ccea90328ab9504e5d13cb43c867d7b59089d58a88aa02f4665be23da4675b8494665de4f057fd90ae93c16_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof6 {
        G1_value_type(
            0x14270b293f633aee76188b5d8f496cf81ca6dcbfa462e572dd9c900419b05bb973c41bfc40fe316f43d4282a81bad513_cppui381,
            0x153693e1ef0e85b7d84f54f5f336fabb54f4b2e74710e01df779466189d89d2596330f1598183f459f6297f8e74c8aee_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x021f53f802498a91ebd379d1525f5300f0d21056281d4de2146da347f43a438c06c26901ef8ece63ba32d539ca1ab08b_cppui381,
                0x015eee3fa73b2cf77ba42deba054a345530c4e4517b16dec7ea29311376f581d575bcfb623f6cc512ef484502b8cc4df_cppui381),
            fq2_value_type(
                0x19108a89a62b4e6bda06530e528f6e891c47f9b1459606070019a5a87521b1188cca6fd722efbc3b5dac826c7cc98772_cppui381,
                0x053e6a7bf5f842807bd7fa2d1785eff081ca25276a5be0270bcb8c075c2ba747b2ec8290d68178a3ebd13385d0540e9c_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x07cea16b159a1c1c0818c9486dc643190928c2fc960d4c2ed4effcf95f5e65983c0ed0c16f9277df23702f673073c8d5_cppui381,
            0x0bd626a288cbfea5ef86efd563870a349c1f973a0e0145d188e4ef1889a3aace1533e41d422301c86037559853c7cc81_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof7 {
        G1_value_type(
            0x0d0957fb362f95b80b1dbb15ce408a0e4ed696ec1eaa5050a2543c3d5f291ed34b33da66cc81651b35f03ffbbe80370d_cppui381,
            0x14cdf79ae0e28b523f3e27708842db58d2f1e2894b38f7cd497ecbbdc71c308924aaaa6a010eb16eb540f399c0cb58e9_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0a89706df62508ea10e56f9928550358e46b4337ce55c6027b30cbbdc45f5045260c4a580b7c77e156cf3e74644fb136_cppui381,
                0x12eb2f183de720450d8adc458316f1d730b686e0fc9e228b2190228b56bbaaf11709d4618bc17cdb6e592b686dbb4341_cppui381),
            fq2_value_type(
                0x07082157feb2f6a89be56189949480a6efd2fcd25daedb009c80716643d7d3dc618a870bb88b38fa95adae451fa30b33_cppui381,
                0x06fc50dc536fee7db97086787ee0bb05569fb5f8f8af5c3f35402f91ce14455bef3c195807496da53124db511812e398_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x1063836b18674249053f14ff942ed81ce0c33ffea290095b29171aacd9d476d5b8b3e6c181effdbbb5a5579cf52547dd_cppui381,
            0x1054390bf07ccbd9250b25e1ec8bf6ecd919917b4a19b94985f345cf72ca269279300bceb1fc04f2ebdeadbc5410dff9_cppui381,
            fq_value_type::one())};
    std::array<r1cs_gg_ppzksnark_proof<curve_type>, n> proofs_vec {
        {proof0, proof1, proof2, proof3, proof4, proof5, proof6, proof7}};
    std::array<std::uint8_t, 3> tr_inc {1, 2, 3};
    r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof =
        aggregate_proofs<curve_type>(pk, tr_inc.begin(), tr_inc.end(), proofs_vec.begin(), proofs_vec.end());

    fq12_value_type ip_ab(
        fq6_value_type(
            fq2_value_type(
                0x010ab5c1270076fa49f42030fbaca54cd5dee58eedbdb95e8c5a066884a275fd714898735db5caa77083b02136486852_cppui381,
                0x0e19a8176df6c2f8a07bcaf481e0800c083211cf0dfc7cf0ba403f6576dc4eedf43e25b7ec9f21c79df8afa4cd9cf19e_cppui381),
            fq2_value_type(
                0x110d174323289306ace22fa08a3d279981d05ab7cebc0a2684b2cb6e702b0c08da1612f492a3d2cfbc471426f6cad81c_cppui381,
                0x1731f463630104f8d7532988388fec5ff8176daac9cf76ebe6f861dbe91669e6c9f312b65bfee4190c16b3765c526c4b_cppui381),
            fq2_value_type(
                0x162048b72d7e7e4a250a8203bd6960c9becbd0d9cebd254b454c6def811b4406267b2d653c93b634021a22ee89281ba4_cppui381,
                0x13470bf40ed633988b5f544fb015f61a6466db5711633974b6c64e23038ddb5648f5a4482de7bb0b26828d3670ad5c38_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x1878869f594c600ea92e35533e59069dd523d614d588e1c336ffc51363d20f34035a78a6dd5f4ea5c0f6dc82a05cfa32_cppui381,
                0x03947a3bdfc5607034d2a1ab34859c776290064930309ac4818b601afc87fc14896ac7c5fe45e295e0c379311d5da823_cppui381),
            fq2_value_type(
                0x0f3bef7d1c6e20d5693b8c71c6c0ae3843b3561c3e38dce9885c799e7431fc5d27f35bcddbe8fc74d00bb1ff480daad1_cppui381,
                0x0b81eff92fb3721a1ec3d46ab7de2395b99b4ec1923690c67b51e92ea4abe3b71d4ef06622dc9c3d4f726fa5f4c19226_cppui381),
            fq2_value_type(
                0x1648358021be1738e812c0e6fc1cb1fdc8be87612f6faec26b980c39d53e6f5002e272b35fdaec4aa0ce8589bad35473_cppui381,
                0x16cd2344fa4a5883b70bd971ee22d54bf1d025e3cfa36b30e21022c1a03a1baf81f48bd21710c94308a6e7a01d5a4db9_cppui381)));
    G1_value_type agg_c(
        0x18d53fa2edc6058e92f321842b3f32de4e050c4b60a4aa6439c860d1c13a4a524f14c67b098c533557722a66550fa3bd_cppui381,
        0x0730a6a8fe4131d46064a99bb108cd8879aa658e9dfe617d63d69195e915599875c477f5d72019a74faa4f2347284f7b_cppui381,
        fq_value_type::one());
    fq12_value_type com_ab_0(
        fq6_value_type(
            fq2_value_type(
                0x0f4fdfae6bcbce33b5e02916c83524282ae532b5c7a8b927163ae5a46472fe3c21cf8a6822b1a52ab368d1eb09f65215_cppui381,
                0x0593452fa0c263e38132bded35be873466518e7d7f31dedb791adccb59e2257b501d8159e486e06507c136d5b880b8af_cppui381),
            fq2_value_type(
                0x0f2a79394916966f58f3a5c503407277641849d75400a5b3efcdcce5a41d5cd294e839f100a3c55d2a1a95ce1e18426c_cppui381,
                0x1389ba34160b7da61635f8dbef7669e6222cbd35d1a66bcc3b03fa90723a535a80dbe4a11ef5ecce31336308257534f0_cppui381),
            fq2_value_type(
                0x0aaf03d53046ab7d1fce5e1b56c8effe4f866df0895c196a0fdf35759853d1ac5d2c9b165142935645aed4b83792ce9f_cppui381,
                0x00095bbb7ceb73c8da601c4e3d810652ce209b09df4c120dfa1eb70e8fdab5c8f030b6f8bdc6cbae7afd9287e0acfed7_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x16ee8d1e1a637908cda08cd31cf48a73304320eaca897b31a42d7809fb546c6376d5bf25c29b87a80b4cb38320bcad63_cppui381,
                0x13837d4a3f234bd8a1b01bf500c841b0d413cda3e7ff06bb9306891706f86a9aa430b3306b5295db70fe65ce4efe063c_cppui381),
            fq2_value_type(
                0x01519ed738facc5f415e1972cbd07c0758c6dcda6474826201b723c9b4c1ab3c4a24fbf7d5377c60ed42046de2c28efa_cppui381,
                0x0ac95ff7740c14ac5bd4d6ea6a6fcb70305d8fe02a64af314b444eea715ef171f1126a0af03afa8c6d7655a3e4370537_cppui381),
            fq2_value_type(
                0x1674e87165510b048dc6ef111d1dfea850ff6d213502acb18f5f08347c9b01dba1c8017f1dc969ba32efb3c19b0f97b1_cppui381,
                0x11c15da5181c1652b2000f3d219bc043acabf62cbf78e8948cd2eeac615333c9ae82021dbb3fa1dbee11051e628c8bd7_cppui381)));
    fq12_value_type com_ab_1(
        fq6_value_type(
            fq2_value_type(
                0x0460ac600ccf2a3ffea00bf37e01608f19a0a2ef87e7d75083f5f972737c6d58b964ab29222a6fd7fd36d33844e3e6b9_cppui381,
                0x029bb833019e727a8b5b6a3008df173cb0e3d27ee4a1e2a0b22d8da09f81d7e147d911c60815d2a08d2b5eddb527b612_cppui381),
            fq2_value_type(
                0x019d6f62de0f07389bb862bf2bbcf8d40582ccc08c4a886798d41fa7596ec76191f4356287ce220b13f40b7fb8cf0516_cppui381,
                0x024b533812cf6a9bdf926dfd24d21423ef9d6d18c2af70171f256a1352462074f55d9bfc5ce053fdb0179ea67d8df890_cppui381),
            fq2_value_type(
                0x11eb89caa4a7d35bfc41c7560d3c63dd900fe4359bf3d0c1cf58f7848754d28a537cecff0fc9ef372ba63a600b17b583_cppui381,
                0x121cd1b20ac7555db6236defa223a3c8765ddb6b5a18034dd307e8b6a0ed17ad0f53d52d424bb7d21ddd63be4ad94e6d_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x051300588df783e1e125ab70e6292a2362d0fd4f658f7c695d2ed0f4d1317c328d635e6fbe8bd0e651aacbd747f47def_cppui381,
                0x14f55ade4cec70dae475ef212ded9d8d10d6cc31640d88bf252b917ef5d1786e6ac60b6daeba268390b3ed7e6e95e781_cppui381),
            fq2_value_type(
                0x07692887ef60da6c3411bec6f4c090a41b4a75e62945e892700c31945ff643c59f7709b1efb91c16a63ab1722433407b_cppui381,
                0x14027d6a023f4f3d4762f5259a3bc08c354e66b27cffce03d230f70800937ea9e662bed09ba48de91cdf6db0c949ce74_cppui381),
            fq2_value_type(
                0x165a12ab1e9cdca4196b0848e9bd1e8447b54c2de99f691af350309946a5245c62d72dfbfc7e47b3b51b7a4f31d402f1_cppui381,
                0x09cf8217dd740f54106b93f8ba32023f3258b1b80dcef4714d7f938cc495c293cb8d394c16d138ae5e909d2eb259e664_cppui381)));
    fq12_value_type com_c_0(
        fq6_value_type(
            fq2_value_type(
                0x040fad3f4a622de66361515f3b2395cbdcae7d931d5d1a80a994f15fe5a725b65931fca28b536e9d56c4b423147b48d5_cppui381,
                0x1571f317060a0d196f4358e0bca709ff641e7154a3b6f3616b4feb233db7eaa616bb5b03ef383727d770732b688ddb74_cppui381),
            fq2_value_type(
                0x11883ec050c8bac3c2114314d3b2067c7bafd1c0c262318244a0fd39c118b4abe3745c1b17ac0f0b303e2ae39654cc19_cppui381,
                0x0a356ce38167c1ae2110b60303ada103bcecf0704e6100d77f54b07e2af8c009af8c67bf7c71b4a54c4b6671a11178e7_cppui381),
            fq2_value_type(
                0x12efeaeb08c0dfd2c50fab7c9002f8d2118be6f9866ead0d5a33d25322269a95b89f02e9bac4a10901154ec0d9f6bfcb_cppui381,
                0x06932f220be2791dbbdf1cfd2e854599b63cc8f151e7efd5515af652a3ef5349d4e955544deee00850f6eb7708f5ef30_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x04573403d1c7a652788eaedb0444abb3c223e151062fe992f2c5e426b871aa48c1623e2bd1989146d5589934ed96ce9c_cppui381,
                0x1881d218074fef0cb26d0b49841131d6c6697d119c92c43477d72cc39664120e739e0bc34ba037bd1fadc5469607418b_cppui381),
            fq2_value_type(
                0x004587f75ea20b84628a5504005098c50f9f6343b961ee558f2701b30b2cb65ab304204d0f6188fdeb30414d8681a286_cppui381,
                0x1424bbb47299e63b9ee3e08a779a185e0362e23c2e1639d9e09560a947a03f91726f1ed60bc85f0398bf3f399516d054_cppui381),
            fq2_value_type(
                0x080709e88a7aa70bf43c822074b6766578848fbf710b1c76d120d21388088a8f501a77d8f6231479bbe49725d860b358_cppui381,
                0x10f3c9975758e39fde72f2d02c24850c90da685c0b9174a8c67e10b460e0a61fee2c16f9f6f80c7f52bca3b26abe1fce_cppui381)));
    fq12_value_type com_c_1(
        fq6_value_type(
            fq2_value_type(
                0x05a2fbcfa26f5c6d93fea74a7dff2766e47fd2e318fb62d878571aabe12ff73d5cf68fe179a4c3aee9e117df2d2ea304_cppui381,
                0x0fd650e2e93b1ea227430f970e90790ec5481b11ec3e6f04f2048a6546ca9a15fbc0be7e2bd7af2fbf44c7c1e8c5022d_cppui381),
            fq2_value_type(
                0x13bc175bf3d1cf3334b5c901bb8329e361c6f5a6b19590bbe18dd007354e8df939d125ad83cdd295c5ba9ec22b6727ac_cppui381,
                0x0ec7c7571f2659e1a093833a04762888b47390ceffe4d308536e26e0c581e12328aacdf0f85c3f76ff30f3388b574575_cppui381),
            fq2_value_type(
                0x0a544ab73ccb09473aac1e2dad4ca256f57261469e46515d9d48d6ac568cc9166f56f52e04fb94710aee46b9fad1f90d_cppui381,
                0x0415484d7589a1b2484aaa8631a680c959848f933a070674256ac0b6e2d0e3a7b8b1690443a348be2cad5620808ddb32_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x080297c08e85bbe018c19380d2b791d1e1ed1c3d61fbe3726fd3ba12711138d08217fa3e2f79754d8cb8bdb8542449ff_cppui381,
                0x0f00d2246c101f87d11abc5a0d5287c79fd83c49b8a2bc0a5c415e38ee4e490b2fcbe9c19ae6253c864679a41d49680b_cppui381),
            fq2_value_type(
                0x07366d6576763e79869a00939b6485191eed11a26045b87d8a5245c8edd96d973dd711217f06f0fafd8e592d2b9a36d2_cppui381,
                0x1931c180402186cb6bc5ead827de4222386cdb294d18499b329c1e452de6f7fda29d1cb274c63fe0c9b05b08631527b3_cppui381),
            fq2_value_type(
                0x18bbc3e489b5f9f314af2c5112a6f083fce2fdaa9044f6e8702d7d367710c66b0f4c3ddb454990fa93dcb5043b439da5_cppui381,
                0x012bd76b9bf64d0afc7f1fcea86d9eda8c8c394c0bf328104e6fc2b7d7e0576fe3e822eb9372055e99500bb49140c8b9_cppui381)));
    BOOST_CHECK_EQUAL(ip_ab, agg_proof.ip_ab);
    BOOST_CHECK_EQUAL(agg_c, agg_proof.agg_c);
    BOOST_CHECK_EQUAL(com_ab_0, agg_proof.com_ab.first);
    BOOST_CHECK_EQUAL(com_ab_1, agg_proof.com_ab.second);
    BOOST_CHECK_EQUAL(com_c_0, agg_proof.com_c.first);
    BOOST_CHECK_EQUAL(com_c_1, agg_proof.com_c.second);
    // TODO: complete
    // TODO: shrink
}

BOOST_AUTO_TEST_CASE(bls381_verification) {
    fq12_value_type pvk_alpha_g1_beta_g2(
        fq6_value_type(
            fq2_value_type(
                0x0aa81811bb28216360cc6f57f12fe1dfd293607693e2b8fdbdc378773f03f5412ce641e0c656f12b28d1d7d333ad78f0_cppui381,
                0x140d55024df5c9a7c6ba02f8f510c891f691ae4b1951ece8a7c2e06f0aaef38f45b96caf0cd85cac418ec613ffe5e431_cppui381),
            fq2_value_type(
                0x0144c6f0a2f5e54416dc631b9e3d378ba31c28ddcefe8f4e6732a45c029452681641375841987f17f912a80ca9dc86d5_cppui381,
                0x002f20f85d577bbde71ff8650b982d367e88a66c3a6387ddaeeacc54eb3f36c18687a7103c88dec1c8b8c1182887c331_cppui381),
            fq2_value_type(
                0x090fed6e61fb38670e310dd6bb62fc9f83de455650053c69aac46887d60afbc590324ac83fc6fd2719583821249cee46_cppui381,
                0x0106304bcffad07a17050a237e89dc49fce562ca7c46f35ef9e617ea2eb475da8f401021f6eb03ce672d9f7cbbf53cf4_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0232cc692a114f4def3fb38c266fc52d72d8c3bf02ae7734970028e877f8764f44e1a3a9d96417ff9cc45e48a05bf5c6_cppui381,
                0x19833af420b359496b156c09f8f28a9dee7c446159b06df32392bae5f491cfb05ffb12d5f2806db465e8e70bda25be1f_cppui381),
            fq2_value_type(
                0x05686dfea41ece87de5f348b8d9dd860ddfb2d9514ec470603eb0d567bb5e3f7ae628de1fb5279103f11f8f69bdf14ec_cppui381,
                0x17464bcf3d0de930181d7988d8a29f3be32a8b99d2dbee305575818df9e90010a62cf9ce4ae574bdf842131e24f015d1_cppui381),
            fq2_value_type(
                0x000d956e4b7a1d122247edf85734dac2df30e89bc2d09cb5278e9c2ca1b814c64a9787d25cca42ab6908248773c6d8f8_cppui381,
                0x0ea9ae7c562f168ac2ad57fb8c1cebfc2ab66d4ceae0701387bddbdc19e3dea782ef01f2e47029d31003418a3f58cff2_cppui381)));
    G2_value_type pvk_gamma_g2(
        fq2_value_type(
            0x021cd836d798f907c3b73824e1b84d0427a6a0bbc695049f58a3b5dcca75430280c8171ab1c16bf4eb2deda356bcfb51_cppui381,
            0x039e4a0dcd774d78540a461ca6b07d91fbe395ddb02e7934106d0a822c985809d960c2a8269b5c9a2a49647ebbce867b_cppui381),
        fq2_value_type(
            0x0d6e0aeb7429a1079ac21c9252307fa1271c21c14c4e7ac9dd4192fcd3284f60fde0efdb570111f51669187416c88c98_cppui381,
            0x18e5ec06b14be70900ba8b1c5da1bb5a309ee96e746d6aa8cad096a8a0de7fd8c2f95a5943d84b14c2078930c5c46802_cppui381),
        fq2_value_type::one());
    G2_value_type pvk_delta_g2(
        fq2_value_type(
            0x00ac6394f709a2ef3a8df034d1222d60e80c63e64668e8e3d6761ac02e91fc5481bbc56d995c56384b750a04c5937dd0_cppui381,
            0x00beffad20e73086e140adca13b6414d8f31f6a30c11f273b7d9948c9530d892255cdfafb1b8d0e7c0402942e4f33d9c_cppui381),
        fq2_value_type(
            0x08f72550571ef685122ea9c90d5775be6ee78bc40c26710e32f5e90fcfb6aba1f7b89f9fd1970f95b12e2be0503aaf4f_cppui381,
            0x05759f1829923f4ac5538b7daac7203c093853827bf3e65bc05a015a37776844e8759f1bc8a722977b0cb23ef602c0ac_cppui381),
        fq2_value_type::one());
    std::vector<G1_value_type> pvk_ic = {
        G1_value_type(
            0x02a08a97776a482e72670d49f55d48b6978b1572e77024c3c6b55f8fb65e50d2c735bed502dd8371d6a4fc1792f1ce11_cppui381,
            0x03793e5a45aa9ce3c173f8d17923bdf9f483e3b975dab075630b34710b9bce2f52989b532075710dcdf507d08e148ecb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x04043f1d9436bab64ce43f167931ab7e4e0ccdd688cfc2793e1f63f3d84e024b1516c9ca82296ad8011219cf43c55408_cppui381,
            0x107506c05d8f79a88c33449a6d1e37037762f05a5d7eefe3e23856f96d62a9be60e3c58ed2ab2f86aa3ff2ddda13e9b8_cppui381,
            fq_value_type::one()),
    };


}

BOOST_AUTO_TEST_SUITE_END()
