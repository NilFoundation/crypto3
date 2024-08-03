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

#define BOOST_TEST_MODULE algebra_curves_static_test

#include <iostream>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
// #include <nil/crypto3/algebra/curves/brainpool_r1.hpp>
// #include <nil/crypto3/algebra/curves/frp_v1.hpp>
// #include <nil/crypto3/algebra/curves/gost_A.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
// #include <nil/crypto3/algebra/curves/p192.hpp>
// #include <nil/crypto3/algebra/curves/p224.hpp>
// #include <nil/crypto3/algebra/curves/p256.hpp>
// #include <nil/crypto3/algebra/curves/p384.hpp>
// #include <nil/crypto3/algebra/curves/p521.hpp>
// #include <nil/crypto3/algebra/curves/secp.hpp>
// #include <nil/crypto3/algebra/curves/sm2p_v1.hpp>
// #include <nil/crypto3/algebra/curves/x962_p.hpp>

using namespace nil::crypto3::algebra;


namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };

        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_AUTO_TEST_SUITE(curves_manual_static_tests)

BOOST_AUTO_TEST_CASE(curve_operation_test_bls12_381_g1) {
    using curve_type = curves::bls12<381>;
    using g_value_type = typename curve_type::g1_type<>::value_type;
    using g_value_type_affine = typename curve_type::g1_type<curves::coordinates::affine>::value_type;
    using g_value_type_projective = typename curve_type::g1_type<curves::coordinates::projective>::value_type;

    constexpr g_value_type p1(
        0x19a8ce51e3507d9ed66343fc7abda65f24a02a5054c262ba82dd067f91de595469ba0029571b22007d3712a51a14b66b_cppui_modular381,
        0x151c956a92fe067a60533e2f9f4d90c75a460f9ca0a6d3beb2b0388fe2be7f1f21de58af7fd2c85ef13326856408a3a4_cppui_modular381,
        0x814f8119ab9939282414f63efe8421ea0893343f697dba821cc21abb4c0c72573c542becd25d84d3f97d76951cb44bd_cppui_modular381);

    constexpr g_value_type p2(
        0xe5944419aae6b311708fdee3e7a3169ef47f7a509ec5e6781a918eb42294a0c3a3916df0f5c3bf75b1553ee7c66198a_cppui_modular381,
        0x80f8b87d65fa717f44c74f944e6f8b9c5493a87bfa0b48395c6326ad2c83e848280a7b7a81cfc3e44be18c2b721cf31_cppui_modular381,
        0x12dde0758a406a2d79166ade03f68799b359910c31d65ccb63090720eb6191393661cf26c3e83c922a804305027c2803_cppui_modular381);

    constexpr g_value_type p_add(
        0x13034f3fbe9a557cc7daf9aaffbc1a4b3d1a4c88c11ba5fd4502aed63ed08f3f52e1bce1ba9a5ea70d862436cd8c0a53_cppui_modular381,
        0x2c731465ff3bd544bd350c9b6bb5fafca2cbfe31c0a3221566d1fc5547d463914b64e26b4107a78c0179a004c7642af_cppui_modular381,
        0x214b8ebcf8c5293040a2c85d41d27593829f116fb11224cb6b530a288bc66e3d4007d5087f71aa1c209f9d98b87111f_cppui_modular381);

    constexpr g_value_type p_sub(
        0x8d3551b80950015b4dbaac4c60e7c48f1470c13ca93b203f1e3d38e874a4c19356b237b823ee551865afa5f7eefd487_cppui_modular381,
        0xfa74f3643c4fef7f88fb5d844652185d8343f5c2f2a4394c626d8f3c773bd9d60158f30158f1feefa7b6c12e07cf0ef_cppui_modular381,
        0x214b8ebcf8c5293040a2c85d41d27593829f116fb11224cb6b530a288bc66e3d4007d5087f71aa1c209f9d98b87111f_cppui_modular381);

    constexpr g_value_type p_mul_C(
        0x111152cbd1f7ff876f9f13ceacf6a535831ff5fbf59fe5f54ce37efef87b70ba89bc47d8d63c85565e29c4e1310cc8e9_cppui_modular381,
        0x16e86e2375254ce972334364277bc8ada71598631902013b23356752e653f6b51eeebf72cb72b446e8f32208ef27c58_cppui_modular381,
        0xe2b294ae8d8181dc4fd9c6edfe3d79215232abbacd879e339e9fb7ffc7d8158f292c1c408731d227507181e16708cbc_cppui_modular381);
    constexpr auto C1 = 0x2b4bd538_cppui_modular381;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        0x163c6586913d88ba0ca1f082e90f5dc6b97c9b8fc28e9f9f6140c357a8b97c20088da93e51089a3d870c9ac4cd7419ec_cppui_modular381,
        0x1987e74481a1bfa0ba3f38753c44af0cf77d64753812a22ed2c83f64990a5735ccb24aebc72b8ab559cab1a76e1fd20b_cppui_modular381,
        0xe65506b39c7874b40449480e82a0f94e09702038694504b36b90750c36b606c8691311677d524faa9d6d37ccd401880_cppui_modular381);
    constexpr auto C2 = 0x33345b17_cppui_modular381;

    constexpr g_value_type_affine p_to_affine(
        0x97c062b9a9bee0bc02f762c7b7057a0cfa52f336f9bce0b130aaa2402bc7c820cc4f30f29ed69d87342c3137659af29_cppui_modular381,
        0x10eabcbf296774122daf3b60e289f0885485b66c4111d1a229bea7566aea5c9f87d1cbc8ae752e13288ec885d3f97eb6_cppui_modular381);

    constexpr g_value_type_projective p_to_projective(
        0xf2d335bf6370059219a693b1b50dfe9f966c371f052b36f70e426bf84750dcd4bb3da3beeef4e013c4532f4f78e06c1_cppui_modular381,
        0x54deeaa0db80987f8d81cfb4c716ae590c3b7641656f3fef45859a6446144c6eb191bbeb88929cbd90b2b9995574c90_cppui_modular381,
        0x1_cppui_modular381);

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
    static_assert(p2.to_projective() == p_to_projective, "to projective error");
}

BOOST_AUTO_TEST_CASE(curve_operation_test_bls12_381_g2) {
    using curve_type = typename curves::bls12<381>;
    using g_value_type = typename curve_type::g2_type<>::value_type;
    using g_value_type_affine = typename curve_type::g2_type<curves::coordinates::affine>::value_type;
    using g_value_type_projective = typename curve_type::g2_type<curves::coordinates::projective>::value_type;

    constexpr g_value_type p1(
        {{
            0x12e7556630d7b731637d261c08fb26992098207486c56b152e902f7a287e4d7998c18fb3c21d3bc56b960f66e6b13d54_cppui_modular381,
            0x17eb1b09dfeadb08f3335511101067b74b03680f58b8d13797c3b0bf8359dd289fb18fc987ff0017520a98114028d89e_cppui_modular381,
        }},
        {{
            0x18c01544aed3e8ff438c9aaebb5b905001cb03d5982733c85b71e036afead169b34d2c72d2417df44dca61d3dbbc9a9e_cppui_modular381,
            0x193ea114716be66883ceca4d5a162c308f09028fa0fce3dbcad49f7355a4e3a813013f6ea671dcb7f29464d8fcddeb8_cppui_modular381,
        }},
        {{
            0x48a155f876c814ebcf3efd02a99e9c0ddcdf2caba2c63929396fb02c8339817dcb2cdaf4dd0e3a353dbaafd84ee76c_cppui_modular381,
            0x3caf52cc8d881f00f7dd35510d9cc55cbf55bb7eddac1ca29799cb23bad7b76983e0820298d4c778ae46a5f546ad81a_cppui_modular381,
        }});

    constexpr g_value_type p2(
        {{
            0xeb2a45074d3e817643c8511c2965d5a2fe84dfed298b2254fc6ea54630120ddcc03538e587ef15cad6809dcb29b13f6_cppui_modular381,
            0x1499cb9c615d17534459e5177f38e0d94e36afeed3c0f8584dfa8e41151823fe341c197b1c619e6fc2e1032e7f644067_cppui_modular381,
        }},
        {{
            0x113504af0d2a73c699c09f9beb32286b701c35cdda882d3386022f5a51b5f977ba32a7c3b94bf3a06bd29f913b39efa1_cppui_modular381,
            0x195488cb4697a6c61b4884e4cfa7e42c865e62e781d7cc23d3c7149ba40566933308e4286f809b87eca83eb644e46073_cppui_modular381,
        }},
        {{
            0xfa6067c056fb379d03f389de881dc14502b372fe9693c4f03b1dfbcf33fe9c17426a2c2060be6ad3c5bb8cc1b368c93_cppui_modular381,
            0x843fcebd62ecaff9b157729414b13f87663f5ce79c9b74fca97cf5fac8b08683c04223aba8ac07b253e320275767d91_cppui_modular381,
        }});

    constexpr g_value_type p_add(
        {{
            0x1532ee0d7b280f5a8f7acbd758d9c0ed87f4e88ad51c6365c14ba7f570f68935102025f2c211856a3b62b9118fcfe2fd_cppui_modular381,
            0xf6c5277a9ca80792503c833dea93b54da27da7973ec32e71398782ab2f6239ea1ee1d61443211002a80bb4b1223d76c_cppui_modular381,
        }},
        {{
            0x33782d06d4d3d0ef1a963065527a76fc9105933cc3bd393affb6f532be9fef9bc558e6dfba00d327a26ed081b016887_cppui_modular381,
            0x1086ce74c1086ce1b04ef9a556b8d00ef659b8eae55d664f9e18e877552577a8dc83f54dc28e01a30525180a8f9e775a_cppui_modular381,
        }},
        {{
            0x4d34706912ff38211a5600e92b5d4658a01667ba0fb1720b2a3408e4db7370d622f7c128905e7ac5c57c1494af100c6_cppui_modular381,
            0x174d075076274082e4bc19016d6ed20d6c227a638713bb0f5adcab833853aa01e5227a3f768b96e7f05e38bf094627bc_cppui_modular381,
        }});

    constexpr g_value_type p_sub(
        {{
            0xc79e43a21a88a71344251504208ddf45447bfc1010d4b3320978f47982b2d29021619f280409d202d019e470461555c_cppui_modular381,
            0x182de0d3384dac598c24d2a39159ef0e3d2b5576f52839d8d713a222cad156a12ea69e1c0b2ab919ebed0cf7f3fd2499_cppui_modular381,
        }},
        {{
            0xaf0123a190cb639abbbcc0e882e79fb1716dc84eccd53f69342b841b9ea8cdbf2381d11ff853fa7fa5643325f2a21c4_cppui_modular381,
            0xd9eb9c10f3b75bffacab71fc974cce60d4fe658dbaf0d7ce02180bc634ecbe1f7c4ba21b763b06dbcad61384742c096_cppui_modular381,
        }},
        {{
            0x4d34706912ff38211a5600e92b5d4658a01667ba0fb1720b2a3408e4db7370d622f7c128905e7ac5c57c1494af100c6_cppui_modular381,
            0x174d075076274082e4bc19016d6ed20d6c227a638713bb0f5adcab833853aa01e5227a3f768b96e7f05e38bf094627bc_cppui_modular381,
        }});

    constexpr g_value_type p_mul_C(
        {{
            0x16d0bbd48a70913215c4e64eae9c1fb0ff5d52296dea38f4856ea7d516c57b4981867611b2ac8b8c8e42ee1ac6b38ee7_cppui_modular381,
            0x1184f39be53f1c7c868348c773499b23eb37fbc1a2eae5eaf995b6453d7429255dca5800802e9e73009af32442f35715_cppui_modular381,
        }},
        {{
            0x1677412fac92f535f4919c7602b2533df3dc3a0a9ed0499051accbe92d46b65efb17015e310e20a5b09e35d6756103c4_cppui_modular381,
            0xba41fb5dc2beb04a9a1fed616e96442b0dcbbcdee2a75a70c29d77ffa328c03a6e971fddf13d72f6168cadf66e0c8f0_cppui_modular381,
        }},
        {{
            0xa7f8b42ac42d3dc8d4ca183b817de43aaea394536c137ad3cd642c3b9e941b82985b0fe5f8764240a8402ca16ecb001_cppui_modular381,
            0x146c9ff29e2173b7a25d802f2170e728d7991074b4886637ec9aa139106d99d9b9f59f2f805c9143f49fe69dd8191ca9_cppui_modular381,
        }});
    constexpr auto C1 = 0x3a93c528_cppui_modular381;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        {{
            0xdd60c2c749f1aad1923f4e57dad584ffa762a558a7fed5fe032945dc7b144643ad418f89f511cd3105256e2d0a0f1e8_cppui_modular381,
            0x8c654ca6993764d8a33dfd57d52ee5039a563733f202eb0b6237a5b95edc1a5fb00ea5f26ead584fe849cfe420b7c96_cppui_modular381,
        }},
        {{
            0x9464e81873a2c2c0c57bd2e526633634d23e44e4db0dc9d46bf136e644ea5d8d5f9c1f5298a03f016af7bdebefb326f_cppui_modular381,
            0x111c60de7db040df6fe9ff6383148404b017232d276ed1a964ddd4378a4a53f07288c770501c8bd258a223a120296cdc_cppui_modular381,
        }},
        {{
            0x15e055a4d7738d9df5d0cf000b08493f47d2285ee62a87df26b2e85056592d8bc2c34ef2e9db4008fcf29c1caaafd993_cppui_modular381,
            0x156fbc5a7201accb386051cc22d9d5fe1cf32088fb4db2eb9b07f8a32060f53e7d93b8ee64aa00b18d7a178d28810531_cppui_modular381,
        }});
    constexpr auto C2 = 0x3b74e323_cppui_modular381;

    constexpr g_value_type_affine p_to_affine(
        {{
            0x916d8851e884d2c3f4e22e7fc54e09e9df98728073c9004c5a3b609a9687b0361fc2b0f5e35e55ff18c88670319398c_cppui_modular381,
            0x5f4813fb300f1c826001ef7398f9aea50c18c2780d8fae2046d8a8b40b151cfa7bf5a27f3cfbe1cfe683cd02475d4f2_cppui_modular381,
        }},
        {{
            0x14a402fe40ef20ae44599107bebd360a8ecabe2e080cb14eacdb31a521c70fc5d54e9215d02833bde8816c174cef5a2f_cppui_modular381,
            0xe86efa5c2fb9e319bf1fe2a2324b8d6c21c4d3233df0a4f963413ed1942108ab9b422f49f0670101ca60a088ee179b8_cppui_modular381,
        }});

    constexpr g_value_type_projective p_to_projective(
        {{
            0x17f0b8a163b05e2419acb6e40155e79cea21b271929bb69c81f0742d621706130582b30f44970664a9d1f7755288567a_cppui_modular381,
            0x19bb8698b9f032816c6c77e8875a35fc4f4a5757e393d66a2ff1cd1bc2275cc851d96e04b60818e2e9f47a6741d62ea4_cppui_modular381,
        }},
        {{
            0xf690d5d0527fc74fca3531ef3277160694aa37b93e1cbc5453a87a5e35a42ebcb29c9a124c6e4a7094bee05735a3207_cppui_modular381,
            0xf3c46767aaf74e29aa885d086663893c80b96f71f9da914ac410a2e4e2d60aa9f41e736d9b04c7374dfa570f354042b_cppui_modular381,
        }},
        {{
            0x1_cppui_modular381,
            0x0_cppui_modular381,
        }});

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
    static_assert(p2.to_projective() == p_to_projective, "to projective error");
}

BOOST_AUTO_TEST_CASE(curve_operation_test_mnt4_g1) {
    using curve_type = typename curves::mnt4<298>;
    using g_value_type = typename curve_type::g1_type<>::value_type;
    using g_value_type_affine = typename curve_type::g1_type<curves::coordinates::affine>::value_type;
    // projective coordinates are used by default

    constexpr g_value_type p1(
        0x172c9fb6da01e8d0f5a0ba556a5655f8c67a7d344a91e87096b75de7801ce70d5801b48d449_cppui_modular298,
        0x27762604113aaab90bf1e0c0007fd1ebae2659e13db4c00ffd068c1c1555a678eaf06e69451_cppui_modular298,
        0x6878c8d17a189b711b54eb88727c09afaa080bcb4806a18626f23645367ccaea53a867d68d_cppui_modular298);

    constexpr g_value_type p2(
        0x29db0d99a3e0776e0fa8c71ee592a279c9c9a4f4dd33e02eeb49a827033fdd4e900c67777a1_cppui_modular298,
        0x7ab574da4fa1419ba9e3358134f19db9effd1025c4381d0e84950e48fda00cd758244f2d1a_cppui_modular298,
        0x224bec0b2109f240bea93a11752f449a1cac2683a9fbe720268ae85a5447f925f13bfa421eb_cppui_modular298);

    constexpr g_value_type p_add(
        0x95989548c0041034a6dbfb9c9314e9ba4d144fee2841873bfdd1a4a286d9473bafa0fdb7b5_cppui_modular298,
        0x312ff49f1eafd934a7bb8544c8d7e216905d28811831ac4660927937f1c5c2a8aee2b2b16b6_cppui_modular298,
        0xd50f5b970b7bf4b04c1891b99bd6f19a8c85ddb6356b8f72a8e1b90457542d82a813560bdf_cppui_modular298);

    constexpr g_value_type p_sub(
        0x5bd843770194e9b664fedeecd096d50e0fc954e4fdb63e105c92a7b355ec131e3ebfce5864_cppui_modular298,
        0x178ce9482c2cd67c9f04357d1f53109456fc5ebf1de15fb7bc4bdbe11bf14a5de1a8cbea79f_cppui_modular298,
        0xd50f5b970b7bf4b04c1891b99bd6f19a8c85ddb6356b8f72a8e1b90457542d82a813560bdf_cppui_modular298);

    constexpr g_value_type p_mul_C(
        0x3d7e8f6940d2b4e0f14f67989d8d9e3b7496c6297134316edabadf69eeb2b6ca3cdda99f1_cppui_modular298,
        0x2d8c9f6174c64aa2f895ce780481fea10e9402de8129efef10634b105b3fd99dc17f090d3b9_cppui_modular298,
        0x15b67d3fc690050b6f02e41a5f368b7988ecbdaeb1bb3adf868af0592b65cb8e0fa34e0c6b5_cppui_modular298);
    constexpr auto C1 = 0x1203b4c8_cppui_modular298;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        0x1be974b419f4bd1b4fc026b3bb296b9cd671cb987be4c99bdc01fa2fe5112532ca90ca2916d_cppui_modular298,
        0x2664af306794bff602f9699325fc1d57b6b00ace13f58514ca7d5f962f92561c058bb1b263d_cppui_modular298,
        0x13af3d5a92282e8469d99c2f9c57650d51de7f36af8826bf0db8c7ee58a3f26db28d8c13296_cppui_modular298);
    constexpr auto C2 = 0x3151bfb5_cppui_modular298;

    constexpr g_value_type_affine p_to_affine(
        0xbb3d23412558d18845c24476f095447170df03a009809ef6f50f72039948bf7346494e7453_cppui_modular298,
        0x1d8c86a75caf489bc5f3fa2ea263e5f2e991d22d244e732c5689b45ec5401fbdf940c589b0a_cppui_modular298);

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
}

BOOST_AUTO_TEST_CASE(curve_operation_test_mnt4_g2) {
    using curve_type = typename curves::mnt4<298>;
    using g_value_type = typename curve_type::g2_type<>::value_type;
    using g_value_type_affine = typename curve_type::g2_type<curves::coordinates::affine>::value_type;
    // projective coordinates are used by default

    constexpr g_value_type p1(
        {{
            0x20a6d7541c1bd7b1ada94f55476236053e042b6c72cf77264a5c40c671b62ef5a46f84e45af_cppui_modular298,
            0x2f92e835fa005f56fd629fb6eb0725e63296435dc76e3450df0c8694f3bec2ba1f0eebbc21a_cppui_modular298,
        }},
        {{
            0xee24d19afc2b9015b72cf14281476114ccd6fafa4776c2d4a9ace68d6bbbce6125adf29189_cppui_modular298,
            0xefe5105762de13caaf1b1049000b01500041b8e2023c0020522f4621fe3d9e05c0a86abdc_cppui_modular298,
        }},
        {{
            0xca53e4b6482c1396bbc7452fb661f71c44a79faaa9b5ba9dad563e35e21c26cdbfe1c8aa98_cppui_modular298,
            0x2ce8febdb8bad8f49db73ceede9683456d3be7e29ff8e70e8edb5792e78ccb8bbe36f6819d5_cppui_modular298,
        }});

    constexpr g_value_type p2(
        {{
            0x26c0c01f9c5ac08d1f67d8f7c140388f0e72baace84f8532cb58e60bd194772ad482dc2db24_cppui_modular298,
            0x259768e62ff04c824f5e617ffcdafa0628e975627cdf260eed99fa18220db8134742cfba1ca_cppui_modular298,
        }},
        {{
            0x2cf2fe38bed35a4377a5aca9c9b90f328e1d9e4a301eadc8effd0f132a38e57434947f4630b_cppui_modular298,
            0x1941e41c7b859b816fcabd405fd22922be84f518e37434df4b8244a1bf235c6d8bebdedd0fd_cppui_modular298,
        }},
        {{
            0x361a51963df89d966446b818735b9b50ad2b3c5641bfab0da37ef895f2a3504e584926cc721_cppui_modular298,
            0x2245c06b5b8e29b0e0ce6c57dc1a79210e135e438ed8da978572589fb8795809c2d38ef0dc0_cppui_modular298,
        }});

    constexpr g_value_type p_add(
        {{
            0x12d011f779525b7b5d5f5f8a2dae1043fa2e5da9f1775a76dd36033011b6ad50e9de7d77f5c_cppui_modular298,
            0x47fe4ec44216e7c32408440a632a196965a24f8e035cc0151ec66e327505cfbb573bbfa5a8_cppui_modular298,
        }},
        {{
            0x3172399c37418fe2807f4169448475411f3f5c7ed5946715d379504f13a7bd27d7c0e70b337_cppui_modular298,
            0xf7453acf9dfbf0da70375e100205aa6e5a0a985636e78a517892ed7fe166dca29fd90a1e55_cppui_modular298,
        }},
        {{
            0x2a09837cdd8680efe77f5347ac0da50257e678f38f76bcbaa1c8446248dc1b716279442f10f_cppui_modular298,
            0x18929e9d8a6da77075e75a3beaa2d385cab7791a6cb344d07b6763dfaba5364864940ed0cae_cppui_modular298,
        }});

    constexpr g_value_type p_sub(
        {{
            0x27e2ec5fe6c03c75a49ece61e8d479b83ba7f5c194d1494ce4205b6f910d459c8ab602256ca_cppui_modular298,
            0x38c606b68b431dc9a0ca8e54e0d7cb40ca7ed388949cc571d9284747a80229d3d05dbd7f734_cppui_modular298,
        }},
        {{
            0x2f0c28a9a31ca73a13ad70a808ae191ad926bf4259270874abb66fc34017708ea697fd5e893_cppui_modular298,
            0x31b8bdeac49e4cef23bcd02d23194a49a06d403d4bbd68dd8b5120b90da84ff71f5203d58f6_cppui_modular298,
        }},
        {{
            0x2a09837cdd8680efe77f5347ac0da50257e678f38f76bcbaa1c8446248dc1b716279442f10f_cppui_modular298,
            0x18929e9d8a6da77075e75a3beaa2d385cab7791a6cb344d07b6763dfaba5364864940ed0cae_cppui_modular298,
        }});

    constexpr g_value_type p_mul_C(
        {{
            0x231f54b94ab9818a9589dcbf3a9244ed341cfab7d684e77b1c2c13574fdc70964fbfea9bb03_cppui_modular298,
            0x2fb15e5d3c407d989b4d69106c06d8b27e605c34f12a8b9008e64565e87486e504882e0866f_cppui_modular298,
        }},
        {{
            0x39f2bc82039293559d08d75dc0e7ff024f6778bd1ca4a7e11bb7ac3e918a5732ee7627522fa_cppui_modular298,
            0x1557a37274e7367336455516935eaa561d36f2ec8894f5dda1868fe8d9cda169c8767d0055_cppui_modular298,
        }},
        {{
            0x26e5bd64e7b7495084ef219f02bb56996d06256b106a0bd493c0188c86047df5711eb57606e_cppui_modular298,
            0x368b1962424eb1f14bca10eed68b136effae88450d9e8b55d4d788eb0ace1355b3d55e9e55b_cppui_modular298,
        }});
    constexpr auto C1 = 0x2bb7bc77_cppui_modular298;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        {{
            0x26726650ed2b9bc0568fabbe68508cf634d5b6332b563757c301fea0c8677c74a301ed6d304_cppui_modular298,
            0x202a62fa559200cf31ff20c996046affee5985d0f38d49b655416866bcc8de540c7a05a4cee_cppui_modular298,
        }},
        {{
            0x307dfe6cc9e141f53ce57001ce51f492196f8f04104a2a99ee28eca549f79b1e603d388d05a_cppui_modular298,
            0x5ac431716e91aceff94567d15c3f7ae25c20bb401721cf654092805289c1fb709c7674f969_cppui_modular298,
        }},
        {{
            0x365802a6f8000d9cecf2c026bdb8636a053ab3398b091e043ca7aacc4e3cff014ac7671784a_cppui_modular298,
            0x35c57d344509428b944c4517a26b2e71de6af80ffe81c2e582a3ef33adf4f89a830b409a30b_cppui_modular298,
        }});
    constexpr auto C2 = 0x2bb63f0d_cppui_modular298;

    constexpr g_value_type_affine p_to_affine(
        {{
            0xe4a4a941c54a49e9864402e2802dd02995ae0ccb2dec69d313fbef300c8e12e3079230df5b_cppui_modular298,
            0x1d2264d6890ae100d330a744cfce4d652638d306d84f33e501157b715882ed6ea59a9e4179e_cppui_modular298,
        }},
        {{
            0xaf6ca9a009902c1c61f6234578a3ac5443c4c3fc8284d3837d73d778e0b354fd0bc95d46d6_cppui_modular298,
            0x31a130fa72f42e8f7bdedaa05a9d69f08a9e5db44fbc0a4de8a5d50f9e9e48a880dca313091_cppui_modular298,
        }});

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
}

BOOST_AUTO_TEST_CASE(curve_operation_test_mnt6_g1) {
    using curve_type = typename curves::mnt6<298>;
    using g_value_type = typename curve_type::g1_type<>::value_type;
    using g_value_type_affine = typename curve_type::g1_type<curves::coordinates::affine>::value_type;
    using g_value_type_projective = typename curve_type::g1_type<curves::coordinates::projective>::value_type;

    constexpr g_value_type p1(
        0x1ddb2c8af8fe69693b8f13167e2a777fe09eb91d463353c0d2206985fb5cc9a3f298b755383_cppui_modular298,
        0xf9e00ccd15c34450589956a9ec92119be2357872a78eeab24b05b9c6049bf686722dfbc2da_cppui_modular298,
        0x34f61578569ea7545e32977222b0ad4fd111ffb00e48bfea530f9b28148d6c66ecc25638715_cppui_modular298);

    constexpr g_value_type p2(
        0x335b9af13de99ba9967d434405334d3ca682f227bdcb5cafcff26ee59d9549206db3224aba8_cppui_modular298,
        0x19df8867acc42990e842c680183e56f537fe67ed1b3a0b3b4e6a9a9d2f6b9c00728580f66bb_cppui_modular298,
        0xc312d28a4b8dd159a148ec47a53c6f428075ee610049bf97e041058ae289176a347eeaa449_cppui_modular298);

    constexpr g_value_type p_add(
        0x3ba7cdb059289e6c2c79ac99f3c0a171e8a74d0802ae7c1dd20fe153e8b38da5e0223f741a5_cppui_modular298,
        0x3aa9e50daf831fe1f92d2bec1d045b52201b72023b2846dd6c3013fe1f9649228dde3c437b9_cppui_modular298,
        0x1df9d34f97b980f385c6d0affcd37062d10e5ca55cc2521188c0cbd1e7a51e66b6f4a5ea223_cppui_modular298);

    constexpr g_value_type p_sub(
        0x1ad61843a56ef2f3bfcf5447640bd8d441d84ab68a9ca37c818c5c5aa49776d3b9c1bb34f23_cppui_modular298,
        0x354fc0efb6552ecb641058c423f42fff14d1655607159b5e4e4ad5f1500173bf6380b1a5449_cppui_modular298,
        0x1df9d34f97b980f385c6d0affcd37062d10e5ca55cc2521188c0cbd1e7a51e66b6f4a5ea223_cppui_modular298);

    constexpr g_value_type p_mul_C(
        0xdc2e25c576e7198843f161324c3d4fc163ee93f0b42122993fa41737e16618f312651de2d4_cppui_modular298,
        0x32d35b5dd7359a5a6aa4aa7707366bd37ada05a185e416af60a9ded488ed08036d0e300cced_cppui_modular298,
        0x2c885e23b668ab74c3cf0362b10ed725d22e474e754d90cb05aee3ba174b3c6770d860dbc6d_cppui_modular298);
    constexpr auto C1 = 0x182949bc_cppui_modular298;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        0x27afd87c01419311766686d035c6ebc281c18f5401ad75eb54126c79d20fd1e1e01bcba427b_cppui_modular298,
        0x2c28ead8c2fa233ae647c9819df14cd657d4bc4e9d028bd9c22982601f0d91bfb23a56c1780_cppui_modular298,
        0x222429673e7acd3578db38480bc1c2720cbf6a96477c13a04354f47bda90893087d7c9c3371_cppui_modular298);
    constexpr auto C2 = 0x3ea7e208_cppui_modular298;

    constexpr g_value_type_affine p_to_affine(
        0x99180b367e81aac8adcd54fd1ebd085d434d43e57304127deb54287885c301fb6a907a970f_cppui_modular298,
        0x1358a1a7c7c7db2f60e48b38ee4845caa21958caa41743406eb5d689e666a369f82320f7aba_cppui_modular298);

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
}

BOOST_AUTO_TEST_CASE(curve_operation_test_mnt6_g2) {
    using curve_type = typename curves::mnt6<298>;
    using g_value_type = typename curve_type::g2_type<>::value_type;
    using g_value_type_affine = typename curve_type::g2_type<curves::coordinates::affine>::value_type;
    // projective coordinates are used by default

    constexpr g_value_type p1(
        {{
            0x15da78bbd604999fc1125b0c59287a0d3510803774c39e0392604cfc128a6a3d93197271647_cppui_modular298,
            0x2f96c32ac6feb0c131182cb3f166f79d1d27da0acedef4886a0b1d5e23c54296b8ee7160139_cppui_modular298,
            0x1bd181a3093c60e4508e02b99a3dfb219b2a63994c0270f15e762598441352b7a8f66289ef2_cppui_modular298,
        }},
        {{
            0x501d8d37d0eb035530f4086aab196119e1c9f9e9d742f534c5463f3d80f51ead20a19aac11_cppui_modular298,
            0x8c6ae7d27359469281039a4ebf3d1e75427a019fb5b95c10f6e31ef3b7e638ad75129b9238_cppui_modular298,
            0x3a8eb00bd449fb1a82609ba3c9b580ab0e97903383a3be6e4cc61d019d6fbde331ffe6b926a_cppui_modular298,
        }},
        {{
            0x10529eb0e3ad62508adf0a72458c7094145ffb867707b40534b93dd23c515570bb19b827b3a_cppui_modular298,
            0xd52131aa267f5d09e19e1642771399602c1480f5d55390390ce7336be616d479f386c5ed3f_cppui_modular298,
            0x31e30206c05edc932b953d0729a2795d5194766d9fda3e0a9530b6ff5140cf267f1bc315460_cppui_modular298,
        }});

    constexpr g_value_type p2(
        {{
            0x1966aea3f8eac82f244bb7b74afef1933b24369aee766ffffa940312f0c7d3cbc1f7b842c1d_cppui_modular298,
            0x1ebcfc8c1f711c487edc9433a21369dd117f652107ad29761d69eb5e5ac7d3976089fc0d02d_cppui_modular298,
            0xb6254c4b28bd678a46d94fbf17ddd107997d39da61bffcb4d31de9832dbfcd456a9a635f62_cppui_modular298,
        }},
        {{
            0x1740a4e6686c5c21cfc4531a11b058a876e1eb78c54ab9b713fb7424fabdbe3915db906ce64_cppui_modular298,
            0x35519cd02031c4f5f8169f77b77b01c338fd2c0dde7c1958fc6d646c15f7eb34a317283bf59_cppui_modular298,
            0x361d88a99c1a956a86ddbfb2ce582c0005d494e6e70a63d961483d926b29a3ab8f0018bbea5_cppui_modular298,
        }},
        {{
            0x1178a07e802d91293cc5d121a37da8740a44c2820fae8876b4dde89e69c3f605ec632d1a22a_cppui_modular298,
            0x13a043a487fd3c41f7f8719b7ec4d886a3a3a1a39e2e05fd88c41da757669d3f4305578023f_cppui_modular298,
            0x281a2130ee2326a191099e093bf8f731e43f0481e9a308e1630284ba284711a2b4f5833ebd9_cppui_modular298,
        }});

    constexpr g_value_type p_add(
        {{
            0x286ea7e4330a358a8cefd0523a6faffd55edd2fc8a886ebac349189697d792ff68a83c06e5d_cppui_modular298,
            0x1591ca6dce1f85ca16fd330b9fc7c2238c905bdcf437248ace8e677f79393f4e4c9f2689e08_cppui_modular298,
            0x2d19aa4b6c3e770674d594f9f60a1df1ccb6a1efc523b1b223f5b360613c4900ee1fee068f0_cppui_modular298,
        }},
        {{
            0xb5a0b62486b8397124c5d8f4b4badd19e6fa0242c8058a056082cd9f18425996c6f74b5f49_cppui_modular298,
            0x2aa0e105745810e02d21e15fd5c067b1f8ace341932b5dc665557aa297a4dbb898a6fd675e2_cppui_modular298,
            0x21c4869ad25d55e5ac63fe01832445f57f7db6f69d210280232da4a115be4bdb43737558c8c_cppui_modular298,
        }},
        {{
            0xce450fcbf00c7a0071855273cd44eb809866c38a062efc57417520a00e700d6e8f464ca52f_cppui_modular298,
            0x3784776dcdafb623bb37158d94cfea9fe8d2f868e01bb527960c75da8f210469afb2f55c842_cppui_modular298,
            0xe705feaf05146e5e93f1286af29e8303160d3f47bbf19d992ad01ae1e42c675eb153ddfce7_cppui_modular298,
        }});

    constexpr g_value_type p_sub(
        {{
            0x38b477f6d57a1749428955eb86c10a5013fd573e61492113420dce42e7c461fcece378e2721_cppui_modular298,
            0x2f0450a3baab9a36987082505ee28553c02745a6993d5fb46e83e4e5e2bcce3149cae39be6e_cppui_modular298,
            0x12828908e5f99ffcd5299790c297fe6acc039e0acc4b7caecb39f8afbc87e489f7a6dfe73ba_cppui_modular298,
        }},
        {{
            0x1d2d1879f1e03503da2d50c5d6db772c7cf2562aafbf2f99b551c2e4a666a8885161baf0aa7_cppui_modular298,
            0x1ff619aa1c2d5e08872e53baccc57960d91845560646471e0ef1f68fd69f94c09fd0a0d7e0e_cppui_modular298,
            0xfa8387d06db82c0d7ad20295e59bec7e51bafeeabbf805489b7bcee2f43f8a9ccb7ee38018_cppui_modular298,
        }},
        {{
            0xce450fcbf00c7a0071855273cd44eb809866c38a062efc57417520a00e700d6e8f464ca52f_cppui_modular298,
            0x3784776dcdafb623bb37158d94cfea9fe8d2f868e01bb527960c75da8f210469afb2f55c842_cppui_modular298,
            0xe705feaf05146e5e93f1286af29e8303160d3f47bbf19d992ad01ae1e42c675eb153ddfce7_cppui_modular298,
        }});

    constexpr g_value_type p_mul_C(
        {{
            0xf358e2e4f0a735ee8416253408fcb668c287608391763eea99567f2f28731e7627ea469ba7_cppui_modular298,
            0x257a8a922bd63ed32ecb88ad4880fd586d45ca1df7e10285da4f0a9dc4d1ff835659905c004_cppui_modular298,
            0x29c78c46f4fbaff26996deddbcf312bf8ce50adf52c32f425474afeb41760e323af03220437_cppui_modular298,
        }},
        {{
            0xa95b7aaff44dc8ccbbf44e8aa76e6fdc3d7a7466ac8d0e0289cb3f883b98701f5566045f28_cppui_modular298,
            0x1cdf0db54b00251d016854892591e1036ca536da3654369fc62c4133f2f3276b2eb6f490c4f_cppui_modular298,
            0x33ac203454dd8b15577c697c2e19c1956c3f98c7543faf18b169775f0547a5011d319cc3292_cppui_modular298,
        }},
        {{
            0x373f09a0e36bd458c32091f03411ceeae30beef128d0a7fd15986701b5b4488dd04a0c38094_cppui_modular298,
            0x24cd0a32c86fe5fe77085773d22a622d804c3829ea08141597e97eb00d7c665237d81ebc10d_cppui_modular298,
            0x38d7bdb40b6cb4cd1ae9c939658fbb62618dd1346e643dca4513ad8ff2514284f1292596ed2_cppui_modular298,
        }});
    constexpr auto C1 = 0x3da94465_cppui_modular298;

    constexpr g_value_type p_mul_C1_plus_p_mul_C2(
        {{
            0x26524ae056ee5ae0dd807f0e575d1383aef2d271c5aa47516a1bcdd7314933fa0b45cbaa8e9_cppui_modular298,
            0x34a13d100b8a245841d4b7f093fae3c2b1bb339bf4774d234456492b6a54668a62d19e74c9_cppui_modular298,
            0x228ef624a105d545e386a4033134790ca1658f228d4adf2891c7e6703dc517abbb2790892e1_cppui_modular298,
        }},
        {{
            0xd7744722859fefca11bcb06c615d1ae83883bb14556ec92d67bc1a83ff53caaf469d33b395_cppui_modular298,
            0x27df7ef0c9216ab59e9e576cd3ed2610f2fa2f739953f8fb77bd7e5e437919a29d558dad720_cppui_modular298,
            0x194c561af60a2b6b81ac48048f7aef84c1a98c731cd95365cf61d949945600af9b6e57f94af_cppui_modular298,
        }},
        {{
            0x241ab5965aa82b4f7ddcfbdf46406629a191cd1bd3b7e4de5d995649c137016db8201d68753_cppui_modular298,
            0x2f72bc5310bd70c64445a639196240948d9bbfecd474608f68882d57e5f8e1b0bf92d684463_cppui_modular298,
            0x3395ab796861b1a13545042bdc6e55f59a10e56cc88b1cb529eafdbf018ea0caf4533dae5d_cppui_modular298,
        }});
    constexpr auto C2 = 0x33c96283_cppui_modular298;

    constexpr g_value_type_affine p_to_affine(
        {{
            0x362c5501b25d0063dfa31dcf27b9862b51a8b89782424bfbfe688b2d042141e204e916aced4_cppui_modular298,
            0x2b8f4aa9f2d7bf206f240bc12dfa029fd5c6474c7965ab5e9a764baf122ca38f10b8ed2e9aa_cppui_modular298,
            0x39649249c1fbbf2fdf4479318167d1f7884fbc94f2644c18b40d8ca1c636d5b1afaac2808cd_cppui_modular298,
        }},
        {{
            0x46538ec45b82981bdf3aa73189f15304f421bb90d6762a956238a18bfe6baee0dd4d475463_cppui_modular298,
            0x15ea8ac9b9323ebf7869211d0781fa8d04ee39f936ef38910528dab82c1b9dfa99b6d558f10_cppui_modular298,
            0x5f297a07039e20469dd49c2b13ea266e419f1b189b7eda9d9a44787765894b9392500c9d98_cppui_modular298,
        }});

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.to_affine() == p_to_affine, "to affine error");
}

BOOST_AUTO_TEST_SUITE_END()
