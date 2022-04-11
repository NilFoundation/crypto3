//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP

#include <nil/crypto3/detail/literals.hpp>
#include <nil/crypto3/algebra/matrix/matrix.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename FieldType,
                         std::size_t... WireIndexes>
                class poseidon;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename FieldType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class poseidon<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    FieldType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t state_size = 3;
                    constexpr static const std::size_t rounds_amount = 55;

                    constexpr static const std::size_t rounds_per_row = 5;

                    constexpr static const std::size_t sbox_alpha = 7;

                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, state_size> mds =
                        {{
                            {{
                            0x1a9bd250757e29ef4959b9bef59b4e60e20a56307d6491e7b7ea1fac679c7903_cppui253,
                            0x384aa09faf3a48737e2d64f6a030aa242e6d5d455ae4a13696b48a7320c506cd_cppui253,
                            0x3d2b7b0209bc3080064d5ce4a7a03653f8346506bfa6d076061217be9e6cfed5_cppui253
                            }},
                            {{
                            0x9ee57c70bc351220b107983afcfabbea79868a4a8a5913e24b7aaf3b4bf3a42_cppui253,
                            0x20989996bc29a96d17684d3ad4c859813115267f35225d7e1e9a5b5436a2458f_cppui253,
                            0x14e39adb2e171ae232116419ee7f26d9191edde8a5632298347cdb74c3b2e69d_cppui253
                            }},
                            {{
                            0x174544357b687f65a9590c1df621818b5452d5d441597a94357f112316ef67cb_cppui253,
                            0x3ca9263dc1a19d17cfbf15b0166bb25f95dffc53212db207fcee35f02c2c4137_cppui253,
                            0x3cf1fbef75d4ab63b7a812f80b7b0373b2dc21d269ba7c4c4d6581d50aae114c_cppui253
                            }},
                        }};


                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, rounds_amount> round_constant =
                        {{
                            {{
                            0x2ec559cd1a1f2f6889fc8ae5f07757f202b364429677c8ff6603fd6d93659b47_cppui253,
                            0x2553b08c788551bfe064d91c17eb1edb8662283229757711b2b30895f0aa3bad_cppui253,
                            0x25a706fb0f35b260b6f28d61e082d36a8f161be1f4d9416371a7b65f2bfafe4e_cppui253
                            }},
                            {{
                            0x37c0281fda664cc2448d0e7dd77aaa04752250817a945abeea8cfaaf3ee39ba0_cppui253,
                            0x140488321291998b8582eaceeb3fa9ca3980eb64a453573c5aaa2910405936b6_cppui253,
                            0x3a73fe35b1bdd66b809aad5eab47b5c83b0146fd7fc632dfb49cd91ae1169378_cppui253
                            }},
                            {{
                            0x21b7c2b35fd7710b06245711f26c0635d3e21de4db10dd3a7369f59f468d7be6_cppui253,
                            0x1803a068d25fef2ef652c8a4847aa18a29d1885e7bf77fd6a34d66536d09cad7_cppui253,
                            0x291de61c5e6268213772cf7e03c80c2e833eb77c58c46548d158a70fbbd9724b_cppui253
                            }},
                            {{
                            0x230043a0dc2dfab63607cbe1b9c482fdd937fdefecc6905aa5012e89babead13_cppui253,
                            0x218af77a05c502d3fa3144efcf47a0f2a0292498c10c6e2368565674e78764f4_cppui253,
                            0x223e2d94c177d27e071d55729d13a9b216955c7102cc9a95ea40058efb506117_cppui253
                            }},
                            {{
                            0x2a18257c15ad9b6fe8b7c5ad2129394e902c3c3802e738f24ce2f585ae5f6a38_cppui253,
                            0xa6f7ba75f216403d2e4940469d199474a65aa5ef814e36400bddef06158dcf8_cppui253,
                            0x169be41c6227956efef5b4cdde65d00d5e04fe766178bdc731615c6e5b93e31e_cppui253
                            }},
                            {{
                            0x2e28f50a9a55d2e91774083072734544417e290a1cfebc01801b94d0728fe663_cppui253,
                            0xfdedf8da8654a22831040cfc74432464b173ee68628fd90498480b9902f2819_cppui253,
                            0x46a3ed9863d2d739dd8bc9e90a746fda1197162d0a0bec3db1f2f6042cf04e2_cppui253
                            }},
                            {{
                            0x219e08b460c305b428670bacab86ac1e9458075778d35c3619ae7ba1f9b2ed76_cppui253,
                            0x38bb36a12ebcec4d4e8728eb43e3f12a6e33b1ffa1463379018d4e12424e62ca_cppui253,
                            0x1e9aa3fe25d116ccfbd6a8fccdae0aa9bc164a03ab7e951704ee9a715fbedee6_cppui253
                            }},
                            {{
                            0x30f33ed70da4c2bfb844ff1a7558b817d1ec300da86a1694f2db45047d5f18b_cppui253,
                            0x282b04137350495ab417cf2c47389bf681c39f6c22d9e370b7af75cbcbe4bb1_cppui253,
                            0x9b1528dea2eb5bd96905b88ff05fdf3e0f220fe1d93d1b54953ac98fec825f0_cppui253
                            }},
                            {{
                            0x30083dbbb5eab39311c7a8bfd5e55567fa864b3468b5f9200e529cda03d9ef71_cppui253,
                            0x17eace73cf67c6112239cbf51dec0e714ee4e5a91dbc9209dc17bbea5bcd094_cppui253,
                            0x37af1de8f5475ba165b90f8d568683d54e215df97e9287943370cf4118428097_cppui253
                            }},
                            {{
                            0x16ff7592836a45340ec6f2b0f122736d03f0bcb84012f922a4baa73ea0e66f51_cppui253,
                            0x1a5985d4b359d03de60b2edabb1853f476915febc0e40f83a2d1d0084efc3fd9_cppui253,
                            0x255a9d4beb9b5ea18ab9782b1abb267fc5b773b98ab655fd4d469698e1e1f975_cppui253
                            }},
                            {{
                            0x34a8d9f45200a9ac28021712be81e905967bac580a0b9ee57bc4231f5ecb936a_cppui253,
                            0x979556cb3edcbe4f33edd2094f1443b4b4ec6c457b0425b8463e788b9a2dcda_cppui253,
                            0x2a4d028c09ad39c30666b78b45cfadd5279f6239379c689a727f626679272654_cppui253
                            }},
                            {{
                            0xc31b68f6850b3bd71fe4e89984e2c87415523fb54f24ec8ae71430370154b33_cppui253,
                            0x1a27ca0b953d3dba6b8e01cf07d76c611a211d139f2dff5ac023ed2454f2ed90_cppui253,
                            0x109ae97c25d60242b86d7169196d2212f268b952dfd95a3937916b9905303180_cppui253
                            }},
                            {{
                            0x3698c932f2a16f7bb9abac089ec2de79c9965881708878683caf53caa83ad9c4_cppui253,
                            0x3c7e25e0ac8fba3dc1360f8a9a9fa0be0e031c8c76a93497b7cac7ed32ade6c0_cppui253,
                            0x2fc5023c5e4aed5aa7dfca0f5492f1b6efab3099360ec960237512f48c858a79_cppui253
                            }},
                            {{
                            0x2c124735f3f924546fb4fdfa2a018e03f53063d3a2e87fd285ba8d647eda6765_cppui253,
                            0x12c875c9b79591acf9033f8b6c1e357126c44b23f3486fbee0d98340a3382251_cppui253,
                            0x3cda935e895857d39a7db8476aeda5a5131cb165a353073fd3e473fd8855528d_cppui253
                            }},
                            {{
                            0x218eb756fa5f1df9f1eb922ef80b0852588779a7368e3d010def1512815d8759_cppui253,
                            0x23bcf1032957015ef171fbb4329bca0c57d59885522f25f4b082a3cf301cfbc6_cppui253,
                            0x17474c3b6a9bc1057df64b9e4d62badbc7f3867b3dd757c71c1f656205d7bceb_cppui253
                            }},
                            {{
                            0x19826c0ee22972deb41745d3bd412c2ae3d4c18535f4b60c9e870edffa3d550_cppui253,
                            0x30bcb17dfd622c46f3275f698319b68d8816bed0368ded435ed61992bc43efa9_cppui253,
                            0x3bd816c214c66410229cfbd1f4a3a42e6a0f82f3c0d49b09bc7b4c042ff2c94b_cppui253
                            }},
                            {{
                            0x8943ec01d9fb9f43c840757738979b146c3b6d1982280e92a52e8d045633ea1_cppui253,
                            0x2670bf8c01822e31c70976269d89ed58bc79ad2f9d1e3145df890bf898b57e47_cppui253,
                            0xdd53b41599ae78dbd3e689b65ebcca493effa94ed765eeec75a0d3bb20407f9_cppui253
                            }},
                            {{
                            0x68177d293585e0b8c8e76a8a565c8689a1d88e6a9afa79220bb0a2253f203c3_cppui253,
                            0x35216f471043866edc324ad8d8cf0cc792fe7a10bf874b1eeac67b451d6b2cf5_cppui253,
                            0x1fd6efb2536bfe11ec3736e7f7448c01eb2a5a9041bbf84631cc83ee0464f6af_cppui253
                            }},
                            {{
                            0x2c982c7352102289fc1b48dafcd9e3cc364d5a4324575e4721daf0af10033c67_cppui253,
                            0x352f7e8c7662d86db9c722d4d07778858771b832af5bb5dc3b13cf94851c1b45_cppui253,
                            0x18e3c0c1caa5e3ed66ee1ab6f55a5c8063d8c9b034ae47db43435147149e37d5_cppui253
                            }},
                            {{
                            0x3124b12deb37dcbb3d96c1a08d507523e30e03e0919559bf2daaab238422eade_cppui253,
                            0x143bf0def31437eb21095200d2d406e6e5727833683d9740b9bfc1713215dc9a_cppui253,
                            0x1ebee92143f32b4f9d9a90ad62b8483c977480767b53c71f6bde934a8ef38f17_cppui253
                            }},
                            {{
                            0xff6c794ad1afaa494088d5f8ee6c47bf9e83013478628cf9f41f2e81383ebeb_cppui253,
                            0x3d0a10ac3ee707c62e8bdf2cdb49ac2cf4096cf41a7f214fdd1f8f9a24804f17_cppui253,
                            0x1d61014cd3ef0d87d037c56bdfa370a73352b95d472ead1937bed06a31801c91_cppui253
                            }},
                            {{
                            0x123e185b2ec7f072507ac1e4e743589bb25c8fdb468e329e7de169875f90c525_cppui253,
                            0x30b780c0c1cb0609623732824c75017da9799bdc7e08b527bae7f409ebdbecf2_cppui253,
                            0x1dfb3801b7ae4e209f68195612965c6e37a2ed5cf1eeee3d46edf655d6f5afef_cppui253
                            }},
                            {{
                            0x2fdee42805b2774064e963c741552556019a9611928dda728b78311e1f049528_cppui253,
                            0x31b2b65c431212ed36fdda5358d90cd9cb51c9f493bff71cdc75654547e4a22b_cppui253,
                            0x1e3ca033d8413b688db7a543e62ac2e69644c0614801379cfe62fa220319e0ef_cppui253
                            }},
                            {{
                            0xc8ef1168425028c52a32d93f9313153e52e9cf15e5ec2b4ca09d01730dad432_cppui253,
                            0x378c73373a36a5ed94a34f75e5de7a7a6187ea301380ecfb6f1a22cf8552638e_cppui253,
                            0x3218aeec20048a564015e8f221657fbe489ba404d7f5f15b829c7a75a85c2f44_cppui253
                            }},
                            {{
                            0x3312ef7cbbad31430f20f30931b070379c77119c1825c6560cd2c82cf767794e_cppui253,
                            0x356449a71383674c607fa31ded8c0c0d2d20fb45c36698d258cecd982dba478c_cppui253,
                            0xcc88d1c91481d5321174e55b49b2485682c87fac2adb332167a20bcb57db359_cppui253
                            }},
                            {{
                            0x1defccbd33740803ad284bc48ab959f349b94e18d773c6c0c58a4b9390cc300f_cppui253,
                            0x2d263cc2e9af126d768d9e1d2bf2cbf32063be831cb1548ffd716bc3ee7034fe_cppui253,
                            0x111e314db6fb1a28e241028ce3d347c52558a33b6b11285a97fffa1b479e969d_cppui253
                            }},
                            {{
                            0x27409401e92001d434cba2868e9e371703199c2372d23ef329e537b513f453e_cppui253,
                            0x24a852bdf9cb2a8fedd5e85a59867d4916b8a57bdd5f84e1047d410770ffffa0_cppui253,
                            0x205d1b0ee359f621845ac64ff7e383a3eb81e03d2a2966557746d21b47329d6e_cppui253
                            }},
                            {{
                            0x25c327e2cc93ec6f0f23b5e41c931bfbbe4c12da7d55a2b1c91c79db982df903_cppui253,
                            0x39df3e22d22b09b4265da50ef175909ce79e8f0b9599dff01cf80e70884982b9_cppui253,
                            0x9b08d58853d8ac908c5b14e5eb8611b45f40faaa59cb8dff98fb30efcdfaa01_cppui253
                            }},
                            {{
                            0x1ece62374d79e717db4a68f9cddaaf52f8884f397375c0f3c5c1dbaa9c57a0a6_cppui253,
                            0x3bd089b727a0ee08e263fa5e35b618db87d7bcce03441475e3fd49639b9fa1c1_cppui253,
                            0x3fedea75f37ad9cfc94c95141bfb4719ee9b32b874b93dcfc0cc12f51a7b2aff_cppui253
                            }},
                            {{
                            0x36dfa18a9ba1b194228494a8acaf0668cb43aca9d4e0a251b20ec3424d0e65cd_cppui253,
                            0x119e98db3f49cd7fcb3b0632567d9ccaa5498b0d411a1437f57c658f41931d0c_cppui253,
                            0x1100b21c306475d816b3efcd75c3ae135c54ad3cc56ca22abd9b7f45e6d02c19_cppui253
                            }},
                            {{
                            0x15791f9bbea213937208c82794eb667f157f003c65b64aa9800f4bbee4ea5119_cppui253,
                            0x1adbeb5e9c4d515ecfd250ebee56a2a816eb3e3dc8d5d440c1ab4285b350be64_cppui253,
                            0x1fbf4738844a9a249aec253e8e4260e4ab09e26bea29ab0020bf0e813ceecbc3_cppui253
                            }},
                            {{
                            0x3418a929556ec51a086459bb9e63a821d407388cce83949b9af3e3b0434eaf0e_cppui253,
                            0x9406b5c3af0290f997405d0c51be69544afb240d48eeab1736cda0432e8ff9e_cppui253,
                            0x23ece5d70b38ccc9d43cd923e5e3e2f62d1d873c9141ef01f89b6de1336f5bc7_cppui253
                            }},
                            {{
                            0x1852d574e46d370a0b1e64f6c41eeb8d40cf96c524a62965661f2ef87e67234d_cppui253,
                            0xa657027cce8d4f238ea896dde273b7537b508674a366c66b3789d9828b0ce90_cppui253,
                            0x3482f98a46ec358108fbbb68fd94f8f2baa73c723baf21922a850e45511f5a2d_cppui253
                            }},
                            {{
                            0x3f62f164f8c905b335a6cbf76131d2430237e17ad6abc76d2a6329c1ec5463ee_cppui253,
                            0x7e397f503f9c1cea028465b2950ea444b15c5eab567d5a69ea2925685694df0_cppui253,
                            0x405f1fc711872373d6eb50a09fbfb05b2703ae0a0b4edb86aedb216db17a876_cppui253
                            }},
                            {{
                            0xbe0848eb3e09c7027110ad842c502441c97afa14a844406fcfec754a25658c1_cppui253,
                            0x26b78788fd98ac020bac92d0e7792bb5ffed06b697d847f61d984f905d9ba870_cppui253,
                            0x38fd5318d39055c82fef9bdd33315a541c0ec4363e6cc0687005871355dfa573_cppui253
                            }},
                            {{
                            0x380bd03b840c48c8ba3830e7cace72f91a5002218c617294e8c8bc687d5216de_cppui253,
                            0x2c6e57ddc1d7c81a0299ed49c3d74759416bc8426f30e2af5622895c531b4e1c_cppui253,
                            0x11d3a81b262fc76ef506ee6d88e5991d0de8cb9dd162d97c58b175e3bc4584f3_cppui253
                            }},
                            {{
                            0x9b6b283ebaf45fbb1e448969ace9be62adf67ddf58614925741deb6a1ba7def_cppui253,
                            0x15d5095164c885763fa83cdf776d436382821a17bc5563a5b6f6dfcdac504ade_cppui253,
                            0x3427fdbfca3cea23063eb138c5055c6cad9c4252b23d12c12293308eff7d9124_cppui253
                            }},
                            {{
                            0x272f12e731077b74317ef2543c33b86194db1da5f6a7e1eee0656672c81685fe_cppui253,
                            0x5323f85deb8c07c193c37a73d76f6114967913a2bdce11995f183e769f42967_cppui253,
                            0x3d5ce415ecae4ba42b417ea3a501b44694f46efddff2fcca952b097f3852d3d8_cppui253
                            }},
                            {{
                            0xe8ec18c7b52c514d42047f1f0b2a90cb8c0c7391cf9479cd7fd5bfe1d3db8f2_cppui253,
                            0x1591c865ea7065d54304519f8bb268bddbeaf3afae54edcd01a833ed0a9ef1a_cppui253,
                            0x3eddbeeee5eca5deee4bf1789c435e1241e0d71186d8f0f62d74729dfc3119fb_cppui253
                            }},
                            {{
                            0x23691c7009b9283b268766e8d491716d3c1993e6ecf458def8f762af3e355707_cppui253,
                            0x26cdab2c837ebeac5bea4be1d6f0488034907374d81a61a34f1c4db397d4c09b_cppui253,
                            0x2d2206730664d58be0676dad1fee0e990c264a7410a2cdb6b55653c1df72ef56_cppui253
                            }},
                            {{
                            0x2bb74bb185372334a4ef5f6d18e2ece54086e62b04985dd794b7117b0be9217f_cppui253,
                            0x366250fe928c45d8d5aa35f0a142754907ff3c598410199b589b28cd851b2204_cppui253,
                            0x1868f8118482c6b4a5a61a81c8aaca128953179c20f73a44022d9976bdc34af1_cppui253
                            }},
                            {{
                            0xb7901c670e1d75d726eb88d000950b3c963f0f7a6ca24994bdc07ae2f78b4d3_cppui253,
                            0x32c4bd8ab70e1f25af77af57dd340c8e6c8a101dfc5e8dd03314566db90b870_cppui253,
                            0x1ce36db31fe6ea3cd9308db9aa43a8af5c41a8f0a6509bfe00f0e7b486c0ab8a_cppui253
                            }},
                            {{
                            0x26596ea9e1915e53da3479e9d13c3c920505e2449e325810ff6ca855fe4b7c6e_cppui253,
                            0x30f296a269868a7fca8f5b1e269c0116304df31729559a270e713509d3a6d5dc_cppui253,
                            0x2588961eff7897d87eb6ac72350ef9f52640647cbd23136919a994dfd1979d5_cppui253
                            }},
                            {{
                            0x16a49e69721e80690d41e06229e9bc2dbaf9a2abf4b89388db2485595409d62b_cppui253,
                            0x3d7aca02c051fcad8073cfd67210cd423a31888afc4a444d9d3adf3d6c5da7bf_cppui253,
                            0x299bd48a740b7790075268312ab8072c72421de5a6437fa5e25431ef951847b4_cppui253
                            }},
                            {{
                            0x11a69b867d9ea22ec1b2f28e96617129e36eefaea9e8126bdc6a42b99072902b_cppui253,
                            0x25bc1af391f3c1f2284a95da92b5883d1b3a40794b2358b2e7a70fca22da64ce_cppui253,
                            0x361ab3843f4d8ddadede39d82bb1a8109f89b6d9aa117b8f365de43895de0baa_cppui253
                            }},
                            {{
                            0x38ef3ab5b61c117a3465a017a9c8ba4c227659b41fdf145206d5c960f49dd45b_cppui253,
                            0x3992f83f26143dbdbd335604a1a14daf238ae43c249783f694feaf560aaae20f_cppui253,
                            0x350287977eb71c81b10ecd039aad99cfa9ed84a04301cb30869e1dc7fa1dc638_cppui253
                            }},
                            {{
                            0x3afb5bc126020586dcccba32dd054cd9a3f3b834ca9678d6802c48b1da97d6ed_cppui253,
                            0x172b7c2d8e7e4b06d183a2575b790749d0970c54966407fa8f59072c729de671_cppui253,
                            0x2eb53fe3a278688a70494569e54a0f0d269935aec6c897bef4d368c1f67d57e4_cppui253
                            }},
                            {{
                            0x375ae56b8d9310d553ed77d406dedc3f0393e5a321b71caee6a5bb7078b5035_cppui253,
                            0x1d49a0d53bc2993cbf1fb5d1da9bb76fe46a7031d5e5d43fadbf54bc17c1ef38_cppui253,
                            0x132d17b87cab6d707ddfa1f01df1724ad37957e989c44f1ff71426367f953160_cppui253
                            }},
                            {{
                            0x62da5280948d8c6c4acc7e6a1aa421f0f9ec179a44146750060be4be6755f85_cppui253,
                            0xa4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui253,
                            0x3356f1fbeac493ccab752b70bbed821ce49965c19284d7aacd78fbf3ff864e91_cppui253
                            }},
                            {{
                            0x42721e8a9cc32557851feb0e0190c5dfbf4cb1b8f47d37e7e653ec6ff8a4059_cppui253,
                            0x53d9b2633fff31ca4fc5724ce6b4422318128cdf01897d321e86f47cdf748b1_cppui253,
                            0x267d96caeafde5dbd3db1f0668b09ccd532a22f0205494716a786219fb4c801c_cppui253
                            }},
                            {{
                            0x39316997737610193c3f9ffcfd4e23d38aac12cd7b95b8d256d774101650a6ca_cppui253,
                            0x191e377462986563fdabf9b23529f7c84c6b200b9101b3a5096bca5f377981fb_cppui253,
                            0x20f89af9722f79c860d2059a0ec209cf3a7925ad0798cab655eca62fe73ff3d9_cppui253
                            }},
                            {{
                            0x1ca568aeddb2ef391a7c78ecf104d32d785b9ca145d97e35879df3534a7d1e0b_cppui253,
                            0x25de9ba0a37472c3b4c0b9c3bc25cbbf78d91881b6f94ee70e4abf090211251c_cppui253,
                            0x3393debd38d311881c7583bee07e605ef0e55c62f0508ccc2d26518cd568e1ef_cppui253
                            }},
                            {{
                            0x38df2fd18a8d7563806aa9d994a611f642d5c397388d1dd3e78bc7a4515c5b1_cppui253,
                            0x5c6503ff1ee548f2435ad9148d7fb94c9222b0908f445537a6667047f6d501c_cppui253,
                            0x104c88d6d0682d82d3d664826dc9565db101a220aa8f90572eb798468a82a2ab_cppui253
                            }},
                            {{
                            0x2caad6108c09ee6aee7851b4a2d2d3b7c3ca3c56a80003c8471f90bfa4ac628b_cppui253,
                            0xa57dbd4c327826c8a97bc7285f94bcddb966177346f1792c4bd7088aa0353f3_cppui253,
                            0x3c15552f9124318b8433d01bb53ba04ba1cc9eb91d83b918e32fea39fbe908fa_cppui253
                            }},
                            {{
                            0xe10c10cbbe1717a9441c6299c4fc087c222208bd4fa8f3be66d2075f623b513_cppui253,
                            0x1e8b254cbff2c92a83dff1728c81dd22a9570f590e497cb2d640042cb879a930_cppui253,
                            0x1812dbcd70c440610057bbfdd0cc4d31d1faf5786419b53841c4adc43f2b2352_cppui253
                            }},
                        }};


                 public:

                    constexpr static const std::size_t required_rows_amount = 12;

                    struct public_params_type { };

                    struct private_params_type {
                        std::array<typename ArithmetizationType::field_type::value_type, state_size> input_state;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {
                        std::size_t j = component_start_row;
                        for (std::size_t z = 0; z < rounds_amount; z += rounds_per_row){
                            std::size_t selector_index = public_assignment.add_selector(j);
                            auto constraint_1 = bp.add_constraint(var(W3, 0) -
                                (var(W0, 0).pow(sbox_alpha) * mds[0][0] +
                                var(W1, 0).pow(sbox_alpha) * mds[0][1] +
                                var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0]));
                            auto constraint_2 = bp.add_constraint(var(W4, 0) -
                                (var(W0, 0).pow(sbox_alpha) * mds[1][0] +
                                 var(W1, 0).pow(sbox_alpha) * mds[1][1] +
                                 var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1]));
                            auto constraint_3 = bp.add_constraint(var(W5, 0) -
                                (var(W0, 0).pow(sbox_alpha) * mds[2][0] +
                                 var(W1, 0).pow(sbox_alpha) * mds[2][1] +
                                 var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2]));

                            auto constraint_4 = bp.add_constraint(var(W6, 0) -
                                (var(W3, 0).pow(sbox_alpha) * mds[0][0] +
                                 var(W4, 0).pow(sbox_alpha) * mds[0][1] +
                                 var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0]));
                            auto constraint_5 = bp.add_constraint(var(W7, 0) -
                                (var(W3, 0).pow(sbox_alpha) * mds[1][0] +
                                 var(W4, 0).pow(sbox_alpha) * mds[1][1] +
                                 var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1]));
                            auto constraint_6 = bp.add_constraint(var(W8, 0) -
                                (var(W3, 0).pow(sbox_alpha) * mds[2][0] +
                                 var(W4, 0).pow(sbox_alpha) * mds[2][1] +
                                 var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2]));

                            auto constraint_7 = bp.add_constraint(var(W9, 0) -
                                (var(W6, 0).pow(sbox_alpha) * mds[0][0] +
                                 var(W7, 0).pow(sbox_alpha) * mds[0][1] +
                                 var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0]));
                            auto constraint_8 = bp.add_constraint(var(W10, 0) -
                                (var(W6, 0).pow(sbox_alpha) * mds[1][0] +
                                 var(W7, 0).pow(sbox_alpha) * mds[1][1] +
                                 var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1]));
                            auto constraint_9 = bp.add_constraint(var(W11, 0) -
                                (var(W6, 0).pow(sbox_alpha) * mds[2][0] +
                                 var(W7, 0).pow(sbox_alpha) * mds[2][1] +
                                 var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2]));

                            auto constraint_10 = bp.add_constraint(var(W12, 0) -
                                (var(W9, 0).pow(sbox_alpha) * mds[0][0] +
                                 var(W10, 0).pow(sbox_alpha) * mds[0][1] +
                                 var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0]));
                            auto constraint_11 = bp.add_constraint(var(W13, 0) -
                                (var(W9, 0).pow(sbox_alpha) * mds[1][0] +
                                 var(W10, 0).pow(sbox_alpha) * mds[1][1] +
                                 var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1]));
                            auto constraint_12 = bp.add_constraint(var(W14, 0) -
                                (var(W9, 0).pow(sbox_alpha) * mds[2][0] +
                                 var(W10, 0).pow(sbox_alpha) * mds[2][1] +
                                 var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2]));

                            auto constraint_13 = bp.add_constraint(var(W0, +1) -
                                (var(W12, 0).pow(sbox_alpha) * mds[0][0] +
                                 var(W13, 0).pow(sbox_alpha) * mds[0][1] +
                                 var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0]));
                            auto constraint_14 = bp.add_constraint(var(W1, +1) -
                                (var(W12, 0).pow(sbox_alpha) * mds[1][0] +
                                 var(W13, 0).pow(sbox_alpha) * mds[1][1] +
                                 var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1]));
                            auto constraint_15 = bp.add_constraint(var(W2, +1) -
                                (var(W12, 0).pow(sbox_alpha) * mds[2][0] +
                                 var(W13, 0).pow(sbox_alpha) * mds[2][1] +
                                 var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2]));

                            bp.add_gate(selector_index,
                            {constraint_1, constraint_2, constraint_3,
                                          constraint_4, constraint_5, constraint_6, constraint_7, constraint_8, constraint_9, constraint_10,
                                          constraint_11, constraint_12, constraint_13, constraint_14, constraint_15});
                            j++;
                        }
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {

                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const private_params_type &params,
                        const std::size_t &component_start_row) {

                        std::array<typename ArithmetizationType::field_type::value_type, state_size> state = params.input_state;
                        std::array<typename ArithmetizationType::field_type::value_type, state_size> next_state;

                        
                        std::size_t row = component_start_row;
                        private_assignment.witness(W0)[row] = state[0];
                        private_assignment.witness(W1)[row] = state[1];
                        private_assignment.witness(W2)[row] = state[2];

                        for (std::size_t i = row; i < row + required_rows_amount - 1; i++) {
                            for (int j = 0; j < state_size; j++) {
                                next_state[j] = state[0].pow(sbox_alpha) * mds[j][0] + state[1].pow(sbox_alpha) * mds[j][1] + state[2].pow(sbox_alpha) * mds[j][2] + round_constant[(i - row)*5][j];
                            }
                            private_assignment.witness(W3)[i] = next_state[0];
                            private_assignment.witness(W4)[i] = next_state[1];
                            private_assignment.witness(W5)[i] = next_state[2];
                            state = next_state;
                            for (int j = 0; j < state_size; j++) {
                                next_state[j] = state[0].pow(sbox_alpha) * mds[j][0] + state[1].pow(sbox_alpha) * mds[j][1] + state[2].pow(sbox_alpha) * mds[j][2] + round_constant[(i - row)*5 + 1][j];
                            }
                            private_assignment.witness(W6)[i] = next_state[0];
                            private_assignment.witness(W7)[i] = next_state[1];
                            private_assignment.witness(W8)[i] = next_state[2];
                            state = next_state;
                            for (int j = 0; j < state_size; j++) {
                                next_state[j] = state[0].pow(sbox_alpha) * mds[j][0] + state[1].pow(sbox_alpha) * mds[j][1] + state[2].pow(sbox_alpha) * mds[j][2] + round_constant[(i - row)*5 + 2][j];
                            }
                            private_assignment.witness(W9)[i] = next_state[0];
                            private_assignment.witness(W10)[i] = next_state[1];
                            private_assignment.witness(W11)[i] = next_state[2];
                            state = next_state;
                            for (int j = 0; j < state_size; j++) {
                                next_state[j] = state[0].pow(sbox_alpha) * mds[j][0] + state[1].pow(sbox_alpha) * mds[j][1] + state[2].pow(sbox_alpha) * mds[j][2] + round_constant[(i-row)*5 + 3][j];
                            }
                            private_assignment.witness(W12)[i] = next_state[0];
                            private_assignment.witness(W13)[i] = next_state[1];
                            private_assignment.witness(W14)[i] = next_state[2];
                            state = next_state;
                            for (int j = 0; j < state_size; j++) {
                                next_state[j] = state[0].pow(sbox_alpha) * mds[j][0] + state[1].pow(sbox_alpha) * mds[j][1] + state[2].pow(sbox_alpha) * mds[j][2] + round_constant[(i - row)*5 + 4][j];
                            }
                            private_assignment.witness(W0)[i + 1] = next_state[0];
                            private_assignment.witness(W1)[i + 1] = next_state[1];
                            private_assignment.witness(W2)[i + 1] = next_state[2];
                            state = next_state;
                        }
                        std::cout<<"Circuit result: "<<state[0].data<<" "<< state[1].data<<" " <<state[2].data<<std::endl;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP
