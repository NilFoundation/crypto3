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

#ifndef CRYPTO3_BLUEPRINT_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP
#define CRYPTO3_BLUEPRINT_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP

#include <nil/crypto3/algebra/matrix/matrix.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename ConstFieldType, std::size_t state_size, std::size_t rounds_amount>
                struct poseidon_constants;

                template<std::size_t state_size, std::size_t rounds_amount>
                struct poseidon_constants<typename nil::crypto3::algebra::fields::pallas_base_field,
                                          state_size,
                                          rounds_amount> {
                    using FieldType = nil::crypto3::algebra::fields::pallas_base_field;

                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>,
                                                      state_size>
                        mds = {{
                            {{0x1a9bd250757e29ef4959b9bef59b4e60e20a56307d6491e7b7ea1fac679c7903_cppui253,
                              0x384aa09faf3a48737e2d64f6a030aa242e6d5d455ae4a13696b48a7320c506cd_cppui253,
                              0x3d2b7b0209bc3080064d5ce4a7a03653f8346506bfa6d076061217be9e6cfed5_cppui253}},
                            {{0x9ee57c70bc351220b107983afcfabbea79868a4a8a5913e24b7aaf3b4bf3a42_cppui253,
                              0x20989996bc29a96d17684d3ad4c859813115267f35225d7e1e9a5b5436a2458f_cppui253,
                              0x14e39adb2e171ae232116419ee7f26d9191edde8a5632298347cdb74c3b2e69d_cppui253}},
                            {{0x174544357b687f65a9590c1df621818b5452d5d441597a94357f112316ef67cb_cppui253,
                              0x3ca9263dc1a19d17cfbf15b0166bb25f95dffc53212db207fcee35f02c2c4137_cppui253,
                              0x3cf1fbef75d4ab63b7a812f80b7b0373b2dc21d269ba7c4c4d6581d50aae114c_cppui253}},
                        }};

                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>,
                                                      rounds_amount>
                        round_constant = {{
                            {{0x2ec559cd1a1f2f6889fc8ae5f07757f202b364429677c8ff6603fd6d93659b47_cppui253,
                              0x2553b08c788551bfe064d91c17eb1edb8662283229757711b2b30895f0aa3bad_cppui253,
                              0x25a706fb0f35b260b6f28d61e082d36a8f161be1f4d9416371a7b65f2bfafe4e_cppui253}},
                            {{0x37c0281fda664cc2448d0e7dd77aaa04752250817a945abeea8cfaaf3ee39ba0_cppui253,
                              0x140488321291998b8582eaceeb3fa9ca3980eb64a453573c5aaa2910405936b6_cppui253,
                              0x3a73fe35b1bdd66b809aad5eab47b5c83b0146fd7fc632dfb49cd91ae1169378_cppui253}},
                            {{0x21b7c2b35fd7710b06245711f26c0635d3e21de4db10dd3a7369f59f468d7be6_cppui253,
                              0x1803a068d25fef2ef652c8a4847aa18a29d1885e7bf77fd6a34d66536d09cad7_cppui253,
                              0x291de61c5e6268213772cf7e03c80c2e833eb77c58c46548d158a70fbbd9724b_cppui253}},
                            {{0x230043a0dc2dfab63607cbe1b9c482fdd937fdefecc6905aa5012e89babead13_cppui253,
                              0x218af77a05c502d3fa3144efcf47a0f2a0292498c10c6e2368565674e78764f4_cppui253,
                              0x223e2d94c177d27e071d55729d13a9b216955c7102cc9a95ea40058efb506117_cppui253}},
                            {{0x2a18257c15ad9b6fe8b7c5ad2129394e902c3c3802e738f24ce2f585ae5f6a38_cppui253,
                              0xa6f7ba75f216403d2e4940469d199474a65aa5ef814e36400bddef06158dcf8_cppui253,
                              0x169be41c6227956efef5b4cdde65d00d5e04fe766178bdc731615c6e5b93e31e_cppui253}},
                            {{0x2e28f50a9a55d2e91774083072734544417e290a1cfebc01801b94d0728fe663_cppui253,
                              0xfdedf8da8654a22831040cfc74432464b173ee68628fd90498480b9902f2819_cppui253,
                              0x46a3ed9863d2d739dd8bc9e90a746fda1197162d0a0bec3db1f2f6042cf04e2_cppui253}},
                            {{0x219e08b460c305b428670bacab86ac1e9458075778d35c3619ae7ba1f9b2ed76_cppui253,
                              0x38bb36a12ebcec4d4e8728eb43e3f12a6e33b1ffa1463379018d4e12424e62ca_cppui253,
                              0x1e9aa3fe25d116ccfbd6a8fccdae0aa9bc164a03ab7e951704ee9a715fbedee6_cppui253}},
                            {{0x30f33ed70da4c2bfb844ff1a7558b817d1ec300da86a1694f2db45047d5f18b_cppui253,
                              0x282b04137350495ab417cf2c47389bf681c39f6c22d9e370b7af75cbcbe4bb1_cppui253,
                              0x9b1528dea2eb5bd96905b88ff05fdf3e0f220fe1d93d1b54953ac98fec825f0_cppui253}},
                            {{0x30083dbbb5eab39311c7a8bfd5e55567fa864b3468b5f9200e529cda03d9ef71_cppui253,
                              0x17eace73cf67c6112239cbf51dec0e714ee4e5a91dbc9209dc17bbea5bcd094_cppui253,
                              0x37af1de8f5475ba165b90f8d568683d54e215df97e9287943370cf4118428097_cppui253}},
                            {{0x16ff7592836a45340ec6f2b0f122736d03f0bcb84012f922a4baa73ea0e66f51_cppui253,
                              0x1a5985d4b359d03de60b2edabb1853f476915febc0e40f83a2d1d0084efc3fd9_cppui253,
                              0x255a9d4beb9b5ea18ab9782b1abb267fc5b773b98ab655fd4d469698e1e1f975_cppui253}},
                            {{0x34a8d9f45200a9ac28021712be81e905967bac580a0b9ee57bc4231f5ecb936a_cppui253,
                              0x979556cb3edcbe4f33edd2094f1443b4b4ec6c457b0425b8463e788b9a2dcda_cppui253,
                              0x2a4d028c09ad39c30666b78b45cfadd5279f6239379c689a727f626679272654_cppui253}},
                            {{0xc31b68f6850b3bd71fe4e89984e2c87415523fb54f24ec8ae71430370154b33_cppui253,
                              0x1a27ca0b953d3dba6b8e01cf07d76c611a211d139f2dff5ac023ed2454f2ed90_cppui253,
                              0x109ae97c25d60242b86d7169196d2212f268b952dfd95a3937916b9905303180_cppui253}},
                            {{0x3698c932f2a16f7bb9abac089ec2de79c9965881708878683caf53caa83ad9c4_cppui253,
                              0x3c7e25e0ac8fba3dc1360f8a9a9fa0be0e031c8c76a93497b7cac7ed32ade6c0_cppui253,
                              0x2fc5023c5e4aed5aa7dfca0f5492f1b6efab3099360ec960237512f48c858a79_cppui253}},
                            {{0x2c124735f3f924546fb4fdfa2a018e03f53063d3a2e87fd285ba8d647eda6765_cppui253,
                              0x12c875c9b79591acf9033f8b6c1e357126c44b23f3486fbee0d98340a3382251_cppui253,
                              0x3cda935e895857d39a7db8476aeda5a5131cb165a353073fd3e473fd8855528d_cppui253}},
                            {{0x218eb756fa5f1df9f1eb922ef80b0852588779a7368e3d010def1512815d8759_cppui253,
                              0x23bcf1032957015ef171fbb4329bca0c57d59885522f25f4b082a3cf301cfbc6_cppui253,
                              0x17474c3b6a9bc1057df64b9e4d62badbc7f3867b3dd757c71c1f656205d7bceb_cppui253}},
                            {{0x19826c0ee22972deb41745d3bd412c2ae3d4c18535f4b60c9e870edffa3d550_cppui253,
                              0x30bcb17dfd622c46f3275f698319b68d8816bed0368ded435ed61992bc43efa9_cppui253,
                              0x3bd816c214c66410229cfbd1f4a3a42e6a0f82f3c0d49b09bc7b4c042ff2c94b_cppui253}},
                            {{0x8943ec01d9fb9f43c840757738979b146c3b6d1982280e92a52e8d045633ea1_cppui253,
                              0x2670bf8c01822e31c70976269d89ed58bc79ad2f9d1e3145df890bf898b57e47_cppui253,
                              0xdd53b41599ae78dbd3e689b65ebcca493effa94ed765eeec75a0d3bb20407f9_cppui253}},
                            {{0x68177d293585e0b8c8e76a8a565c8689a1d88e6a9afa79220bb0a2253f203c3_cppui253,
                              0x35216f471043866edc324ad8d8cf0cc792fe7a10bf874b1eeac67b451d6b2cf5_cppui253,
                              0x1fd6efb2536bfe11ec3736e7f7448c01eb2a5a9041bbf84631cc83ee0464f6af_cppui253}},
                            {{0x2c982c7352102289fc1b48dafcd9e3cc364d5a4324575e4721daf0af10033c67_cppui253,
                              0x352f7e8c7662d86db9c722d4d07778858771b832af5bb5dc3b13cf94851c1b45_cppui253,
                              0x18e3c0c1caa5e3ed66ee1ab6f55a5c8063d8c9b034ae47db43435147149e37d5_cppui253}},
                            {{0x3124b12deb37dcbb3d96c1a08d507523e30e03e0919559bf2daaab238422eade_cppui253,
                              0x143bf0def31437eb21095200d2d406e6e5727833683d9740b9bfc1713215dc9a_cppui253,
                              0x1ebee92143f32b4f9d9a90ad62b8483c977480767b53c71f6bde934a8ef38f17_cppui253}},
                            {{0xff6c794ad1afaa494088d5f8ee6c47bf9e83013478628cf9f41f2e81383ebeb_cppui253,
                              0x3d0a10ac3ee707c62e8bdf2cdb49ac2cf4096cf41a7f214fdd1f8f9a24804f17_cppui253,
                              0x1d61014cd3ef0d87d037c56bdfa370a73352b95d472ead1937bed06a31801c91_cppui253}},
                            {{0x123e185b2ec7f072507ac1e4e743589bb25c8fdb468e329e7de169875f90c525_cppui253,
                              0x30b780c0c1cb0609623732824c75017da9799bdc7e08b527bae7f409ebdbecf2_cppui253,
                              0x1dfb3801b7ae4e209f68195612965c6e37a2ed5cf1eeee3d46edf655d6f5afef_cppui253}},
                            {{0x2fdee42805b2774064e963c741552556019a9611928dda728b78311e1f049528_cppui253,
                              0x31b2b65c431212ed36fdda5358d90cd9cb51c9f493bff71cdc75654547e4a22b_cppui253,
                              0x1e3ca033d8413b688db7a543e62ac2e69644c0614801379cfe62fa220319e0ef_cppui253}},
                            {{0xc8ef1168425028c52a32d93f9313153e52e9cf15e5ec2b4ca09d01730dad432_cppui253,
                              0x378c73373a36a5ed94a34f75e5de7a7a6187ea301380ecfb6f1a22cf8552638e_cppui253,
                              0x3218aeec20048a564015e8f221657fbe489ba404d7f5f15b829c7a75a85c2f44_cppui253}},
                            {{0x3312ef7cbbad31430f20f30931b070379c77119c1825c6560cd2c82cf767794e_cppui253,
                              0x356449a71383674c607fa31ded8c0c0d2d20fb45c36698d258cecd982dba478c_cppui253,
                              0xcc88d1c91481d5321174e55b49b2485682c87fac2adb332167a20bcb57db359_cppui253}},
                            {{0x1defccbd33740803ad284bc48ab959f349b94e18d773c6c0c58a4b9390cc300f_cppui253,
                              0x2d263cc2e9af126d768d9e1d2bf2cbf32063be831cb1548ffd716bc3ee7034fe_cppui253,
                              0x111e314db6fb1a28e241028ce3d347c52558a33b6b11285a97fffa1b479e969d_cppui253}},
                            {{0x27409401e92001d434cba2868e9e371703199c2372d23ef329e537b513f453e_cppui253,
                              0x24a852bdf9cb2a8fedd5e85a59867d4916b8a57bdd5f84e1047d410770ffffa0_cppui253,
                              0x205d1b0ee359f621845ac64ff7e383a3eb81e03d2a2966557746d21b47329d6e_cppui253}},
                            {{0x25c327e2cc93ec6f0f23b5e41c931bfbbe4c12da7d55a2b1c91c79db982df903_cppui253,
                              0x39df3e22d22b09b4265da50ef175909ce79e8f0b9599dff01cf80e70884982b9_cppui253,
                              0x9b08d58853d8ac908c5b14e5eb8611b45f40faaa59cb8dff98fb30efcdfaa01_cppui253}},
                            {{0x1ece62374d79e717db4a68f9cddaaf52f8884f397375c0f3c5c1dbaa9c57a0a6_cppui253,
                              0x3bd089b727a0ee08e263fa5e35b618db87d7bcce03441475e3fd49639b9fa1c1_cppui253,
                              0x3fedea75f37ad9cfc94c95141bfb4719ee9b32b874b93dcfc0cc12f51a7b2aff_cppui253}},
                            {{0x36dfa18a9ba1b194228494a8acaf0668cb43aca9d4e0a251b20ec3424d0e65cd_cppui253,
                              0x119e98db3f49cd7fcb3b0632567d9ccaa5498b0d411a1437f57c658f41931d0c_cppui253,
                              0x1100b21c306475d816b3efcd75c3ae135c54ad3cc56ca22abd9b7f45e6d02c19_cppui253}},
                            {{0x15791f9bbea213937208c82794eb667f157f003c65b64aa9800f4bbee4ea5119_cppui253,
                              0x1adbeb5e9c4d515ecfd250ebee56a2a816eb3e3dc8d5d440c1ab4285b350be64_cppui253,
                              0x1fbf4738844a9a249aec253e8e4260e4ab09e26bea29ab0020bf0e813ceecbc3_cppui253}},
                            {{0x3418a929556ec51a086459bb9e63a821d407388cce83949b9af3e3b0434eaf0e_cppui253,
                              0x9406b5c3af0290f997405d0c51be69544afb240d48eeab1736cda0432e8ff9e_cppui253,
                              0x23ece5d70b38ccc9d43cd923e5e3e2f62d1d873c9141ef01f89b6de1336f5bc7_cppui253}},
                            {{0x1852d574e46d370a0b1e64f6c41eeb8d40cf96c524a62965661f2ef87e67234d_cppui253,
                              0xa657027cce8d4f238ea896dde273b7537b508674a366c66b3789d9828b0ce90_cppui253,
                              0x3482f98a46ec358108fbbb68fd94f8f2baa73c723baf21922a850e45511f5a2d_cppui253}},
                            {{0x3f62f164f8c905b335a6cbf76131d2430237e17ad6abc76d2a6329c1ec5463ee_cppui253,
                              0x7e397f503f9c1cea028465b2950ea444b15c5eab567d5a69ea2925685694df0_cppui253,
                              0x405f1fc711872373d6eb50a09fbfb05b2703ae0a0b4edb86aedb216db17a876_cppui253}},
                            {{0xbe0848eb3e09c7027110ad842c502441c97afa14a844406fcfec754a25658c1_cppui253,
                              0x26b78788fd98ac020bac92d0e7792bb5ffed06b697d847f61d984f905d9ba870_cppui253,
                              0x38fd5318d39055c82fef9bdd33315a541c0ec4363e6cc0687005871355dfa573_cppui253}},
                            {{0x380bd03b840c48c8ba3830e7cace72f91a5002218c617294e8c8bc687d5216de_cppui253,
                              0x2c6e57ddc1d7c81a0299ed49c3d74759416bc8426f30e2af5622895c531b4e1c_cppui253,
                              0x11d3a81b262fc76ef506ee6d88e5991d0de8cb9dd162d97c58b175e3bc4584f3_cppui253}},
                            {{0x9b6b283ebaf45fbb1e448969ace9be62adf67ddf58614925741deb6a1ba7def_cppui253,
                              0x15d5095164c885763fa83cdf776d436382821a17bc5563a5b6f6dfcdac504ade_cppui253,
                              0x3427fdbfca3cea23063eb138c5055c6cad9c4252b23d12c12293308eff7d9124_cppui253}},
                            {{0x272f12e731077b74317ef2543c33b86194db1da5f6a7e1eee0656672c81685fe_cppui253,
                              0x5323f85deb8c07c193c37a73d76f6114967913a2bdce11995f183e769f42967_cppui253,
                              0x3d5ce415ecae4ba42b417ea3a501b44694f46efddff2fcca952b097f3852d3d8_cppui253}},
                            {{0xe8ec18c7b52c514d42047f1f0b2a90cb8c0c7391cf9479cd7fd5bfe1d3db8f2_cppui253,
                              0x1591c865ea7065d54304519f8bb268bddbeaf3afae54edcd01a833ed0a9ef1a_cppui253,
                              0x3eddbeeee5eca5deee4bf1789c435e1241e0d71186d8f0f62d74729dfc3119fb_cppui253}},
                            {{0x23691c7009b9283b268766e8d491716d3c1993e6ecf458def8f762af3e355707_cppui253,
                              0x26cdab2c837ebeac5bea4be1d6f0488034907374d81a61a34f1c4db397d4c09b_cppui253,
                              0x2d2206730664d58be0676dad1fee0e990c264a7410a2cdb6b55653c1df72ef56_cppui253}},
                            {{0x2bb74bb185372334a4ef5f6d18e2ece54086e62b04985dd794b7117b0be9217f_cppui253,
                              0x366250fe928c45d8d5aa35f0a142754907ff3c598410199b589b28cd851b2204_cppui253,
                              0x1868f8118482c6b4a5a61a81c8aaca128953179c20f73a44022d9976bdc34af1_cppui253}},
                            {{0xb7901c670e1d75d726eb88d000950b3c963f0f7a6ca24994bdc07ae2f78b4d3_cppui253,
                              0x32c4bd8ab70e1f25af77af57dd340c8e6c8a101dfc5e8dd03314566db90b870_cppui253,
                              0x1ce36db31fe6ea3cd9308db9aa43a8af5c41a8f0a6509bfe00f0e7b486c0ab8a_cppui253}},
                            {{0x26596ea9e1915e53da3479e9d13c3c920505e2449e325810ff6ca855fe4b7c6e_cppui253,
                              0x30f296a269868a7fca8f5b1e269c0116304df31729559a270e713509d3a6d5dc_cppui253,
                              0x2588961eff7897d87eb6ac72350ef9f52640647cbd23136919a994dfd1979d5_cppui253}},
                            {{0x16a49e69721e80690d41e06229e9bc2dbaf9a2abf4b89388db2485595409d62b_cppui253,
                              0x3d7aca02c051fcad8073cfd67210cd423a31888afc4a444d9d3adf3d6c5da7bf_cppui253,
                              0x299bd48a740b7790075268312ab8072c72421de5a6437fa5e25431ef951847b4_cppui253}},
                            {{0x11a69b867d9ea22ec1b2f28e96617129e36eefaea9e8126bdc6a42b99072902b_cppui253,
                              0x25bc1af391f3c1f2284a95da92b5883d1b3a40794b2358b2e7a70fca22da64ce_cppui253,
                              0x361ab3843f4d8ddadede39d82bb1a8109f89b6d9aa117b8f365de43895de0baa_cppui253}},
                            {{0x38ef3ab5b61c117a3465a017a9c8ba4c227659b41fdf145206d5c960f49dd45b_cppui253,
                              0x3992f83f26143dbdbd335604a1a14daf238ae43c249783f694feaf560aaae20f_cppui253,
                              0x350287977eb71c81b10ecd039aad99cfa9ed84a04301cb30869e1dc7fa1dc638_cppui253}},
                            {{0x3afb5bc126020586dcccba32dd054cd9a3f3b834ca9678d6802c48b1da97d6ed_cppui253,
                              0x172b7c2d8e7e4b06d183a2575b790749d0970c54966407fa8f59072c729de671_cppui253,
                              0x2eb53fe3a278688a70494569e54a0f0d269935aec6c897bef4d368c1f67d57e4_cppui253}},
                            {{0x375ae56b8d9310d553ed77d406dedc3f0393e5a321b71caee6a5bb7078b5035_cppui253,
                              0x1d49a0d53bc2993cbf1fb5d1da9bb76fe46a7031d5e5d43fadbf54bc17c1ef38_cppui253,
                              0x132d17b87cab6d707ddfa1f01df1724ad37957e989c44f1ff71426367f953160_cppui253}},
                            {{0x62da5280948d8c6c4acc7e6a1aa421f0f9ec179a44146750060be4be6755f85_cppui253,
                              0xa4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui253,
                              0x3356f1fbeac493ccab752b70bbed821ce49965c19284d7aacd78fbf3ff864e91_cppui253}},
                            {{0x42721e8a9cc32557851feb0e0190c5dfbf4cb1b8f47d37e7e653ec6ff8a4059_cppui253,
                              0x53d9b2633fff31ca4fc5724ce6b4422318128cdf01897d321e86f47cdf748b1_cppui253,
                              0x267d96caeafde5dbd3db1f0668b09ccd532a22f0205494716a786219fb4c801c_cppui253}},
                            {{0x39316997737610193c3f9ffcfd4e23d38aac12cd7b95b8d256d774101650a6ca_cppui253,
                              0x191e377462986563fdabf9b23529f7c84c6b200b9101b3a5096bca5f377981fb_cppui253,
                              0x20f89af9722f79c860d2059a0ec209cf3a7925ad0798cab655eca62fe73ff3d9_cppui253}},
                            {{0x1ca568aeddb2ef391a7c78ecf104d32d785b9ca145d97e35879df3534a7d1e0b_cppui253,
                              0x25de9ba0a37472c3b4c0b9c3bc25cbbf78d91881b6f94ee70e4abf090211251c_cppui253,
                              0x3393debd38d311881c7583bee07e605ef0e55c62f0508ccc2d26518cd568e1ef_cppui253}},
                            {{0x38df2fd18a8d7563806aa9d994a611f642d5c397388d1dd3e78bc7a4515c5b1_cppui253,
                              0x5c6503ff1ee548f2435ad9148d7fb94c9222b0908f445537a6667047f6d501c_cppui253,
                              0x104c88d6d0682d82d3d664826dc9565db101a220aa8f90572eb798468a82a2ab_cppui253}},
                            {{0x2caad6108c09ee6aee7851b4a2d2d3b7c3ca3c56a80003c8471f90bfa4ac628b_cppui253,
                              0xa57dbd4c327826c8a97bc7285f94bcddb966177346f1792c4bd7088aa0353f3_cppui253,
                              0x3c15552f9124318b8433d01bb53ba04ba1cc9eb91d83b918e32fea39fbe908fa_cppui253}},
                            {{0xe10c10cbbe1717a9441c6299c4fc087c222208bd4fa8f3be66d2075f623b513_cppui253,
                              0x1e8b254cbff2c92a83dff1728c81dd22a9570f590e497cb2d640042cb879a930_cppui253,
                              0x1812dbcd70c440610057bbfdd0cc4d31d1faf5786419b53841c4adc43f2b2352_cppui253}},
                        }};
                };

                template<std::size_t state_size, std::size_t rounds_amount>
                struct poseidon_constants<typename nil::crypto3::algebra::fields::vesta_base_field,
                                          state_size,
                                          rounds_amount> {
                    using FieldType = nil::crypto3::algebra::fields::vesta_base_field;

                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>,
                                                      state_size>
                        mds = {{
                            {{
                                0x3e28f7dd17f47a7e304a54d377dd7aeead6b92027d60baf300246cf023dd594e_cppui255,
                                0x30db06abb696fccb92b28ac214f4893d3fd84b3d4a9018754975e24477c32600_cppui255,
                                0x174110bc1b058c6016ff5e8152ab3ffb6e2e6c4d01e66aba302659c51b7f563a_cppui255,
                            }},
                            {{
                                0x12d36fa83503146980c05a1d48bcd50d2e9d4390e353a158a0fe387e2b4aeb0c_cppui255,
                                0x2ab17c8eb369bea76e9f0c385e8bafc71536bedc8e06d06fd65c1670e94d9c55_cppui255,
                                0xcc915328165c13986af127e108b9e5d9a60c5dc92e3e7636b8c3da5b4a8537_cppui255,
                            }},
                            {{
                                0x4d9a6d270696688eb4346153b380c613a3dcaf0fb5a1e8380409ae0a143d31b_cppui255,
                                0x2a805eee3317c8bae1f7d15abe4d27fee5fabcf9a3334d18b1932a33774c324_cppui255,
                                0x19b092e9c6dffd1eb1b6df2dbc00bb2283b9a787273dcbad9b8d89cd502b7bbd_cppui255,
                            }},
                        }};

                    constexpr static const std::array<std::array<typename FieldType::value_type, state_size>,
                                                      rounds_amount>
                        round_constant = {{
                            {{
                                0x590ef2a14ba3cef7e8f93a6dde4d481057d5d0547f6f09341b6b8be19c00ee6_cppui255,
                                0x77faa77ed78ff8b695859df34db5157f6b491567f5f382a8fce538f0e5ffe6f_cppui255,
                                0x3e54b7c94955c8994ed16ec9950d59aca4c9b6e419ef4935682528c2eba2de50_cppui255,
                            }},
                            {{
                                0x37d991dc8d4de3912355745c7d78f8b04516b14d30e29324bb5dd075ca0f0c1d_cppui255,
                                0xc0614dd1cff6c6817aff09d82ef828e80caed4da023823088fd021020f81f0e_cppui255,
                                0x3335e335a3fed44842359528b3e88e1824a173da819d7ee6905e82eed054243_cppui255,
                            }},
                            {{
                                0xb2202aa54d42f4f07693766723b9624c9fca4d33a2b9ee40f1c809a15a48a1d_cppui255,
                                0x290253e0e1d2c72b32a5b272137a0892b5934b0b8f26b4fc25ea00d63a70e9df_cppui255,
                                0x3e99873e73025d7c8b71fd209d13dba7a1021013f0815ea33a42ae94b63d00f3_cppui255,
                            }},
                            {{
                                0x164682f55ec314f639f5f8062a4ddf11ed80d5822591a22ff54f340d90165d85_cppui255,
                                0x309ba21093c9d04c81bd5273ad1064e1bd9067312d3269dddadf74c2eb1d3e01_cppui255,
                                0x159e72bb030cb8994b2eac1d4ee7d0f06b0b092e7611d460605b3d8c60a274d9_cppui255,
                            }},
                            {{
                                0xd743dbfc6f3c833ce2ef4956bead3c118fd3198652038781903ac929218fdd6_cppui255,
                                0x18cb5a9230eb74045ede834ac6dd129bd2a0462dca1d96d167b9be0e1e96a688_cppui255,
                                0x2d82f85fc222b215902d61c85c968b39759d6c2e9aa0e11fd08881bfae311e66_cppui255,
                            }},
                            {{
                                0x2920828be5972cb8ff8023386a90a837bbfcca99be240137f7d211ecb72521e6_cppui255,
                                0x3101774e1c3d72d010efb29c16c476e988bdb47321af3f82e05cc9c6b0360853_cppui255,
                                0x327b4e6353c099e41a8ffab9103996b9d29d07da0f1a191aa6fb55c0720c6f54_cppui255,
                            }},
                            {{
                                0x71c29018dd48d5c557379ea9d4afd80b92788ed509ced6bac47a65ba8b475c_cppui255,
                                0x25efdeef6c5ad56834b24cfe03d57360b4335ec902c78ee9348ebaceab726038_cppui255,
                                0x109ffe5cd918fcd7da7fdb40d32ac406f453874fda431c35c9e35601bcf708e9_cppui255,
                            }},
                            {{
                                0x1f4de5d78b4378e0eca49ed94999d8bc91489fadfd896c8affbaa6e2654d18bf_cppui255,
                                0x173185e1eaad0664ba1c01b8e417a4422c22a43d622c5df98c11481e205e499e_cppui255,
                                0x161a0e8b31a6fd42727dc0a37ae4f715683af35873bd37e78e10abcb0e21fabd_cppui255,
                            }},
                            {{
                                0x3decab3f42934acc644cc227315ecd6bcee79e5d92dc686823f60e6a3c40a7cd_cppui255,
                                0x29d7541d2a4fcdf9c7f144ce1e957a5e5c6d5d064618416817d0ad39708b2807_cppui255,
                                0x1d0525558685977d321fe86c05f462ae2e569e6d202bd5c62b0815320454114a_cppui255,
                            }},
                            {{
                                0x27d1aec0ccc80f71d09d2a9c0b76ee5fe9a87516f0e691a9f5fba360cb79f32_cppui255,
                                0x1c28ed68159e54df8296e654b0c1b5872de41557b7b02adc256dcc1600229ba8_cppui255,
                                0x15c9cbe29bf4e7d8bae22dd2213c86724e9944ea4b9e34b6681beb1b0972215e_cppui255,
                            }},
                            {{
                                0xd479e19db4686f5cb1ef9a8331a1ab680c5d3770e9a9a8a7a6ac58f8006c38a_cppui255,
                                0x3494f6ecf12d5c3d758c5380652154e26f7f3c888d362ea512da8dc265fc32b0_cppui255,
                                0x37ed9343bcc46adb4300f3d8cb88c311383061710836351ded0a146de837966_cppui255,
                            }},
                            {{
                                0x35548be14e1cbcbd7d2c0e8c4a95e5fc2893daba34197ef41c350ae7072cde4e_cppui255,
                                0x34e58327efe8d41b81b66b6c3fad424b2ff9008392909bb90eb10f08462b998b_cppui255,
                                0xf55c1223abf50500c4ac4103f679dcfea4eebb368cf64ef3a63ee27146846f_cppui255,
                            }},
                            {{
                                0x11dd4ab1734f7069498cc390a41b7de375d8968cec91b5c74cef9812e8ee7ce7_cppui255,
                                0x1e344f255d7c5e537439e75f9c4ea64dd1fda1b0988e5c83626055859369b43c_cppui255,
                                0x147db9afad2d2f7c4249357587faba99a6a38da16fe9ba74ef2f3fc5a0878f44_cppui255,
                            }},
                            {{
                                0x31774ce29d00f566bd499f181517df231be7205c05e7527d71a1c89cb0e841a7_cppui255,
                                0x32bdf60a6685665871f654169996f508be8710c99f3fa6f44a7bc4d2c25fbfd8_cppui255,
                                0x2f567f84ec13720611900c4b9e8303f04c8cc5c57daa4d95d9ee009514205e65_cppui255,
                            }},
                            {{
                                0x2dbd279621e591da57f54459f4160dde2f5c78e478d20f2f4763832e013bc07f_cppui255,
                                0x1275fb5ba53b7d2b5322e63f09a48026d684369c8e12241a808085a78ab3a369_cppui255,
                                0x1dd0beba925fe1df13f732b03287cad943569d62ec9059afc2c8120655e97d78_cppui255,
                            }},
                            {{
                                0xa37d78e392a5c8441f98e9dbd51a9151e78fb877885ecb885b0834c50cfea4d_cppui255,
                                0x1ebb7e2592122cd16d27e13410b2b48d520d8e99d38c1d86af0ac13565dfeb88_cppui255,
                                0x24a6454b0a69c59916d64f532b56226f8d49969432b7d0efc675f599c3bdb64f_cppui255,
                            }},
                            {{
                                0x269668b3e7835df2f85b82e9ef8647c43205e799135ce669256bf55f07448209_cppui255,
                                0x15c87375d4514bbdddbfd84e51f246446f1b16bb58bd4bd9fa2ff57e6aa66057_cppui255,
                                0x11ce62bbe1242334c260a67817be908a9422d9b9c6ee96c00772fcc8fc501db6_cppui255,
                            }},
                            {{
                                0x20348b7d6b381bfd3ac923d60b965086d281d8a654ad5f3210d277789641fe98_cppui255,
                                0x1398d090fd1144d1e84798e3a0efa942abfe650947e4a3cfa409ff14b541fae9_cppui255,
                                0x2461a1a2d6e3a0b2e5185ae6c844fe2a3b2d85dfb1cf891efc79ae80dd776bed_cppui255,
                            }},
                            {{
                                0x3e1f1de94c4af008188ba5eaef1da9ab9792ce54eda56bb5a519a65cd808885b_cppui255,
                                0x1dee6ead07fbc0fe883f4d397994d75ba3c4f90720e74ae2da13066bc3a7dc3b_cppui255,
                                0x287d06396bcb63555cb2ff408ea075cf402b10a3c608043d0cf2e3685ec6e2ad_cppui255,
                            }},
                            {{
                                0x36d84c953d584607478da6183dc4da71bdbf737d45fb57d5a53badc123ae071c_cppui255,
                                0x24c8fd13d2687a9f90c61da26823d4934b350cfa488d528482399e106a70ac74_cppui255,
                                0x52e052a6a493457c9476ccc4fd9924e5c7247b98e58a3cfa688c0f8314bea68_cppui255,
                            }},
                            {{
                                0x2fd32bae8a40ab498f6ba290733bb82504de1be782c1cdf039e2fbc843a01e52_cppui255,
                                0x4e8e7d3413c8c8ccfe154dc51f31c7682627c71fa4b50daab27f2a4d2623ea6_cppui255,
                                0x20c16d0097cebeb385508b606487baaf3bad515ba8a0b977f15cb50239418e38_cppui255,
                            }},
                            {{
                                0x34f1df6035aac75204368125b0c4cec107e2f9eb0005517d26d6113e1f366271_cppui255,
                                0x375973b59ed7b4bdb33642d20e6364f37a942f9018f6bca5abc10705481425e0_cppui255,
                                0x269e8c978803e51d43439b7c18c4260e819e09e7d8c8d38706463bbb811c698c_cppui255,
                            }},
                            {{
                                0x21be1913f874f3edb88a1f60cd157fcb76ff20b4eb139aae205b5a2764098782_cppui255,
                                0x37a0a8ba83db884f721c25027d188c7ab7c7840b7860675b33e1c93e4023927f_cppui255,
                                0x56d0e67fde779b7be5f308a3ce119e23e0503e6dabdbbd5189bb44dc6a6f0a4_cppui255,
                            }},
                            {{
                                0x144723436a329da5644cce96fee4952b066092c36bd12838b4ffd4283cfe82c4_cppui255,
                                0xec0b5f14ba50aa2b022d06fbb920a2aafb465b8c7f81fc119371a4cbb6acff7_cppui255,
                                0x685de18d9a346a35c44a2a4ac7283d6fe2e4a9dc058bd537700bc2495271721_cppui255,
                            }},
                            {{
                                0x178dcb74b546adea41afd5d93ef564cb3adb0ef5200201daea0faa5026bb8cbc_cppui255,
                                0x1c1dcb1ef6cf5f036ae0030bf78f1643c439843959dd74fa28ea3663735cc923_cppui255,
                                0xcfae6c99994c5f702cba3b32a4e38f3764207bfe7cd9bf577633b41843ea138_cppui255,
                            }},
                            {{
                                0x2838a02558716d2b49c06fb34c49cd820ec71e861caa935f4a303e42030ae3df_cppui255,
                                0x2c1944f3ec2852ed6b50fbc4abbc8f284797b36a23b321d2763ef48b1a5a0212_cppui255,
                                0x30a218acd109f04657954e82f9faccc477731f4a954cf8ac12d15ebd450e9dcb_cppui255,
                            }},
                            {{
                                0x2488defa4553fa5bd5afbb5fd28a1e99c585c5f541c6242e702215b2212c1d23_cppui255,
                                0x3d0c9d7282245c776daa1655697fa879e470a26fcbb3bea62fa8ff32a4f04e50_cppui255,
                                0x33aac46524f32f3556ed16a0912ef27482c2afcacbfb99ced98394b6c0e3765f_cppui255,
                            }},
                            {{
                                0x1858a5f543ab0a70cb3957e0884b146b42cc3863fba4e034145ab09cc77d428d_cppui255,
                                0x2d9d6fae68eff2e79396617207e28dba3d793b1e3739d30e9e9b10644e9f99cd_cppui255,
                                0x1747fab074b37cc1ca7dbf7d6dc136740f5d26e30319b3577fc8987f1247caae_cppui255,
                            }},
                            {{
                                0x38f905db5128f24e498e36a84df5a58ed3c0b0ed8f39336eb792cb634f86b87_cppui255,
                                0xfffe42ce4a87a0b3a9ebe7eedf16c0cdb29c959b6e594faa69c0727c6e825f_cppui255,
                                0x314c3090cd0a465da95afd515c0771703e4ee2a8eabe8fa405daf8bd49bce458_cppui255,
                            }},
                            {{
                                0x3e5fb71d9071c658c39fe64392e90bac65bdaf8f723b6790cce7dd7440ce06aa_cppui255,
                                0x3e9fe7b8fd0aaa379fa7be0dbd64309607cc5b00474ef6670370e631902e98cd_cppui255,
                                0x33ee4f76ff95bd735ec602ee6f4d1664caec27a7c435ead3b4c8df6cb51f010e_cppui255,
                            }},
                            {{
                                0x1670c2080f2965bed3f49db0b63aef5f562b347235645b921c0132b01cc82130_cppui255,
                                0x210565224e2ee64dd479be3a969dc30c65933352ba9b2271a0942bf1bf485743_cppui255,
                                0x9a7c6dd48dfbf50b13055b30fe85f934be9518b8af074b88f9de4b1df689616_cppui255,
                            }},
                            {{
                                0x1f9116811eaadf677e6cb50fb59ce0fab11fa9f0ddf1432403610e1932a7aa1c_cppui255,
                                0x19b51a48c225daf9b34611ccc5ba077ebbc0a19cfc9bbbd78ade11cfa655075f_cppui255,
                                0x3286d29eb60c3d6204eb534d13f40d1af6364f0fe1622a12ba5fa069886f31fe_cppui255,
                            }},
                            {{
                                0x9bd403d05db137ea793f10b6dd087a74a78c9b01bcd6f9daf39af2ef57d346e_cppui255,
                                0x3a71654023e43363e60889eac50eb1f17c044606886771eaaf851bb2d00b3aeb_cppui255,
                                0x3415b94f62c59466f102442b4bae7d6bb348987154cce16bd187525a6fb5b443_cppui255,
                            }},
                            {{
                                0x3ca35f0fc660092b81f15dd6f0b3d17a16a053480ef2f935fce806dd0d9a3466_cppui255,
                                0x26e1360af7fdc62e9be08651c2c5900ed5aefcb0d84b3aa88e354c6658a07863_cppui255,
                                0x30d05884174d7a1de9d34c89224d17f3b9dbdfb0793b54c0d2aaaeedcc357bd6_cppui255,
                            }},
                            {{
                                0x2c7f66f8b0580236f025dd626520049a09e1bfff0e5fd9f69cbc70daf0ac56c4_cppui255,
                                0xc5cb9a350d2dc463dd05dbd696e122c6917b76654180c323937dee44c6beb93_cppui255,
                                0x14d4d799d43d91b4d09d9c2bfdc13a64b48d18750503324361f9bf7267ec9b92_cppui255,
                            }},
                            {{
                                0x60c56a884cd6a1d3514f2895816b84e7160df5106e8d031710769be1ac5c04c_cppui255,
                                0x23e15f37c21266c86ead998a46e42f6e97fbd5d1c384f51d8b54d051a80d753d_cppui255,
                                0x25eb2911034ab6bef4a969653f5cc33e6914b8b6411f064ec01bcf157fea4e55_cppui255,
                            }},
                            {{
                                0x1e95c04c5057abd1b43a2fbc942b2391d0e0daef873838b3494e6d5fb067a117_cppui255,
                                0x1547602fc83558aa1327221fd220fa22bcb1f6ec42edb7cc05eff508c65883cb_cppui255,
                                0x16b669eac31e72a9e739fb03fd7ea3882fc5791b157143929ae12fc2fefe8b3d_cppui255,
                            }},
                            {{
                                0x7034f4e251a65c4423479dc9d5287a341c108e0b56e29a391f9a07a0ca822f1_cppui255,
                                0x3fdf9d5731ba040dc568e61b8571ea95ead2e89f0a9856b2d12a7e87e43f5683_cppui255,
                                0x33f2cdf6960139a0fb4a3a8127992e2abbd42847728425228a35ee72bd5b01c7_cppui255,
                            }},
                            {{
                                0x35616d55033d8fc092398f6c58bfc6eaaf2ec9dd500122516f489dbc631457b_cppui255,
                                0x1eca80189643df1473e98da93fe58a9576def0d192d4153faebcd1b210c1603f_cppui255,
                                0x26223ca4af2d8d878ca5530c3e67ff1c95b50b9c5b8295e19150bc31ef90ba98_cppui255,
                            }},
                            {{
                                0x19180fa5facb64ee9b4827ccd766622adf12fe80ab17c7395075368e10a2a361_cppui255,
                                0x169f165855e097501f25d6b3aae815ce6e8a1c289850936d956657f0ed99446_cppui255,
                                0x363a8f891de5974f06bae043bc6a26b4518d217af6590e9318e325fb215cda00_cppui255,
                            }},
                            {{
                                0x122aaa7c330ddcb57180749e659600a4dfac5dda7b9b68ab0f8b2ee6de350ced_cppui255,
                                0xed203defca13ebdf6af805a9f5dbdfef90007df2ad32fb1c83165e837ab5e3f_cppui255,
                                0x11cce94bbc7a96e9708e99d3666c0a275329ac4bff42634a5f989ddcfc28fd68_cppui255,
                            }},
                            {{
                                0x1705663587a03cb11485ac9d01fd10cb1138be1820d26a14e4ab7b1c0fdec8d2_cppui255,
                                0x12ad28a60485a2d911639051971f43dd15a0dfd2f8a0de756f0c847fed63ed7d_cppui255,
                                0xa9e61cc35eba9374eea117753aaaa93d6b29f550c2c54bce0a6078e05db9475_cppui255,
                            }},
                            {{
                                0x72c3d62cf006a95dc8b2a53f878bb26fcaf3c28d709a91634f3a09f525054ad_cppui255,
                                0x1ce8f168b446f7e797b91677fc46a975d2caa63dc359132c7c9729f5be24a7c_cppui255,
                                0xe846a7211efda3d8115b5bf76aab7eac2b6099026fc7504fb81ac4a77c5560d_cppui255,
                            }},
                            {{
                                0xabb8fd9d6fa3772022fa88800c12bdcbb1234473022cd141213d452255a0f55_cppui255,
                                0x1c5d9938bc35a4832e8375dc307dba7a116d2a566e406ab31e8b03a36ec807cf_cppui255,
                                0x35bea7ac6f40e0f50f08d325be9f051fd75ada8c03461f4d15b2c5e1a3d72431_cppui255,
                            }},
                            {{
                                0x419357c205a7e1e028c0f49cbdeab85b82f4db78f1afb1b5568ec1bd2e48cb0_cppui255,
                                0x1933e424c788e7466a159f1fe015ac7210f47044d9df6872cdfa227ae4d2190a_cppui255,
                                0xde27ccdda95abb3d98db76d6f7f152a08d37ba81758beaf2eddbc58d13e560f_cppui255,
                            }},
                            {{
                                0x35a312d5d6cbf00d55f097febaf9bd5eac5f2881ebf0afa377e2ba7cdcf2f51_cppui255,
                                0xce6f415449ca515e4da9177527c9242adcc988de5e1846d07cdd5284f39f9d0_cppui255,
                                0x38fd71543da5c4c0447dc22aa2c1e3744cb84eb1ff17040640b50f5ddf8c8e61_cppui255,
                            }},
                            {{
                                0x158de859aad53c6a17de455ab067a09ad6cba22f4101d19e77d8a2975c0dc965_cppui255,
                                0x2c300588eeae8cbc3814bd1d7646f472ef6b44a60c710bf6100937504e532c8b_cppui255,
                                0xb198cf742a029409ac02397b91e2704fa94ecf147909fa8d71ece5087e2cfc3_cppui255,
                            }},
                            {{
                                0x100b375c21d357d5679d8e6d9eb7bff8edd4575535bf651ba0b1bd83cfb54598_cppui255,
                                0x15a474d44590e2b23b8bb1e79f5613f1659e7ae2bce10def0ce1a101eb3e3ce5_cppui255,
                                0x2aa20e6642a989e1e6f9814c24f022991c23a7e40af505d4b931079025b7ed4d_cppui255,
                            }},
                            {{
                                0x196597f2d65c5692706795bf46eb7be96b31647c23441213642ccceedc01ebc4_cppui255,
                                0x248291aa516daa0a6cd191c1c651a82f7d1b5f087dcb7cee91a27c488483e2bd_cppui255,
                                0x36c02b98ad2722b774aeb131b31bfd087c6a7f2d0a3faa40bd9899e5f270877f_cppui255,
                            }},
                            {{
                                0x1240e06949a1ad92bd8ae90772b5d8505174182c87a23227aa74b7630dba4195_cppui255,
                                0x3b83f7e36f30939a78ec63cb2554aa0669a1bfc1b8b8714c6b8a3958beb6a163_cppui255,
                                0x1668b0582ce04f7f5b1e35e1b7cc3e05be23cc2c9e0be9436559193f2a8d102e_cppui255,
                            }},
                            {{
                                0x26d6a708e9464c85e9c7605e87fb96036fd1fe87379ac43ad560885582e4026d_cppui255,
                                0x594fccf1863993b43ad0a13c5fc7a53f59f7d622e7b206d425907243a69e62d_cppui255,
                                0x78e4c588b6ddd0fe7ed53a9f25b6ac3c2eac1c63faecc7e916f4d4599051940_cppui255,
                            }},
                            {{
                                0xf44ea3e14c3e4849ee7a525fe77170b8658a6753680e269c9fd1d12932af69d_cppui255,
                                0x2e8567bc9e8e369bdf7748d6c7f677837c601455d4651a2f102b94ff1f951379_cppui255,
                                0x37c35b056171982cc7d74e6081fcac2f764f1fe30ee985db306a22b097d51bae_cppui255,
                            }},
                            {{
                                0x29dbcffd5b55d671c85ca42037ac5e64d2ef42d2704af47a20877e3a5e5f1d9d_cppui255,
                                0x201098422e054c1ddcc465411d002d2bc5a824e1c7f4f2ded9443c37bd04a520_cppui255,
                                0x7de32ed4c5143430ef43aef100f948ef859ab3793aa52640156f5e7d92cdc84_cppui255,
                            }},
                            {{
                                0x34e95adcc0c5c34fd38ab9246a04cc1029f678ba53c0f6fd27f8805094e36199_cppui255,
                                0x1d5faf157126c599232982356ca0ea7b81d875c01d842b5cd1998a5c470fa623_cppui255,
                                0x160a80176bd281e3fa9b82e44063cc7bf86eb81397e51e41fe4745e27c57e1d2_cppui255,
                            }},
                            {{
                                0x17ecc7f5deb148c542a22d02b098439724910a3bbd4903428c8fc680f31b2406_cppui255,
                                0x20a6aae17f822bc7035da3b8931896c82152346f2a43ab4e0029dbf0101b3d_cppui255,
                                0x9ea0ec10c0e77b9385a58ccd5ecc3c88b5bed58af72a6d87bb446e14fa7c8d6_cppui255,
                            }},
                        }};
                };

            }    // namespace detail
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP
