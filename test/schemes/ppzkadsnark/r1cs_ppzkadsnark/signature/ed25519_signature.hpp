//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_ED25519SIG_HPP
#define CRYPTO3_ZK_ED25519SIG_HPP

#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_signature.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                class ed25519_sigT {
                public:
                    unsigned char sig_bytes[64];
                };

                class ed25519_vkT {
                public:
                    unsigned char vk_bytes[32];
                };

                class ed25519_skT {
                public:
                    unsigned char sk_bytes[64];
                };

                template<>
                kpT<default_r1cs_ppzkadsnark_pp> sigGen<default_r1cs_ppzkadsnark_pp>(void) {
                    kpT<default_r1cs_ppzkadsnark_pp> keys;
                    crypto_sign_ed25519_amd64_51_30k_keypair(keys.vk.vk_bytes, keys.sk.sk_bytes);
                    return keys;
                }

                template<>
                ed25519_sigT
                    sigSign<default_r1cs_ppzkadsnark_pp>(const ed25519_skT &sk, const label_type &label,
                                                         const snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type &Lambda) {
                    ed25519_sigT sigma;
                    unsigned long long sigmalen;
                    unsigned char signature[64 + 16 + 320];
                    unsigned char message[16 + 320];

                    snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type Lambda_copy = Lambda.to_affine();

                    for (std::size_t i = 0; i < 16; i++)
                        message[i] = label.label_bytes[i];

                    // More efficient way to get canonical point rep?
                    std::stringstream stream;
                    stream.rdbuf()->pubsetbuf(((char *)message) + 16, 320);
                    stream << Lambda_copy;
                    std::size_t written = stream.tellp();
                    while (written < 320)
                        message[16 + written++] = 0;

                    crypto_sign_ed25519_amd64_51_30k(signature, &sigmalen, message, 16 + 320, sk.sk_bytes);

                    assert(sigmalen == 64 + 16 + 320);

                    for (std::size_t i = 0; i < 64; i++)
                        sigma.sig_bytes[i] = signature[i];

                    return sigma;
                }

                template<>
                bool sigVerif<default_r1cs_ppzkadsnark_pp>(const ed25519_vkT &vk, const label_type &label,
                                                           const snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type &Lambda,
                                                           const ed25519_sigT &sig) {
                    unsigned long long msglen;
                    unsigned char message[64 + 16 + 320];
                    unsigned char signature[64 + 16 + 320];

                    snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type Lambda_copy = Lambda.to_affine();

                    for (std::size_t i = 0; i < 64; i++)
                        signature[i] = sig.sig_bytes[i];

                    for (std::size_t i = 0; i < 16; i++)
                        signature[64 + i] = label.label_bytes[i];

                    // More efficient way to get canonical point rep?
                    std::stringstream stream;
                    stream.rdbuf()->pubsetbuf(((char *)signature) + 64 + 16, 320);
                    stream << Lambda_copy;
                    std::size_t written = stream.tellp();
                    while (written < 320)
                        signature[64 + 16 + written++] = 0;

                    int res =
                        crypto_sign_ed25519_amd64_51_30k_open(message, &msglen, signature, 64 + 16 + 320, vk.vk_bytes);
                    return (res == 0);
                }

                template<>
                bool sigBatchVerif<default_r1cs_ppzkadsnark_pp>(
                    const ed25519_vkT &vk, const std::vector<label_type> &labels,
                    const std::vector<snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type> &Lambdas,
                    const std::vector<ed25519_sigT> &sigs) {
                    std::stringstream stream;

                    assert(labels.size() == Lambdas.size());
                    assert(labels.size() == sigs.size());

                    unsigned long long msglen[labels.size()];
                    unsigned long long siglen[labels.size()];
                    unsigned char *messages[labels.size()];
                    unsigned char *signatures[labels.size()];
                    unsigned char *pks[labels.size()];

                    unsigned char pk_copy[32];
                    for (std::size_t i = 0; i < 32; i++) {
                        pk_copy[i] = vk.vk_bytes[i];
                    }

                    unsigned char *messagemem = (unsigned char *)malloc(labels.size() * (64 + 16 + 320));
                    assert(messagemem != NULL);
                    unsigned char *signaturemem = (unsigned char *)malloc(labels.size() * (64 + 16 + 320));
                    assert(signaturemem != NULL);

                    for (std::size_t i = 0; i < labels.size(); i++) {
                        siglen[i] = 64 + 16 + 320;
                        messages[i] = messagemem + (64 + 16 + 320) * i;
                        signatures[i] = signaturemem + (64 + 16 + 320) * i;
                        pks[i] = pk_copy;

                        for (std::size_t j = 0; j < 64; j++)
                            signaturemem[i * (64 + 16 + 320) + j] = sigs[i].sig_bytes[j];

                        for (std::size_t j = 0; j < 16; j++)
                            signaturemem[i * (64 + 16 + 320) + 64 + j] = labels[i].label_bytes[j];

                        // More efficient way to get canonical point rep?
                        snark_pp<default_r1cs_ppzkadsnark_pp>::g2_type Lambda_copy = Lambdas[i].to_affine();
                        stream.clear();
                        stream.rdbuf()->pubsetbuf((char *)(signaturemem + i * (64 + 16 + 320) + 64 + 16), 320);
                        stream << Lambda_copy;
                        std::size_t written = stream.tellp();
                        while (written < 320)
                            signaturemem[i * (64 + 16 + 320) + 64 + 16 + written++] = 0;
                    }

                    int res = crypto_sign_ed25519_amd64_51_30k_open_batch(messages, msglen, signatures, siglen, pks,
                                                                          labels.size());

                    return (res == 0);
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_ED25519SIG_HPP
