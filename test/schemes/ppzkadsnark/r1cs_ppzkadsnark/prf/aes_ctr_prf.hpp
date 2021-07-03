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

#ifndef CRYPTO3_ZK_AESCTRPRF_HPP
#define CRYPTO3_ZK_RUN_R1CS_MP_PPZKPCD_HPP

#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/prf.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                class aesPrfKeyT {
                public:
                    unsigned char key_bytes[32];
                };

                template<>
                aesPrfKeyT prfGen<default_r1cs_ppzkadsnark_pp>() {
                    aesPrfKeyT key;
                    randombytes(key.key_bytes, 32);
                    return key;
                }

                template<>
                algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>
                    prfCompute<default_r1cs_ppzkadsnark_pp>(const aesPrfKeyT &key, const label_type &label) {
                    unsigned char seed_bytes[16];
                    mpz_t aux, Fr_mod;
                    unsigned char random_bytes[16 * 3];
                    std::size_t exp_len;

                    mpz_init(aux);
                    mpz_init(Fr_mod);

                    // compute random seed using AES as PRF
                    crypto_core_aes128encrypt_openssl(seed_bytes, label.label_bytes, key.key_bytes, NULL);

                    // use first 128 bits of output to seed AES-CTR
                    // PRG to expand to 3*128 bits
                    crypto_core_aes128encrypt_openssl(random_bytes, seed_bytes, key.key_bytes + 16, NULL);

                    mpz_import(aux, 16, 0, 1, 0, 0, seed_bytes);
                    mpz_add_ui(aux, aux, 1);
                    mpz_export(seed_bytes, &exp_len, 0, 1, 0, 0, aux);
                    while (exp_len < 16)
                        seed_bytes[exp_len++] = 0;

                    crypto_core_aes128encrypt_openssl(random_bytes + 16, seed_bytes, key.key_bytes + 16, NULL);

                    mpz_add_ui(aux, aux, 1);
                    mpz_export(seed_bytes, &exp_len, 0, 1, 0, 0, aux);
                    while (exp_len < 16)
                        seed_bytes[exp_len++] = 0;

                    crypto_core_aes128encrypt_openssl(random_bytes + 32, seed_bytes, key.key_bytes + 16, NULL);

                    // see output as integer and reduce modulo r
                    mpz_import(aux, 16 * 3, 0, 1, 0, 0, random_bytes);
                    algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>::mod.to_mpz(Fr_mod);
                    mpz_mod(aux, aux, Fr_mod);

                    return algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>(
                        algebra::bigint<algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>::num_limbs>(aux));
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_RUN_R1CS_MP_PPZKPCD_HPP
