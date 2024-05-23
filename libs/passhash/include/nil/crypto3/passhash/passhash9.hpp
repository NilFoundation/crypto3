//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PASSHASH_PASSHASH9_HPP
#define CRYPTO3_PASSHASH_PASSHASH9_HPP

#include <nil/crypto3/passhash/detail/passhash9/passhash9_policy.hpp>

#include <string>
#include <climits>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            struct pbkdf2;
        }

        namespace passhash {
            struct passhash9_params {
                constexpr static const std::size_t workfactor_bits = 2 * CHAR_BIT;
                constexpr static const std::size_t workfactor_scale = 1000;

                constexpr static const std::size_t salt_bits = 12 * CHAR_BIT;
                constexpr static const std::size_t algid_bits = CHAR_BIT;
                constexpr static const std::size_t pbkdf_output_bits = 192;

                constexpr static const char *prefix = "$9$";
            };

            /**
             * PBKDF2-based password hashing technique called passhash9 is also provided.
             *
             * Passhash9 hashes look like:
             * "$9$AAAKxwMGNPSdPkOKJS07Xutm3+1Cr3ytmbnkjO6LjHzCMcMQXvcT"
             *
             * @ingroup passhash
             *
             * @note This function should be secure with the proper parameters, and will remain in
             * the library for the forseeable future, but it is specific to the library rather than
             * being a widely used password hash. Prefer bcrypt.
             *
             * @warning This password format string ("$9$") conflicts with the format used
             * for scrypt password hashes on Cisco systems.
             */
            template<typename MessageAuthenticationCode, std::size_t Workfactor = 10,
                     typename PasswordBasedKeyDerivationFunction = pbkdf::pbkdf2,
                     typename ParamsType = passhash9_params>
            class passhash9 {
                typedef detail::passhash9_policy<MessageAuthenticationCode, Workfactor, ParamsType> policy_type;

            public:
                typedef typename policy_type::mac_type mac_type;
                typedef typename policy_type::pbkdf_type pbkdf_type;

                /*!
                 * @brief Create a password hash using PBKDF2
                 *
                 * The work factor must be greater than zero and less than 512.
                 * This performs 10000 * ``work_factor`` PBKDF2 iterations, using
                 * 96 bits of salt taken from ``rng``. Using work factor of 10 or
                 * more is recommended.
                 *
                 * @tparam UniformRandomGenerator
                 *
                 * @param password the password
                 * @param rng a random number generator
                 * @param work_factor how much work to do to slow down guessing attacks
                 * @param alg_id specifies which PRF to use with PBKDF2
                 *        0 is HMAC(SHA-1)
                 *        1 is HMAC(SHA-256)
                 *        2 is CMAC(Blowfish)
                 *        3 is HMAC(SHA-384)
                 *        4 is HMAC(SHA-512)
                 *        all other values are currently undefined
                 */
                template<typename UniformRandomGenerator>
                static void generate(const std::string &password, UniformRandomGenerator &rng, uint8_t alg_id = 1) {
                    std::unique_ptr<MessageAuthenticationCode> prf = get_pbkdf_prf(alg_id);

                    if (!prf) {
                        throw std::invalid_argument("Passhash9: Algorithm id " + std::to_string(alg_id) +
                                                    " is not defined");
                    }

                    PKCS5_PBKDF2 kdf(prf.release());    // takes ownership of pointer

                    secure_vector<uint8_t> salt(SALT_BYTES);
                    rng.randomize(salt.data(), salt.size());

                    const size_t kdf_iterations = WORK_FACTOR_SCALE * Workfactor;

                    secure_vector<uint8_t> blob;
                    blob.push_back(alg_id);
                    blob.push_back(extract_uint_t<CHAR_BIT>(Workfactor, 0));
                    blob.push_back(extract_uint_t<CHAR_BIT>(Workfactor, 1));
                    blob += salt;
                    blob += kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN, pass, salt.data(), salt.size(), kdf_iterations)
                                .bits_of();

                    return MAGIC_PREFIX + base64_encode(blob);
                }

                /*!
                 * @brief Check a previously created password hash
                 * @param password the password to check against
                 * @param hash the stored hash to check against
                 * @return
                 */
                static bool check(const std::string &pass, const std::string &hash) {
                    const size_t BINARY_LENGTH =
                        ALGID_BYTES + WORKFACTOR_BYTES + PASSHASH9_PBKDF_OUTPUT_LEN + SALT_BYTES;

                    const size_t BASE64_LENGTH = MAGIC_PREFIX.size() + (BINARY_LENGTH * 8) / 6;

                    if (hash.size() != BASE64_LENGTH) {
                        return false;
                    }

                    for (size_t i = 0; i != MAGIC_PREFIX.size(); ++i) {
                        if (hash[i] != MAGIC_PREFIX[i]) {
                            return false;
                        }
                    }

                    secure_vector<uint8_t> bin = base64_decode(hash.c_str() + MAGIC_PREFIX.size());

                    if (bin.size() != BINARY_LENGTH) {
                        return false;
                    }

                    uint8_t alg_id = bin[0];

                    const size_t work_factor = load_be<uint16_t>(&bin[ALGID_BYTES], 0);

                    // Bug in the format, bad states shouldn't be representable, but are...
                    if (work_factor == 0) {
                        return false;
                    }

                    if (work_factor > 512) {
                        throw std::invalid_argument("Requested passhash9 work factor " + std::to_string(work_factor) +
                                                    " is too large");
                    }

                    const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;

                    std::unique_ptr<MessageAuthenticationCode> pbkdf_prf = get_pbkdf_prf(alg_id);

                    if (!pbkdf_prf) {
                        return false;
                    }    // unknown algorithm, reject

                    PKCS5_PBKDF2 kdf(pbkdf_prf.release());    // takes ownership of pointer

                    secure_vector<uint8_t> cmp =
                        kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN, pass, &bin[ALGID_BYTES + WORKFACTOR_BYTES],
                                       SALT_BYTES, kdf_iterations)
                            .bits_of();

                    return constant_time_compare(cmp.data(), &bin[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES],
                                                 PASSHASH9_PBKDF_OUTPUT_LEN);
                }
            };
        }    // namespace passhash
    }        // namespace crypto3
}    // namespace nil

#endif
