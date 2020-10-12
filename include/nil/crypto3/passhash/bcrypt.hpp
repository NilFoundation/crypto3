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

#ifndef CRYPTO3_PASSHASH_BCRYPT_HPP
#define CRYPTO3_PASSHASH_BCRYPT_HPP

#include <nil/crypto3/passhash/detail/bcrypt/bcrypt_functions.hpp>

#include <nil/crypto3/utilities/types.hpp>

#include <string>

namespace nil {
    namespace crypto3 {
        namespace block {
            class blowfish;
        }
        namespace passhash {
            /*!
             * @brief Bcrypt is a password hashing scheme originally designed for
             * use in OpenBSD, but numerous other implementations exist.
             *
             * It has the advantage that it requires a small amount (4K) of fast
             * RAM to compute, which can make hardware password cracking somewhat
             * more expensive.
             * Bcrypt provides outputs that look like this:
             * "$2a$12$7KIYdyv8Bp32WAvc.7YvI.wvRlyVn0HP/EhPmmOyMQA4YKxINO0p2"
             *
             * @note Due to the design of bcrypt, the password is effectively
             * truncated at 72 characters; further characters are ignored and do
             * not change the hash. To support longer passwords, one common
             * approach is to pre-hash the password with SHA-256, then run
             * bcrypt using the hex or base64 encoding of the hash as
             * the password. (Many bcrypt implementations truncate the password
             * at the first NULL character, so hashing the raw binary SHA-256
             * may cause problems. Provided bcrypt implementation will hash
             * whatever values are given in the incoming Container including any
             * embedded NULLs so this is not an issue, but might cause interop
             * problems if another library needs to validate the password hashes.)
             *
             * @ingroup passhash
             *
             * @tparam BlockCipher
             * @see https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf
             */
            template<typename BlockCipher = block::blowfish>
            class bcrypt {
                typedef detail::bcrypt_functions<BlockCipher> policy_type;

            public:
                typedef typename policy_type::cipher_type cipher_type;

                /*!
                 * @brief Takes the password to hash, a rng, and a work factor.
                 * The resulting password hash is returned as a string.
                 *
                 * Higher work factors increase the amount of time the algorithm runs,
                 * increasing the cost of cracking attempts. The increase is exponential, so a
                 * work factor of 12 takes roughly twice as long as work factor 11. The default
                 * work factor was set to 10 up until the 2.8.0 release.
                 * It is recommended to set the work factor as high as your system can tolerate
                 * (from a performance and latency perspective) since higher workfactors greatly
                 * improve the security against GPU-based attacks.  For example, for protecting
                 * high value administrator passwords, consider using work factor 15 or 16; at
                 * these work factors each bcrypt computation takes several seconds. Since admin
                 * logins will be relatively uncommon, it might be acceptable for each login
                 * attempt to take some time. As of 2018, a good password cracking rig (with 8
                 * NVIDIA 1080 cards) can attempt about 1 billion bcrypt computations per month
                 * for work factor 13. For work factor 12, it can do twice as many.  For work
                 * factor 15, it can do only one quarter as many attempts.
                 *
                 * Due to bugs affecting various implementations of bcrypt, several different
                 * variants of the algorithm are defined. As of 2.7.0 Botan supports generating
                 * (or checking) the 2a, 2b, and 2y variants.  Since Botan has never been
                 * affected by any of the bugs which necessitated these version upgrades, all
                 * three versions are identical beyond the version identifier.
                 * Which variant to use is controlled by the ``bcrypt_version`` argument.
                 *
                 * The bcrypt work factor must be at least 4 (though at this work factor bcrypt
                 * is not very secure). The bcrypt format allows up to 31, but Botan currently
                 * rejects all work factors greater than 18 since even that work factor requires
                 * roughly 15 seconds of computation on a fast machine.
                 *
                 * @param pass
                 * @param salt
                 * @param work_factor
                 */
                static void generate(const std::string &pass, const std::vector<uint8_t> &salt, uint16_t work_factor) {
                    // Include the trailing NULL byte, so we need c_str() not data()
                    blowfish.eks_key_schedule(cast_char_ptr_to_uint8(pass.c_str()), pass.length() + 1, salt.data(),
                                              work_factor);

                    std::vector<uint8_t> ctext(BCRYPT_MAGIC, BCRYPT_MAGIC + 8 * 3);

                    for (size_t i = 0; i != 64; ++i) {
                        blowfish.encrypt_n(ctext.data(), ctext.data(), 3);
                    }

                    std::string salt_b64 = bcrypt_base64_encode(salt.data(), salt.size());

                    std::string work_factor_str = std::to_string(work_factor);
                    if (work_factor_str.length() == 1) {
                        work_factor_str = "0" + work_factor_str;
                    }

                    return "$2a$" + work_factor_str + "$" + salt_b64.substr(0, 22)
                           + bcrypt_base64_encode(ctext.data(), ctext.size() - 1);
                }

                /*!
                 * @brief Takes a password and a bcrypt output and returns true if the
                 * password is the same as the one that was used to generate the bcrypt hash.
                 * @param pass
                 * @param hash
                 * @return
                 */
                static bool check(const std::string &pass, const std::string &hash) const {
                    if (hash.size() != 60 || hash[0] != '$' || hash[1] != '2' || hash[2] != 'a' || hash[3] != '$'
                        || hash[6] != '$') {
                        return false;
                    }

                    const uint16_t workfactor = to_uint16(hash.substr(4, 2));

                    const std::vector<uint8_t> salt = bcrypt_base64_decode(hash.substr(7, 22));
                    if (salt.size() != 16) {
                        return false;
                    }

                    const std::string compare = generate(pass, salt, workfactor);

                    return same_mem(hash.data(), compare.data(), compare.size());
                }
            };
        }    // namespace passhash

        /**
         * Create a password hash using Bcrypt
         * @param password the password
         * @param rng a random number generator
         * @param work_factor how much work to do to slow down guessing attacks
         *
         * @see https://www.usenix.org/events/usenix99/provos/provos_html/
         */
        template<typename UniformRandomGenerator>
        std::string generate_bcrypt(const std::string &password, UniformRandomGenerator &rng,
                                    uint16_t work_factor = 10) {
            return make_bcrypt(password, unlock(rng.random_vec(16)), work_factor);
        }

        /**
         * Check a previously created password hash
         * @param password the password to check against
         * @param hash the stored hash to check against
         */
        bool check_bcrypt(const std::string &password, const std::string &hash);
    }    // namespace crypto3
}    // namespace nil

#endif
