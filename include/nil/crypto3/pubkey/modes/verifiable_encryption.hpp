//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_VERIFIABLE_ENCRYPTION_MODE_HPP
#define CRYPTO3_PUBKEY_VERIFIABLE_ENCRYPTION_MODE_HPP

#include <type_traits>

#include <nil/crypto3/pubkey/keys/agreement_key.hpp>
#include <nil/crypto3/pubkey/keys/verification_key.hpp>

#include <nil/crypto3/pubkey/operations/generate_keypair_op.hpp>
#include <nil/crypto3/pubkey/operations/encrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/decrypt_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_encryption_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_decryption_op.hpp>
#include <nil/crypto3/pubkey/operations/rerandomize_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, template<typename, typename = void> class Operation>
                struct verifiable_encryption {
                    typedef Scheme scheme_type;

                    typedef Operation<scheme_type> op_type;
                    typedef typename op_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename op_type::result_type result_type;

                    template<typename... Args>
                    static inline internal_accumulator_type init_accumulator(Args &...args) {
                        return op_type::init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(Args &...args) {
                        op_type::update(args...);
                    }

                    template<typename... Args>
                    static inline result_type process(Args &...args) {
                        return op_type::process(args...);
                    }
                };
            }    // namespace detail

            namespace modes {
                /*!
                 * @defgroup scheme_modes Scheme Modes
                 * @brief
                 *
                 * @defgroup pubkey_scheme_modes Public Key Cryptography Schemes Modes
                 * @ingroup scheme_modes
                 * @brief
                 */

                /*!
                 * @brief
                 * @tparam Scheme
                 */
                template<typename Scheme>
                struct verifiable_encryption {
                    typedef Scheme scheme_type;

                    typedef detail::verifiable_encryption<scheme_type, generate_keypair_op> keypair_generation_policy;
                    typedef detail::verifiable_encryption<scheme_type, encrypt_op> encryption_policy;
                    typedef detail::verifiable_encryption<scheme_type, decrypt_op> decryption_policy;
                    typedef detail::verifiable_encryption<scheme_type, verify_encryption_op>
                        encryption_verification_policy;
                    typedef detail::verifiable_encryption<scheme_type, verify_decryption_op>
                        decryption_verification_policy;
                    typedef detail::verifiable_encryption<scheme_type, rerandomize_op>
                        rerandomization_policy;
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_VERIFIABLE_ENCRYPTION_MODE_HPP
