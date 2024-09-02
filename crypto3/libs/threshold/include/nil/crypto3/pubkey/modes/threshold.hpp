//---------------------------------------------------------------------------//
// Copyright (c) 2019-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP
#define CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP

#include <nil/crypto3/pubkey/modes/detail/threshold_scheme.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/modes/part_public_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme>
                struct threshold_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                };

                template<typename Scheme>
                struct threshold_signing_policy : public threshold_policy<Scheme> {
                    typedef typename threshold_policy<Scheme>::scheme_type scheme_type;

                    typedef private_key<scheme_type> key_type;
                    typedef void op_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename key_type::part_signature_type result_type;

                    template<typename... Args>
                    static inline void init_accumulator(const key_type &key, Args &...args) {
                        key.init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                        key.update(args...);
                    }

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.sign(args...);
                    }
                };

                template<typename Scheme>
                struct threshold_verification_policy : public threshold_policy<Scheme> {
                    typedef typename threshold_policy<Scheme>::scheme_type scheme_type;

                    typedef public_key<scheme_type> key_type;
                    typedef void op_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef bool result_type;

                    template<typename... Args>
                    static inline void init_accumulator(const key_type &key, Args &...args) {
                        key.init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                        key.update(args...);
                    }

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.verify(args...);
                    }
                };

                template<typename Scheme>
                struct threshold_part_verification_policy : public threshold_policy<Scheme> {
                    typedef typename threshold_policy<Scheme>::scheme_type scheme_type;

                    typedef part_public_key<scheme_type> key_type;
                    typedef void op_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef bool result_type;

                    template<typename... Args>
                    static inline void init_accumulator(const key_type &key, Args &...args) {
                        key.init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                        key.update(args...);
                    }

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.part_verify(args...);
                    }
                };

                template<typename Scheme>
                struct threshold_aggregation_policy : public threshold_policy<Scheme> {
                    typedef typename threshold_policy<Scheme>::scheme_type scheme_type;

                    typedef void key_type;
                    typedef aggregate_op<scheme_type> op_type;
                    typedef typename op_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename op_type::signature_type result_type;

                    template<typename... Args>
                    static inline void init_accumulator(Args &...args) {
                        op_type::init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(Args &...args) {
                        op_type::update(args...);
                    }

                    template<typename... Args>
                    static inline result_type process(Args &...args) {
                        return op_type::aggregate(args...);
                    }
                };

                template<typename Policy>
                class threshold {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::scheme_type scheme_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::op_type op_type;
                    typedef typename policy_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename policy_type::result_type result_type;

                    template<typename... Args>
                    static inline void init_accumulator(Args &...args) {
                        policy_type::init_accumulator(args...);
                    }

                    template<typename... Args>
                    inline static void update(Args &...args) {
                        policy_type::update(args...);
                    }

                    template<typename... Args>
                    inline static result_type process(Args &...args) {
                        return policy_type::process(args...);
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
                template<typename BaseScheme, template<typename> class SecretSharingScheme>
                struct threshold {
                    typedef nil::crypto3::pubkey::detail::threshold_scheme<BaseScheme, SecretSharingScheme> scheme_type;

                    typedef detail::threshold_signing_policy<scheme_type> signing_policy;
                    typedef detail::threshold_verification_policy<scheme_type> verification_policy;
                    typedef detail::threshold_part_verification_policy<scheme_type> part_verification_policy;
                    typedef detail::threshold_aggregation_policy<scheme_type> aggregation_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::threshold<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP
