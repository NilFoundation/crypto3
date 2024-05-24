//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_SCHEME_MODES_HPP
#define CRYPTO3_PUBKEY_SCHEME_MODES_HPP

#include <type_traits>

#include <nil/crypto3/pubkey/keys/agreement_key.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_op.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_verify_op.hpp>
#include <nil/crypto3/pubkey/operations/aggregate_verify_single_msg_op.hpp>
#include <nil/crypto3/pubkey/operations/deal_shares_op.hpp>
#include <nil/crypto3/pubkey/operations/verify_share_op.hpp>
#include <nil/crypto3/pubkey/operations/reconstruct_secret_op.hpp>
#include <nil/crypto3/pubkey/operations/reconstruct_public_secret_op.hpp>
#include <nil/crypto3/pubkey/operations/deal_share_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme>
                struct isomorphic_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                };

                template<typename Scheme>
                struct isomorphic_signing_policy : public isomorphic_policy<Scheme> {
                    typedef typename isomorphic_policy<Scheme>::scheme_type scheme_type;

                    typedef private_key<scheme_type> key_type;
                    typedef void op_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename key_type::signature_type result_type;

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
                struct isomorphic_verification_policy : public isomorphic_policy<Scheme> {
                    typedef typename isomorphic_policy<Scheme>::scheme_type scheme_type;

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

                template<typename Op>
                struct isomorphic_operation_policy : public isomorphic_policy<typename Op::scheme_type> {
                    typedef typename isomorphic_policy<typename Op::scheme_type>::scheme_type scheme_type;

                    typedef void key_type;
                    typedef Op op_type;
                    typedef typename op_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename op_type::result_type result_type;

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
                        return op_type::process(args...);
                    }
                };

                template<typename Scheme>
                struct isomorphic_pop_proving_policy : public isomorphic_policy<Scheme> {
                    typedef typename isomorphic_policy<Scheme>::scheme_type scheme_type;

                    typedef private_key<scheme_type> key_type;
                    typedef void op_type;
                    // TODO: refactor internal_accumulator_type
                    typedef bool internal_accumulator_type;
                    typedef typename key_type::signature_type result_type;

                    template<typename... Args>
                    static inline void init_accumulator(const key_type &key, Args &...args) {
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                    }

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.pop_prove();
                    }
                };

                template<typename Scheme>
                struct isomorphic_pop_verification_policy : public isomorphic_policy<Scheme> {
                    typedef typename isomorphic_policy<Scheme>::scheme_type scheme_type;

                    typedef public_key<scheme_type> key_type;
                    typedef void op_type;
                    // TODO: refactor internal_accumulator_type
                    typedef bool internal_accumulator_type;
                    typedef bool result_type;

                    template<typename... Args>
                    static inline void init_accumulator(const key_type &key, Args &...args) {
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                    }

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.pop_verify(args...);
                    }
                };

                template<typename Policy>
                class isomorphic {
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
                template<typename Scheme>
                struct isomorphic {
                    typedef Scheme scheme_type;

                    typedef detail::isomorphic_signing_policy<scheme_type> signing_policy;
                    typedef detail::isomorphic_verification_policy<scheme_type> verification_policy;
                    typedef detail::isomorphic_operation_policy<aggregate_op<scheme_type>> aggregation_policy;
                    typedef detail::isomorphic_operation_policy<aggregate_verify_op<scheme_type>>
                        aggregate_verification_policy;
                    typedef detail::isomorphic_operation_policy<aggregate_verify_single_msg_op<scheme_type>>
                        single_msg_aggregate_verification_policy;
                    typedef detail::isomorphic_pop_proving_policy<scheme_type> pop_proving_policy;
                    typedef detail::isomorphic_pop_verification_policy<scheme_type> pop_verification_policy;
                    typedef detail::isomorphic_operation_policy<deal_shares_op<scheme_type>> shares_dealing_policy;
                    typedef detail::isomorphic_operation_policy<verify_share_op<scheme_type>> share_verification_policy;
                    typedef detail::isomorphic_operation_policy<reconstruct_secret_op<scheme_type>>
                        secret_reconstructing_policy;
                    typedef detail::isomorphic_operation_policy<reconstruct_public_secret_op<scheme_type>>
                        public_secret_reconstructing_policy;
                    typedef detail::isomorphic_operation_policy<deal_share_op<scheme_type>> share_dealing_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::isomorphic<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SCHEME_MODES_HPP
