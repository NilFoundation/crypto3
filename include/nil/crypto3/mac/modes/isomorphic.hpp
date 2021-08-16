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

#ifndef CRYPTO3_MAC_SCHEME_MODES_HPP
#define CRYPTO3_MAC_SCHEME_MODES_HPP

#include <type_traits>

#include <nil/crypto3/mac/mac_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename Mac>
                struct isomorphic_policy {
                    typedef std::size_t size_type;

                    typedef Mac mac_type;
                };

                template<typename Mac>
                struct isomorphic_computation_policy : public isomorphic_policy<Mac> {
                    typedef typename isomorphic_policy<Mac>::mac_type mac_type;

                    typedef mac_key<mac_type> key_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename key_type::digest_type result_type;

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.compute(args...);
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                        key.update(args...);
                    }

                    template<typename... Args>
                    inline static void init_accumulator(const key_type &key, Args &...args) {
                        key.init_accumulator(args...);
                    }
                };

                template<typename Mac>
                struct isomorphic_verification_policy : public isomorphic_policy<Mac> {
                    typedef typename isomorphic_policy<Mac>::mac_type mac_type;

                    typedef mac_key<mac_type> key_type;
                    typedef typename key_type::internal_accumulator_type internal_accumulator_type;
                    typedef bool result_type;

                    template<typename... Args>
                    static inline result_type process(const key_type &key, Args &...args) {
                        return key.verify(args...);
                    }

                    template<typename... Args>
                    inline static void update(const key_type &key, Args &...args) {
                        key.update(args...);
                    }

                    template<typename... Args>
                    inline static void init_accumulator(const key_type &key, Args &...args) {
                        key.init_accumulator(args...);
                    }
                };

                template<typename Policy>
                class isomorphic {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::mac_type mac_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::internal_accumulator_type internal_accumulator_type;
                    typedef typename policy_type::result_type result_type;

                    template<typename... Args>
                    inline static result_type process(Args &...args) {
                        return policy_type::process(args...);
                    }

                    template<typename... Args>
                    inline static void update(Args &...args) {
                        policy_type::update(args...);
                    }

                    template<typename... Args>
                    inline static void init_accumulator(Args &...args) {
                        policy_type::init_accumulator(args...);
                    }
                };
            }    // namespace detail

            namespace modes {
                /*!
                 * @defgroup mac_modes Mac Modes
                 * @brief
                 *
                 * @defgroup mac_modes
                 * @ingroup mac_modes
                 * @brief
                 */

                /*!
                 * @brief
                 * @tparam Mac
                 */
                template<typename Mac, template<typename> class Padding>
                struct isomorphic {
                    typedef Mac mac_type;
                    // TODO: refactor padding concept
                    typedef Padding<Mac> padding_type;

                    typedef detail::isomorphic_computation_policy<mac_type> computation_policy;
                    typedef detail::isomorphic_verification_policy<mac_type> verification_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::isomorphic<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_SCHEME_MODES_HPP
