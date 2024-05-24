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

#ifndef CRYPTO3_MAC_PROCESSING_POLICIES_HPP
#define CRYPTO3_MAC_PROCESSING_POLICIES_HPP

#include <type_traits>

#include <nil/crypto3/mac/mac_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename Mac>
                struct basic_policy {
                    typedef std::size_t size_type;

                    typedef Mac mac_type;
                };

                template<typename Mac>
                struct computation_policy : public basic_policy<Mac> {
                    typedef typename basic_policy<Mac>::mac_type mac_type;

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
                struct verification_policy : public basic_policy<Mac> {
                    typedef typename basic_policy<Mac>::mac_type mac_type;

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
            }    // namespace detail

            /*!
             * @defgroup mac_processing_policies Mac Modes
             * @brief
             *
             * @defgroup mac_processing_policies
             * @ingroup mac_processing_policies
             *
             * @tparam Mac
             */
            template<typename Mac, template<typename> class Padding>
            struct processing_policies {
                typedef Mac mac_type;
                // TODO: refactor padding concept
                typedef Padding<Mac> padding_type;

                typedef detail::computation_policy<mac_type> computation_policy;
                typedef detail::verification_policy<mac_type> verification_policy;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_PROCESSING_POLICIES_HPP
