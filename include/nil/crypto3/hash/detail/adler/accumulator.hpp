//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ADLER_ACCUMULATOR_HPP
#define CRYPTO3_ADLER_ACCUMULATOR_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits>
            class adler;
        }

        namespace accumulators {
            namespace impl {
                template<typename Hash>
                struct hash_impl;

                /*!
                 * @brief
                 * @tparam DigestBits
                 * @note Adler hash-specific non-caching accumulator.
                 */
                template<std::size_t DigestBits>
                struct hash_impl<hash::adler<DigestBits>> : boost::accumulators::accumulator_base {
                protected:
                    typedef hash::adler<DigestBits> hash_type;
                    typedef typename hash_type::construction_type construction_type;

                    constexpr static const std::size_t word_bits = construction_type::word_bits;
                    typedef typename construction_type::word_type word_type;

                    constexpr static const std::size_t state_bits = construction_type::state_bits;
                    constexpr static const std::size_t state_words = construction_type::state_words;
                    typedef typename construction_type::state_type state_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                public:
                    typedef typename hash_type::digest_type result_type;

                    // The constructor takes an argument pack.
                    template<typename ArgumentPack>
                    hash_impl(const ArgumentPack &args) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample], args[bits | std::size_t()]);
                    }

                    template<typename ArgumentPack>
                    inline result_type result(const ArgumentPack &args) const {
                        return construction.digest();
                    }

                protected:
                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, word_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, block_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    template<typename InputIterator,
                             typename = typename std::enable_if<
                                 ::nil::crypto3::detail::is_iterator<InputIterator>::value>::type>
                    inline void resolve_type(InputIterator p, std::size_t bits) {
                        construction(p, p + bits / word_bits);
                    }

                    inline void process(const word_type &value, std::size_t bits) {
                        construction(value);
                    }

                    inline void process(const block_type &block, std::size_t bits) {
                        construction(std::begin(block), std::end(block));
                    }

                    construction_type construction;
                };
            }    // namespace impl
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ADLER_ACCUMULATOR_HPP
