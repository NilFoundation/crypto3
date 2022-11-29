//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_CRC_ACCUMULATOR_HPP
#define CRYPTO3_CRC_ACCUMULATOR_HPP

#include <boost/crc.hpp>
#include <boost/static_assert.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

// Boost.CRC undefs this, so re-define it
#if !(defined(BOOST_NO_DEPENDENT_TYPES_IN_TEMPLATE_VALUE_PARAMETERS) || (defined(BOOST_MSVC) && (BOOST_MSVC <= 1300)))
#define BOOST_CRC_PARM_TYPE typename ::boost::uint_t<DigestBits>::fast
#else
#define BOOST_CRC_PARM_TYPE unsigned long
#endif

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<std::size_t DigestBits, BOOST_CRC_PARM_TYPE TruncPoly, BOOST_CRC_PARM_TYPE InitRem,
                     BOOST_CRC_PARM_TYPE FinalXor, bool ReflectIn, bool ReflectRem>
            class crc;

        }
        namespace accumulators {
            namespace impl {
                template<typename Hash, typename>
                struct hash_impl;

                /*!
                 * @brief
                 * @tparam DigestBits
                 * @tparam TruncPoly
                 * @tparam InitRem
                 * @tparam FinalXor
                 * @tparam ReflectIn
                 * @tparam ReflectRem
                 *
                 * @note CRC hash-specific accumulator. Be careful.
                 */
                template<std::size_t DigestBits, BOOST_CRC_PARM_TYPE TruncPoly, BOOST_CRC_PARM_TYPE InitRem,
                         BOOST_CRC_PARM_TYPE FinalXor, bool ReflectIn, bool ReflectRem>
                struct hash_impl<hashes::crc<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem>>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef hashes::crc<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem> hash_type;
                    typedef typename hash_type::construction::type construction_type;

                    constexpr static const std::size_t value_bits = construction_type::value_bits;
                    typedef typename construction_type::value_type value_type;

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
                    inline void resolve_type(const value_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, value_bits);
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
                        construction(p, p + bits / value_bits);
                    }

                    inline void process(const value_type &value, std::size_t bits) {
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

#endif    // CRYPTO3_CRC_ACCUMULATOR_HPP
