//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_STREAM_PROCESSOR_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_STREAM_PROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>
#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>
#include <nil/crypto3/hash/accumulators/parameters/salt.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {

            /*!
             * @brief This will do the usual Merkle-Damgård-style strengthening,
             * padding with a 1 bit, then 0 bits as needed, then, if requested,
             * the length.
             *
             * @tparam Hash
             * @tparam StateAccumulator
             * @tparam Params
             */
            template<typename Construction, typename StateAccumulator, typename Params>
            class merkle_damgard_stream_processor {
            protected:
                typedef typename Construction::type construction_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                constexpr static const std::size_t word_bits = construction_type::word_bits;

                constexpr static const std::size_t block_bits = construction_type::block_bits;
                typedef typename construction_type::block_type block_type;

            public:
                typedef typename params_type::endian endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(word_bits % value_bits == 0);
                constexpr static const std::size_t block_values = block_bits / value_bits;
                typedef std::array<value_type, block_values> value_array_type;

            protected:
                constexpr static const std::size_t length_bits = params_type::length_bits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                    length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;

                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);
                BOOST_STATIC_ASSERT(block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                inline void process_block(std::size_t bb = block_bits) {
                    using namespace nil::crypto3::detail;

                    // Convert the input into words
                    block_type block;
                    pack<endian_type, value_bits, word_bits>(value_array, block);

                    // Process the block
                    acc(block, accumulators::bits = bb);
                }

            public:
                merkle_damgard_stream_processor &update_one(value_type value) {
                    //std::cout << "Value bits one:" << value_bits << "\n";
                    value_array[cache_size] = value;
                    ++cache_size;
                    if (cache_size == block_values) {
                        // Process the completed block
                        process_block();
                        cache_size = 0;
                    }
                    return *this;
                }

                merkle_damgard_stream_processor &update_last() {
                    process_block(cache_size * value_bits);
                    cache_size = 0;
                    return *this;
                }

                template<typename InputIterator>
                merkle_damgard_stream_processor &update_n(InputIterator p, size_t n) {
                    for (; n; --n) {
                        update_one(*p++)
                    }
                        
                    return *this;
                }

                template<typename InputIterator>
                inline merkle_damgard_stream_processor &operator()(InputIterator b, InputIterator e,
                                                                   std::random_access_iterator_tag) {
                     while (b != e) {
                        update_one(*b++);
                    }

                    return update_last();
                    //return update_n(b, e - b).end_message();
                }

                template<typename InputIterator, typename Category>
                inline merkle_damgard_stream_processor &operator()(InputIterator b, InputIterator e, Category) {
                    while (b != e) {
                        update_one(*b++);
                    }

                    return update_last();
                }

                template<typename InputIterator>
                inline merkle_damgard_stream_processor &operator()(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return operator()(b, e, cat());
                }

                template<typename ContainerT>
                inline merkle_damgard_stream_processor &operator()(const ContainerT &c) {
                    return update_n(c.data(), c.size());
                }


            public:
                merkle_damgard_stream_processor(accumulator_type &acc) :
                    acc(acc), value_array(), cache_size(0) {
                }

                virtual ~merkle_damgard_stream_processor() {
                    //                    using namespace nil::crypto3::detail;
                    //
                    //                    // Convert the input into words
                    //                    block_type block;
                    //                    pack<endian_type, value_bits, word_bits>(value_array, block);
                    //
                    //                    // Process the block
                    //                    std::size_t bb = block_bits;
                    //                    acc(block, accumulators::bits = bb);
                }

                void reset() {
                    cache_size = 0;
                }

            private:
                accumulator_type &acc;

                value_array_type value_array;
                length_type cache_size;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
