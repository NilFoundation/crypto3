//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_KECCAK_PADDING_HPP
#define CRYPTO3_KECCAK_PADDING_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename Hash>
                class keccak_1600_padding {
                    typedef Hash policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    typedef ::nil::crypto3::detail::injector<stream_endian::big_octet_little_bit, word_bits,
                                                             block_words, block_bits>
                        injector_type;

                    bool is_last;

                public:
                    keccak_1600_padding() : is_last(true) {
                    }

                    bool is_last_block() const {
                        return is_last;
                    }

                    void operator()(block_type &block, std::size_t &block_seen) {
                        using namespace nil::crypto3::detail;

                        if ((block_bits - block_seen) > 1) {
                            // try to handle bit NIST tests
                            /*if (block_seen % octet_bits) {
                                pack<stream_endian::big_octet_big_bit, stream_endian::big_octet_little_bit,
                                word_bits, word_bits>(block.begin(), block.end(), block.begin());
                            }*/
                            // pad 1
                            injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 1), 7), 1, block,
                                                  block_seen);
                            // pad 0*
                            block_type zeros;
                            std::fill(zeros.begin(), zeros.end(), 0);
                            injector_type::inject(zeros, block_bits - 1 - block_seen, block, block_seen);
                            // pad 1
                            injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 1), 7), 1, block,
                                                  block_seen);
                        }

                        else {
                            is_last = false;
                            block[block_words - 1] &= ~high_bits<word_bits>(~word_type(), 1);
                        }
                    }

                    void process_last(block_type &block, std::size_t &block_seen) {
                        using namespace nil::crypto3::detail;

                        // pad 0*
                        block_type zeros;
                        std::fill(zeros.begin(), zeros.end(), 0);
                        injector_type::inject(zeros, block_bits - 1, block, block_seen);
                        // pad 1
                        injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 1), 7), 1, block,
                                              block_seen);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_PADDING_HPP
