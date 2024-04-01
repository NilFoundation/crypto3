//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

#ifndef CRYPTO3_HASH_BLOCK_CACHE_HPP
#define CRYPTO3_HASH_BLOCK_CACHE_HPP

#include <nil/crypto3/detail/inject.hpp>


namespace nil {
    namespace crypto3 {
        namespace hashes {

            template <typename BlockType, typename WordType, std::size_t WordBits, std::size_t BlockWords, typename EndianType>
            class block_cache {
                public:
                    void append(WordType word, const std::size_t inject_bits_n, const std::size_t word_offset = 0) {
                        if (inject_bits_n > block_bits_ - filled_bits_n_) {
                            return;
                        }

                        // TODO: move these optimizations to injector
                        if (is_word_alligned() && word_offset == 0) {
                            storage_[filled_bits_n_ / WordBits] = word;
                            filled_bits_n_ += inject_bits_n;
                        } else {
                            injector_type::inject(word, inject_bits_n, storage_, filled_bits_n_, word_offset);
                        }
                    }

                    void append(const BlockType& block, const std::size_t inject_bits_n, const std::size_t block_offset = 0) {
                        if (inject_bits_n > block_bits_ - filled_bits_n_) {
                            return;
                        }

                        if (is_empty() && block_offset == 0) {
                            storage_ = block;
                            filled_bits_n_ = inject_bits_n;
                        } else {
                            if (is_word_alligned() && block_offset % WordBits == 0) {
                                std::size_t block_offset_words = block_offset / WordBits;
                                std::copy(
                                    block.begin() + block_offset_words,
                                    block.begin() + block_offset_words + inject_bits_n / WordBits + (inject_bits_n % WordBits ? 1 : 0),
                                    storage_.begin() + filled_bits_n_/WordBits
                                );

                                filled_bits_n_ += inject_bits_n;
                            } else {
                                injector_type::inject(block, inject_bits_n, storage_, filled_bits_n_, block_offset);
                            }
                        }
                    }

                    const BlockType& get_block() const {
                        return storage_;
                    }

                    BlockType& get_block() {
                        return storage_;
                    }

                    void clean() {
                        filled_bits_n_ = 0;
                    }

                    bool is_full() const {
                        return filled_bits_n_ == block_bits_;
                    }

                    bool is_empty() const {
                        return filled_bits_n_ == 0;
                    }

                    std::size_t bits_used() const {
                        return filled_bits_n_;
                    }

                    std::size_t capacity() const {
                        return block_bits_;
                    }

                    bool is_word_alligned() const {
                        return filled_bits_n_ % WordBits == 0;
                    }

                private:
                    static constexpr std::size_t block_bits_ = WordBits * BlockWords;
                    using injector_type = nil::crypto3::detail::injector<EndianType, EndianType, WordBits, BlockWords>;

                    BlockType storage_ = BlockType();
                    std::size_t filled_bits_n_ = 0;
            };

            template <typename BlockType, typename WordType, std::size_t BlockWords>
            class algebra_block_cache {
                public:
                    void append(WordType word) {
                        if (is_full()) {
                            return;
                        }
                        storage_[filled_words_n_++] = word;
                    }

                    void append(const BlockType& block, const std::size_t words_n_to_append, const std::size_t block_offset_words = 0) {
                        if (words_n_to_append > BlockWords - filled_words_n_) {
                            return;
                        }

                        if (is_empty() && block_offset_words == 0) {
                            storage_ = block;
                        } else {
                            std::copy(
                                block.begin() + block_offset_words,
                                block.begin() + block_offset_words + words_n_to_append,
                                storage_.begin() + filled_words_n_
                            );

                        }
                        filled_words_n_ += words_n_to_append;
                    }

                    const BlockType& get_block() const {
                        return storage_;
                    }

                    BlockType& get_block() {
                        return storage_;
                    }

                    void clean() {
                        filled_words_n_ = 0;
                    }

                    bool is_full() const {
                        return filled_words_n_ == BlockWords;
                    }

                    bool is_empty() const {
                        return filled_words_n_ == 0;
                    }

                    std::size_t words_used() const {
                        return filled_words_n_;
                    }

                    std::size_t capacity() const {
                        return filled_words_n_;
                    }

                private:
                    BlockType storage_ = BlockType();
                    std::size_t filled_words_n_ = 0;
                };

        }    // hashes
    }    // crypto3
}    // nil

#endif // CRYPTO3_HASH_BLOCK_CACHE_HPP
