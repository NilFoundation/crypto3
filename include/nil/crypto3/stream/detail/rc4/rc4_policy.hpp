//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_RC4_POLICY_HPP
#define CRYPTO3_STREAM_RC4_POLICY_HPP

#include <memory>

#include <nil/crypto3/stream/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t IVBits, std::size_t KeyBits, template<typename> class Allocator = std::allocator>
                struct rc4_policy : public basic_functions<32> {
                    typedef typename basic_functions<32>::byte_type byte_type;
                    typedef typename basic_functions<32>::word_type word_type;

                    constexpr static const std::size_t min_key_bits = CHAR_BIT;
                    constexpr static const std::size_t max_key_bits = 256 * CHAR_BIT;
                    constexpr static const std::size_t key_bits = KeyBits;
                    constexpr static const std::size_t key_size = key_bits / CHAR_BIT;
                    BOOST_STATIC_ASSERT(min_key_bits <= KeyBits && KeyBits <= max_key_bits);
                    typedef std::array<byte_type, key_size> key_type;

                    constexpr static const std::size_t key_schedule_size = 256;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_size * CHAR_BIT;
                    typedef std::array<byte_type, key_schedule_size> key_schedule_type;

                    constexpr static const std::size_t state_size = 256;
                    constexpr static const std::size_t state_bits = state_size * CHAR_BIT;
                    struct state_type {
                        std::size_t x = 0, y = 0;
                        std::array<byte_type, state_size> data = {0};

                        BOOST_FORCEINLINE void fill(const byte_type &v) {
                            data.fill(v);
                        }

                        BOOST_FORCEINLINE byte_type &operator[](std::size_t i) {
                            return data[i];
                        }

                        BOOST_FORCEINLINE const byte_type &operator[](std::size_t i) const {
                            return data[i];
                        }

                        BOOST_FORCEINLINE std::size_t size() const {
                            return data.size();
                        }
                    };

                    constexpr static const std::size_t iv_bits = IVBits;
                    constexpr static const std::size_t iv_size = IVBits / CHAR_BIT;
                    typedef std::array<byte_type, iv_size> iv_type;
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RC4_POLICY_HPP
