//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_RANDOM_HASH_BASED_ALGEBRAIC_ENGINE_HPP
#define CRYPTO3_RANDOM_HASH_BASED_ALGEBRAIC_ENGINE_HPP

#include <type_traits>
#include <vector>
#include <array>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/algebra/marshalling.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace random {
            template<typename Hash, typename ResultType, typename = void>
            struct hash;

            // TODO: replace pack with marshaling
            template<typename Hash, typename ResultType>
            struct hash<
                Hash,
                ResultType,
                typename std::enable_if<
                    algebra::is_field<typename ResultType::field_type>::value &&
                    !algebra::is_extended_field<typename ResultType::field_type>::value &&
                    (ResultType::field_type::value_bits <= Hash::digest_bits)>::type> {
                typedef Hash hash_type;
                typedef ResultType result_type;
                typedef std::uint64_t input_type;

                hash() {
                    seed();
                }

                hash(const hash &other) {
                    seed(other.state);
                    if (other.cached) {
                        cache = other.cache;
                        cached = true;
                    }
                }

                hash(input_type x) {
                    seed(x);
                }

                inline void seed() {
                    seed(0);
                }

                inline void seed(input_type x) {
                    state = x;
                    cached = false;
                }

                inline result_type operator()() {
                    using bincode = ::nil::marshalling::field_bincode<typename result_type::field_type>;

                    if (cached) {
                        return cache;
                    }

                    input_type iter = 0;
                    std::array<std::uint8_t, 2 * sizeof(input_type)> seed_bytes;
                    typename hash_type::digest_type res;
                    typename result_type::field_type::modulus_type result;
                    do {
                        ::nil::crypto3::detail::pack<stream_endian::little_byte_big_bit,
                                                     stream_endian::big_byte_big_bit,
                                                     sizeof(input_type) * 8,
                                                     8>(
                            std::vector<input_type> {
                                state,
                                iter,
                            },
                            seed_bytes);
                        res = ::nil::crypto3::hash<hash_type>(seed_bytes);
                        ::nil::crypto3::multiprecision::import_bits(
                            result, res.begin(), res.begin() + bincode::modulus_chunks, 8, false);

                        ++iter;
                    } while (result >= result_type::field_type::modulus);
                    cache = result;
                    cached = true;

                    return cache;
                }

                inline void discard(std::size_t n) {
                    if (n > 0 && !cached) {
                        operator()();
                    }
                }

                inline bool operator==(const hash &other) const {
                    return state == other.state;
                }

                inline bool operator!=(const hash &other) const {
                    return !(*this == other);
                }

                template<typename OS, typename HashT, typename ResultT>
                friend OS &operator<<(OS &, const hash<HashT, ResultT> &);

                template<typename IS, typename HashT, typename ResultT>
                friend IS &operator>>(IS &, hash<HashT, ResultT> &);

            protected:
                input_type state;
                result_type cache;
                bool cached;
            };

            template<typename OS, typename Hash, typename ResultType>
            OS &operator<<(OS &os, const hash<Hash, ResultType> &e) {
                os << e.state;
                return os;
            }

            template<typename IS, typename HashT, typename ResultT>
            IS &operator>>(IS &is, hash<HashT, ResultT> &e) {
                typename hash<HashT, ResultT>::input_type x;
                is >> x;
                e.seed(x);
                return is;
            }
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RANDOM_HASH_BASED_ALGEBRAIC_ENGINE_HPP
