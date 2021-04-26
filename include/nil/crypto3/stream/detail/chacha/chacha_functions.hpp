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

#ifndef CRYPTO3_STREAM_CHACHA_FUNCTIONS_HPP
#define CRYPTO3_STREAM_CHACHA_FUNCTIONS_HPP

#include <boost/predef/architecture.h>

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
#include <nil/crypto3/stream/detail/chacha/chacha_avx2_impl.hpp>
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
#include <nil/crypto3/stream/detail/chacha/chacha_sse2_impl.hpp>
#else
#include <nil/crypto3/stream/detail/chacha/chacha_impl.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Round, std::size_t IVSize, std::size_t KeyBits>
                struct chacha_functions : public chacha_policy<Round, IVSize, KeyBits> {
                    typedef chacha_policy<Round, IVSize, KeyBits> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, IVSize, KeyBits> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, IVSize, KeyBits> impl_type;
#else
                    typedef detail::chacha_impl<Round, IVSize, KeyBits> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::sigma()[0];
                        schedule[1] = policy_type::sigma()[1];
                        schedule[2] = policy_type::sigma()[2];
                        schedule[3] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 2 * 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round, std::size_t IVSize>
                struct chacha_functions<Round, IVSize, 128> : public chacha_policy<Round, IVSize, 128> {
                    typedef chacha_policy<Round, IVSize, 128> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, IVSize, 128> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, IVSize, 128> impl_type;
#else
                    typedef detail::chacha_impl<Round, IVSize, 128> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::tau()[0];
                        schedule[1] = policy_type::tau()[1];
                        schedule[2] = policy_type::tau()[2];
                        schedule[3] = policy_type::tau()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 2 * 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round>
                struct chacha_functions<Round, 64, 128> : public chacha_policy<Round, 64, 128> {
                    typedef chacha_policy<Round, 64, 128> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, 64, 128> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, 64, 128> impl_type;
#else
                    typedef detail::chacha_impl<Round, 64, 128> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        schedule[12] = 0;
                        schedule[13] = 0;
                        schedule[14] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[15] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));

                        impl_type::chacha_x<4>(block, schedule);
                    }

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::tau()[0];
                        schedule[1] = policy_type::tau()[1];
                        schedule[2] = policy_type::tau()[2];
                        schedule[3] = policy_type::tau()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 2 * 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round>
                struct chacha_functions<Round, 96, 128> : public chacha_policy<Round, 96, 128> {
                    typedef chacha_policy<Round, 96, 128> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, 96, 128> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, 96, 128> impl_type;
#else
                    typedef detail::chacha_impl<Round, 96, 128> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        schedule[12] = 0;
                        schedule[13] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[14] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));
                        schedule[15] = boost::endian::native_to_little(make_uint_t(iv[8], iv[9], iv[10], iv[11]));

                        impl_type::chacha_x<4>(block, schedule);
                    }

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::tau()[0];
                        schedule[1] = policy_type::tau()[1];
                        schedule[2] = policy_type::tau()[2];
                        schedule[3] = policy_type::tau()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 2 * 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round, std::size_t IVSize>
                struct chacha_functions<Round, IVSize, 256> : public chacha_policy<Round, IVSize, 256> {

                    typedef chacha_policy<Round, IVSize, 256> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, IVSize, 256> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, IVSize, 256> impl_type;
#else
                    typedef detail::chacha_impl<Round, IVSize, 256> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::sigma()[0];
                        schedule[1] = policy_type::sigma()[1];
                        schedule[2] = policy_type::sigma()[2];
                        schedule[3] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 8; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round>
                struct chacha_functions<Round, 64, 256> : public chacha_policy<Round, 64, 256> {

                    typedef chacha_policy<Round, 64, 256> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, 64, 256> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, 64, 256> impl_type;
#else
                    typedef detail::chacha_impl<Round, 64, 256> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        schedule[12] = 0;
                        schedule[13] = 0;
                        schedule[14] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[15] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));

                        impl_type::chacha_x<4>(block, schedule);
                    }

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::sigma()[0];
                        schedule[1] = policy_type::sigma()[1];
                        schedule[2] = policy_type::sigma()[2];
                        schedule[3] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 8; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };

                template<std::size_t Round>
                struct chacha_functions<Round, 96, 256> : public chacha_policy<Round, 96, 256> {

                    typedef chacha_policy<Round, 96, 256> policy_type;

#if defined(CRYPTO3_HAS_CHACHA_AVX2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_AVX2_VERSION
                    typedef detail::chacha_avx2_impl<Round, 96, 256> impl_type;
#elif defined(CRYPTO3_HAS_CHACHA_SSE2) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSE2_VERSION
                    typedef detail::chacha_sse2_impl<Round, 96, 256> impl_type;
#else
                    typedef detail::chacha_impl<Round, 96, 256> impl_type;
#endif

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    static void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        schedule[12] = 0;
                        schedule[13] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[14] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));
                        schedule[15] = boost::endian::native_to_little(make_uint_t(iv[8], iv[9], iv[10], iv[11]));

                        impl_type::chacha_x<4>(block, schedule);
                    }

                    static void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::sigma()[0];
                        schedule[1] = policy_type::sigma()[1];
                        schedule[2] = policy_type::sigma()[2];
                        schedule[3] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 8; itr++) {
                            schedule[itr + 4] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 0], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHACHA_FUNCTIONS_HPP
