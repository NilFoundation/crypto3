///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_MP_CPP_INT_CORE_HPP
#define BOOST_MP_CPP_INT_CORE_HPP

#include <boost/integer.hpp>
#include <boost/integer_traits.hpp>
#include <boost/assert.hpp>

#ifdef TVM
#include <mask_int/mask_int.hpp>
#endif

#ifdef __EVM__
#define NIL_THROW(...) std::abort()
#else
#define NIL_THROW(...) throw __VA_ARGS__
#endif

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            namespace detail {

                //
                // These traits calculate the largest type in the list
                // [unsigned] boost::long_long_type, long, int, which has the specified number
                // of bits.  Note that intN_t and boost::int_t<N> find the first
                // member of the above list, not the last.  We want the last in the
                // list to ensure that mixed arithmetic operations are as efficient
                // as possible.
                //
                template<unsigned N>
                struct largest_signed_type {
                    using type = typename std::conditional<
                        1 + std::numeric_limits<boost::long_long_type>::digits == N, boost::long_long_type,
                        typename std::conditional<
                            1 + std::numeric_limits<long>::digits == N, long,
                            typename std::conditional<1 + std::numeric_limits<int>::digits == N, int,
                                                      typename boost::int_t<N>::exact>::type>::type>::type;
                };

                template<unsigned N>
                struct largest_unsigned_type {
                    using type = typename std::conditional<
                        std::numeric_limits<boost::ulong_long_type>::digits == N, boost::ulong_long_type,
                        typename std::conditional<
                            std::numeric_limits<unsigned long>::digits == N, unsigned long,
                            typename std::conditional<std::numeric_limits<unsigned int>::digits == N, unsigned int,
                                                      typename boost::uint_t<N>::exact>::type>::type>::type;
                };

            }    // namespace detail
#ifdef __EVM__
            using limb_type = __uint128_t;
            using signed_limb_type = __int128_t;
            using double_limb_type = __uint256_t;
            using signed_double_limb_type = __int256_t;

            constexpr const unsigned bits_per_limb = 128;
            constexpr const unsigned limb_size = sizeof(double_limb_type);

            constexpr const limb_type limb_value_max = ~static_cast<limb_type>(0u);

            constexpr const limb_type max_block_10 = 1000000000000000000uLL;
            constexpr const limb_type digits_per_block_10 = 18;

            inline BOOST_MP_CXX14_CONSTEXPR limb_type block_multiplier(unsigned count) {
                constexpr const limb_type values[digits_per_block_10] = {10,
                                                                         100,
                                                                         1000,
                                                                         10000,
                                                                         100000,
                                                                         1000000,
                                                                         10000000,
                                                                         100000000,
                                                                         1000000000,
                                                                         10000000000,
                                                                         100000000000,
                                                                         1000000000000,
                                                                         10000000000000,
                                                                         100000000000000,
                                                                         1000000000000000,
                                                                         10000000000000000,
                                                                         100000000000000000,
                                                                         1000000000000000000};

                BOOST_ASSERT(count < digits_per_block_10);
                return values[count];
            }
#elif defined(TVM)
            using namespace mask_int;
            using limb_type = mask_uint128;
            using signed_limb_type = mask_int128;
            using double_limb_type = mask_uint256;
            using signed_double_limb_type = mask_int256;


            constexpr const unsigned bits_per_limb = 128;
            constexpr const limb_type limb_value_max = limb_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            constexpr const unsigned limb_size = sizeof(limb_type);


            constexpr const limb_type max_block_10 = limb_type(100000000000000000000000000000000000000);
            constexpr const unsigned int digits_per_block_10 = 38;

            inline unsigned int block_multiplier(unsigned count) {
                constexpr const unsigned int values[digits_per_block_10] = {
                    10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000, 1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000, 10000000000000000000, 100000000000000000000, 1000000000000000000000, 10000000000000000000000, 100000000000000000000000, 1000000000000000000000000, 10000000000000000000000000, 100000000000000000000000000, 1000000000000000000000000000, 10000000000000000000000000000, 100000000000000000000000000000, 1000000000000000000000000000000, 10000000000000000000000000000000, 100000000000000000000000000000000, 1000000000000000000000000000000000, 10000000000000000000000000000000000, 100000000000000000000000000000000000, 1000000000000000000000000000000000000, 10000000000000000000000000000000000000, 100000000000000000000000000000000000000};
                BOOST_ASSERT(count < digits_per_block_10);
                return values[count];
            }
#elif defined(BOOST_HAS_INT128)

            using limb_type = detail::largest_unsigned_type<64>::type;
            using signed_limb_type = detail::largest_signed_type<64>::type;
            using double_limb_type = boost::uint128_type;
            using signed_double_limb_type = boost::int128_type;
            constexpr const limb_type max_block_10 = 1000000000000000000uLL;
            constexpr const limb_type digits_per_block_10 = 18;

            constexpr const unsigned bits_per_limb = 64;
            constexpr const unsigned limb_size = sizeof(limb_type);
            constexpr const limb_type limb_value_max = ~static_cast<limb_type>(0u);

            inline BOOST_MP_CXX14_CONSTEXPR limb_type block_multiplier(unsigned count) {
                constexpr const limb_type values[digits_per_block_10] = {10,
                                                                         100,
                                                                         1000,
                                                                         10000,
                                                                         100000,
                                                                         1000000,
                                                                         10000000,
                                                                         100000000,
                                                                         1000000000,
                                                                         10000000000,
                                                                         100000000000,
                                                                         1000000000000,
                                                                         10000000000000,
                                                                         100000000000000,
                                                                         1000000000000000,
                                                                         10000000000000000,
                                                                         100000000000000000,
                                                                         1000000000000000000};
                BOOST_ASSERT(count < digits_per_block_10);
                return values[count];
            }

// Can't do formatted IO on an __int128
#define BOOST_MP_NO_DOUBLE_LIMB_TYPE_IO

            // Need to specialise integer_traits for __int128 as it's not a normal native type:
        }
    }
}    // namespace nil::crypto3::multiprecision

namespace boost {
    template<>
    class integer_traits<nil::crypto3::multiprecision::double_limb_type>
        : public std::numeric_limits<nil::crypto3::multiprecision::double_limb_type>,
          public detail::integer_traits_base<nil::crypto3::multiprecision::double_limb_type, 0,
                                             ~static_cast<nil::crypto3::multiprecision::double_limb_type>(0)> { };
    template<>
    class integer_traits<nil::crypto3::multiprecision::signed_double_limb_type>
        : public std::numeric_limits<nil::crypto3::multiprecision::signed_double_limb_type>,
          public detail::integer_traits_base<
              nil::crypto3::multiprecision::signed_double_limb_type,
              static_cast<nil::crypto3::multiprecision::signed_double_limb_type>(
                  (static_cast<nil::crypto3::multiprecision::double_limb_type>(1) << 127)),
              static_cast<nil::crypto3::multiprecision::signed_double_limb_type>(
                  ((~static_cast<nil::crypto3::multiprecision::double_limb_type>(0)) >> 1))> { };
}    // namespace boost

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

#else
            using limb_type = detail::largest_unsigned_type<32>::type;
            using signed_limb_type = detail::largest_signed_type<32>::type;
            using double_limb_type = detail::largest_unsigned_type<64>::type;
            using signed_double_limb_type = detail::largest_signed_type<64>::type;

            constexpr const unsigned bits_per_limb = 32;
            constexpr const limb_type limb_value_max = ~static_cast<limb_type>(0u);

            constexpr const limb_type max_block_10 = 1000000000;
            constexpr const limb_type digits_per_block_10 = 9;

            inline limb_type block_multiplier(unsigned count) {
                constexpr const limb_type values[digits_per_block_10] = {
                    10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};
                BOOST_ASSERT(count < digits_per_block_10);
                return values[count];
            }

#endif

            template<class T>
            inline BOOST_MP_CXX14_CONSTEXPR void minmax(const T& a, const T& b, T& aa, T& bb) {
                if (a < b) {
                    aa = a;
                    bb = b;
                } else {
                    aa = b;
                    bb = a;
                }
            }

            enum cpp_integer_type {
                signed_magnitude = 1,
                unsigned_magnitude = 0,
                signed_packed = 3,
                unsigned_packed = 2
            };

            enum cpp_int_check_type { checked = 1, unchecked = 0 };
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MP_CPP_INT_CORE_HPP
