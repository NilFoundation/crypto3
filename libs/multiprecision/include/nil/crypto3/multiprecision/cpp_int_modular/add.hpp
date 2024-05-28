///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_CPP_INT_ADD_HPP
#define CRYPTO3_CPP_INT_ADD_HPP

#include <boost/multiprecision/detail/constexpr.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/add_unsigned.hpp>

namespace boost {
    namespace multiprecision {
        namespace backends {
            //
            // Adding a single limb to a non-trivial cpp_int:
            //
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void
                add_unsigned(cpp_int_modular_backend<Bits>& result,
                             const cpp_int_modular_backend<Bits>& a,
                             const limb_type& o) noexcept {
                // Addition using modular arithmetic.
                // Nothing fancy, just let uintmax_t take the strain:

                double_limb_type carry = o;
                typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();
                typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                unsigned i = 0;
                // Addition with carry until we either run out of digits or carry is zero:
                for (; carry && (i < result.size()); ++i) {
                    carry += static_cast<double_limb_type>(pa[i]);
                    pr[i] = static_cast<limb_type>(carry);
                    carry >>= cpp_int_modular_backend<Bits>::limb_bits;
                }
                // Just copy any remaining digits:
                if (&a != &result) {
                    boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
                }
                if (Bits % cpp_int_modular_backend<Bits>::limb_bits == 0)
                    result.set_carry(carry);
                else {
                    limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                    // If we have set any bit above "Bits", then we have a carry.
                    if (pr[result.size() - 1] & ~mask) {
                        pr[result.size() - 1] &= mask;
                        result.set_carry(true);
                    }
                }
            }

            //
            // And again to subtract a single limb: caller is responsible to check that a > b and the result is non-negative.
            //
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void
                subtract_unsigned(cpp_int_modular_backend<Bits>& result,
                                  const cpp_int_modular_backend<Bits>& a,
                                  const limb_type& b) noexcept {
                BOOST_ASSERT(!eval_lt(a, b));

                // Subtract one limb.
                // Nothing fancy, just let uintmax_t take the strain:
                BOOST_MP_CXX14_CONSTEXPR double_limb_type borrow = static_cast<double_limb_type>(cpp_int_modular_backend<Bits>::max_limb_value) + 1;
                typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();
                typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                if (*pa >= b) {
                    *pr = *pa - b;
                    if (&result != &a) {
                        boost::multiprecision::std_constexpr::copy(pa + 1, pa + a.size(), pr + 1);
                    }
                } else if (result.size() == 1) {
                    *pr = b - *pa;
                } else {
                    *pr = static_cast<limb_type>((borrow + *pa) - b);
                    unsigned i = 1;
                    while (!pa[i]) {
                        pr[i] = cpp_int_modular_backend<Bits>::max_limb_value;
                        ++i;
                    }
                    pr[i] = pa[i] - 1;
                    if (&result != &a) {
                        ++i;
                        boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
                    }
                }
            }

            //
            // Now the actual functions called by the front end, all of which forward to one of the above:
            //
            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                eval_add(cpp_int_modular_backend<Bits>& result,
                         const cpp_int_modular_backend<Bits>& o) noexcept {
                eval_add(result, result, o);
            }
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                type
                eval_add(cpp_int_modular_backend<Bits>& result,
                         const cpp_int_modular_backend<Bits>& a,
                         const cpp_int_modular_backend<Bits>& b) noexcept {
                add_unsigned(result, a, b);
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                cpp_int_modular_backend<Bits>>::value>::type
                eval_add(
                    cpp_int_modular_backend<Bits>& result,
                    const limb_type& o) noexcept {
                add_unsigned(result, result, o);
            }
            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                eval_add(
                    cpp_int_modular_backend<Bits>& result,
                    const cpp_int_modular_backend<Bits>& a,
                    const limb_type& o) noexcept {
                add_unsigned(result, a, o);
            }
            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                cpp_int_modular_backend<Bits>>::value>::type
                eval_subtract(
                    cpp_int_modular_backend<Bits>& result,
                    const limb_type& o) noexcept {
                subtract_unsigned(result, result, o);
            }
            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                eval_subtract(
                    cpp_int_modular_backend<Bits>& result,
                    const cpp_int_modular_backend<Bits>& a,
                    const limb_type& o) noexcept {
                subtract_unsigned(result, a, o);
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                cpp_int_modular_backend<Bits>>::value>::type
                eval_increment(cpp_int_modular_backend<Bits>& result) noexcept {

                if ((result.limbs()[0] < cpp_int_modular_backend<Bits>::max_limb_value))
                    ++result.limbs()[0];
                else
                    eval_add(result, (limb_type)1);
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                cpp_int_modular_backend<Bits>>::value>::type
                eval_decrement(cpp_int_modular_backend<Bits>& result) noexcept {

                BOOST_MP_CXX14_CONSTEXPR const limb_type one = 1;

                if (result.limbs()[0])
                    --result.limbs()[0];
                else
                    eval_subtract(result, one);
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                type
                eval_subtract(cpp_int_modular_backend<Bits>& result,
                              const cpp_int_modular_backend<Bits>& o) noexcept {
                eval_subtract(result, result, o);
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                type
                eval_subtract(cpp_int_modular_backend<Bits>& result,
                              const cpp_int_modular_backend<Bits>& a,
                              const cpp_int_modular_backend<Bits>& b
                            ) noexcept {
                subtract_unsigned(result, a, b);
            }

            template<unsigned Bits1, unsigned Bits2>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value && 
                (Bits1 > Bits2)>::type
                eval_subtract(cpp_int_modular_backend<Bits1>& result,
                              const cpp_int_modular_backend<Bits2>& o) noexcept {
                cpp_int_modular_backend<Bits1> o_larger = o;
                eval_subtract(result, result, o_larger);
            }

            template<unsigned Bits1, unsigned Bits2>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value &&
                (Bits1 > Bits2)>::type
                eval_subtract(cpp_int_modular_backend<Bits1>& result,
                              const cpp_int_modular_backend<Bits1>& a,
                              const cpp_int_modular_backend<Bits2>& b
                            ) noexcept {
                cpp_int_modular_backend<Bits1> b_larger = b;
                subtract_unsigned(result, a, b_larger);
            }

            //
            // Simple addition and subtraction routine for trivial cpp_int's come last:
            //
            // Simple version for two unsigned arguments:
            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                type
                eval_add(cpp_int_modular_backend<Bits>& result,
                         const cpp_int_modular_backend<Bits>& o) noexcept {
                double_limb_type sum = *result.limbs();
                sum += *o.limbs();
                double_limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                if ((sum & ~mask) != 0) {
                    result.set_carry(true);
                    *result.limbs() = sum & mask;
                } else {
                    *result.limbs() = sum;
                }
            }

            template<unsigned Bits1, unsigned Bits2>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type
                eval_subtract(cpp_int_modular_backend<Bits1>& result,
                              const cpp_int_modular_backend<Bits2>& o) noexcept {
                BOOST_ASSERT(*result.limbs() >= *o.limbs());
                *result.limbs() -= *o.limbs();
            }

            template<unsigned Bits>
            BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                type
                eval_subtract(cpp_int_modular_backend<Bits>& result,
                              const cpp_int_modular_backend<Bits>& a,
                              const cpp_int_modular_backend<Bits>& b) noexcept {
                BOOST_ASSERT(*a.limbs() >= *b.limbs());
                *result.limbs() = *a.limbs() - *b.limbs();
            }
        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif
