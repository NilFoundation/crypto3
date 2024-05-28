///////////////////////////////////////////////////////////////
//  Copyright 2020 Madhur Chauhan.
//  Copyright 2020 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_MP_ADD_UNSIGNED_ADDC_32_HPP
#define CRYPTO3_MP_ADD_UNSIGNED_ADDC_32_HPP

#include <boost/multiprecision/detail/constexpr.hpp>
#include <boost/multiprecision/cpp_int/intel_intrinsics.hpp> // for addcarry_limb

namespace boost {
    namespace multiprecision {
        namespace backends {
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void
                add_unsigned_constexpr(
                    cpp_int_modular_backend<Bits>& result, 
                    const cpp_int_modular_backend<Bits>& a,
                    const cpp_int_modular_backend<Bits>& b) noexcept {

                using ::boost::multiprecision::std_constexpr::swap;
                //
                // This is the generic, C++ only version of addition.
                // It's also used for all BOOST_MP_CXX14_CONSTEXPR branches, hence the name.
                // Nothing fancy, just let uintmax_t take the strain:
                //
                double_limb_type carry = 0;
                std::size_t s = a.size();
                if (s == 1) {
                    double_limb_type r = static_cast<double_limb_type>(*a.limbs()) + static_cast<double_limb_type>(*b.limbs());
                    double_limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                    if (r & ~mask) {
                        result = r & mask;
                        result.set_carry(true);
                    } else {
                        result = r;
                    }
                    return;
                }

                typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                typename cpp_int_modular_backend<Bits>::const_limb_pointer pb = b.limbs();
                typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();

                // First where a and b overlap:
                for (std::size_t i = 0; i < s; ++i) {
                    carry += static_cast<double_limb_type>(*pa) + static_cast<double_limb_type>(*pb);
#ifdef _C_RUNTIME_CHECKS
                    *pr = static_cast<limb_type>(carry & ~static_cast<limb_type>(0));
#else
                    *pr = static_cast<limb_type>(carry);
#endif
                    carry >>= cpp_int_modular_backend<Bits>::limb_bits;
                    ++pr, ++pa, ++pb;
                }
                if (Bits % cpp_int_modular_backend<Bits>::limb_bits == 0)
                    result.set_carry(carry);
                else {
                    limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                    // If we have set any bit above "Bits", then we have a carry.
                    if (result.limbs()[s - 1] & ~mask) {
                        result.limbs()[s - 1] &= mask;
                        result.set_carry(true);
                    }
                }
            }

            //
            // Core subtraction routine for all non-trivial cpp_int's:
            // It is the caller's responsibility to make sure that a >= b.
            //
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void subtract_unsigned_constexpr(
                    cpp_int_modular_backend<Bits>& result,
                    const cpp_int_modular_backend<Bits>& a,
                    const cpp_int_modular_backend<Bits>& b) noexcept {
                BOOST_MP_ASSERT(!eval_lt(a, b));

                //
                // This is the generic, C++ only version of subtraction.
                // It's also used for all BOOST_MP_CXX14_CONSTEXPR branches, hence the name.
                // Nothing fancy, just let uintmax_t take the strain:
                //
                std::size_t s = a.size();
                if (s == 1) {
                    result = *a.limbs() - *b.limbs();
                    return;
                }
                typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                typename cpp_int_modular_backend<Bits>::const_limb_pointer pb = b.limbs();
                typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();

                double_limb_type borrow = 0;
                // First where a and b overlap:
                for (std::size_t i = 0; i < s; ++i) {
                    borrow = static_cast<double_limb_type>(pa[i]) - static_cast<double_limb_type>(pb[i]) - borrow;
                    pr[i] = static_cast<limb_type>(borrow);
                    borrow = (borrow >> cpp_int_modular_backend<Bits>::limb_bits) & 1u;
                }
                // if a > b, then borrow must be 0 at the end.
                BOOST_MP_ASSERT(0 == borrow);
            }

#ifdef CO3_MP_HAS_IMMINTRIN_H
            //
            // This is the key addition routine where all the argument types are non-trivial cpp_int's:
            //
            //
            // This optimization is limited to: GCC, LLVM, ICC (Intel), MSVC for x86_64 and i386.
            // If your architecture and compiler supports ADC intrinsic, please file a bug
            //
            // As of May, 2020 major compilers don't recognize carry chain though adc
            // intrinsics are used to hint compilers to use ADC and still compilers don't
            // unroll the loop efficiently (except LLVM) so manual unrolling is done.
            //
            // Also note that these intrinsics were only introduced by Intel as part of the
            // ADX processor extensions, even though the addc instruction has been available
            // for basically all x86 processors.  That means gcc-9, clang-9, msvc-14.2 and up
            // are required to support these intrinsics.
            //
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void add_unsigned(
                    cpp_int_modular_backend<Bits>& result,
                    const cpp_int_modular_backend<Bits>& a,
                    const cpp_int_modular_backend<Bits>& b) noexcept {

#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                if (BOOST_MP_IS_CONST_EVALUATED(a.size())) {
                    add_unsigned_constexpr(result, a, b);
                } else
#endif
                {
                    using std::swap;

                    // Nothing fancy, just let uintmax_t take the strain:
                    unsigned s = a.size();
                    if (s == 1) {
                        double_limb_type v = static_cast<double_limb_type>(*a.limbs()) + 
                            static_cast<double_limb_type>(*b.limbs());
                        double_limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                        if (v & ~mask) {
                            v &= mask;
                            result.set_carry(true);
                        }
                        result = v;
                        return;
                    }
                    typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                    typename cpp_int_modular_backend<Bits>::const_limb_pointer pb = b.limbs();
                    typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();

                    unsigned char carry = 0;
#if defined(BOOST_MSVC) && !defined(BOOST_HAS_INT128) && defined(_M_X64)
                    //
                    // Special case for 32-bit limbs on 64-bit architecture - we can process
                    // 2 limbs with each instruction.
                    //
                    std::size_t i = 0;
                    for (; i + 8 <= s; i += 8) {
                        carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 0),
                                              *(unsigned long long*)(pb + i + 0), (unsigned long long*)(pr + i));
                        carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 2),
                                          *(unsigned long long*)(pb + i + 2), (unsigned long long*)(pr + i + 2));
                        carry = _addcarry_u64(carry, *(unsigned long long*)(pa + i + 4),
                                          *(unsigned long long*)(pb + i + 4), (unsigned long long*)(pr + i + 4));
                        carry =_addcarry_u64(carry, *(unsigned long long*)(pa + i + 6),
                                          *(unsigned long long*)(pb + i + 6), (unsigned long long*)(pr + i + 6));
                    }
#else
                    for (; i + 4 <= s; i += 4) {
                        carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 0], pb[i + 0],
                                                                                      pr + i);
                        carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 1], pb[i + 1],
                                                                                      pr + i + 1);
                        carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 2], pb[i + 2],
                                                                                      pr + i + 2);
                        carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i + 3], pb[i + 3],
                                                                                      pr + i + 3);
                    }
#endif
                    for (; i < s; ++i)
                        carry = ::boost::multiprecision::detail::addcarry_limb(carry, pa[i], pb[i], pr + i);
                    
                    if (Bits % cpp_int_modular_backend<Bits>::limb_bits == 0)
                        result.set_carry(carry);
                    else {
                        limb_type mask = cpp_int_modular_backend<Bits>::upper_limb_mask;
                        // If we have set any bit above "Bits", then we have a carry.
                        if (result.limbs()[s - 1] & ~mask) {
                            result.limbs()[s - 1] &= mask;
                            result.set_carry(true);
                        }
                    }
                }
            }

            // It is the caller's responsibility to make sure that a > b.
            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void subtract_unsigned(
                    cpp_int_modular_backend<Bits>& result,
                    const cpp_int_modular_backend<Bits>& a,
                    const cpp_int_modular_backend<Bits>& b) noexcept {
                BOOST_MP_ASSERT(!eval_lt(a, b));

#ifndef TO3_MP_NO_CONSTEXPR_DETECTION
                if (BOOST_MP_IS_CONST_EVALUATED(a.size())) {
                    subtract_unsigned_constexpr(result, a, b);
                } else
#endif
                {
                    using std::swap;

                    // Nothing fancy, just let uintmax_t take the strain:
                    std::size_t s = a.size();

                    //
                    // special cases for small limb counts:
                    //
                    if (s == 1) {
                        result = *a.limbs() - *b.limbs();
                        return;
                    }
                    // Now that a, b, and result are stable, get pointers to their limbs:
                    typename cpp_int_modular_backend<Bits>::const_limb_pointer pa = a.limbs();
                    typename cpp_int_modular_backend<Bits>::const_limb_pointer pb = b.limbs();
                    typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();

                    std::size_t i = 0;
                    unsigned char borrow = 0;
                    // First where a and b overlap:
#if defined(BOOST_MSVC) && !defined(BOOST_HAS_INT128) && defined(_M_X64)
                    //
                    // Special case for 32-bit limbs on 64-bit architecture - we can process
                    // 2 limbs with each instruction.
                    //
                    for (; i + 8 <= m; i += 8) {
                        borrow = _subborrow_u64(borrow, *reinterpret_cast<const unsigned long long*>(pa + i),
                                                *reinterpret_cast<const unsigned long long*>(pb + i),
                                                reinterpret_cast<unsigned long long*>(pr + i));
                        borrow = _subborrow_u64(borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 2),
                                                *reinterpret_cast<const unsigned long long*>(pb + i + 2),
                                                reinterpret_cast<unsigned long long*>(pr + i + 2));
                        borrow = _subborrow_u64(borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 4),
                                                *reinterpret_cast<const unsigned long long*>(pb + i + 4),
                                                reinterpret_cast<unsigned long long*>(pr + i + 4));
                        borrow = _subborrow_u64(borrow, *reinterpret_cast<const unsigned long long*>(pa + i + 6),
                                                *reinterpret_cast<const unsigned long long*>(pb + i + 6),
                                                reinterpret_cast<unsigned long long*>(pr + i + 6));
                    }
#else
                    for (; i + 4 <= m; i += 4) {
                        borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);
                        borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 1], pb[i + 1],
                                                                                      pr + i + 1);
                        borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 2], pb[i + 2],
                                                                                      pr + i + 2);
                        borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i + 3], pb[i + 3],
                                                                                      pr + i + 3);
                    }
#endif
                    for (; i < m; ++i)
                        borrow = boost::multiprecision::detail::subborrow_limb(borrow, pa[i], pb[i], pr + i);

                    BOOST_MP_ASSERT(0 == borrow);

                }    // constepxr.
            }

#else

            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void
                add_unsigned(cpp_int_modular_backend<Bits>& result, const cpp_int_modular_backend<Bits>& a, const cpp_int_modular_backend<Bits>& b) noexcept {
                add_unsigned_constexpr(result, a, b);
            }

            template<unsigned Bits>
            inline BOOST_MP_CXX14_CONSTEXPR void
                subtract_unsigned(cpp_int_modular_backend<Bits>& result, const cpp_int_modular_backend<Bits>& a, const cpp_int_modular_backend<Bits>& b) noexcept {
                subtract_unsigned_constexpr(result, a, b);
            }

#endif
        }    // namespace backends
    }   // namespace multiprecision

}   // namespace boost
#endif
