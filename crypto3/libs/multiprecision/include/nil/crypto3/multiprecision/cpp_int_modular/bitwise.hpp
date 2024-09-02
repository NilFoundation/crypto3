///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_BIT_HPP
#define CRYPTO3_MP_CPP_INT_BIT_HPP

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4319)
#endif

namespace boost {
    namespace multiprecision {
        namespace backends {

                template<unsigned Bits, class Op>
                BOOST_MP_CXX14_CONSTEXPR void bitwise_op(
                    cpp_int_modular_backend<Bits>& result, const cpp_int_modular_backend<Bits>& o, Op op) noexcept {
                    //
                    // Both arguments are unsigned types, very simple case handled as a special case.
                    //
                    // First figure out how big the result needs to be and set up some data:
                    //
                    unsigned rs = result.size();
                    unsigned os = o.size();
                    unsigned m(0), x(0);
                    minmax(rs, os, m, x);
                    typename cpp_int_modular_backend<Bits>::limb_pointer pr = result.limbs();
                    typename cpp_int_modular_backend<Bits>::const_limb_pointer po = o.limbs();
                    for (unsigned i = rs; i < x; ++i)
                        pr[i] = 0;

                    for (unsigned i = 0; i < os; ++i)
                        pr[i] = op(pr[i], po[i]);
                    for (unsigned i = os; i < x; ++i)
                        pr[i] = op(pr[i], limb_type(0));
                    result.normalize();
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_and());
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_or(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_or());
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_xor(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_xor());
                }
                //
                // Again for operands which are single limbs:
                //
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        limb_type l) noexcept {
                    result.limbs()[0] &= l;
                    result.zero_after(1);
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_or(cpp_int_modular_backend<Bits>& result, limb_type l) noexcept {
                    result.limbs()[0] |= l;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_xor(cpp_int_modular_backend<Bits>& result, limb_type l) noexcept {
                    result.limbs()[0] ^= l;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_complement(cpp_int_modular_backend<Bits>& result, const cpp_int_modular_backend<Bits>& o) noexcept {

                    unsigned os = o.size();
                    for (unsigned i = 0; i < os; ++i)
                        result.limbs()[i] = ~o.limbs()[i];
                    result.normalize();
                }

                // Left shift will throw away upper bits.
                // This function must be called only when s % 8 == 0, i.e. we shift bytes.
                template<unsigned Bits>
                inline void left_shift_byte(cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;

                    typename Int::limb_pointer pr = result.limbs();

                    std::size_t bytes = static_cast<std::size_t>(s / CHAR_BIT);
                    if (s >= Bits)
                        // Set result to 0.
                        result.zero_after(0);
                    else {
                        unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                        std::memmove(pc + bytes, pc, result.size() * sizeof(limb_type) - bytes);
                        std::memset(pc, 0, bytes);
                    }
                }

                // Left shift will throw away upper bits.
                // This function must be called only when s % limb_bits == 0, i.e. we shift limbs, which are normally 64 bit.
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR void left_shift_limb(
                        cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;

                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    BOOST_ASSERT(static_cast<limb_type>(s % Int::limb_bits) == 0);

                    typename Int::limb_pointer pr = result.limbs();

                    if (s >= Bits) {
                        // Set result to 0.
                        result.zero_after(0);
                    } else {
                        unsigned i = offset;
                        std::size_t rs = result.size() + offset;
                        for (; i < result.size(); ++i)
                            pr[rs - 1 - i] = pr[result.size() - 1 - i];
                        for (; i < rs; ++i)
                            pr[rs - 1 - i] = 0;
                    }
                }

                // Left shift will throw away upper bits.
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR void left_shift_generic(
                        cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;

                    if (s >= Bits) {
                        // Set result to 0.
                        result.zero_after(0);
                    } else {
                        limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                        limb_type shift = static_cast<limb_type>(s % Int::limb_bits);

                        typename Int::limb_pointer pr = result.limbs();
                        std::size_t i = 0;
                        std::size_t rs = result.size();
                        // This code only works when shift is non-zero, otherwise we invoke undefined behaviour!
                        BOOST_ASSERT(shift);
                        for (; rs - i >= 2 + offset; ++i) {
                            pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                            pr[rs - 1 - i] |= pr[rs - 2 - i - offset] >> (Int::limb_bits - shift);
                        }
                        if (rs - i >= 1 + offset) {
                            pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                            ++i;
                        }
                        for (; i < rs; ++i)
                            pr[rs - 1 - i] = 0;
                    }
                }

                // Shifting left throws away upper bits.
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_left_shift(cpp_int_modular_backend<Bits>& result, double_limb_type s) noexcept {
                    if (!s)
                        return;

#if BOOST_ENDIAN_LITTLE_BYTE && defined(CRYPTO3_MP_USE_LIMB_SHIFT)
                    BOOST_MP_CXX14_CONSTEXPR const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    BOOST_MP_CXX14_CONSTEXPR const limb_type byte_shift_mask = CHAR_BIT - 1;

                    if ((s & limb_shift_mask) == 0) {
                        left_shift_limb(result, s);
                    }
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    else if ((s & byte_shift_mask) == 0)
#else
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                    {
                        left_shift_byte(result, s);
                    }
#elif BOOST_ENDIAN_LITTLE_BYTE
                    BOOST_MP_CXX14_CONSTEXPR const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if ((s & byte_shift_mask) == 0)
#else
                    BOOST_MP_CXX14_CONSTEXPR limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0))
                        left_shift_limb(result, s);
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                    {
                        left_shift_byte(result, s);
                    }
#else
                    BOOST_MP_CXX14_CONSTEXPR const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;

                    if ((s & limb_shift_mask) == 0) {
                        left_shift_limb(result, s);
                    }
#endif
                    else {
                        left_shift_generic(result, s);
                    }
                    result.normalize();
                }

#ifndef TVM
                template<unsigned Bits>
                inline void right_shift_byte(cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;

                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    BOOST_ASSERT((s % CHAR_BIT) == 0);
                    unsigned ors = result.size();
                    unsigned rs = ors;
                    if (offset >= rs) {
                        result.zero_after(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                    limb_type shift = static_cast<limb_type>(s / CHAR_BIT);
                    std::memmove(pc, pc + shift, ors * sizeof(pr[0]) - shift);
                    shift = (sizeof(limb_type) - shift % sizeof(limb_type)) * CHAR_BIT;
                    if (shift < Int::limb_bits) {
                        pr[ors - offset - 1] &= (static_cast<limb_type>(1u) << shift) - 1;
                        if (!pr[ors - offset - 1] && (rs > 1))
                            --rs;
                    }
                    // Set zeros after 'rs', alternative to resizing to size 'rs'.
                    result.zero_after(rs);
                }
#endif

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR void right_shift_limb(cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;

                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    BOOST_ASSERT((s % Int::limb_bits) == 0);
                    unsigned ors = result.size();
                    unsigned rs = ors;
                    if (offset >= rs) {
                        result.zero_after(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    unsigned i = 0;
                    for (; i < rs; ++i)
                        pr[i] = pr[i + offset];
                    // Set zeros after 'rs', alternative to resizing to size 'rs'.
                    result.zero_after(rs);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR void right_shift_generic(cpp_int_modular_backend<Bits>& result, double_limb_type s) {
                    typedef cpp_int_modular_backend<Bits> Int;
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    limb_type shift = static_cast<limb_type>(s % Int::limb_bits);
                    unsigned ors = result.size();
                    unsigned rs = ors;

                    if (offset >= rs) {
                        result = limb_type(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    if ((pr[ors - 1] >> shift) == 0) {
                        if (--rs == 0) {
                            result = limb_type(0);
                            return;
                        }
                    }
                    unsigned i = 0;

                    // This code only works for non-zero shift, otherwise we invoke undefined behaviour!
                    BOOST_ASSERT(shift);
                    for (; i + offset + 1 < ors; ++i) {
                        pr[i] = pr[i + offset] >> shift;
                        pr[i] |= pr[i + offset + 1] << (Int::limb_bits - shift);
                    }
                    pr[i] = pr[i + offset] >> shift;

                    // We cannot resize any more, so we need to set all the limbs to zero.
                    result.zero_after(rs);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_right_shift(
                        cpp_int_modular_backend<Bits>& result,
                        double_limb_type s) noexcept {
                    if (!s)
                        return;

#if BOOST_ENDIAN_LITTLE_BYTE && defined(CRYPTO3_MP_USE_LIMB_SHIFT) && !defined(TVM)
                    BOOST_MP_CXX14_CONSTEXPR const limb_type limb_shift_mask = cpp_int_modular_backend<Bits>::limb_bits - 1;
                    BOOST_MP_CXX14_CONSTEXPR const limb_type byte_shift_mask = CHAR_BIT - 1;

                    if ((s & limb_shift_mask) == 0)
                        right_shift_limb(result, s);
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    else if ((s & byte_shift_mask) == 0)
#else
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                        right_shift_byte(result, s);
#elif BOOST_ENDIAN_LITTLE_BYTE && !defined(TVM)
                    BOOST_MP_CXX14_CONSTEXPR const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if ((s & byte_shift_mask) == 0)
#else
                    BOOST_MP_CXX14_CONSTEXPR limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0))
                        right_shift_limb(result, s);
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                        right_shift_byte(result, s);
#else
                    BOOST_MP_CXX14_CONSTEXPR const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;

                    if ((s & limb_shift_mask) == 0)
                        right_shift_limb(result, s);
#endif
                    else
                        right_shift_generic(result, s);
                }

                //
                // Over again for trivial cpp_int's:
                //
                template<unsigned Bits, class T>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<boost::multiprecision::backends::is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_left_shift(cpp_int_modular_backend<Bits>& result, T s) noexcept {
                    *result.limbs() <<= s;
                }

                template<unsigned Bits, class T>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_right_shift(cpp_int_modular_backend<Bits>& result, T s) noexcept {
                    // Nothing to check here... just make sure we don't invoke undefined behavior:
                    *result.limbs() = (static_cast<unsigned>(s) >= sizeof(*result.limbs()) * CHAR_BIT) ?
                                          0 :
                                          (*result.limbs() >> s);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_complement(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>&
                            o) noexcept {
                    *result.limbs() = ~*o.limbs();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() &= *o.limbs();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_or(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() |= *o.limbs();
                    result.normalize();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_xor(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() ^= *o.limbs();
                }

        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
