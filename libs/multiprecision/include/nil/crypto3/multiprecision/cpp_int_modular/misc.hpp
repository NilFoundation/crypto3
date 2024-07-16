///////////////////////////////////////////////////////////////
//  Copyright 2012-2020 John Maddock.
//  Copyright 2020 Madhur Chauhan.
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at
//   https://www.boost.org/LICENSE_1_0.txt)
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_MISC_HPP
#define CRYPTO3_MP_CPP_INT_MISC_HPP

#include <boost/multiprecision/detail/constexpr.hpp>
#include <boost/multiprecision/detail/bitscan.hpp>    // lsb etc
#include <boost/functional/hash_fwd.hpp>
#include <boost/functional/hash.hpp>

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 4702)
#pragma warning(disable : 4127)    // conditional expression is constant
#pragma warning(disable : 4146)    // unary minus operator applied to unsigned type, result still unsigned
#endif

namespace boost {
    namespace multiprecision {
        namespace backends {
                using boost::multiprecision::backends::is_trivial_cpp_int_modular;
                using boost::multiprecision::backends::cpp_int_modular_backend;

                template<class R, unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                        boost::multiprecision::detail::is_integral<R>::value &&
                        !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, void>::type
                    eval_convert_to(R *result, const cpp_int_modular_backend<Bits> &backend) {

                    BOOST_IF_CONSTEXPR(
                        numeric_limits_workaround<R>::digits <
                        cpp_int_modular_backend<Bits>::limb_bits) {
                        if (boost::multiprecision::detail::is_signed<R>::value &&
                                   boost::multiprecision::detail::is_integral<R>::value && 
                                   static_cast<boost::multiprecision::limb_type>(
                                       (std::numeric_limits<R>::max)()) <= backend.limbs()[0]) {
                            *result = (numeric_limits_workaround<R>::max)();
                            return;
                        } else
                            *result = static_cast<R>(backend.limbs()[0]);
                    }
                    else
                        *result = static_cast<R>(backend.limbs()[0]);

                    unsigned shift = cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned i = 1;
                    BOOST_IF_CONSTEXPR(
                        numeric_limits_workaround<R>::digits >
                        cpp_int_modular_backend<Bits>::limb_bits) {
                        while ((i < backend.size()) &&
                               (shift <
                                static_cast<unsigned>(
                                    numeric_limits_workaround<R>::digits -
                                    cpp_int_modular_backend<Bits>::limb_bits))) {
                            *result += static_cast<R>(backend.limbs()[i]) << shift;
                            shift += cpp_int_modular_backend<Bits>::limb_bits;
                            ++i;
                        }
                        //
                        // We have one more limb to extract, but may not need all the bits, so treat this as a special
                        // case:
                        //
                        if (i < backend.size()) {
                            const limb_type mask =
                                numeric_limits_workaround<R>::digits - shift ==
                                        cpp_int_modular_backend<Bits>::
                                            limb_bits ?
                                    ~static_cast<limb_type>(0) :
                                    (static_cast<limb_type>(1u) << (numeric_limits_workaround<R>::digits - shift)) - 1;
                            *result += (static_cast<R>(backend.limbs()[i]) & mask) << shift;
                            if ((static_cast<R>(backend.limbs()[i]) & static_cast<limb_type>(~mask)) ||
                                (i + 1 < backend.size())) {
                                // Overflow:
                                if (boost::multiprecision::detail::is_signed<R>::value)
                                    *result = (numeric_limits_workaround<R>::max)();
                                return;
                            }
                        }
                    }
                    else if (backend.size() > 1) {
                        // We will check for overflow here.
                        for (std::size_t i = 1; i < backend.size(); ++i) {
                            BOOST_ASSERT(backend.limbs()[i] == 0);
                        }
                    }
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, bool>::type
                    eval_is_zero(const cpp_int_modular_backend<Bits> &val) noexcept {
                    // std::all_of is not constexpr, so writing manually.
                    for (std::size_t i = 0; i < val.size(); ++i) {
                        if (val.limbs()[i] != 0)
                            return false;
                    }
                    return true;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, bool>::type
                    eval_is_zero(const cpp_int_modular_backend<Bits> &val) noexcept {
                    return *val.limbs() == 0;
                }

                //
                // Get the location of the least-significant-bit:
                //
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_lsb(const cpp_int_modular_backend<Bits> &a) {

                    //
                    // Find the index of the least significant limb that is non-zero:
                    //
                    std::size_t index = 0;
                    while (!a.limbs()[index] && (index < a.size()))
                        ++index;
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    unsigned result = boost::multiprecision::detail::find_lsb(a.limbs()[index]);

                    return result + index * cpp_int_modular_backend<Bits>::limb_bits;
                }

                //
                // Get the location of the most-significant-bit:
                //
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb_imp(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the most significant bit that is non-zero:
                    //
                    for (std::size_t i = a.size() - 1; i > 0; --i) {
                        if (a.limbs()[i] != 0)
                            return i * cpp_int_modular_backend<Bits>::limb_bits + 
                                boost::multiprecision::detail::find_msb(a.limbs()[i]);
                    } 
                    return boost::multiprecision::detail::find_msb(a.limbs()[0]);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb(const cpp_int_modular_backend<Bits> &a) {
                    return eval_msb_imp(a);
                }

#ifdef BOOST_GCC
//
// We really shouldn't need to be disabling this warning, but it really does appear to be
// spurious.  The warning appears only when in release mode, and asserts are on.
//
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_bit_test(const cpp_int_modular_backend<Bits> &val, std::size_t index) noexcept {
                    unsigned offset = index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift = index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = limb_type(1u) << shift;
                    if (offset >= val.size())
                        return false;
                    return val.limbs()[offset] & mask ? true : false;
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, bool>::type
                    eval_bit_test(const cpp_int_modular_backend<Bits> &val, std::size_t index) noexcept {
                    // For trivial cpp_int_modular, limb_type sometimes can be 128 bits, not 64. So we need to use 
                    // local_limb_type instead of limb_type for trivial_cpp_int when using bit operations.
                    using local_limb_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::local_limb_type;

                    if (index >= Bits)
                        return false;
                    local_limb_type mask = local_limb_type(1u) << index;
                    return (*val.limbs()) & mask ? true : false;
                }

#ifdef BOOST_GCC
#pragma GCC diagnostic pop
#endif

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_set(cpp_int_modular_backend<Bits> &val, std::size_t index) {

                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = limb_type(1u) << shift;
                    if (offset >= val.size()) {
                        return;    // fixed precision overflow
                    }
                    val.limbs()[offset] |= mask;
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_set(cpp_int_modular_backend<Bits> &val, std::size_t index) {
                    // For trivial cpp_int_modular, limb_type sometimes can be 128 bits, not 64. So we need to use 
                    // local_limb_type instead of limb_type for trivial_cpp_int when using bit operations.
                    using local_limb_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::local_limb_type;

                    BOOST_ASSERT(index < Bits);
                    local_limb_type mask = 1u;
                    mask <<= index;
                    *val.limbs() |= mask;
                }


                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_unset(cpp_int_modular_backend<Bits> &val,
                                   std::size_t index) noexcept {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = limb_type(1u) << shift;
                    if (offset >= val.size())
                        return;
                    val.limbs()[offset] &= ~mask;
                    val.normalize();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_unset(cpp_int_modular_backend<Bits> &val, std::size_t index) {
                    // For trivial cpp_int_modular, limb_type sometimes can be 128 bits, not 64. So we need to use 
                    // local_limb_type instead of limb_type for trivial_cpp_int when using bit operations.
                    using local_limb_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::local_limb_type;

                    BOOST_ASSERT(index < Bits);
                    local_limb_type mask = 1u;
                    mask <<= index;
                    *val.limbs() &= ~mask;
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_flip(cpp_int_modular_backend<Bits> &val,
                                  std::size_t index) {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = limb_type(1u) << shift;
                    if (offset >= val.size()) {
                        return;    // fixed precision overflow
                    }
                    val.limbs()[offset] ^= mask;
                    val.normalize();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_flip(cpp_int_modular_backend<Bits> &val, std::size_t index) {
                    // For trivial cpp_int_modular, limb_type sometimes can be 128 bits, not 64. So we need to use 
                    // local_limb_type instead of limb_type for trivial_cpp_int when using bit operations.
                    using local_limb_type = typename boost::multiprecision::backends::cpp_int_modular_backend<Bits>::local_limb_type;

                    BOOST_ASSERT(index < Bits);
                    local_limb_type mask = 1u;
                    mask <<= index;
                    *val.limbs() ^= mask;
                }


                template<class R, unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    std::is_convertible<
                        typename cpp_int_modular_backend<Bits>::local_limb_type,
                        R>::value>::type
                    eval_convert_to(R *result, const cpp_int_modular_backend<Bits> &val) {
                    using common_type = typename std::common_type<
                        R,
                        typename cpp_int_modular_backend<Bits>::local_limb_type>::type;
                    BOOST_IF_CONSTEXPR(std::numeric_limits<R>::is_specialized) {
                        if (static_cast<common_type>(*val.limbs()) >
                            static_cast<common_type>((std::numeric_limits<R>::max)())) {
                            *result = boost::multiprecision::detail::is_signed<R>::value &&
                                boost::multiprecision::detail::is_integral<R>::value ?
                                    (std::numeric_limits<R>::max)() :
                                    static_cast<R>(*val.limbs());
                        } else
                            *result = static_cast<R>(*val.limbs());
                    }
                    else *result = static_cast<R>(*val.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_lsb(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    return boost::multiprecision::detail::find_lsb(*a.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb_imp(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    return boost::multiprecision::detail::find_msb(*a.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb(const cpp_int_modular_backend<Bits> &a) {
                    
                    return eval_msb_imp(a);
                }

                // Since we don't have signed_type in cpp_int_modular_backend, we need to override this function.
                template<unsigned Bits, class Integer>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::detail::is_unsigned<Integer>::value &&
                        !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    Integer>::type
                    eval_integer_modulus(const cpp_int_modular_backend<Bits> &a, Integer mod) {
                    BOOST_IF_CONSTEXPR(sizeof(Integer) <= sizeof(limb_type)) {
                        if (mod <= (std::numeric_limits<limb_type>::max)()) {
                            const int n = a.size();
                            const double_limb_type two_n_mod =
                                static_cast<limb_type>(1u) + (~static_cast<limb_type>(0u) - mod) % mod;
                            limb_type res = a.limbs()[n - 1] % mod;

                            for (int i = n - 2; i >= 0; --i)
                                res = static_cast<limb_type>((res * two_n_mod + a.limbs()[i]) % mod);
                            return res;
                        } else
                            return default_ops::eval_integer_modulus(a, mod);
                    }
                    else {
                        return default_ops::eval_integer_modulus(a, mod);
                    }
                }

                template<unsigned Bits,
                         class Integer>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::detail::is_signed<Integer>::value &&
                        boost::multiprecision::detail::is_integral<Integer>::value &&
                        !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    Integer>::type
                    eval_integer_modulus(const cpp_int_modular_backend<Bits> &x, Integer val) {
                    return eval_integer_modulus(x, boost::multiprecision::detail::unsigned_abs(val));
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR std::size_t hash_value(
                    const cpp_int_modular_backend<Bits> &val) noexcept {
                    std::size_t result = 0;
                    for (unsigned i = 0; i < val.size(); ++i) {
                        boost::hash_combine(result, val.limbs()[i]);
                    }
                    return result;
                }

#ifdef BOOST_MSVC
#pragma warning(pop)
#endif

        } // namespace backends

        namespace detail {

            // We need to specialize this class, because cpp_int_modular_backend does not have signed_types.
            // All we have changed here is Backend::signed_types -> Backend::unsigned_types, this will work for our use cases.
            template <class Val, unsigned Bits>
            struct canonical_imp<Val, backends::cpp_int_modular_backend<Bits>, std::integral_constant<int, 0> >
            {
               static BOOST_MP_CXX14_CONSTEXPR int index = find_index_of_large_enough_type<typename backends::cpp_int_modular_backend<Bits>::unsigned_types, 0, bits_of<Val>::value>::value;
               using type = typename dereference_tuple<index, typename backends::cpp_int_modular_backend<Bits>::unsigned_types, Val>::type;
            };

        } // namespace detail
    } // namespace multiprecision
}  // namespace boost


#endif
