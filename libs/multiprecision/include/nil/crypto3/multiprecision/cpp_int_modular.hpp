//---------------------------------------------------------------------------//
//  Copyright 2012 John Maddock. 
//  Copyright 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CPP_INT_MODULAR_HPP
#define CRYPTO3_CPP_INT_MODULAR_HPP

// Suddenly, BOOST_MP_ASSERT is NOT BOOST_MP_CXX14_CONSTEXPR, and it is used in BOOST_MP_CXX14_CONSTEXPR functions throughout the boost, resulting to compilation errors on all compilers in debug mode. We need to switch assertions off inside cpp_int to make this code compile in debug mode. So we use this workaround to turn off file 'boost/multiprecision/detail/assert.hpp' which contains definition of BOOST_MP_ASSERT and BOOST_MP_ASSERT_MSG. 

#include <boost/multiprecision/detail/number_base.hpp> // for BOOST_MP_IS_CONST_EVALUATED

#ifndef BOOST_MP_DETAIL_ASSERT_HPP
#define BOOST_MP_DETAIL_ASSERT_HPP
    // Using BOOST_STATIC_ASSERT_MSG on the next line results to compilation issues on older compilers like clang-12,
    // so commenting it for now. In case we decide to use only fresher compilers, it can be uncommented.
    #ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
        #define BOOST_MP_ASSERT_MSG(expr, msg)      \
            if (BOOST_MP_IS_CONST_EVALUATED()) {    \
                /* BOOST_STATIC_ASSERT_MSG(expr, msg); */ \
            } else {                                \
                BOOST_ASSERT_MSG(expr, msg);        \
            }
    #else
        #define BOOST_MP_ASSERT_MSG(expr, msg)
    #endif

    #ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
        #define BOOST_MP_ASSERT(expr)               \
            if (BOOST_MP_IS_CONST_EVALUATED()) {    \
                /* BOOST_STATIC_ASSERT(expr);*/     \
            } else {                                \
                BOOST_ASSERT(expr);                 \
            }
    #else
        #define BOOST_MP_ASSERT(expr)
    #endif

#endif

// Sometimes we convert cpp_int_modular_backend to cpp_int_backend of boost for testing and for division.
// Also we reuse definitions of limb_type and similar.
#include <boost/multiprecision/cpp_int.hpp>

#ifndef TVM
#include <iostream>
#include <iomanip>
#include <cstdint>

#include <boost/array.hpp>

#include <boost/predef/other/endian.h>
#endif

#include <boost/integer/static_min_max.hpp>
#include <boost/multiprecision/detail/constexpr.hpp>
#include <boost/multiprecision/traits/std_integer_traits.hpp>
#include <boost/multiprecision/traits/is_byte_container.hpp>
#include <boost/multiprecision/detail/number_base.hpp>
#include <boost/multiprecision/cpp_int/value_pack.hpp>

namespace boost {
    namespace multiprecision {
        namespace backends {

             template<unsigned Bits>
             class cpp_int_modular_backend;

             template<unsigned Bits, bool trivial = false>
             class cpp_int_modular_base;

        }    // namespace backends
        namespace detail {

            template<unsigned Bits>
            struct is_byte_container<backends::cpp_int_modular_backend<Bits>>
                : public boost::false_type { };

        } // namespace detail

        namespace backends {
            template<class T>
            struct max_precision;

            template<unsigned Bits>
            struct max_precision<boost::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                static BOOST_MP_CXX14_CONSTEXPR const unsigned value = Bits;
            };

            template<class T>
            struct min_precision;

            template<unsigned Bits>
            struct min_precision<boost::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                static BOOST_MP_CXX14_CONSTEXPR const unsigned value = Bits;
            };


        }    // namespace backends

        //
        // Traits class to determine whether a cpp_int_modular_backend is signed or not:
        //
        template<unsigned Bits>
        struct is_unsigned_number<boost::multiprecision::backends::cpp_int_modular_backend<Bits>>
            : public std::integral_constant<bool, true> { };

        namespace backends {
            //
            // Traits class, determines whether the cpp_int is fixed precision or not:
            //
            template<class T>
            struct is_fixed_precision;

            template<unsigned Bits>
            struct is_fixed_precision<boost::multiprecision::backends::cpp_int_modular_backend<Bits>>
                : public std::integral_constant<
                      bool,
                      max_precision<boost::multiprecision::backends::cpp_int_modular_backend<Bits>>::value != UINT_MAX> { };
            //
            // Traits class determines whether the number of bits precision requested could fit in a native type,
            // we call this a "trivial" cpp_int:
            //
            template<class T>
            struct is_trivial_cpp_int_modular {
                static BOOST_MP_CXX14_CONSTEXPR const bool value = false;
            };

            template<unsigned Bits>
            struct is_trivial_cpp_int_modular<boost::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                static BOOST_MP_CXX14_CONSTEXPR const bool value = (Bits <= (sizeof(double_limb_type) * CHAR_BIT));
            };

            template<unsigned Bits>
            struct is_trivial_cpp_int_modular<boost::multiprecision::backends::cpp_int_modular_base<Bits, true>> {
                static BOOST_MP_CXX14_CONSTEXPR const bool value = true;
            };

            //
            // Now define the various data layouts that are possible.
            // For modular we only use fixed precision (i.e. no allocator), unsigned type with limb-usage count:
            //
            template<unsigned Bits>
            class cpp_int_modular_base<Bits, false> {
            public:
                using limb_pointer = limb_type*;
                using const_limb_pointer = const limb_type*;

                struct scoped_shared_storage {
                    BOOST_MP_CXX14_CONSTEXPR scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                    }
                    BOOST_MP_CXX14_CONSTEXPR void deallocate(unsigned) {
                    }
                };
                //
                // Interface invariants:
                //
                static_assert(Bits > sizeof(double_limb_type) * CHAR_BIT,
                              "Template parameter Bits is inconsistent with the parameter trivial - did you "
                              "mistakingly try to override the trivial parameter?");

                static BOOST_MP_CXX14_CONSTEXPR unsigned limb_bits = sizeof(limb_type) * CHAR_BIT;
                static BOOST_MP_CXX14_CONSTEXPR limb_type max_limb_value = ~static_cast<limb_type>(0u);
                static BOOST_MP_CXX14_CONSTEXPR unsigned internal_limb_count =
                    Bits / limb_bits + ((Bits % limb_bits) ? 1 : 0);
                static BOOST_MP_CXX14_CONSTEXPR limb_type upper_limb_mask =
                    (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0));
                static_assert(internal_limb_count >= 2,
                              "A fixed precision integer type must have at least 2 limbs");

            private:
                union data_type {
                    // m_data[0] contains the lowest bits.
                    limb_type m_data[internal_limb_count];
                    limb_type m_first_limb;
                    double_limb_type m_double_first_limb;

                    // We are requred to set this to 0 to make it BOOST_MP_CXX14_CONSTEXPR.
                    BOOST_MP_CXX14_CONSTEXPR data_type() : m_data{0} { }

                    BOOST_MP_CXX14_CONSTEXPR data_type(const data_type& o) 
                        : m_data{0} {
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                        if (BOOST_MP_IS_CONST_EVALUATED(internal_limb_count)) {
                            for (unsigned i = 0; i < internal_limb_count; ++i)
                                m_data[i] = o.m_data[i];
                        } else
#endif
                        {
                            if (this != &o) {
                                std::memcpy(m_data, o.m_data, internal_limb_count * sizeof(limb_type));
                            }
                        }
                    }

                    BOOST_MP_CXX14_CONSTEXPR data_type(limb_type i) : m_data {i} {
                    }
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                    BOOST_MP_CXX14_CONSTEXPR data_type(limb_type i, limb_type j) : m_data {i, j} {
                    }
#endif

#if !defined(TVM) && !defined(EVM)
                    BOOST_MP_CXX14_CONSTEXPR data_type(double_limb_type i) : m_double_first_limb(i) {
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                        if (BOOST_MP_IS_CONST_EVALUATED(m_double_first_limb)) {
                            data_type t(static_cast<limb_type>(i & max_limb_value),
                                        static_cast<limb_type>(i >> limb_bits));
                            *this = t;
                        }
#endif
                    }
#endif // TVM

                    template<limb_type... VALUES>
                    BOOST_MP_CXX14_CONSTEXPR data_type(boost::multiprecision::literals::detail::value_pack<VALUES...>) : m_data {VALUES...} {
                    }
                } m_wrapper;

                // This is a temporary value which is set when carry has happend during addition.
                // If this value is true, reduction by modulus must happen next.
                bool m_carry = false;

            public:
                //
                // Direct construction:
                //
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(limb_type i) noexcept : m_wrapper(i) {
                    zero_after(1);
                }

#if BOOST_ENDIAN_LITTLE_BYTE && !defined(BOOST_MP_TEST_NO_LE)

                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(double_limb_type i) noexcept : m_wrapper(i) {
                    zero_after(2);
                }
#endif
                template<limb_type... VALUES>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(boost::multiprecision::literals::detail::value_pack<VALUES...> i) :
                    m_wrapper(i) {
                }
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(boost::multiprecision::literals::detail::value_pack<>) {
                    zero_after(0);
                }
                inline explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(scoped_shared_storage&, unsigned) noexcept {
                    zero_after(0);
                }
                //
                // Helper functions for getting at our internal data, and manipulating storage:
                //
                inline BOOST_MP_CXX14_CONSTEXPR unsigned size() const noexcept {
                    static_assert(internal_limb_count != 0, "No limbs in cpp_int_modular_base.");
                    return internal_limb_count;
                }
                inline BOOST_MP_CXX14_CONSTEXPR limb_pointer limbs() noexcept {
                    return m_wrapper.m_data;
                }
                inline BOOST_MP_CXX14_CONSTEXPR const_limb_pointer limbs() const noexcept {
                    return m_wrapper.m_data;
                }
                inline BOOST_MP_CXX14_CONSTEXPR bool sign() const noexcept {
                    // We need this function for compatibility with boost, it's always returning false for us.
                    return false;
                }

                // Zeros out everything after limb[i], replaces resizing.
                inline BOOST_MP_CXX14_CONSTEXPR void zero_after(std::size_t start_index) {
                    auto pr = this->limbs();
                    for (std::size_t i = start_index; i < this->size(); ++i) {
                        pr[i] = 0;
                    }
                }
                inline BOOST_MP_CXX14_CONSTEXPR bool has_carry() const noexcept {
                    return m_carry;
                }
                inline BOOST_MP_CXX14_CONSTEXPR void set_carry(bool carry) noexcept {
                    m_carry = carry;
                }

                inline BOOST_MP_CXX14_CONSTEXPR void normalize() noexcept {
                    limb_pointer p = limbs();
                    p[internal_limb_count - 1] &= upper_limb_mask;
                }   

                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base() noexcept
                    : m_wrapper() {
                }

                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(const cpp_int_modular_base& o) noexcept
                    : m_wrapper(o.m_wrapper) {
                }

                inline BOOST_MP_CXX14_CONSTEXPR void assign(const cpp_int_modular_base& o) noexcept {
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if (BOOST_MP_IS_CONST_EVALUATED(internal_limb_count)) {
                        for (unsigned i = 0; i < internal_limb_count; ++i)
                            limbs()[i] = o.limbs()[i];
                    } else
#endif
                    {
                        if (this != &o) {
                            std::memcpy(limbs(), o.limbs(), o.size() * sizeof(limbs()[0]));
                        }
                    }
                }

            public:
                inline BOOST_MP_CXX14_CONSTEXPR void do_swap(cpp_int_modular_base& o) noexcept {
                    for (unsigned i = 0; i < internal_limb_count; ++i)
                        boost::multiprecision::std_constexpr::swap(m_wrapper.m_data[i], o.m_wrapper.m_data[i]);
                }

            };

            //
            // Backend for unsigned fixed precision (i.e. no allocator) type which will fit entirely inside a
            // "double_limb_type":
            //
            template<unsigned Bits>
            class cpp_int_modular_base<Bits, true> {
            public:
                using local_limb_type = typename trivial_limb_type<Bits>::type;
                using limb_pointer = local_limb_type*;
                using const_limb_pointer = const local_limb_type*;
                static BOOST_MP_CXX14_CONSTEXPR unsigned limb_bits = sizeof(local_limb_type) * CHAR_BIT;
                static BOOST_MP_CXX14_CONSTEXPR limb_type max_limb_value = ~static_cast<limb_type>(0u);
 

                struct scoped_shared_storage {
                    BOOST_MP_CXX14_CONSTEXPR scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                    }
                    BOOST_MP_CXX14_CONSTEXPR void deallocate(unsigned) {
                    }
                };

                // Even though we have just 1 limb here, we still name this variable upper_limb_mask to be similar to non-trivial.
                static BOOST_MP_CXX14_CONSTEXPR local_limb_type upper_limb_mask = limb_bits != Bits ?
                    (~local_limb_type(0) >> (limb_bits - Bits)) : ~local_limb_type(0);

            private:
                local_limb_type m_data;
                bool m_carry = false;

                //
                // Interface invariants:
                //
                static_assert(Bits <= sizeof(double_limb_type) * CHAR_BIT,
                              "Template parameter Bits is inconsistent with the parameter trivial - did you "
                              "mistakingly try to override the trivial parameter?");

            public:
                //
                // Direct construction:
                //
                template<class UI>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(
                    UI i,
                    typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value
                                            >::type const* = 0) noexcept :
                    m_data(static_cast<local_limb_type>(i) & upper_limb_mask) {
                }
                BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(boost::multiprecision::literals::detail::value_pack<>) noexcept :
                    m_data(static_cast<local_limb_type>(0u)) {
                }
                template<limb_type a>
                BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(boost::multiprecision::literals::detail::value_pack<a>) noexcept :
                    m_data(static_cast<local_limb_type>(a)) {
                }
                template<limb_type a, limb_type b>
                BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(boost::multiprecision::literals::detail::value_pack<a, b>) noexcept :
                    m_data(static_cast<local_limb_type>(a) | (static_cast<local_limb_type>(b) << bits_per_limb)) {
                }
                explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(scoped_shared_storage&, unsigned) noexcept : m_data(0) {
                }
                //
                // Helper functions for getting at our internal data, and manipulating storage:
                //
                inline BOOST_MP_CXX14_CONSTEXPR unsigned size() const noexcept {
                    return 1;
                }
                inline BOOST_MP_CXX14_CONSTEXPR limb_pointer limbs() noexcept {
                    return &m_data;
                }
                inline BOOST_MP_CXX14_CONSTEXPR const_limb_pointer limbs() const noexcept {
                    return &m_data;
                }
                inline BOOST_MP_CXX14_CONSTEXPR void normalize() noexcept {
                    m_data &= upper_limb_mask;
                }   
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base() noexcept : m_data(0) {
                }
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(const cpp_int_modular_base& o) noexcept
                    : m_data(o.m_data) {
                }
                inline BOOST_MP_CXX14_CONSTEXPR void assign(const cpp_int_modular_base& o) noexcept {
                    m_data = o.m_data;
                }
                inline BOOST_MP_CXX14_CONSTEXPR void do_swap(cpp_int_modular_base& o) noexcept {
                    boost::multiprecision::std_constexpr::swap(m_data, o.m_data);
                }
                inline BOOST_MP_CXX14_CONSTEXPR bool has_carry() const noexcept {
                    return m_carry;
                }
                inline BOOST_MP_CXX14_CONSTEXPR void set_carry(bool carry) noexcept {
                    m_carry = carry;
                }
            };

            //
            // Traits class, lets us know whether type T can be directly converted to the base type,
            // used to enable/disable constructors etc:
            //
            template<class Arg, class Base>
            struct is_allowed_cpp_int_modular_base_conversion
                : public std::conditional<std::is_same<Arg, limb_type>::value
#ifdef TVM
                                              || std::is_same<Arg, unsigned int>::value||
                                              std::is_same<Arg, int>::value
#endif
#if BOOST_ENDIAN_LITTLE_BYTE && !defined(BOOST_MP_TEST_NO_LE)
                                              || std::is_same<Arg, double_limb_type>::value
#endif
                                              || boost::multiprecision::literals::detail::is_value_pack<Arg>::value ||
                                              (is_trivial_cpp_int_modular<Base>::value &&
                                               boost::multiprecision::detail::is_arithmetic<Arg>::value),
                                          std::integral_constant<bool, true>,
                                          std::integral_constant<bool, false>>::type {
            };

            template<unsigned Bits>
            class cpp_int_modular_backend
                : public cpp_int_modular_base<Bits, is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value> {

            public:
                using self_type = cpp_int_modular_backend<Bits>;
                using base_type = cpp_int_modular_base<Bits, is_trivial_cpp_int_modular<self_type>::value>;
                using trivial_tag = std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>;
#ifdef TVM
                using unsigned_types = std::tuple<unsigned, limb_type, double_limb_type>;
#else

                using unsigned_types = typename std::conditional<is_trivial_cpp_int_modular<self_type>::value,
                                                                 std::tuple<unsigned char,
                                                                            unsigned short,
                                                                            unsigned,
                                                                            unsigned long,
                                                                            boost::ulong_long_type,
                                                                            double_limb_type>,
                                                                 std::tuple<limb_type, double_limb_type>>::type;
                using cpp_int_type = boost::multiprecision::cpp_int_backend<
                    Bits, Bits,  boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>; 
#endif
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend() noexcept
                { }
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(const cpp_int_modular_backend& o) noexcept
                    : base_type(o)
                { }

                // rvalue copy:
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(cpp_int_modular_backend&& o) noexcept
                    : base_type(static_cast<base_type&&>(o)) {
                }

                // Sometimes we need to convert from one bit length to another. For example from 'Backend_doubled_limbs' to 'Backend'.
                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                        cpp_int_modular_backend<Bits2>&& o) noexcept {
                    // Call operator=, which will call do_assign.
                    *this = o;
                }

                //
                // Direct construction from arithmetic type:
                //
                template<class Arg>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                    Arg i,
                    typename std::enable_if<is_allowed_cpp_int_modular_base_conversion<Arg, base_type>::value>::type const* = 0) noexcept
                        : base_type(i) {
                }

                //
                // Aliasing constructor: the result will alias the memory referenced, unless
                // we have fixed precision and storage, in which case we copy the memory:
                //
                inline explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(limb_type* data, unsigned offset, unsigned len) noexcept
                    : base_type(data, offset, len) {
                }
                inline explicit cpp_int_modular_backend(const limb_type* data, unsigned offset, unsigned len) noexcept
                    : base_type(data, offset, len) {
                    this->normalize();
                }
                inline explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                        typename base_type::scoped_shared_storage& data,
                        unsigned len) noexcept
                    : base_type(data, len) {
                }

            private:
                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void
                    do_assign(const cpp_int_modular_backend<Bits2>& other,
                              std::integral_constant<bool, true> const&,
                              std::integral_constant<bool, true> const&) noexcept {
                    // Assigning trivial type to trivial type:
                    *this->limbs() = static_cast<typename self_type::local_limb_type>(*other.limbs());
                    this->normalize();
                }

                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void
                    do_assign(const cpp_int_modular_backend<Bits2>& other,
                              std::integral_constant<bool, true> const&,
                              std::integral_constant<bool, false> const&) noexcept {
                    // non-trivial to trivial narrowing conversion:
                    double_limb_type v = *other.limbs();
                    if (other.size() > 1) {
                        v |= static_cast<double_limb_type>(other.limbs()[1]) << bits_per_limb;
                    }
                    *this = v;
                    this->normalize();
                }
                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void do_assign(const cpp_int_modular_backend<Bits2>& other,
                                         std::integral_constant<bool, false> const&,
                                         std::integral_constant<bool, true> const&) noexcept {
                    // trivial to non-trivial.
                    *this = static_cast<typename boost::multiprecision::detail::canonical<
                        typename cpp_int_modular_backend<Bits2>::local_limb_type,
                        cpp_int_modular_backend<Bits>>::type>(*other.limbs());
                    this->normalize();
                }

                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void do_assign(
                        const cpp_int_modular_backend<Bits2>& other,
                        std::integral_constant<bool, false> const&,
                        std::integral_constant<bool, false> const&) noexcept {
#if !defined(BOOST_MP_HAS_IS_CONSTANT_EVALUATED) && !defined(BOOST_MP_HAS_BUILTIN_IS_CONSTANT_EVALUATED) && \
    !defined(BOOST_NO_CXX14_CONSTEXPR)
                    unsigned count = (std::min)(other.size(), this->size());
                    for (unsigned i = 0; i < count; ++i)
                        this->limbs()[i] = other.limbs()[i];
#else
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if (BOOST_MP_IS_CONST_EVALUATED(other.size())) {
                        unsigned count = (std::min)(other.size(), this->size());
                        for (unsigned i = 0; i < count; ++i)
                            this->limbs()[i] = other.limbs()[i];
                    } else
#endif
                        std::memcpy(this->limbs(),
                                other.limbs(),
                                (std::min)(other.size(), this->size()) * sizeof(this->limbs()[0]));
#endif
                    // Zero out everything after (std::min)(other.size(), this->size()), so if size of other was less,
                    // we have 0s at the end.
                    this->zero_after((std::min)(other.size(), this->size()));
                    this->normalize();
                }

            public:
                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                    const cpp_int_modular_backend<Bits2>& other) noexcept
                        : base_type()  {
                    do_assign(
                        other,
                        std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>(),
                        std::integral_constant<
                            bool,
                            is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>());
                }

                // Constructor from cpp_int of boost.
                inline explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(const cpp_int_type& other) {
                    this->from_cpp_int(other);
                }

                inline BOOST_MP_CXX14_CONSTEXPR void from_cpp_int(const cpp_int_type& other) {
                    // Here we need other.size(), not this->size(), because cpp_int may not use all the 
                    // limbs it has, but we will.
                    for (unsigned i = 0; i < other.size(); ++i)
                        this->limbs()[i] = other.limbs()[i];
                    // Zero out the rest.
                    for (unsigned i = other.size(); i < this->size(); ++i)
                        this->limbs()[i] = 0;
                }

                // Converting to cpp_int. We need this for multiplication, division and string conversions.
                // Since these operations are rare, there's no reason to implement then for cpp_int_modular_backend,
                // converting to cpp_int does not result to performance penalty.
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_type to_cpp_int() const {
                    cpp_int_type result;
                    result.resize(this->size(), this->size());
                    for (unsigned i = 0; i < this->size(); ++i)
                        result.limbs()[i] = this->limbs()[i];
                    result.normalize();
                    return std::move(result);
                }

                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend& operator=(const cpp_int_modular_backend<Bits2>& other) noexcept {
                    do_assign(
                        other,
                        std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>(),
                        std::integral_constant<
                            bool,
                            is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>());
                    return *this;
                }

                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend& operator=(const cpp_int_modular_backend& o) noexcept {
                    this->assign(o);
                    return *this;
                }

                // rvalue copy:
                inline BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend& operator=(cpp_int_modular_backend&& o) noexcept {
                    *static_cast<base_type*>(this) = static_cast<base_type&&>(o);
                    return *this;
                }
                template<unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR
                    typename std::enable_if<(Bits2 <= Bits), cpp_int_modular_backend&>::type
                    operator=(cpp_int_modular_backend<Bits2>&& o) noexcept {
                    *static_cast<base_type*>(this) = static_cast<typename cpp_int_modular_backend<Bits2>::base_type&&>(o);
                    return *this;
                }
               
            private:
                // Second argument "std::integral_constant<bool, true>" is set to true to indicate A being a "trivial cpp_int type".
                template<class A>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<boost::multiprecision::detail::is_unsigned<A>::value>::type
                    do_assign_arithmetic(A val, const std::integral_constant<bool, true>&) noexcept {
                    *this->limbs() = static_cast<typename self_type::local_limb_type>(val);
                    this->normalize();
                }

                inline BOOST_MP_CXX14_CONSTEXPR void do_assign_arithmetic(
                    limb_type i, const std::integral_constant<bool, false>&) noexcept {

                    *this->limbs() = i;
                    this->zero_after(1);
                    this->normalize();
                }

                inline BOOST_MP_CXX14_CONSTEXPR void do_assign_arithmetic(
                    double_limb_type i, const std::integral_constant<bool, false>&) noexcept {
#ifndef  TVM
                    static_assert(sizeof(i) == 2 * sizeof(limb_type), "Failed integer size check");
#endif // TVM
                    static_assert(base_type::internal_limb_count >= 2, "Failed internal limb count");
                    typename base_type::limb_pointer p = this->limbs();
#ifdef __MSVC_RUNTIME_CHECKS
                    *p = static_cast<limb_type>(i & ~static_cast<limb_type>(0));
#else
                    *p = static_cast<limb_type>(i);
#endif
                    p[1] = static_cast<limb_type>(i >> base_type::limb_bits);
                    this->zero_after(2);
                    this->normalize();
                }
#ifdef TVM
                inline BOOST_MP_CXX14_CONSTEXPR void
                    do_assign_arithmetic(unsigned i, const std::integral_constant<bool, false>& tag) noexcept {
                    do_assign_arithmetic(double_limb_type(i), tag);
                }
#endif

            public:
                template<class Arithmetic>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !boost::multiprecision::detail::is_byte_container<Arithmetic>::value,
                    cpp_int_modular_backend&>::type
                    operator=(Arithmetic val) noexcept {
                    do_assign_arithmetic(val, trivial_tag());
                    return *this;
                }
#ifndef TVM
            public:
                cpp_int_modular_backend& operator=(const char* s) {
                    cpp_int_type value;
                    value = s;
                    this->from_cpp_int(value);
                    return *this;
                }
#endif
                inline BOOST_MP_CXX14_CONSTEXPR void swap(cpp_int_modular_backend& o) noexcept {
                    this->do_swap(o);
                }
#ifndef TVM
            public:
                std::string str(std::streamsize digits, std::ios_base::fmtflags f) const {
                    cpp_int_type value = to_cpp_int();
                    return value.str(digits, f);
                }
#endif // TVM
            public:
                template<class Container>
                BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                    const Container& c,
                    typename std::enable_if<
                        boost::multiprecision::detail::is_byte_container<Container>::value>::type const* =
                        0) {
                    cpp_int_type value(c);
                    this->from_cpp_int(value);
                }

                BOOST_MP_CXX14_CONSTEXPR int compare_imp(const cpp_int_modular_backend<Bits>& o,
                                         const std::integral_constant<bool, false>&,
                                         const std::integral_constant<bool, false>&) const noexcept {
                    return compare_unsigned(o);
                }
                BOOST_MP_CXX14_CONSTEXPR int compare_imp(const cpp_int_modular_backend<Bits>& o,
                                          const std::integral_constant<bool, true>&,
                                          const std::integral_constant<bool, false>&) const {
                    cpp_int_modular_backend<Bits> t(*this);
                    return t.compare(o);
                }
                BOOST_MP_CXX14_CONSTEXPR int compare_imp(const cpp_int_modular_backend<Bits>& o,
                                          const std::integral_constant<bool, false>&,
                                          const std::integral_constant<bool, true>&) const {
                    cpp_int_modular_backend<Bits> t(o);
                    return compare(t);
                }
                BOOST_MP_CXX14_CONSTEXPR int compare_imp(const cpp_int_modular_backend<Bits>& o,
                                          const std::integral_constant<bool, true>&,
                                          const std::integral_constant<bool, true>&) const noexcept {
                    return *this->limbs() < *o.limbs() ? -1 : (*this->limbs() > *o.limbs() ? 1 : 0);
                }
                BOOST_MP_CXX14_CONSTEXPR int compare(const cpp_int_modular_backend<Bits>& o) const noexcept {
                    using t = std::integral_constant<
                        bool,
                        is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>;
                    return compare_imp(o, t(), t());
                }
                BOOST_MP_CXX14_CONSTEXPR int compare_unsigned(const cpp_int_modular_backend<Bits>& o) const noexcept {
                    typename base_type::const_limb_pointer pa = this->limbs();
                    typename base_type::const_limb_pointer pb = o.limbs();
                    for (int i = this->size() - 1; i >= 0; --i) {
                        if (pa[i] != pb[i])
                            return pa[i] > pb[i] ? 1 : -1;
                    }
                    return 0;
                }
                template<class Arithmetic>
                inline BOOST_MP_CXX14_CONSTEXPR
                    typename std::enable_if<boost::multiprecision::detail::is_arithmetic<Arithmetic>::value,
                                            int>::type
                    compare(Arithmetic i) const {
                    // braindead version:
                    cpp_int_modular_backend t;
                    t = i;
                    return compare(t);
                }
            };

            template<unsigned Bits>
            std::ostream& operator<<(std::ostream& os, const cpp_int_modular_backend<Bits>& value) {
                // Conver to number and print.
                os << std::hex << boost::multiprecision::number<cpp_int_modular_backend<Bits>>(value) << std::endl;
                return os;
            }
        }    // namespace backends
        using boost::multiprecision::backends::cpp_int_modular_backend;

        template<unsigned Bits>
        struct number_category<cpp_int_modular_backend<Bits>>
            : public std::integral_constant<int, number_kind_integer> { };

        template<unsigned Bits>
        struct expression_template_default<boost::multiprecision::backends::cpp_int_modular_backend<Bits>> {
            static BOOST_MP_CXX14_CONSTEXPR const expression_template_option value = boost::multiprecision::et_off;
        };

        // Fixed precision unsigned types:
        using uint128_modular_t = number<cpp_int_modular_backend<128>>;
        using uint256_modular_t = number<cpp_int_modular_backend<256>>;
        using uint512_modular_t = number<cpp_int_modular_backend<512>>;
        using uint1024_modular_t = number<cpp_int_modular_backend<1024>>;

    } // namespace multiprecision
} // namespace boost


#ifdef _MSC_VER
#pragma warning(pop)
#endif


//
// Last of all we include the implementations of all the eval_* non member functions:
//
#include <nil/crypto3/multiprecision/cpp_int_modular/bitwise.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/limits.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/comparison.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/add.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/eval_jacobi.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/multiply.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/divide.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/misc.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/import_export.hpp>
#include <nil/crypto3/multiprecision/traits/is_backend.hpp>

#endif
