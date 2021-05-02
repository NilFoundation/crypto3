///////////////////////////////////////////////////////////////////////////////
// Copyright Christopher Kormanyos 2002 - 2013.
// Copyright 2011 -2013 John Maddock. Distributed under the Boost
// Software License, Version 1.0. (See accompanying file
// LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This work is based on an earlier work:
// "Algorithm 910: A Portable C++ Multiple-Precision System for Special-Function Calculations",
// in ACM TOMS, {VOL 37, ISSUE 4, (February 2011)} (C) ACM, 2011. http://doi.acm.org/10.1145/1916461.1916469
//
// Note that there are no "noexcept" specifications on the functions in this file: there are too many
// calls to lexical_cast (and similar) to easily analyse the code for correctness. So until compilers
// can detect noexcept misuse at compile time, the only realistic option is to simply not use it here.
//

#ifndef BOOST_MP_CPP_DEC_FLOAT_BACKEND_HPP
#define BOOST_MP_CPP_DEC_FLOAT_BACKEND_HPP

#include <boost/config.hpp>
#include <boost/cstdint.hpp>
#include <limits>
#ifndef BOOST_NO_CXX11_HDR_ARRAY
#include <array>
#else
#include <boost/array.hpp>
#endif
#include <boost/cstdint.hpp>
#include <boost/functional/hash_fwd.hpp>
#include <boost/mpl/list.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/detail/big_lanczos.hpp>
#include <nil/crypto3/multiprecision/detail/dynamic_array.hpp>
#include <nil/crypto3/multiprecision/detail/itos.hpp>

//
// Headers required for Boost.Math integration:
//
#include <boost/math/policies/policy.hpp>
//
// Some includes we need from Boost.Math, since we rely on that library to provide these functions:
//
#include <boost/math/special_functions/asinh.hpp>
#include <boost/math/special_functions/acosh.hpp>
#include <boost/math/special_functions/atanh.hpp>
#include <boost/math/special_functions/cbrt.hpp>
#include <boost/math/special_functions/expm1.hpp>
#include <boost/math/special_functions/gamma.hpp>

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 6326)    // comparison of two constants
#endif

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                template<unsigned Digits10, class ExponentType = boost::int32_t, class Allocator = void>
                class cpp_dec_float;

            }    // namespace backends

            template<unsigned Digits10, class ExponentType, class Allocator>
            struct number_category<backends::cpp_dec_float<Digits10, ExponentType, Allocator>>
                : public boost::mpl::int_<number_kind_floating_point> { };

            namespace backends {

                template<unsigned Digits10, class ExponentType, class Allocator>
                class cpp_dec_float {
                private:
                    static const boost::int32_t cpp_dec_float_digits10_setting = Digits10;

                    // We need at least 16-bits in the exponent type to do anything sensible:
                    BOOST_STATIC_ASSERT_MSG(boost::is_signed<ExponentType>::value,
                                            "ExponentType must be a signed built in integer type.");
                    BOOST_STATIC_ASSERT_MSG(sizeof(ExponentType) > 1, "ExponentType is too small.");

                public:
                    typedef boost::mpl::list<boost::long_long_type> signed_types;
                    typedef boost::mpl::list<boost::ulong_long_type> unsigned_types;
                    typedef boost::mpl::list<double, long double> float_types;
                    typedef ExponentType exponent_type;

                    static const boost::int32_t cpp_dec_float_radix = 10L;
                    static const boost::int32_t cpp_dec_float_digits10_limit_lo = 9L;
                    static const boost::int32_t cpp_dec_float_digits10_limit_hi =
                        boost::integer_traits<boost::int32_t>::const_max - 100;
                    static const boost::int32_t cpp_dec_float_digits10 =
                        ((cpp_dec_float_digits10_setting < cpp_dec_float_digits10_limit_lo) ?
                             cpp_dec_float_digits10_limit_lo :
                             ((cpp_dec_float_digits10_setting > cpp_dec_float_digits10_limit_hi) ?
                                  cpp_dec_float_digits10_limit_hi :
                                  cpp_dec_float_digits10_setting));
                    static const ExponentType cpp_dec_float_max_exp10 =
                        (static_cast<ExponentType>(1) << (std::numeric_limits<ExponentType>::digits - 5));
                    static const ExponentType cpp_dec_float_min_exp10 = -cpp_dec_float_max_exp10;
                    static const ExponentType cpp_dec_float_max_exp = cpp_dec_float_max_exp10;
                    static const ExponentType cpp_dec_float_min_exp = cpp_dec_float_min_exp10;

                    BOOST_STATIC_ASSERT((cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_max_exp10 ==
                                         -cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp10));

                private:
                    static const boost::int32_t cpp_dec_float_elem_digits10 = 8L;
                    static const boost::int32_t cpp_dec_float_elem_mask = 100000000L;

                    BOOST_STATIC_ASSERT(0 == cpp_dec_float_max_exp10 % cpp_dec_float_elem_digits10);

                    // There are three guard limbs.
                    // 1) The first limb has 'play' from 1...8 decimal digits.
                    // 2) The last limb also has 'play' from 1...8 decimal digits.
                    // 3) One limb can get lost when justifying after multiply,
                    // as only half of the triangle is multiplied and a carry
                    // from below is missing.
                    static const boost::int32_t cpp_dec_float_elem_number_request = static_cast<boost::int32_t>(
                        (cpp_dec_float_digits10 / cpp_dec_float_elem_digits10) +
                        (((cpp_dec_float_digits10 % cpp_dec_float_elem_digits10) != 0) ? 1 : 0));

                    // The number of elements needed (with a minimum of two) plus three added guard limbs.
                    static const boost::int32_t cpp_dec_float_elem_number = static_cast<boost::int32_t>(
                        ((cpp_dec_float_elem_number_request < 2L) ? 2L : cpp_dec_float_elem_number_request) + 3L);

                public:
                    static const boost::int32_t cpp_dec_float_total_digits10 =
                        static_cast<boost::int32_t>(cpp_dec_float_elem_number * cpp_dec_float_elem_digits10);

                private:
                    typedef enum enum_fpclass_type {
                        cpp_dec_float_finite,
                        cpp_dec_float_inf,
                        cpp_dec_float_NaN
                    } fpclass_type;

#ifndef BOOST_NO_CXX11_HDR_ARRAY
                    typedef typename boost::mpl::if_<
                        boost::is_void<Allocator>,
                        std::array<boost::uint32_t, cpp_dec_float_elem_number>,
                        detail::dynamic_array<boost::uint32_t, cpp_dec_float_elem_number, Allocator>>::type array_type;
#else
                    typedef typename boost::mpl::if_<
                        boost::is_void<Allocator>,
                        boost::array<boost::uint32_t, cpp_dec_float_elem_number>,
                        detail::dynamic_array<boost::uint32_t, cpp_dec_float_elem_number, Allocator>>::type array_type;
#endif

                    array_type data;
                    ExponentType exp;
                    bool neg;
                    fpclass_type fpclass;
                    boost::int32_t prec_elem;

                    //
                    // Special values constructor:
                    //
                    cpp_dec_float(fpclass_type c) :
                        data(), exp(static_cast<ExponentType>(0)), neg(false), fpclass(c),
                        prec_elem(cpp_dec_float_elem_number) {
                    }

                    //
                    // Static data initializer:
                    //
                    struct initializer {
                        initializer() {
                            cpp_dec_float<Digits10, ExponentType, Allocator>::nan();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::inf();
                            (cpp_dec_float<Digits10, ExponentType, Allocator>::min)();
                            (cpp_dec_float<Digits10, ExponentType, Allocator>::max)();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::zero();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::one();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::two();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::half();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::double_min();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::double_max();
                            // cpp_dec_float<Digits10, ExponentType, Allocator>::long_double_max();
                            // cpp_dec_float<Digits10, ExponentType, Allocator>::long_double_min();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::long_long_max();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::long_long_min();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::ulong_long_max();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::eps();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(0);
                        }
                        void do_nothing() {
                        }
                    };

                    static initializer init;

                    struct long_double_initializer {
                        long_double_initializer() {
                            cpp_dec_float<Digits10, ExponentType, Allocator>::long_double_max();
                            cpp_dec_float<Digits10, ExponentType, Allocator>::long_double_min();
                        }
                        void do_nothing() {
                        }
                    };

                    static long_double_initializer linit;

                public:
                    // Constructors
                    cpp_dec_float() BOOST_MP_NOEXCEPT_IF(noexcept(array_type())) :
                        data(), exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                        prec_elem(cpp_dec_float_elem_number) {
                    }

                    cpp_dec_float(const char* s) :
                        data(), exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                        prec_elem(cpp_dec_float_elem_number) {
                        *this = s;
                    }

                    template<class I>
                    cpp_dec_float(I i, typename boost::enable_if<boost::is_unsigned<I>>::type* = 0) :
                        data(), exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                        prec_elem(cpp_dec_float_elem_number) {
                        from_unsigned_long_long(i);
                    }

                    template<class I>
                    cpp_dec_float(I i, typename boost::enable_if<boost::is_signed<I>>::type* = 0) :
                        data(), exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                        prec_elem(cpp_dec_float_elem_number) {
                        if (i < 0) {
                            from_unsigned_long_long(nil::crypto3::multiprecision::detail::unsigned_abs(i));
                            negate();
                        } else
                            from_unsigned_long_long(i);
                    }

                    cpp_dec_float(const cpp_dec_float& f)
                        BOOST_MP_NOEXCEPT_IF(noexcept(array_type(std::declval<const array_type&>()))) :
                        data(f.data),
                        exp(f.exp), neg(f.neg), fpclass(f.fpclass), prec_elem(f.prec_elem) {
                    }

                    template<unsigned D, class ET, class A>
                    cpp_dec_float(const cpp_dec_float<D, ET, A>& f,
                                  typename boost::enable_if_c<D <= Digits10>::type* = 0) :
                        data(),
                        exp(f.exp), neg(f.neg), fpclass(static_cast<fpclass_type>(static_cast<int>(f.fpclass))),
                        prec_elem(cpp_dec_float_elem_number) {
                        std::copy(f.data.begin(), f.data.begin() + f.prec_elem, data.begin());
                    }
                    template<unsigned D, class ET, class A>
                    explicit cpp_dec_float(const cpp_dec_float<D, ET, A>& f,
                                           typename boost::disable_if_c<D <= Digits10>::type* = 0) :
                        data(),
                        exp(f.exp), neg(f.neg), fpclass(static_cast<fpclass_type>(static_cast<int>(f.fpclass))),
                        prec_elem(cpp_dec_float_elem_number) {
                        // TODO: this doesn't round!
                        std::copy(f.data.begin(), f.data.begin() + prec_elem, data.begin());
                    }

                    template<class F>
                    cpp_dec_float(const F val,
                                  typename boost::enable_if_c<boost::is_floating_point<F>::value
#ifdef BOOST_HAS_FLOAT128
                                                              && !boost::is_same<F, __float128>::value
#endif
                                                              >::type* = 0) :
                        data(),
                        exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                        prec_elem(cpp_dec_float_elem_number) {
                        *this = val;
                    }

                    cpp_dec_float(const double mantissa, const ExponentType exponent);

                    std::size_t hash() const {
                        std::size_t result = 0;
                        for (int i = 0; i < prec_elem; ++i)
                            boost::hash_combine(result, data[i]);
                        boost::hash_combine(result, exp);
                        boost::hash_combine(result, neg);
                        boost::hash_combine(result, fpclass);
                        return result;
                    }

                    // Specific special values.
                    static const cpp_dec_float& nan() {
                        static const cpp_dec_float val(cpp_dec_float_NaN);
                        init.do_nothing();
                        return val;
                    }

                    static const cpp_dec_float& inf() {
                        static const cpp_dec_float val(cpp_dec_float_inf);
                        init.do_nothing();
                        return val;
                    }

                    static const cpp_dec_float&(max)() {
                        init.do_nothing();
                        static cpp_dec_float val_max =
                            std::string("1.0e" + nil::crypto3::multiprecision::detail::itos(cpp_dec_float_max_exp10))
                                .c_str();
                        return val_max;
                    }

                    static const cpp_dec_float&(min)() {
                        init.do_nothing();
                        static cpp_dec_float val_min =
                            std::string("1.0e" + nil::crypto3::multiprecision::detail::itos(cpp_dec_float_min_exp10))
                                .c_str();
                        return val_min;
                    }

                    static const cpp_dec_float& zero() {
                        init.do_nothing();
                        static cpp_dec_float val(static_cast<boost::ulong_long_type>(0u));
                        return val;
                    }

                    static const cpp_dec_float& one() {
                        init.do_nothing();
                        static cpp_dec_float val(static_cast<boost::ulong_long_type>(1u));
                        return val;
                    }

                    static const cpp_dec_float& two() {
                        init.do_nothing();
                        static cpp_dec_float val(static_cast<boost::ulong_long_type>(2u));
                        return val;
                    }

                    static const cpp_dec_float& half() {
                        init.do_nothing();
                        static cpp_dec_float val(0.5L);
                        return val;
                    }

                    static const cpp_dec_float& double_min() {
                        init.do_nothing();
                        static cpp_dec_float val((std::numeric_limits<double>::min)());
                        return val;
                    }

                    static const cpp_dec_float& double_max() {
                        init.do_nothing();
                        static cpp_dec_float val((std::numeric_limits<double>::max)());
                        return val;
                    }

                    static const cpp_dec_float& long_double_min() {
                        linit.do_nothing();
#ifdef BOOST_MATH_NO_LONG_DOUBLE_MATH_FUNCTIONS
                        static cpp_dec_float val(static_cast<long double>((std::numeric_limits<double>::min)()));
#else
                        static cpp_dec_float val((std::numeric_limits<long double>::min)());
#endif
                        return val;
                    }

                    static const cpp_dec_float& long_double_max() {
                        linit.do_nothing();
#ifdef BOOST_MATH_NO_LONG_DOUBLE_MATH_FUNCTIONS
                        static cpp_dec_float val(static_cast<long double>((std::numeric_limits<double>::max)()));
#else
                        static cpp_dec_float val((std::numeric_limits<long double>::max)());
#endif
                        return val;
                    }

                    static const cpp_dec_float& long_long_max() {
                        init.do_nothing();
                        static cpp_dec_float val((std::numeric_limits<boost::long_long_type>::max)());
                        return val;
                    }

                    static const cpp_dec_float& long_long_min() {
                        init.do_nothing();
                        static cpp_dec_float val((std::numeric_limits<boost::long_long_type>::min)());
                        return val;
                    }

                    static const cpp_dec_float& ulong_long_max() {
                        init.do_nothing();
                        static cpp_dec_float val((std::numeric_limits<boost::ulong_long_type>::max)());
                        return val;
                    }

                    static const cpp_dec_float& eps() {
                        init.do_nothing();
                        static cpp_dec_float val(1.0, 1 - static_cast<int>(cpp_dec_float_digits10));
                        return val;
                    }

                    // Basic operations.
                    cpp_dec_float& operator=(const cpp_dec_float& v) BOOST_MP_NOEXCEPT_IF(
                        noexcept(std::declval<array_type&>() = std::declval<const array_type&>())) {
                        data = v.data;
                        exp = v.exp;
                        neg = v.neg;
                        fpclass = v.fpclass;
                        prec_elem = v.prec_elem;
                        return *this;
                    }

                    template<unsigned D>
                    cpp_dec_float& operator=(const cpp_dec_float<D>& f) {
                        exp = f.exp;
                        neg = f.neg;
                        fpclass = static_cast<enum_fpclass_type>(static_cast<int>(f.fpclass));
                        unsigned elems = (std::min)(f.prec_elem, cpp_dec_float_elem_number);
                        std::copy(f.data.begin(), f.data.begin() + elems, data.begin());
                        std::fill(data.begin() + elems, data.end(), 0);
                        prec_elem = cpp_dec_float_elem_number;
                        return *this;
                    }

                    cpp_dec_float& operator=(boost::long_long_type v) {
                        if (v < 0) {
                            from_unsigned_long_long(
                                1u -
                                boost::ulong_long_type(
                                    v + 1));    // Avoid undefined behaviour in negation of minimum value for long long
                            negate();
                        } else
                            from_unsigned_long_long(v);
                        return *this;
                    }

                    cpp_dec_float& operator=(boost::ulong_long_type v) {
                        from_unsigned_long_long(v);
                        return *this;
                    }

                    template<class Float>
                    typename boost::enable_if_c<boost::is_floating_point<Float>::value, cpp_dec_float&>::type
                        operator=(Float v);

                    cpp_dec_float& operator=(const char* v) {
                        rd_string(v);
                        return *this;
                    }

                    cpp_dec_float& operator+=(const cpp_dec_float& v);
                    cpp_dec_float& operator-=(const cpp_dec_float& v);
                    cpp_dec_float& operator*=(const cpp_dec_float& v);
                    cpp_dec_float& operator/=(const cpp_dec_float& v);

                    cpp_dec_float& add_unsigned_long_long(const boost::ulong_long_type n) {
                        cpp_dec_float t;
                        t.from_unsigned_long_long(n);
                        return *this += t;
                    }

                    cpp_dec_float& sub_unsigned_long_long(const boost::ulong_long_type n) {
                        cpp_dec_float t;
                        t.from_unsigned_long_long(n);
                        return *this -= t;
                    }

                    cpp_dec_float& mul_unsigned_long_long(const boost::ulong_long_type n);
                    cpp_dec_float& div_unsigned_long_long(const boost::ulong_long_type n);

                    // Elementary primitives.
                    cpp_dec_float& calculate_inv();
                    cpp_dec_float& calculate_sqrt();

                    void negate() {
                        if (!iszero())
                            neg = !neg;
                    }

                    // Comparison functions
                    bool isnan BOOST_PREVENT_MACRO_SUBSTITUTION() const {
                        return (fpclass == cpp_dec_float_NaN);
                    }
                    bool isinf BOOST_PREVENT_MACRO_SUBSTITUTION() const {
                        return (fpclass == cpp_dec_float_inf);
                    }
                    bool isfinite BOOST_PREVENT_MACRO_SUBSTITUTION() const {
                        return (fpclass == cpp_dec_float_finite);
                    }

                    bool iszero() const {
                        return ((fpclass == cpp_dec_float_finite) && (data[0u] == 0u));
                    }

                    bool isone() const;
                    bool isint() const;
                    bool isneg() const {
                        return neg;
                    }

                    // Operators pre-increment and pre-decrement
                    cpp_dec_float& operator++() {
                        return *this += one();
                    }

                    cpp_dec_float& operator--() {
                        return *this -= one();
                    }

                    std::string str(boost::intmax_t digits, std::ios_base::fmtflags f) const;

                    int compare(const cpp_dec_float& v) const;

                    template<class V>
                    int compare(const V& v) const {
                        cpp_dec_float<Digits10, ExponentType, Allocator> t;
                        t = v;
                        return compare(t);
                    }

                    void swap(cpp_dec_float& v) {
                        data.swap(v.data);
                        std::swap(exp, v.exp);
                        std::swap(neg, v.neg);
                        std::swap(fpclass, v.fpclass);
                        std::swap(prec_elem, v.prec_elem);
                    }

                    double extract_double() const;
                    long double extract_long_double() const;
                    boost::long_long_type extract_signed_long_long() const;
                    boost::ulong_long_type extract_unsigned_long_long() const;
                    void extract_parts(double& mantissa, ExponentType& exponent) const;
                    cpp_dec_float extract_integer_part() const;

                    void precision(const boost::int32_t prec_digits) {
                        if (prec_digits >= cpp_dec_float_total_digits10) {
                            prec_elem = cpp_dec_float_elem_number;
                        } else {
                            const boost::int32_t elems = static_cast<boost::int32_t>(
                                static_cast<boost::int32_t>((prec_digits + (cpp_dec_float_elem_digits10 / 2)) /
                                                            cpp_dec_float_elem_digits10) +
                                static_cast<boost::int32_t>(((prec_digits % cpp_dec_float_elem_digits10) != 0) ? 1 :
                                                                                                                 0));

                            prec_elem = (std::min)(cpp_dec_float_elem_number,
                                                   (std::max)(elems, static_cast<boost::int32_t>(2)));
                        }
                    }
                    static cpp_dec_float pow2(boost::long_long_type i);
                    ExponentType order() const {
                        const bool bo_order_is_zero =
                            ((!(isfinite)()) || (data[0] == static_cast<boost::uint32_t>(0u)));
                        //
                        // Binary search to find the order of the leading term:
                        //
                        ExponentType prefix = 0;

                        if (data[0] >= 100000UL) {
                            if (data[0] >= 10000000UL) {
                                if (data[0] >= 100000000UL) {
                                    if (data[0] >= 1000000000UL)
                                        prefix = 9;
                                    else
                                        prefix = 8;
                                } else
                                    prefix = 7;
                            } else {
                                if (data[0] >= 1000000UL)
                                    prefix = 6;
                                else
                                    prefix = 5;
                            }
                        } else {
                            if (data[0] >= 1000UL) {
                                if (data[0] >= 10000UL)
                                    prefix = 4;
                                else
                                    prefix = 3;
                            } else {
                                if (data[0] >= 100)
                                    prefix = 2;
                                else if (data[0] >= 10)
                                    prefix = 1;
                            }
                        }

                        return (bo_order_is_zero ? static_cast<ExponentType>(0) :
                                                   static_cast<ExponentType>(exp + prefix));
                    }

                    template<class Archive>
                    void serialize(Archive& ar, const unsigned int /*version*/) {
                        for (unsigned i = 0; i < data.size(); ++i)
                            ar& boost::make_nvp("digit", data[i]);
                        ar& boost::make_nvp("exponent", exp);
                        ar& boost::make_nvp("sign", neg);
                        ar& boost::make_nvp("class-type", fpclass);
                        ar& boost::make_nvp("precision", prec_elem);
                    }

                private:
                    static bool data_elem_is_non_zero_predicate(const boost::uint32_t& d) {
                        return (d != static_cast<boost::uint32_t>(0u));
                    }
                    static bool data_elem_is_non_nine_predicate(const boost::uint32_t& d) {
                        return (d != static_cast<boost::uint32_t>(cpp_dec_float::cpp_dec_float_elem_mask - 1));
                    }
                    static bool char_is_nonzero_predicate(const char& c) {
                        return (c != static_cast<char>('0'));
                    }

                    void from_unsigned_long_long(const boost::ulong_long_type u);

                    int cmp_data(const array_type& vd) const;

                    static boost::uint32_t
                        mul_loop_uv(boost::uint32_t* const u, const boost::uint32_t* const v, const boost::int32_t p);
                    static boost::uint32_t
                        mul_loop_n(boost::uint32_t* const u, boost::uint32_t n, const boost::int32_t p);
                    static boost::uint32_t
                        div_loop_n(boost::uint32_t* const u, boost::uint32_t n, const boost::int32_t p);

                    bool rd_string(const char* const s);

                    template<unsigned D, class ET, class A>
                    friend class cpp_dec_float;
                };

                template<unsigned Digits10, class ExponentType, class Allocator>
                typename cpp_dec_float<Digits10, ExponentType, Allocator>::initializer
                    cpp_dec_float<Digits10, ExponentType, Allocator>::init;
                template<unsigned Digits10, class ExponentType, class Allocator>
                typename cpp_dec_float<Digits10, ExponentType, Allocator>::long_double_initializer
                    cpp_dec_float<Digits10, ExponentType, Allocator>::linit;

                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_radix;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10_setting;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10_limit_lo;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10_limit_hi;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const ExponentType cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_max_exp;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const ExponentType cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const ExponentType cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_max_exp10;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const ExponentType cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp10;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_elem_digits10;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t
                    cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_elem_number_request;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_elem_number;
                template<unsigned Digits10, class ExponentType, class Allocator>
                const boost::int32_t cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_elem_mask;

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::operator+=(
                        const cpp_dec_float<Digits10, ExponentType, Allocator>& v) {
                    if ((isnan)()) {
                        return *this;
                    }

                    if ((isinf)()) {
                        if ((v.isinf)() && (isneg() != v.isneg())) {
                            *this = nan();
                        }
                        return *this;
                    }

                    if (iszero()) {
                        return operator=(v);
                    }

                    if ((v.isnan)() || (v.isinf)()) {
                        *this = v;
                        return *this;
                    }

                    // Get the offset for the add/sub operation.
                    static const ExponentType max_delta_exp =
                        static_cast<ExponentType>((cpp_dec_float_elem_number - 1) * cpp_dec_float_elem_digits10);

                    const ExponentType ofs_exp = static_cast<ExponentType>(exp - v.exp);

                    // Check if the operation is out of range, requiring special handling.
                    if (v.iszero() || (ofs_exp > max_delta_exp)) {
                        // Result is *this unchanged since v is negligible compared to *this.
                        return *this;
                    } else if (ofs_exp < -max_delta_exp) {
                        // Result is *this = v since *this is negligible compared to v.
                        return operator=(v);
                    }

                    // Do the add/sub operation.

                    typename array_type::iterator p_u = data.begin();
                    typename array_type::const_iterator p_v = v.data.begin();
                    bool b_copy = false;
                    const boost::int32_t ofs =
                        static_cast<boost::int32_t>(static_cast<boost::int32_t>(ofs_exp) / cpp_dec_float_elem_digits10);
                    array_type n_data;

                    if (neg == v.neg) {
                        // Add v to *this, where the data array of either *this or v
                        // might have to be treated with a positive, negative or zero offset.
                        // The result is stored in *this. The data are added one element
                        // at a time, each element with carry.
                        if (ofs >= static_cast<boost::int32_t>(0)) {
                            std::copy(v.data.begin(),
                                      v.data.end() - static_cast<size_t>(ofs),
                                      n_data.begin() + static_cast<size_t>(ofs));
                            std::fill(n_data.begin(),
                                      n_data.begin() + static_cast<size_t>(ofs),
                                      static_cast<boost::uint32_t>(0u));
                            p_v = n_data.begin();
                        } else {
                            std::copy(data.begin(),
                                      data.end() - static_cast<size_t>(-ofs),
                                      n_data.begin() + static_cast<size_t>(-ofs));
                            std::fill(n_data.begin(),
                                      n_data.begin() + static_cast<size_t>(-ofs),
                                      static_cast<boost::uint32_t>(0u));
                            p_u = n_data.begin();
                            b_copy = true;
                        }

                        // Addition algorithm
                        boost::uint32_t carry = static_cast<boost::uint32_t>(0u);

                        for (boost::int32_t j = static_cast<boost::int32_t>(cpp_dec_float_elem_number -
                                                                            static_cast<boost::int32_t>(1));
                             j >= static_cast<boost::int32_t>(0);
                             j--) {
                            boost::uint32_t t =
                                static_cast<boost::uint32_t>(static_cast<boost::uint32_t>(p_u[j] + p_v[j]) + carry);
                            carry = t / static_cast<boost::uint32_t>(cpp_dec_float_elem_mask);
                            p_u[j] = static_cast<boost::uint32_t>(
                                t - static_cast<boost::uint32_t>(
                                        carry * static_cast<boost::uint32_t>(cpp_dec_float_elem_mask)));
                        }

                        if (b_copy) {
                            data = n_data;
                            exp = v.exp;
                        }

                        // There needs to be a carry into the element -1 of the array data
                        if (carry != static_cast<boost::uint32_t>(0u)) {
                            std::copy_backward(data.begin(), data.end() - static_cast<std::size_t>(1u), data.end());
                            data[0] = carry;
                            exp += static_cast<ExponentType>(cpp_dec_float_elem_digits10);
                        }
                    } else {
                        // Subtract v from *this, where the data array of either *this or v
                        // might have to be treated with a positive, negative or zero offset.
                        if ((ofs > static_cast<boost::int32_t>(0)) ||
                            ((ofs == static_cast<boost::int32_t>(0)) &&
                             (cmp_data(v.data) > static_cast<boost::int32_t>(0)))) {
                            // In this case, |u| > |v| and ofs is positive.
                            // Copy the data of v, shifted down to a lower value
                            // into the data array m_n. Set the operand pointer p_v
                            // to point to the copied, shifted data m_n.
                            std::copy(v.data.begin(),
                                      v.data.end() - static_cast<size_t>(ofs),
                                      n_data.begin() + static_cast<size_t>(ofs));
                            std::fill(n_data.begin(),
                                      n_data.begin() + static_cast<size_t>(ofs),
                                      static_cast<boost::uint32_t>(0u));
                            p_v = n_data.begin();
                        } else {
                            if (ofs != static_cast<boost::int32_t>(0)) {
                                // In this case, |u| < |v| and ofs is negative.
                                // Shift the data of u down to a lower value.
                                std::copy_backward(data.begin(), data.end() - static_cast<size_t>(-ofs), data.end());
                                std::fill(data.begin(),
                                          data.begin() + static_cast<size_t>(-ofs),
                                          static_cast<boost::uint32_t>(0u));
                            }

                            // Copy the data of v into the data array n_data.
                            // Set the u-pointer p_u to point to m_n and the
                            // operand pointer p_v to point to the shifted
                            // data m_data.
                            n_data = v.data;
                            p_u = n_data.begin();
                            p_v = data.begin();
                            b_copy = true;
                        }

                        boost::int32_t j;

                        // Subtraction algorithm
                        boost::int32_t borrow = static_cast<boost::int32_t>(0);

                        for (j = static_cast<boost::int32_t>(cpp_dec_float_elem_number -
                                                             static_cast<boost::int32_t>(1));
                             j >= static_cast<boost::int32_t>(0);
                             j--) {
                            boost::int32_t t = static_cast<boost::int32_t>(
                                static_cast<boost::int32_t>(static_cast<boost::int32_t>(p_u[j]) -
                                                            static_cast<boost::int32_t>(p_v[j])) -
                                borrow);

                            // Underflow? Borrow?
                            if (t < static_cast<boost::int32_t>(0)) {
                                // Yes, underflow and borrow
                                t += static_cast<boost::int32_t>(cpp_dec_float_elem_mask);
                                borrow = static_cast<boost::int32_t>(1);
                            } else {
                                borrow = static_cast<boost::int32_t>(0);
                            }

                            p_u[j] =
                                static_cast<boost::uint32_t>(static_cast<boost::uint32_t>(t) %
                                                             static_cast<boost::uint32_t>(cpp_dec_float_elem_mask));
                        }

                        if (b_copy) {
                            data = n_data;
                            exp = v.exp;
                            neg = v.neg;
                        }

                        // Is it necessary to justify the data?
                        const typename array_type::const_iterator first_nonzero_elem =
                            std::find_if(data.begin(), data.end(), data_elem_is_non_zero_predicate);

                        if (first_nonzero_elem != data.begin()) {
                            if (first_nonzero_elem == data.end()) {
                                // This result of the subtraction is exactly zero.
                                // Reset the sign and the exponent.
                                neg = false;
                                exp = static_cast<ExponentType>(0);
                            } else {
                                // Justify the data
                                const std::size_t sj =
                                    static_cast<std::size_t>(std::distance<typename array_type::const_iterator>(
                                        data.begin(), first_nonzero_elem));

                                std::copy(data.begin() + static_cast<std::size_t>(sj), data.end(), data.begin());
                                std::fill(data.end() - sj, data.end(), static_cast<boost::uint32_t>(0u));

                                exp -= static_cast<ExponentType>(sj *
                                                                 static_cast<std::size_t>(cpp_dec_float_elem_digits10));
                            }
                        }
                    }

                    // Handle underflow.
                    if (iszero())
                        return (*this = zero());

                    // Check for potential overflow.
                    const bool b_result_might_overflow = (exp >= static_cast<ExponentType>(cpp_dec_float_max_exp10));

                    // Handle overflow.
                    if (b_result_might_overflow) {
                        const bool b_result_is_neg = neg;
                        neg = false;

                        if (compare((cpp_dec_float::max)()) > 0)
                            *this = inf();

                        neg = b_result_is_neg;
                    }

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::operator-=(
                        const cpp_dec_float<Digits10, ExponentType, Allocator>& v) {
                    // Use *this - v = -(-*this + v).
                    negate();
                    *this += v;
                    negate();
                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::operator*=(
                        const cpp_dec_float<Digits10, ExponentType, Allocator>& v) {
                    // Evaluate the sign of the result.
                    const bool b_result_is_neg = (neg != v.neg);

                    // Artificially set the sign of the result to be positive.
                    neg = false;

                    // Handle special cases like zero, inf and NaN.
                    const bool b_u_is_inf = (isinf)();
                    const bool b_v_is_inf = (v.isinf)();
                    const bool b_u_is_zero = iszero();
                    const bool b_v_is_zero = v.iszero();

                    if (((isnan)() || (v.isnan)()) || (b_u_is_inf && b_v_is_zero) || (b_v_is_inf && b_u_is_zero)) {
                        *this = nan();
                        return *this;
                    }

                    if (b_u_is_inf || b_v_is_inf) {
                        *this = inf();
                        if (b_result_is_neg)
                            negate();
                        return *this;
                    }

                    if (b_u_is_zero || b_v_is_zero) {
                        return *this = zero();
                    }

                    // Check for potential overflow or underflow.
                    const bool b_result_might_overflow =
                        ((exp + v.exp) >= static_cast<ExponentType>(cpp_dec_float_max_exp10));
                    const bool b_result_might_underflow =
                        ((exp + v.exp) <= static_cast<ExponentType>(cpp_dec_float_min_exp10));

                    // Set the exponent of the result.
                    exp += v.exp;

                    const boost::int32_t prec_mul = (std::min)(prec_elem, v.prec_elem);

                    const boost::uint32_t carry = mul_loop_uv(data.data(), v.data.data(), prec_mul);

                    // Handle a potential carry.
                    if (carry != static_cast<boost::uint32_t>(0u)) {
                        exp += cpp_dec_float_elem_digits10;

                        // Shift the result of the multiplication one element to the right...
                        std::copy_backward(data.begin(),
                                           data.begin() +
                                               static_cast<std::size_t>(prec_elem - static_cast<boost::int32_t>(1)),
                                           data.begin() + static_cast<std::size_t>(prec_elem));

                        // ... And insert the carry.
                        data.front() = carry;
                    }

                    // Handle overflow.
                    if (b_result_might_overflow && (compare((cpp_dec_float::max)()) > 0)) {
                        *this = inf();
                    }

                    // Handle underflow.
                    if (b_result_might_underflow && (compare((cpp_dec_float::min)()) < 0)) {
                        *this = zero();

                        return *this;
                    }

                    // Set the sign of the result.
                    neg = b_result_is_neg;

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::operator/=(
                        const cpp_dec_float<Digits10, ExponentType, Allocator>& v) {
                    if (iszero()) {
                        if ((v.isnan)()) {
                            return *this = v;
                        } else if (v.iszero()) {
                            return *this = nan();
                        }
                    }

                    const bool u_and_v_are_finite_and_identical =
                        ((isfinite)() && (fpclass == v.fpclass) && (exp == v.exp) &&
                         (cmp_data(v.data) == static_cast<boost::int32_t>(0)));

                    if (u_and_v_are_finite_and_identical) {
                        if (neg != v.neg) {
                            *this = one();
                            negate();
                        } else
                            *this = one();
                        return *this;
                    } else {
                        cpp_dec_float t(v);
                        t.calculate_inv();
                        return operator*=(t);
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::mul_unsigned_long_long(
                        const boost::ulong_long_type n) {
                    // Multiply *this with a constant boost::ulong_long_type.

                    // Evaluate the sign of the result.
                    const bool b_neg = neg;

                    // Artificially set the sign of the result to be positive.
                    neg = false;

                    // Handle special cases like zero, inf and NaN.
                    const bool b_u_is_inf = (isinf)();
                    const bool b_n_is_zero = (n == static_cast<boost::int32_t>(0));

                    if ((isnan)() || (b_u_is_inf && b_n_is_zero)) {
                        return (*this = nan());
                    }

                    if (b_u_is_inf) {
                        *this = inf();
                        if (b_neg)
                            negate();
                        return *this;
                    }

                    if (iszero() || b_n_is_zero) {
                        // Multiplication by zero.
                        return *this = zero();
                    }

                    if (n >= static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask)) {
                        neg = b_neg;
                        cpp_dec_float t;
                        t = n;
                        return operator*=(t);
                    }

                    if (n == static_cast<boost::ulong_long_type>(1u)) {
                        neg = b_neg;
                        return *this;
                    }

                    // Set up the multiplication loop.
                    const boost::uint32_t nn = static_cast<boost::uint32_t>(n);
                    const boost::uint32_t carry = mul_loop_n(data.data(), nn, prec_elem);

                    // Handle the carry and adjust the exponent.
                    if (carry != static_cast<boost::uint32_t>(0u)) {
                        exp += static_cast<ExponentType>(cpp_dec_float_elem_digits10);

                        // Shift the result of the multiplication one element to the right.
                        std::copy_backward(data.begin(),
                                           data.begin() +
                                               static_cast<std::size_t>(prec_elem - static_cast<boost::int32_t>(1)),
                                           data.begin() + static_cast<std::size_t>(prec_elem));

                        data.front() = static_cast<boost::uint32_t>(carry);
                    }

                    // Check for potential overflow.
                    const bool b_result_might_overflow = (exp >= cpp_dec_float_max_exp10);

                    // Handle overflow.
                    if (b_result_might_overflow && (compare((cpp_dec_float::max)()) > 0)) {
                        *this = inf();
                    }

                    // Set the sign.
                    neg = b_neg;

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::div_unsigned_long_long(
                        const boost::ulong_long_type n) {
                    // Divide *this by a constant boost::ulong_long_type.

                    // Evaluate the sign of the result.
                    const bool b_neg = neg;

                    // Artificially set the sign of the result to be positive.
                    neg = false;

                    // Handle special cases like zero, inf and NaN.
                    if ((isnan)()) {
                        return *this;
                    }

                    if ((isinf)()) {
                        *this = inf();
                        if (b_neg)
                            negate();
                        return *this;
                    }

                    if (n == static_cast<boost::ulong_long_type>(0u)) {
                        // Divide by 0.
                        if (iszero()) {
                            *this = nan();
                            return *this;
                        } else {
                            *this = inf();
                            if (isneg())
                                negate();
                            return *this;
                        }
                    }

                    if (iszero()) {
                        return *this;
                    }

                    if (n >= static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask)) {
                        neg = b_neg;
                        cpp_dec_float t;
                        t = n;
                        return operator/=(t);
                    }

                    const boost::uint32_t nn = static_cast<boost::uint32_t>(n);

                    if (nn > static_cast<boost::uint32_t>(1u)) {
                        // Do the division loop.
                        const boost::uint32_t prev = div_loop_n(data.data(), nn, prec_elem);

                        // Determine if one leading zero is in the result data.
                        if (data[0] == static_cast<boost::uint32_t>(0u)) {
                            // Adjust the exponent
                            exp -= static_cast<ExponentType>(cpp_dec_float_elem_digits10);

                            // Shift result of the division one element to the left.
                            std::copy(data.begin() + static_cast<std::size_t>(1u),
                                      data.begin() +
                                          static_cast<std::size_t>(prec_elem - static_cast<boost::int32_t>(1)),
                                      data.begin());

                            data[prec_elem - static_cast<boost::int32_t>(1)] = static_cast<boost::uint32_t>(
                                static_cast<boost::uint64_t>(prev *
                                                             static_cast<boost::uint64_t>(cpp_dec_float_elem_mask)) /
                                nn);
                        }
                    }

                    // Check for potential underflow.
                    const bool b_result_might_underflow = (exp <= cpp_dec_float_min_exp10);

                    // Handle underflow.
                    if (b_result_might_underflow && (compare((cpp_dec_float::min)()) < 0))
                        return (*this = zero());

                    // Set the sign of the result.
                    neg = b_neg;

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::calculate_inv() {
                    // Compute the inverse of *this.
                    const bool b_neg = neg;

                    neg = false;

                    // Handle special cases like zero, inf and NaN.
                    if (iszero()) {
                        *this = inf();
                        if (b_neg)
                            negate();
                        return *this;
                    }

                    if ((isnan)()) {
                        return *this;
                    }

                    if ((isinf)()) {
                        return *this = zero();
                    }

                    if (isone()) {
                        if (b_neg)
                            negate();
                        return *this;
                    }

                    // Save the original *this.
                    cpp_dec_float<Digits10, ExponentType, Allocator> x(*this);

                    // Generate the initial estimate using division.
                    // Extract the mantissa and exponent for a "manual"
                    // computation of the estimate.
                    double dd;
                    ExponentType ne;
                    x.extract_parts(dd, ne);

                    // Do the inverse estimate using double precision estimates of mantissa and exponent.
                    operator=(cpp_dec_float<Digits10, ExponentType, Allocator>(1.0 / dd, -ne));

                    // Compute the inverse of *this. Quadratically convergent Newton-Raphson iteration
                    // is used. During the iterative steps, the precision of the calculation is limited
                    // to the minimum required in order to minimize the run-time.

                    static const boost::int32_t double_digits10_minus_a_few = std::numeric_limits<double>::digits10 - 3;

                    for (boost::int32_t digits = double_digits10_minus_a_few; digits <= cpp_dec_float_total_digits10;
                         digits *= static_cast<boost::int32_t>(2)) {
                        // Adjust precision of the terms.
                        precision(static_cast<boost::int32_t>((digits + 10) * static_cast<boost::int32_t>(2)));
                        x.precision(static_cast<boost::int32_t>((digits + 10) * static_cast<boost::int32_t>(2)));

                        // Next iteration.
                        cpp_dec_float t(*this);
                        t *= x;
                        t -= two();
                        t.negate();
                        *this *= t;
                    }

                    neg = b_neg;

                    prec_elem = cpp_dec_float_elem_number;

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>&
                    cpp_dec_float<Digits10, ExponentType, Allocator>::calculate_sqrt() {
                    // Compute the square root of *this.

                    if ((isinf)() && !isneg()) {
                        return *this;
                    }

                    if (isneg() || (!(isfinite)())) {
                        *this = nan();
                        errno = EDOM;
                        return *this;
                    }

                    if (iszero() || isone()) {
                        return *this;
                    }

                    // Save the original *this.
                    cpp_dec_float<Digits10, ExponentType, Allocator> x(*this);

                    // Generate the initial estimate using division.
                    // Extract the mantissa and exponent for a "manual"
                    // computation of the estimate.
                    double dd;
                    ExponentType ne;
                    extract_parts(dd, ne);

                    // Force the exponent to be an even multiple of two.
                    if ((ne % static_cast<ExponentType>(2)) != static_cast<ExponentType>(0)) {
                        ++ne;
                        dd /= 10.0;
                    }

                    // Setup the iteration.
                    // Estimate the square root using simple manipulations.
                    const double sqd = std::sqrt(dd);

                    *this = cpp_dec_float<Digits10, ExponentType, Allocator>(
                        sqd, static_cast<ExponentType>(ne / static_cast<ExponentType>(2)));

                    // Estimate 1.0 / (2.0 * x0) using simple manipulations.
                    cpp_dec_float<Digits10, ExponentType, Allocator> vi(
                        0.5 / sqd, static_cast<ExponentType>(-ne / static_cast<ExponentType>(2)));

                    // Compute the square root of x. Coupled Newton iteration
                    // as described in "Pi Unleashed" is used. During the
                    // iterative steps, the precision of the calculation is
                    // limited to the minimum required in order to minimize
                    // the run-time.
                    //
                    // Book references:
                    // https://doi.org/10.1007/978-3-642-56735-3
                    // http://www.amazon.com/exec/obidos/tg/detail/-/3540665722/qid=1035535482/sr=8-7/ref=sr_8_7/104-3357872-6059916?v=glance&n=507846

                    static const boost::uint32_t double_digits10_minus_a_few =
                        std::numeric_limits<double>::digits10 - 3;

                    for (boost::int32_t digits = double_digits10_minus_a_few; digits <= cpp_dec_float_total_digits10;
                         digits *= 2u) {
                        // Adjust precision of the terms.
                        precision((digits + 10) * 2);
                        vi.precision((digits + 10) * 2);

                        // Next iteration of vi
                        cpp_dec_float t(*this);
                        t *= vi;
                        t.negate();
                        t.mul_unsigned_long_long(2u);
                        t += one();
                        t *= vi;
                        vi += t;

                        // Next iteration of *this
                        t = *this;
                        t *= *this;
                        t.negate();
                        t += x;
                        t *= vi;
                        *this += t;
                    }

                    prec_elem = cpp_dec_float_elem_number;

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                int cpp_dec_float<Digits10, ExponentType, Allocator>::cmp_data(const array_type& vd) const {
                    // Compare the data of *this with those of v.
                    // Return +1 for *this > v
                    // 0 for *this = v
                    // -1 for *this < v

                    const std::pair<typename array_type::const_iterator, typename array_type::const_iterator>
                        mismatch_pair = std::mismatch(data.begin(), data.end(), vd.begin());

                    const bool is_equal = ((mismatch_pair.first == data.end()) && (mismatch_pair.second == vd.end()));

                    if (is_equal) {
                        return 0;
                    } else {
                        return ((*mismatch_pair.first > *mismatch_pair.second) ? 1 : -1);
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                int cpp_dec_float<Digits10, ExponentType, Allocator>::compare(const cpp_dec_float& v) const {
                    // Compare v with *this.
                    // Return +1 for *this > v
                    // 0 for *this = v
                    // -1 for *this < v

                    // Handle all non-finite cases.
                    if ((!(isfinite)()) || (!(v.isfinite)())) {
                        // NaN can never equal NaN. Return an implementation-dependent
                        // signed result. Also note that comparison of NaN with NaN
                        // using operators greater-than or less-than is undefined.
                        if ((isnan)() || (v.isnan)()) {
                            return ((isnan)() ? 1 : -1);
                        }

                        if ((isinf)() && (v.isinf)()) {
                            // Both *this and v are infinite. They are equal if they have the same sign.
                            // Otherwise, *this is less than v if and only if *this is negative.
                            return ((neg == v.neg) ? 0 : (neg ? -1 : 1));
                        }

                        if ((isinf)()) {
                            // *this is infinite, but v is finite.
                            // So negative infinite *this is less than any finite v.
                            // Whereas positive infinite *this is greater than any finite v.
                            return (isneg() ? -1 : 1);
                        } else {
                            // *this is finite, and v is infinite.
                            // So any finite *this is greater than negative infinite v.
                            // Whereas any finite *this is less than positive infinite v.
                            return (v.neg ? 1 : -1);
                        }
                    }

                    // And now handle all *finite* cases.
                    if (iszero()) {
                        // The value of *this is zero and v is either zero or non-zero.
                        return (v.iszero() ? 0 : (v.neg ? 1 : -1));
                    } else if (v.iszero()) {
                        // The value of v is zero and *this is non-zero.
                        return (neg ? -1 : 1);
                    } else {
                        // Both *this and v are non-zero.

                        if (neg != v.neg) {
                            // The signs are different.
                            return (neg ? -1 : 1);
                        } else if (exp != v.exp) {
                            // The signs are the same and the exponents are different.
                            const int val_cexpression = ((exp < v.exp) ? 1 : -1);

                            return (neg ? val_cexpression : -val_cexpression);
                        } else {
                            // The signs are the same and the exponents are the same.
                            // Compare the data.
                            const int val_cmp_data = cmp_data(v.data);

                            return ((!neg) ? val_cmp_data : -val_cmp_data);
                        }
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                bool cpp_dec_float<Digits10, ExponentType, Allocator>::isone() const {
                    // Check if the value of *this is identically 1 or very close to 1.

                    const bool not_negative_and_is_finite = ((!neg) && (isfinite)());

                    if (not_negative_and_is_finite) {
                        if ((data[0u] == static_cast<boost::uint32_t>(1u)) && (exp == static_cast<ExponentType>(0))) {
                            const typename array_type::const_iterator it_non_zero =
                                std::find_if(data.begin(), data.end(), data_elem_is_non_zero_predicate);
                            return (it_non_zero == data.end());
                        } else if ((data[0u] == static_cast<boost::uint32_t>(cpp_dec_float_elem_mask - 1)) &&
                                   (exp == static_cast<ExponentType>(-cpp_dec_float_elem_digits10))) {
                            const typename array_type::const_iterator it_non_nine =
                                std::find_if(data.begin(), data.end(), data_elem_is_non_nine_predicate);
                            return (it_non_nine == data.end());
                        }
                    }

                    return false;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                bool cpp_dec_float<Digits10, ExponentType, Allocator>::isint() const {
                    if (fpclass != cpp_dec_float_finite) {
                        return false;
                    }

                    if (iszero()) {
                        return true;
                    }

                    if (exp < static_cast<ExponentType>(0)) {
                        return false;
                    }    // |*this| < 1.

                    const typename array_type::size_type offset_decimal_part =
                        static_cast<typename array_type::size_type>(exp / cpp_dec_float_elem_digits10) + 1u;

                    if (offset_decimal_part >= static_cast<typename array_type::size_type>(cpp_dec_float_elem_number)) {
                        // The number is too large to resolve the integer part.
                        // It considered to be a pure integer.
                        return true;
                    }

                    typename array_type::const_iterator it_non_zero =
                        std::find_if(data.begin() + offset_decimal_part, data.end(), data_elem_is_non_zero_predicate);

                    return (it_non_zero == data.end());
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                void cpp_dec_float<Digits10, ExponentType, Allocator>::extract_parts(double& mantissa,
                                                                                     ExponentType& exponent) const {
                    // Extract the approximate parts mantissa and base-10 exponent from the input
                    // cpp_dec_float<Digits10, ExponentType, Allocator> value x.

                    // Extracts the mantissa and exponent.
                    exponent = exp;

                    boost::uint32_t p10 = static_cast<boost::uint32_t>(1u);
                    boost::uint32_t test = data[0u];

                    for (;;) {
                        test /= static_cast<boost::uint32_t>(10u);

                        if (test == static_cast<boost::uint32_t>(0u)) {
                            break;
                        }

                        p10 *= static_cast<boost::uint32_t>(10u);
                        ++exponent;
                    }

                    // Establish the upper bound of limbs for extracting the double.
                    const int max_elem_in_double_count =
                        static_cast<int>(static_cast<boost::int32_t>(std::numeric_limits<double>::digits10) /
                                         cpp_dec_float_elem_digits10) +
                        (static_cast<int>(static_cast<boost::int32_t>(std::numeric_limits<double>::digits10) %
                                          cpp_dec_float_elem_digits10) != 0 ?
                             1 :
                             0) +
                        1;

                    // And make sure this upper bound stays within bounds of the elems.
                    const std::size_t max_elem_extract_count = static_cast<std::size_t>(
                        (std::min)(static_cast<boost::int32_t>(max_elem_in_double_count), cpp_dec_float_elem_number));

                    // Extract into the mantissa the first limb, extracted as a double.
                    mantissa = static_cast<double>(data[0]);
                    double scale = 1.0;

                    // Extract the rest of the mantissa piecewise from the limbs.
                    for (std::size_t i = 1u; i < max_elem_extract_count; i++) {
                        scale /= static_cast<double>(cpp_dec_float_elem_mask);
                        mantissa += (static_cast<double>(data[i]) * scale);
                    }

                    mantissa /= static_cast<double>(p10);

                    if (neg) {
                        mantissa = -mantissa;
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                double cpp_dec_float<Digits10, ExponentType, Allocator>::extract_double() const {
                    // Returns the double conversion of a cpp_dec_float<Digits10, ExponentType, Allocator>.

                    // Check for non-normal cpp_dec_float<Digits10, ExponentType, Allocator>.
                    if (!(isfinite)()) {
                        if ((isnan)()) {
                            return std::numeric_limits<double>::quiet_NaN();
                        } else {
                            return ((!neg) ? std::numeric_limits<double>::infinity() :
                                             -std::numeric_limits<double>::infinity());
                        }
                    }

                    cpp_dec_float<Digits10, ExponentType, Allocator> xx(*this);
                    if (xx.isneg())
                        xx.negate();

                    // Check if *this cpp_dec_float<Digits10, ExponentType, Allocator> is zero.
                    if (iszero() || (xx.compare(double_min()) < 0)) {
                        return 0.0;
                    }

                    // Check if *this cpp_dec_float<Digits10, ExponentType, Allocator> exceeds the maximum of double.
                    if (xx.compare(double_max()) > 0) {
                        return ((!neg) ? std::numeric_limits<double>::infinity() :
                                         -std::numeric_limits<double>::infinity());
                    }

                    std::stringstream ss;
                    ss.imbue(std::locale::classic());

                    ss << str(std::numeric_limits<double>::digits10 + (2 + 1), std::ios_base::scientific);

                    double d;
                    ss >> d;

                    return d;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                long double cpp_dec_float<Digits10, ExponentType, Allocator>::extract_long_double() const {
                    // Returns the long double conversion of a cpp_dec_float<Digits10, ExponentType, Allocator>.

                    // Check if *this cpp_dec_float<Digits10, ExponentType, Allocator> is subnormal.
                    if (!(isfinite)()) {
                        if ((isnan)()) {
                            return std::numeric_limits<long double>::quiet_NaN();
                        } else {
                            return ((!neg) ? std::numeric_limits<long double>::infinity() :
                                             -std::numeric_limits<long double>::infinity());
                        }
                    }

                    cpp_dec_float<Digits10, ExponentType, Allocator> xx(*this);
                    if (xx.isneg())
                        xx.negate();

                    // Check if *this cpp_dec_float<Digits10, ExponentType, Allocator> is zero.
                    if (iszero() || (xx.compare(long_double_min()) < 0)) {
                        return static_cast<long double>(0.0);
                    }

                    // Check if *this cpp_dec_float<Digits10, ExponentType, Allocator> exceeds the maximum of double.
                    if (xx.compare(long_double_max()) > 0) {
                        return ((!neg) ? std::numeric_limits<long double>::infinity() :
                                         -std::numeric_limits<long double>::infinity());
                    }

                    std::stringstream ss;
                    ss.imbue(std::locale::classic());

                    ss << str(std::numeric_limits<long double>::digits10 + (2 + 1), std::ios_base::scientific);

                    long double ld;
                    ss >> ld;

                    return ld;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                boost::long_long_type
                    cpp_dec_float<Digits10, ExponentType, Allocator>::extract_signed_long_long() const {
                    // Extracts a signed long long from *this.
                    // If (x > maximum of long long) or (x < minimum of long long),
                    // then the maximum or minimum of long long is returned accordingly.

                    if (exp < static_cast<ExponentType>(0)) {
                        return static_cast<boost::long_long_type>(0);
                    }

                    const bool b_neg = isneg();

                    boost::ulong_long_type val;

                    if ((!b_neg) && (compare(long_long_max()) > 0)) {
                        return (std::numeric_limits<boost::long_long_type>::max)();
                    } else if (b_neg && (compare(long_long_min()) < 0)) {
                        return (std::numeric_limits<boost::long_long_type>::min)();
                    } else {
                        // Extract the data into an boost::ulong_long_type value.
                        cpp_dec_float<Digits10, ExponentType, Allocator> xn(extract_integer_part());
                        if (xn.isneg())
                            xn.negate();

                        val = static_cast<boost::ulong_long_type>(xn.data[0]);

                        const boost::int32_t imax = (std::min)(
                            static_cast<boost::int32_t>(static_cast<boost::int32_t>(xn.exp) /
                                                        cpp_dec_float_elem_digits10),
                            static_cast<boost::int32_t>(cpp_dec_float_elem_number - static_cast<boost::int32_t>(1)));

                        for (boost::int32_t i = static_cast<boost::int32_t>(1); i <= imax; i++) {
                            val *= static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask);
                            val += static_cast<boost::ulong_long_type>(xn.data[i]);
                        }
                    }

                    if (!b_neg) {
                        return static_cast<boost::long_long_type>(val);
                    } else {
                        // This strange expression avoids a hardware trap in the corner case
                        // that val is the most negative value permitted in boost::long_long_type.
                        // See https://svn.boost.org/trac/boost/ticket/9740.
                        //
                        boost::long_long_type sval = static_cast<boost::long_long_type>(val - 1);
                        sval = -sval;
                        --sval;
                        return sval;
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                boost::ulong_long_type
                    cpp_dec_float<Digits10, ExponentType, Allocator>::extract_unsigned_long_long() const {
                    // Extracts an boost::ulong_long_type from *this.
                    // If x exceeds the maximum of boost::ulong_long_type,
                    // then the maximum of boost::ulong_long_type is returned.
                    // If x is negative, then the boost::ulong_long_type cast of
                    // the long long extracted value is returned.

                    if (isneg()) {
                        return static_cast<boost::ulong_long_type>(extract_signed_long_long());
                    }

                    if (exp < static_cast<ExponentType>(0)) {
                        return static_cast<boost::ulong_long_type>(0u);
                    }

                    const cpp_dec_float<Digits10, ExponentType, Allocator> xn(extract_integer_part());

                    boost::ulong_long_type val;

                    if (xn.compare(ulong_long_max()) > 0) {
                        return (std::numeric_limits<boost::ulong_long_type>::max)();
                    } else {
                        // Extract the data into an boost::ulong_long_type value.
                        val = static_cast<boost::ulong_long_type>(xn.data[0]);

                        const boost::int32_t imax = (std::min)(
                            static_cast<boost::int32_t>(static_cast<boost::int32_t>(xn.exp) /
                                                        cpp_dec_float_elem_digits10),
                            static_cast<boost::int32_t>(cpp_dec_float_elem_number - static_cast<boost::int32_t>(1)));

                        for (boost::int32_t i = static_cast<boost::int32_t>(1); i <= imax; i++) {
                            val *= static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask);
                            val += static_cast<boost::ulong_long_type>(xn.data[i]);
                        }
                    }

                    return val;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>
                    cpp_dec_float<Digits10, ExponentType, Allocator>::extract_integer_part() const {
                    // Compute the signed integer part of x.

                    if (!(isfinite)()) {
                        return *this;
                    }

                    if (exp < static_cast<ExponentType>(0)) {
                        // The absolute value of the number is smaller than 1.
                        // Thus the integer part is zero.
                        return zero();
                    }

                    // Truncate the digits from the decimal part, including guard digits
                    // that do not belong to the integer part.

                    // Make a local copy.
                    cpp_dec_float<Digits10, ExponentType, Allocator> x = *this;

                    // Clear out the decimal portion
                    const size_t first_clear =
                        (static_cast<size_t>(x.exp) / static_cast<size_t>(cpp_dec_float_elem_digits10)) + 1u;
                    const size_t last_clear = static_cast<size_t>(cpp_dec_float_elem_number);

                    if (first_clear < last_clear)
                        std::fill(x.data.begin() + first_clear,
                                  x.data.begin() + last_clear,
                                  static_cast<boost::uint32_t>(0u));

                    return x;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                std::string cpp_dec_float<Digits10, ExponentType, Allocator>::str(boost::intmax_t number_of_digits,
                                                                                  std::ios_base::fmtflags f) const {
                    if ((this->isinf)()) {
                        if (this->isneg())
                            return "-inf";
                        else if (f & std::ios_base::showpos)
                            return "+inf";
                        else
                            return "inf";
                    } else if ((this->isnan)()) {
                        return "nan";
                    }

                    std::string str;
                    boost::intmax_t org_digits(number_of_digits);
                    ExponentType my_exp = order();

                    if (number_of_digits == 0)
                        number_of_digits = cpp_dec_float_total_digits10;

                    if (f & std::ios_base::fixed) {
                        number_of_digits += my_exp + 1;
                    } else if (f & std::ios_base::scientific)
                        ++number_of_digits;
                    // Determine the number of elements needed to provide the requested digits from
                    // cpp_dec_float<Digits10, ExponentType, Allocator>.
                    const std::size_t number_of_elements =
                        (std::min)(static_cast<std::size_t>(
                                       (number_of_digits / static_cast<std::size_t>(cpp_dec_float_elem_digits10)) + 2u),
                                   static_cast<std::size_t>(cpp_dec_float_elem_number));

                    // Extract the remaining digits from cpp_dec_float<Digits10, ExponentType, Allocator> after the
                    // decimal point.
                    std::stringstream ss;
                    ss.imbue(std::locale::classic());
                    ss << data[0];
                    // Extract all of the digits from cpp_dec_float<Digits10, ExponentType, Allocator>, beginning with
                    // the first data element.
                    for (std::size_t i = static_cast<std::size_t>(1u); i < number_of_elements; i++) {
                        ss << std::setw(static_cast<std::streamsize>(cpp_dec_float_elem_digits10))
                           << std::setfill(static_cast<char>('0')) << data[i];
                    }
                    str += ss.str();

                    bool have_leading_zeros = false;

                    if (number_of_digits == 0) {
                        // We only get here if the output format is "fixed" and we just need to
                        // round the first non-zero digit.
                        number_of_digits -= my_exp + 1;    // reset to original value
                        str.insert(
                            static_cast<std::string::size_type>(0), std::string::size_type(number_of_digits), '0');
                        have_leading_zeros = true;
                    }

                    if (number_of_digits < 0) {
                        str = "0";
                        if (isneg())
                            str.insert(static_cast<std::string::size_type>(0), 1, '-');
                        nil::crypto3::multiprecision::detail::format_float_string(
                            str, 0, number_of_digits - my_exp - 1, f, this->iszero());
                        return str;
                    } else {
                        // Cut the output to the size of the precision.
                        if (str.length() > static_cast<std::string::size_type>(number_of_digits)) {
                            // Get the digit after the last needed digit for rounding
                            const boost::uint32_t round = static_cast<boost::uint32_t>(
                                static_cast<boost::uint32_t>(
                                    str[static_cast<std::string::size_type>(number_of_digits)]) -
                                static_cast<boost::uint32_t>('0'));

                            bool need_round_up = round >= 5u;

                            if (round == 5u) {
                                const boost::uint32_t ix = static_cast<boost::uint32_t>(
                                    static_cast<boost::uint32_t>(
                                        str[static_cast<std::string::size_type>(number_of_digits - 1)]) -
                                    static_cast<boost::uint32_t>('0'));
                                if ((ix & 1u) == 0) {
                                    // We have an even digit followed by a 5, so we might not actually need to round up
                                    // if all the remaining digits are zero:
                                    if (str.find_first_not_of(
                                            '0', static_cast<std::string::size_type>(number_of_digits + 1)) ==
                                        std::string::npos) {
                                        bool all_zeros = true;
                                        // No none-zero trailing digits in the string, now check whatever parts we
                                        // didn't convert to the string:
                                        for (std::size_t i = number_of_elements; i < data.size(); i++) {
                                            if (data[i]) {
                                                all_zeros = false;
                                                break;
                                            }
                                        }
                                        if (all_zeros)
                                            need_round_up = false;    // tie break - round to even.
                                    }
                                }
                            }

                            // Truncate the string
                            str.erase(static_cast<std::string::size_type>(number_of_digits));

                            if (need_round_up) {
                                std::size_t ix = static_cast<std::size_t>(str.length() - 1u);

                                // Every trailing 9 must be rounded up
                                while (ix &&
                                       (static_cast<boost::int32_t>(str.at(ix)) - static_cast<boost::int32_t>('0') ==
                                        static_cast<boost::int32_t>(9))) {
                                    str.at(ix) = static_cast<char>('0');
                                    --ix;
                                }

                                if (!ix) {
                                    // There were nothing but trailing nines.
                                    if (static_cast<boost::int32_t>(static_cast<boost::int32_t>(str.at(ix)) -
                                                                    static_cast<boost::int32_t>(0x30)) ==
                                        static_cast<boost::int32_t>(9)) {
                                        // Increment up to the next order and adjust exponent.
                                        str.at(ix) = static_cast<char>('1');
                                        ++my_exp;
                                    } else {
                                        // Round up this digit.
                                        ++str.at(ix);
                                    }
                                } else {
                                    // Round up the last digit.
                                    ++str[ix];
                                }
                            }
                        }
                    }

                    if (have_leading_zeros) {
                        // We need to take the zeros back out again, and correct the exponent
                        // if we rounded up:
                        if (str[std::string::size_type(number_of_digits - 1)] != '0') {
                            ++my_exp;
                            str.erase(0, std::string::size_type(number_of_digits - 1));
                        } else
                            str.erase(0, std::string::size_type(number_of_digits));
                    }

                    if (isneg())
                        str.insert(static_cast<std::string::size_type>(0), 1, '-');

                    nil::crypto3::multiprecision::detail::format_float_string(
                        str, my_exp, org_digits, f, this->iszero());
                    return str;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                bool cpp_dec_float<Digits10, ExponentType, Allocator>::rd_string(const char* const s) {
#ifndef BOOST_NO_EXCEPTIONS
                    try {
#endif

                        std::string str(s);

                        // TBD: Using several regular expressions may significantly reduce
                        // the code complexity (and perhaps the run-time) of rd_string().

                        // Get a possible exponent and remove it.
                        exp = static_cast<ExponentType>(0);

                        std::size_t pos;

                        if (((pos = str.find('e')) != std::string::npos) ||
                            ((pos = str.find('E')) != std::string::npos)) {
                            // Remove the exponent part from the string.
                            exp = boost::lexical_cast<ExponentType>(static_cast<const char*>(str.c_str() + (pos + 1u)));
                            str = str.substr(static_cast<std::size_t>(0u), pos);
                        }

                        // Get a possible +/- sign and remove it.
                        neg = false;

                        if (str.size()) {
                            if (str[0] == '-') {
                                neg = true;
                                str.erase(0, 1);
                            } else if (str[0] == '+') {
                                str.erase(0, 1);
                            }
                        }
                        //
                        // Special cases for infinities and NaN's:
                        //
                        if ((str == "inf") || (str == "INF") || (str == "infinity") || (str == "INFINITY")) {
                            if (neg) {
                                *this = this->inf();
                                this->negate();
                            } else
                                *this = this->inf();
                            return true;
                        }
                        if ((str.size() >= 3) && ((str.substr(0, 3) == "nan") || (str.substr(0, 3) == "NAN") ||
                                                  (str.substr(0, 3) == "NaN"))) {
                            *this = this->nan();
                            return true;
                        }

                        // Remove the leading zeros for all input types.
                        const std::string::iterator fwd_it_leading_zero =
                            std::find_if(str.begin(), str.end(), char_is_nonzero_predicate);

                        if (fwd_it_leading_zero != str.begin()) {
                            if (fwd_it_leading_zero == str.end()) {
                                // The string contains nothing but leading zeros.
                                // This string represents zero.
                                operator=(zero());
                                return true;
                            } else {
                                str.erase(str.begin(), fwd_it_leading_zero);
                            }
                        }

                        // Put the input string into the standard cpp_dec_float<Digits10, ExponentType, Allocator> input
                        // form aaa.bbbbE+/-n, where aaa has 1...cpp_dec_float_elem_digits10, bbbb has an even multiple
                        // of cpp_dec_float_elem_digits10 which are possibly zero padded on the right-end, and n is a
                        // signed 64-bit integer which is an even multiple of cpp_dec_float_elem_digits10.

                        // Find a possible decimal point.
                        pos = str.find(static_cast<char>('.'));

                        if (pos != std::string::npos) {
                            // Remove all trailing insignificant zeros.
                            const std::string::const_reverse_iterator rit_non_zero =
                                std::find_if(str.rbegin(), str.rend(), char_is_nonzero_predicate);

                            if (rit_non_zero != static_cast<std::string::const_reverse_iterator>(str.rbegin())) {
                                const std::string::size_type ofs =
                                    str.length() -
                                    std::distance<std::string::const_reverse_iterator>(str.rbegin(), rit_non_zero);
                                str.erase(str.begin() + ofs, str.end());
                            }

                            // Check if the input is identically zero.
                            if (str == std::string(".")) {
                                operator=(zero());
                                return true;
                            }

                            // Remove leading significant zeros just after the decimal point
                            // and adjust the exponent accordingly.
                            // Note that the while-loop operates only on strings of the form ".000abcd..."
                            // and peels away the zeros just after the decimal point.
                            if (str.at(static_cast<std::size_t>(0u)) == static_cast<char>('.')) {
                                const std::string::iterator it_non_zero =
                                    std::find_if(str.begin() + 1u, str.end(), char_is_nonzero_predicate);

                                std::size_t delta_exp = static_cast<std::size_t>(0u);

                                if (str.at(static_cast<std::size_t>(1u)) == static_cast<char>('0')) {
                                    delta_exp =
                                        std::distance<std::string::const_iterator>(str.begin() + 1u, it_non_zero);
                                }

                                // Bring one single digit into the mantissa and adjust the exponent accordingly.
                                str.erase(str.begin(), it_non_zero);
                                str.insert(static_cast<std::string::size_type>(1u), ".");
                                exp -= static_cast<ExponentType>(delta_exp + 1u);
                            }
                        } else {
                            // Input string has no decimal point: Append decimal point.
                            str.append(".");
                        }

                        // Shift the decimal point such that the exponent is an even multiple of
                        // cpp_dec_float_elem_digits10.
                        std::size_t n_shift = static_cast<std::size_t>(0u);
                        const std::size_t n_exp_rem =
                            static_cast<std::size_t>(exp % static_cast<ExponentType>(cpp_dec_float_elem_digits10));

                        if ((exp % static_cast<ExponentType>(cpp_dec_float_elem_digits10)) !=
                            static_cast<ExponentType>(0)) {
                            n_shift = ((exp < static_cast<ExponentType>(0)) ?
                                           static_cast<std::size_t>(
                                               n_exp_rem + static_cast<std::size_t>(cpp_dec_float_elem_digits10)) :
                                           static_cast<std::size_t>(n_exp_rem));
                        }

                        // Make sure that there are enough digits for the decimal point shift.
                        pos = str.find(static_cast<char>('.'));

                        std::size_t pos_plus_one = static_cast<std::size_t>(pos + 1u);

                        if ((str.length() - pos_plus_one) < n_shift) {
                            const std::size_t sz = static_cast<std::size_t>(n_shift - (str.length() - pos_plus_one));

                            str.append(std::string(sz, static_cast<char>('0')));
                        }

                        // Do the decimal point shift.
                        if (n_shift != static_cast<std::size_t>(0u)) {
                            str.insert(static_cast<std::string::size_type>(pos_plus_one + n_shift), ".");

                            str.erase(pos, static_cast<std::string::size_type>(1u));

                            exp -= static_cast<ExponentType>(n_shift);
                        }

                        // Cut the size of the mantissa to <= cpp_dec_float_elem_digits10.
                        pos = str.find(static_cast<char>('.'));
                        pos_plus_one = static_cast<std::size_t>(pos + 1u);

                        if (pos > static_cast<std::size_t>(cpp_dec_float_elem_digits10)) {
                            const boost::int32_t n_pos = static_cast<boost::int32_t>(pos);
                            const boost::int32_t n_rem_is_zero =
                                ((static_cast<boost::int32_t>(n_pos % cpp_dec_float_elem_digits10) ==
                                  static_cast<boost::int32_t>(0)) ?
                                     static_cast<boost::int32_t>(1) :
                                     static_cast<boost::int32_t>(0));
                            const boost::int32_t n = static_cast<boost::int32_t>(
                                static_cast<boost::int32_t>(n_pos / cpp_dec_float_elem_digits10) - n_rem_is_zero);

                            str.insert(static_cast<std::size_t>(static_cast<boost::int32_t>(
                                           n_pos - static_cast<boost::int32_t>(n * cpp_dec_float_elem_digits10))),
                                       ".");

                            str.erase(pos_plus_one, static_cast<std::size_t>(1u));

                            exp += static_cast<ExponentType>(static_cast<ExponentType>(n) *
                                                             static_cast<ExponentType>(cpp_dec_float_elem_digits10));
                        }

                        // Pad the decimal part such that its value is an even
                        // multiple of cpp_dec_float_elem_digits10.
                        pos = str.find(static_cast<char>('.'));
                        pos_plus_one = static_cast<std::size_t>(pos + 1u);

                        const boost::int32_t n_dec = static_cast<boost::int32_t>(
                            static_cast<boost::int32_t>(str.length() - 1u) - static_cast<boost::int32_t>(pos));
                        const boost::int32_t n_rem = static_cast<boost::int32_t>(n_dec % cpp_dec_float_elem_digits10);

                        boost::int32_t n_cnt = ((n_rem != static_cast<boost::int32_t>(0)) ?
                                                    static_cast<boost::int32_t>(cpp_dec_float_elem_digits10 - n_rem) :
                                                    static_cast<boost::int32_t>(0));

                        if (n_cnt != static_cast<boost::int32_t>(0)) {
                            str.append(static_cast<std::size_t>(n_cnt), static_cast<char>('0'));
                        }

                        // Truncate decimal part if it is too long.
                        const std::size_t max_dec =
                            static_cast<std::size_t>((cpp_dec_float_elem_number - 1) * cpp_dec_float_elem_digits10);

                        if (static_cast<std::size_t>(str.length() - pos) > max_dec) {
                            str = str.substr(static_cast<std::size_t>(0u),
                                             static_cast<std::size_t>(pos_plus_one + max_dec));
                        }

                        // Now the input string has the standard cpp_dec_float<Digits10, ExponentType, Allocator> input
                        // form. (See the comment above.)

                        // Set all the data elements to 0.
                        std::fill(data.begin(), data.end(), static_cast<boost::uint32_t>(0u));

                        // Extract the data.

                        // First get the digits to the left of the decimal point...
                        data[0u] = boost::lexical_cast<boost::uint32_t>(str.substr(static_cast<std::size_t>(0u), pos));

                        // ...then get the remaining digits to the right of the decimal point.
                        const std::string::size_type i_end =
                            ((str.length() - pos_plus_one) /
                             static_cast<std::string::size_type>(cpp_dec_float_elem_digits10));

                        for (std::string::size_type i = static_cast<std::string::size_type>(0u); i < i_end; i++) {
                            const std::string::const_iterator it =
                                str.begin() + pos_plus_one +
                                (i * static_cast<std::string::size_type>(cpp_dec_float_elem_digits10));

                            data[i + 1u] = boost::lexical_cast<boost::uint32_t>(
                                std::string(it, it + static_cast<std::string::size_type>(cpp_dec_float_elem_digits10)));
                        }

                        // Check for overflow...
                        if (exp > cpp_dec_float_max_exp10) {
                            const bool b_result_is_neg = neg;

                            *this = inf();
                            if (b_result_is_neg)
                                negate();
                        }

                        // ...and check for underflow.
                        if (exp <= cpp_dec_float_min_exp10) {
                            if (exp == cpp_dec_float_min_exp10) {
                                // Check for identity with the minimum value.
                                cpp_dec_float<Digits10, ExponentType, Allocator> test = *this;

                                test.exp = static_cast<ExponentType>(0);

                                if (test.isone()) {
                                    *this = zero();
                                }
                            } else {
                                *this = zero();
                            }
                        }

#ifndef BOOST_NO_EXCEPTIONS
                    } catch (const boost::bad_lexical_cast&) {
                        // Rethrow with better error message:
                        std::string msg = "Unable to parse the string \"";
                        msg += s;
                        msg += "\" as a floating point value.";
                        throw std::runtime_error(msg);
                    }
#endif
                    return true;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float(const double mantissa,
                                                                                const ExponentType exponent) :
                    data(),
                    exp(static_cast<ExponentType>(0)), neg(false), fpclass(cpp_dec_float_finite),
                    prec_elem(cpp_dec_float_elem_number) {
                    // Create *this cpp_dec_float<Digits10, ExponentType, Allocator> from a given mantissa and exponent.
                    // Note: This constructor does not maintain the full precision of double.

                    const bool mantissa_is_iszero =
                        (::fabs(mantissa) <
                         ((std::numeric_limits<double>::min)() * (1.0 + std::numeric_limits<double>::epsilon())));

                    if (mantissa_is_iszero) {
                        std::fill(data.begin(), data.end(), static_cast<boost::uint32_t>(0u));
                        return;
                    }

                    const bool b_neg = (mantissa < 0.0);

                    double d = ((!b_neg) ? mantissa : -mantissa);
                    ExponentType e = exponent;

                    while (d > 10.0) {
                        d /= 10.0;
                        ++e;
                    }
                    while (d < 1.0) {
                        d *= 10.0;
                        --e;
                    }

                    boost::int32_t shift =
                        static_cast<boost::int32_t>(e % static_cast<boost::int32_t>(cpp_dec_float_elem_digits10));

                    while (static_cast<boost::int32_t>(shift-- % cpp_dec_float_elem_digits10) !=
                           static_cast<boost::int32_t>(0)) {
                        d *= 10.0;
                        --e;
                    }

                    exp = e;
                    neg = b_neg;

                    std::fill(data.begin(), data.end(), static_cast<boost::uint32_t>(0u));

                    static const boost::int32_t digit_ratio =
                        static_cast<boost::int32_t>(static_cast<boost::int32_t>(std::numeric_limits<double>::digits10) /
                                                    static_cast<boost::int32_t>(cpp_dec_float_elem_digits10));
                    static const boost::int32_t digit_loops =
                        static_cast<boost::int32_t>(digit_ratio + static_cast<boost::int32_t>(2));

                    for (boost::int32_t i = static_cast<boost::int32_t>(0); i < digit_loops; i++) {
                        boost::uint32_t n = static_cast<boost::uint32_t>(static_cast<boost::uint64_t>(d));
                        data[i] = static_cast<boost::uint32_t>(n);
                        d -= static_cast<double>(n);
                        d *= static_cast<double>(cpp_dec_float_elem_mask);
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                template<class Float>
                typename boost::enable_if_c<boost::is_floating_point<Float>::value,
                                            cpp_dec_float<Digits10, ExponentType, Allocator>&>::type
                    cpp_dec_float<Digits10, ExponentType, Allocator>::operator=(Float a) {
                    // Christopher Kormanyos's original code used a cast to boost::long_long_type here, but that fails
                    // when long double has more digits than a boost::long_long_type.
                    using std::floor;
                    using std::frexp;
                    using std::ldexp;

                    if (a == 0)
                        return *this = zero();

                    if (a == 1)
                        return *this = one();

                    if ((boost::math::isinf)(a)) {
                        *this = inf();
                        if (a < 0)
                            this->negate();
                        return *this;
                    }

                    if ((boost::math::isnan)(a))
                        return *this = nan();

                    int e;
                    Float f, term;
                    *this = zero();

                    f = frexp(a, &e);
                    // See https://svn.boost.org/trac/boost/ticket/10924 for an example of why this may go wrong:
                    BOOST_ASSERT((boost::math::isfinite)(f));

                    static const int shift = std::numeric_limits<int>::digits - 1;

                    while (f) {
                        // extract int sized bits from f:
                        f = ldexp(f, shift);
                        BOOST_ASSERT((boost::math::isfinite)(f));
                        term = floor(f);
                        e -= shift;
                        *this *= pow2(shift);
                        if (term > 0)
                            add_unsigned_long_long(static_cast<unsigned>(term));
                        else
                            sub_unsigned_long_long(static_cast<unsigned>(-term));
                        f -= term;
                    }

                    if (e != 0)
                        *this *= pow2(e);

                    return *this;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                void cpp_dec_float<Digits10, ExponentType, Allocator>::from_unsigned_long_long(
                    const boost::ulong_long_type u) {
                    std::fill(data.begin(), data.end(), static_cast<boost::uint32_t>(0u));

                    exp = static_cast<ExponentType>(0);
                    neg = false;
                    fpclass = cpp_dec_float_finite;
                    prec_elem = cpp_dec_float_elem_number;

                    if (u == 0) {
                        return;
                    }

                    std::size_t i = static_cast<std::size_t>(0u);

                    boost::ulong_long_type uu = u;

                    boost::uint32_t temp[(std::numeric_limits<boost::ulong_long_type>::digits10 /
                                          static_cast<int>(cpp_dec_float_elem_digits10)) +
                                         3] = {static_cast<boost::uint32_t>(0u)};

                    while (uu != static_cast<boost::ulong_long_type>(0u)) {
                        temp[i] = static_cast<boost::uint32_t>(
                            uu % static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask));
                        uu = static_cast<boost::ulong_long_type>(
                            uu / static_cast<boost::ulong_long_type>(cpp_dec_float_elem_mask));
                        ++i;
                    }

                    if (i > static_cast<std::size_t>(1u)) {
                        exp +=
                            static_cast<ExponentType>((i - 1u) * static_cast<std::size_t>(cpp_dec_float_elem_digits10));
                    }

                    std::reverse(temp, temp + i);
                    std::copy(
                        temp, temp + (std::min)(i, static_cast<std::size_t>(cpp_dec_float_elem_number)), data.begin());
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                boost::uint32_t
                    cpp_dec_float<Digits10, ExponentType, Allocator>::mul_loop_uv(boost::uint32_t* const u,
                                                                                  const boost::uint32_t* const v,
                                                                                  const boost::int32_t p) {
                    //
                    // There is a limit on how many limbs this algorithm can handle without dropping digits
                    // due to overflow in the carry, it is:
                    //
                    // FLOOR( (2^64 - 1) / (10^8 * 10^8) ) == 1844
                    //
                    BOOST_STATIC_ASSERT_MSG(cpp_dec_float_elem_number < 1800,
                                            "Too many limbs in the data type for the multiplication algorithm - "
                                            "unsupported precision in cpp_dec_float.");

                    boost::uint64_t carry = static_cast<boost::uint64_t>(0u);

                    for (boost::int32_t j = static_cast<boost::int32_t>(p - 1u); j >= static_cast<boost::int32_t>(0);
                         j--) {
                        boost::uint64_t sum = carry;

                        for (boost::int32_t i = j; i >= static_cast<boost::int32_t>(0); i--) {
                            sum += static_cast<boost::uint64_t>(u[j - i] * static_cast<boost::uint64_t>(v[i]));
                        }

                        u[j] =
                            static_cast<boost::uint32_t>(sum % static_cast<boost::uint32_t>(cpp_dec_float_elem_mask));
                        carry =
                            static_cast<boost::uint64_t>(sum / static_cast<boost::uint32_t>(cpp_dec_float_elem_mask));
                    }

                    return static_cast<boost::uint32_t>(carry);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                boost::uint32_t cpp_dec_float<Digits10, ExponentType, Allocator>::mul_loop_n(boost::uint32_t* const u,
                                                                                             boost::uint32_t n,
                                                                                             const boost::int32_t p) {
                    boost::uint64_t carry = static_cast<boost::uint64_t>(0u);

                    // Multiplication loop.
                    for (boost::int32_t j = p - 1; j >= static_cast<boost::int32_t>(0); j--) {
                        const boost::uint64_t t = static_cast<boost::uint64_t>(
                            carry + static_cast<boost::uint64_t>(u[j] * static_cast<boost::uint64_t>(n)));
                        carry = static_cast<boost::uint64_t>(t / static_cast<boost::uint32_t>(cpp_dec_float_elem_mask));
                        u[j] = static_cast<boost::uint32_t>(
                            t - static_cast<boost::uint64_t>(static_cast<boost::uint32_t>(cpp_dec_float_elem_mask) *
                                                             static_cast<boost::uint64_t>(carry)));
                    }

                    return static_cast<boost::uint32_t>(carry);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                boost::uint32_t cpp_dec_float<Digits10, ExponentType, Allocator>::div_loop_n(boost::uint32_t* const u,
                                                                                             boost::uint32_t n,
                                                                                             const boost::int32_t p) {
                    boost::uint64_t prev = static_cast<boost::uint64_t>(0u);

                    for (boost::int32_t j = static_cast<boost::int32_t>(0); j < p; j++) {
                        const boost::uint64_t t = static_cast<boost::uint64_t>(
                            u[j] +
                            static_cast<boost::uint64_t>(prev * static_cast<boost::uint32_t>(cpp_dec_float_elem_mask)));
                        u[j] = static_cast<boost::uint32_t>(t / n);
                        prev = static_cast<boost::uint64_t>(
                            t - static_cast<boost::uint64_t>(n * static_cast<boost::uint64_t>(u[j])));
                    }

                    return static_cast<boost::uint32_t>(prev);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                cpp_dec_float<Digits10, ExponentType, Allocator>
                    cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(const boost::long_long_type p) {
                    // Create a static const table of p^2 for -128 < p < +128.
                    // Note: The size of this table must be odd-numbered and
                    // symmetric about 0.
                    init.do_nothing();
                    static const boost::array<cpp_dec_float<Digits10, ExponentType, Allocator>, 255u> p2_data = {
                        {cpp_dec_float("5."
                                       "8774717541114375398436826861112283890933277838604376075437585313920862972736358"
                                       "64257812500000000000e-39"),
                         cpp_dec_float("1."
                                       "1754943508222875079687365372222456778186655567720875215087517062784172594547271"
                                       "72851562500000000000e-38"),
                         cpp_dec_float("2."
                                       "3509887016445750159374730744444913556373311135441750430175034125568345189094543"
                                       "45703125000000000000e-38"),
                         cpp_dec_float("4."
                                       "7019774032891500318749461488889827112746622270883500860350068251136690378189086"
                                       "91406250000000000000e-38"),
                         cpp_dec_float("9."
                                       "4039548065783000637498922977779654225493244541767001720700136502273380756378173"
                                       "82812500000000000000e-38"),
                         cpp_dec_float("1."
                                       "8807909613156600127499784595555930845098648908353400344140027300454676151275634"
                                       "76562500000000000000e-37"),
                         cpp_dec_float("3."
                                       "7615819226313200254999569191111861690197297816706800688280054600909352302551269"
                                       "53125000000000000000e-37"),
                         cpp_dec_float("7."
                                       "5231638452626400509999138382223723380394595633413601376560109201818704605102539"
                                       "06250000000000000000e-37"),
                         cpp_dec_float("1."
                                       "5046327690525280101999827676444744676078919126682720275312021840363740921020507"
                                       "81250000000000000000e-36"),
                         cpp_dec_float("3."
                                       "0092655381050560203999655352889489352157838253365440550624043680727481842041015"
                                       "62500000000000000000e-36"),
                         cpp_dec_float("6."
                                       "0185310762101120407999310705778978704315676506730881101248087361454963684082031"
                                       "25000000000000000000e-36"),
                         cpp_dec_float("1."
                                       "2037062152420224081599862141155795740863135301346176220249617472290992736816406"
                                       "25000000000000000000e-35"),
                         cpp_dec_float("2."
                                       "4074124304840448163199724282311591481726270602692352440499234944581985473632812"
                                       "50000000000000000000e-35"),
                         cpp_dec_float("4."
                                       "8148248609680896326399448564623182963452541205384704880998469889163970947265625"
                                       "00000000000000000000e-35"),
                         cpp_dec_float("9."
                                       "6296497219361792652798897129246365926905082410769409761996939778327941894531250"
                                       "00000000000000000000e-35"),
                         cpp_dec_float("1."
                                       "9259299443872358530559779425849273185381016482153881952399387955665588378906250"
                                       "00000000000000000000e-34"),
                         cpp_dec_float("3."
                                       "8518598887744717061119558851698546370762032964307763904798775911331176757812500"
                                       "00000000000000000000e-34"),
                         cpp_dec_float("7."
                                       "7037197775489434122239117703397092741524065928615527809597551822662353515625000"
                                       "00000000000000000000e-34"),
                         cpp_dec_float("1."
                                       "5407439555097886824447823540679418548304813185723105561919510364532470703125000"
                                       "00000000000000000000e-33"),
                         cpp_dec_float("3."
                                       "0814879110195773648895647081358837096609626371446211123839020729064941406250000"
                                       "00000000000000000000e-33"),
                         cpp_dec_float("6."
                                       "1629758220391547297791294162717674193219252742892422247678041458129882812500000"
                                       "00000000000000000000e-33"),
                         cpp_dec_float("1."
                                       "2325951644078309459558258832543534838643850548578484449535608291625976562500000"
                                       "00000000000000000000e-32"),
                         cpp_dec_float("2."
                                       "4651903288156618919116517665087069677287701097156968899071216583251953125000000"
                                       "00000000000000000000e-32"),
                         cpp_dec_float("4."
                                       "9303806576313237838233035330174139354575402194313937798142433166503906250000000"
                                       "00000000000000000000e-32"),
                         cpp_dec_float("9."
                                       "8607613152626475676466070660348278709150804388627875596284866333007812500000000"
                                       "00000000000000000000e-32"),
                         cpp_dec_float("1."
                                       "9721522630525295135293214132069655741830160877725575119256973266601562500000000"
                                       "00000000000000000000e-31"),
                         cpp_dec_float("3."
                                       "9443045261050590270586428264139311483660321755451150238513946533203125000000000"
                                       "00000000000000000000e-31"),
                         cpp_dec_float("7."
                                       "8886090522101180541172856528278622967320643510902300477027893066406250000000000"
                                       "00000000000000000000e-31"),
                         cpp_dec_float("1."
                                       "5777218104420236108234571305655724593464128702180460095405578613281250000000000"
                                       "00000000000000000000e-30"),
                         cpp_dec_float("3."
                                       "1554436208840472216469142611311449186928257404360920190811157226562500000000000"
                                       "00000000000000000000e-30"),
                         cpp_dec_float("6."
                                       "3108872417680944432938285222622898373856514808721840381622314453125000000000000"
                                       "00000000000000000000e-30"),
                         cpp_dec_float("1."
                                       "2621774483536188886587657044524579674771302961744368076324462890625000000000000"
                                       "00000000000000000000e-29"),
                         cpp_dec_float("2."
                                       "5243548967072377773175314089049159349542605923488736152648925781250000000000000"
                                       "00000000000000000000e-29"),
                         cpp_dec_float("5."
                                       "0487097934144755546350628178098318699085211846977472305297851562500000000000000"
                                       "00000000000000000000e-29"),
                         cpp_dec_float("1."
                                       "0097419586828951109270125635619663739817042369395494461059570312500000000000000"
                                       "00000000000000000000e-28"),
                         cpp_dec_float("2."
                                       "0194839173657902218540251271239327479634084738790988922119140625000000000000000"
                                       "00000000000000000000e-28"),
                         cpp_dec_float("4."
                                       "0389678347315804437080502542478654959268169477581977844238281250000000000000000"
                                       "00000000000000000000e-28"),
                         cpp_dec_float("8."
                                       "0779356694631608874161005084957309918536338955163955688476562500000000000000000"
                                       "00000000000000000000e-28"),
                         cpp_dec_float("1."
                                       "6155871338926321774832201016991461983707267791032791137695312500000000000000000"
                                       "00000000000000000000e-27"),
                         cpp_dec_float("3."
                                       "2311742677852643549664402033982923967414535582065582275390625000000000000000000"
                                       "00000000000000000000e-27"),
                         cpp_dec_float("6."
                                       "4623485355705287099328804067965847934829071164131164550781250000000000000000000"
                                       "00000000000000000000e-27"),
                         cpp_dec_float("1."
                                       "2924697071141057419865760813593169586965814232826232910156250000000000000000000"
                                       "00000000000000000000e-26"),
                         cpp_dec_float("2."
                                       "5849394142282114839731521627186339173931628465652465820312500000000000000000000"
                                       "00000000000000000000e-26"),
                         cpp_dec_float("5."
                                       "1698788284564229679463043254372678347863256931304931640625000000000000000000000"
                                       "00000000000000000000e-26"),
                         cpp_dec_float("1."
                                       "0339757656912845935892608650874535669572651386260986328125000000000000000000000"
                                       "00000000000000000000e-25"),
                         cpp_dec_float("2."
                                       "0679515313825691871785217301749071339145302772521972656250000000000000000000000"
                                       "00000000000000000000e-25"),
                         cpp_dec_float("4."
                                       "1359030627651383743570434603498142678290605545043945312500000000000000000000000"
                                       "00000000000000000000e-25"),
                         cpp_dec_float("8."
                                       "2718061255302767487140869206996285356581211090087890625000000000000000000000000"
                                       "00000000000000000000e-25"),
                         cpp_dec_float("1."
                                       "6543612251060553497428173841399257071316242218017578125000000000000000000000000"
                                       "00000000000000000000e-24"),
                         cpp_dec_float("3."
                                       "3087224502121106994856347682798514142632484436035156250000000000000000000000000"
                                       "00000000000000000000e-24"),
                         cpp_dec_float("6."
                                       "6174449004242213989712695365597028285264968872070312500000000000000000000000000"
                                       "00000000000000000000e-24"),
                         cpp_dec_float("1."
                                       "3234889800848442797942539073119405657052993774414062500000000000000000000000000"
                                       "00000000000000000000e-23"),
                         cpp_dec_float("2."
                                       "6469779601696885595885078146238811314105987548828125000000000000000000000000000"
                                       "00000000000000000000e-23"),
                         cpp_dec_float("5."
                                       "2939559203393771191770156292477622628211975097656250000000000000000000000000000"
                                       "00000000000000000000e-23"),
                         cpp_dec_float("1."
                                       "0587911840678754238354031258495524525642395019531250000000000000000000000000000"
                                       "00000000000000000000e-22"),
                         cpp_dec_float("2."
                                       "1175823681357508476708062516991049051284790039062500000000000000000000000000000"
                                       "00000000000000000000e-22"),
                         cpp_dec_float("4."
                                       "2351647362715016953416125033982098102569580078125000000000000000000000000000000"
                                       "00000000000000000000e-22"),
                         cpp_dec_float("8."
                                       "4703294725430033906832250067964196205139160156250000000000000000000000000000000"
                                       "00000000000000000000e-22"),
                         cpp_dec_float("1."
                                       "6940658945086006781366450013592839241027832031250000000000000000000000000000000"
                                       "00000000000000000000e-21"),
                         cpp_dec_float("3."
                                       "3881317890172013562732900027185678482055664062500000000000000000000000000000000"
                                       "00000000000000000000e-21"),
                         cpp_dec_float("6."
                                       "7762635780344027125465800054371356964111328125000000000000000000000000000000000"
                                       "00000000000000000000e-21"),
                         cpp_dec_float("1."
                                       "3552527156068805425093160010874271392822265625000000000000000000000000000000000"
                                       "00000000000000000000e-20"),
                         cpp_dec_float("2."
                                       "7105054312137610850186320021748542785644531250000000000000000000000000000000000"
                                       "00000000000000000000e-20"),
                         cpp_dec_float("5."
                                       "4210108624275221700372640043497085571289062500000000000000000000000000000000000"
                                       "00000000000000000000e-20"),
                         cpp_dec_float("1."
                                       "0842021724855044340074528008699417114257812500000000000000000000000000000000000"
                                       "00000000000000000000e-19"),
                         cpp_dec_float("2."
                                       "1684043449710088680149056017398834228515625000000000000000000000000000000000000"
                                       "00000000000000000000e-19"),
                         cpp_dec_float("4."
                                       "3368086899420177360298112034797668457031250000000000000000000000000000000000000"
                                       "00000000000000000000e-19"),
                         cpp_dec_float("8."
                                       "6736173798840354720596224069595336914062500000000000000000000000000000000000000"
                                       "00000000000000000000e-19"),
                         cpp_dec_float("1."
                                       "7347234759768070944119244813919067382812500000000000000000000000000000000000000"
                                       "00000000000000000000e-18"),
                         cpp_dec_float("3."
                                       "4694469519536141888238489627838134765625000000000000000000000000000000000000000"
                                       "00000000000000000000e-18"),
                         cpp_dec_float("6."
                                       "9388939039072283776476979255676269531250000000000000000000000000000000000000000"
                                       "00000000000000000000e-18"),
                         cpp_dec_float("1."
                                       "3877787807814456755295395851135253906250000000000000000000000000000000000000000"
                                       "00000000000000000000e-17"),
                         cpp_dec_float("2."
                                       "7755575615628913510590791702270507812500000000000000000000000000000000000000000"
                                       "00000000000000000000e-17"),
                         cpp_dec_float("5."
                                       "5511151231257827021181583404541015625000000000000000000000000000000000000000000"
                                       "00000000000000000000e-17"),
                         cpp_dec_float("1."
                                       "1102230246251565404236316680908203125000000000000000000000000000000000000000000"
                                       "00000000000000000000e-16"),
                         cpp_dec_float("2."
                                       "2204460492503130808472633361816406250000000000000000000000000000000000000000000"
                                       "00000000000000000000e-16"),
                         cpp_dec_float("4."
                                       "4408920985006261616945266723632812500000000000000000000000000000000000000000000"
                                       "00000000000000000000e-16"),
                         cpp_dec_float("8."
                                       "8817841970012523233890533447265625000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-16"),
                         cpp_dec_float("1."
                                       "7763568394002504646778106689453125000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-15"),
                         cpp_dec_float("3."
                                       "5527136788005009293556213378906250000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-15"),
                         cpp_dec_float("7."
                                       "1054273576010018587112426757812500000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-15"),
                         cpp_dec_float("1."
                                       "4210854715202003717422485351562500000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-14"),
                         cpp_dec_float("2."
                                       "8421709430404007434844970703125000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-14"),
                         cpp_dec_float("5."
                                       "6843418860808014869689941406250000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-14"),
                         cpp_dec_float("1."
                                       "1368683772161602973937988281250000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-13"),
                         cpp_dec_float("2."
                                       "2737367544323205947875976562500000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-13"),
                         cpp_dec_float("4."
                                       "5474735088646411895751953125000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-13"),
                         cpp_dec_float("9."
                                       "0949470177292823791503906250000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-13"),
                         cpp_dec_float("1."
                                       "8189894035458564758300781250000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-12"),
                         cpp_dec_float("3."
                                       "6379788070917129516601562500000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-12"),
                         cpp_dec_float("7."
                                       "2759576141834259033203125000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-12"),
                         cpp_dec_float("1."
                                       "4551915228366851806640625000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-11"),
                         cpp_dec_float("2."
                                       "9103830456733703613281250000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-11"),
                         cpp_dec_float("5."
                                       "8207660913467407226562500000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-11"),
                         cpp_dec_float("1."
                                       "1641532182693481445312500000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-10"),
                         cpp_dec_float("2."
                                       "3283064365386962890625000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-10"),
                         cpp_dec_float("4."
                                       "6566128730773925781250000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-10"),
                         cpp_dec_float("9."
                                       "3132257461547851562500000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-10"),
                         cpp_dec_float("1."
                                       "8626451492309570312500000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-9"),
                         cpp_dec_float("3."
                                       "7252902984619140625000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-9"),
                         cpp_dec_float("7."
                                       "4505805969238281250000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-9"),
                         cpp_dec_float("1."
                                       "4901161193847656250000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-8"),
                         cpp_dec_float("2."
                                       "9802322387695312500000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-8"),
                         cpp_dec_float("5."
                                       "9604644775390625000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-8"),
                         cpp_dec_float("1."
                                       "1920928955078125000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-7"),
                         cpp_dec_float("2."
                                       "3841857910156250000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-7"),
                         cpp_dec_float("4."
                                       "7683715820312500000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-7"),
                         cpp_dec_float("9."
                                       "5367431640625000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-7"),
                         cpp_dec_float("1."
                                       "9073486328125000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-6"),
                         cpp_dec_float("3."
                                       "8146972656250000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-6"),
                         cpp_dec_float("7."
                                       "6293945312500000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e-6"),
                         cpp_dec_float("0."
                                       "0000152587890625000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0000305175781250000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0000610351562500000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0001220703125000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0002441406250000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0004882812500000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0009765625000000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0019531250000000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0039062500000000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0078125000000000000000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000000"),
                         cpp_dec_float("0."
                                       "0156250000000000000000000000000000000000000000000000000000000000000000000000000"
                                       "0000000000000000000000"),
                         cpp_dec_float("0."
                                       "0312500000000000000000000000000000000000000000000000000000000000000000000000000"
                                       "0000000000000000000000"),
                         cpp_dec_float("0."
                                       "0625000000000000000000000000000000000000000000000000000000000000000000000000000"
                                       "0000000000000000000000"),
                         cpp_dec_float("0.125"),
                         cpp_dec_float("0.25"),
                         cpp_dec_float("0.5"),
                         one(),
                         two(),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(4)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(8)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(16)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(32)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(64)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(128)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(256)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(512)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(1024)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(2048)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(4096)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(8192)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(16384)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(32768)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(65536)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(131072)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(262144)),
                         cpp_dec_float(static_cast<boost::ulong_long_type>(524288)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 20u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 21u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 22u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 23u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 24u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 25u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 26u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 27u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 28u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 29u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 30u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uL << 31u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 32u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 33u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 34u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 35u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 36u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 37u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 38u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 39u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 40u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 41u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 42u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 43u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 44u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 45u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 46u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 47u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 48u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 49u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 50u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 51u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 52u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 53u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 54u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 55u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 56u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 57u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 58u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 59u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 60u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 61u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 62u)),
                         cpp_dec_float(static_cast<boost::uint64_t>(1uLL << 63u)),
                         cpp_dec_float("1."
                                       "8446744073709551616000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e19"),
                         cpp_dec_float("3."
                                       "6893488147419103232000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e19"),
                         cpp_dec_float("7."
                                       "3786976294838206464000000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e19"),
                         cpp_dec_float("1."
                                       "4757395258967641292800000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e20"),
                         cpp_dec_float("2."
                                       "9514790517935282585600000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e20"),
                         cpp_dec_float("5."
                                       "9029581035870565171200000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e20"),
                         cpp_dec_float("1."
                                       "1805916207174113034240000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e21"),
                         cpp_dec_float("2."
                                       "3611832414348226068480000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e21"),
                         cpp_dec_float("4."
                                       "7223664828696452136960000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e21"),
                         cpp_dec_float("9."
                                       "4447329657392904273920000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e21"),
                         cpp_dec_float("1."
                                       "8889465931478580854784000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e22"),
                         cpp_dec_float("3."
                                       "7778931862957161709568000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e22"),
                         cpp_dec_float("7."
                                       "5557863725914323419136000000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e22"),
                         cpp_dec_float("1."
                                       "5111572745182864683827200000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e23"),
                         cpp_dec_float("3."
                                       "0223145490365729367654400000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e23"),
                         cpp_dec_float("6."
                                       "0446290980731458735308800000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e23"),
                         cpp_dec_float("1."
                                       "2089258196146291747061760000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e24"),
                         cpp_dec_float("2."
                                       "4178516392292583494123520000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e24"),
                         cpp_dec_float("4."
                                       "8357032784585166988247040000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e24"),
                         cpp_dec_float("9."
                                       "6714065569170333976494080000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e24"),
                         cpp_dec_float("1."
                                       "9342813113834066795298816000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e25"),
                         cpp_dec_float("3."
                                       "8685626227668133590597632000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e25"),
                         cpp_dec_float("7."
                                       "7371252455336267181195264000000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e25"),
                         cpp_dec_float("1."
                                       "5474250491067253436239052800000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e26"),
                         cpp_dec_float("3."
                                       "0948500982134506872478105600000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e26"),
                         cpp_dec_float("6."
                                       "1897001964269013744956211200000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e26"),
                         cpp_dec_float("1."
                                       "2379400392853802748991242240000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e27"),
                         cpp_dec_float("2."
                                       "4758800785707605497982484480000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e27"),
                         cpp_dec_float("4."
                                       "9517601571415210995964968960000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e27"),
                         cpp_dec_float("9."
                                       "9035203142830421991929937920000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e27"),
                         cpp_dec_float("1."
                                       "9807040628566084398385987584000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e28"),
                         cpp_dec_float("3."
                                       "9614081257132168796771975168000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e28"),
                         cpp_dec_float("7."
                                       "9228162514264337593543950336000000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e28"),
                         cpp_dec_float("1."
                                       "5845632502852867518708790067200000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e29"),
                         cpp_dec_float("3."
                                       "1691265005705735037417580134400000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e29"),
                         cpp_dec_float("6."
                                       "3382530011411470074835160268800000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e29"),
                         cpp_dec_float("1."
                                       "2676506002282294014967032053760000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e30"),
                         cpp_dec_float("2."
                                       "5353012004564588029934064107520000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e30"),
                         cpp_dec_float("5."
                                       "0706024009129176059868128215040000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e30"),
                         cpp_dec_float("1."
                                       "0141204801825835211973625643008000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e31"),
                         cpp_dec_float("2."
                                       "0282409603651670423947251286016000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e31"),
                         cpp_dec_float("4."
                                       "0564819207303340847894502572032000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e31"),
                         cpp_dec_float("8."
                                       "1129638414606681695789005144064000000000000000000000000000000000000000000000000"
                                       "00000000000000000000e31"),
                         cpp_dec_float("1."
                                       "6225927682921336339157801028812800000000000000000000000000000000000000000000000"
                                       "00000000000000000000e32"),
                         cpp_dec_float("3."
                                       "2451855365842672678315602057625600000000000000000000000000000000000000000000000"
                                       "00000000000000000000e32"),
                         cpp_dec_float("6."
                                       "4903710731685345356631204115251200000000000000000000000000000000000000000000000"
                                       "00000000000000000000e32"),
                         cpp_dec_float("1."
                                       "2980742146337069071326240823050240000000000000000000000000000000000000000000000"
                                       "00000000000000000000e33"),
                         cpp_dec_float("2."
                                       "5961484292674138142652481646100480000000000000000000000000000000000000000000000"
                                       "00000000000000000000e33"),
                         cpp_dec_float("5."
                                       "1922968585348276285304963292200960000000000000000000000000000000000000000000000"
                                       "00000000000000000000e33"),
                         cpp_dec_float("1."
                                       "0384593717069655257060992658440192000000000000000000000000000000000000000000000"
                                       "00000000000000000000e34"),
                         cpp_dec_float("2."
                                       "0769187434139310514121985316880384000000000000000000000000000000000000000000000"
                                       "00000000000000000000e34"),
                         cpp_dec_float("4."
                                       "1538374868278621028243970633760768000000000000000000000000000000000000000000000"
                                       "00000000000000000000e34"),
                         cpp_dec_float("8."
                                       "3076749736557242056487941267521536000000000000000000000000000000000000000000000"
                                       "00000000000000000000e34"),
                         cpp_dec_float("1."
                                       "6615349947311448411297588253504307200000000000000000000000000000000000000000000"
                                       "00000000000000000000e35"),
                         cpp_dec_float("3."
                                       "3230699894622896822595176507008614400000000000000000000000000000000000000000000"
                                       "00000000000000000000e35"),
                         cpp_dec_float("6."
                                       "6461399789245793645190353014017228800000000000000000000000000000000000000000000"
                                       "00000000000000000000e35"),
                         cpp_dec_float("1."
                                       "3292279957849158729038070602803445760000000000000000000000000000000000000000000"
                                       "00000000000000000000e36"),
                         cpp_dec_float("2."
                                       "6584559915698317458076141205606891520000000000000000000000000000000000000000000"
                                       "00000000000000000000e36"),
                         cpp_dec_float("5."
                                       "3169119831396634916152282411213783040000000000000000000000000000000000000000000"
                                       "00000000000000000000e36"),
                         cpp_dec_float("1."
                                       "0633823966279326983230456482242756608000000000000000000000000000000000000000000"
                                       "00000000000000000000e37"),
                         cpp_dec_float("2."
                                       "1267647932558653966460912964485513216000000000000000000000000000000000000000000"
                                       "00000000000000000000e37"),
                         cpp_dec_float("4."
                                       "2535295865117307932921825928971026432000000000000000000000000000000000000000000"
                                       "00000000000000000000e37"),
                         cpp_dec_float("8."
                                       "5070591730234615865843651857942052864000000000000000000000000000000000000000000"
                                       "00000000000000000000e37"),
                         cpp_dec_float("1."
                                       "7014118346046923173168730371588410572800000000000000000000000000000000000000000"
                                       "00000000000000000000e38")}};

                    if ((p > static_cast<boost::long_long_type>(-128)) &&
                        (p < static_cast<boost::long_long_type>(+128))) {
                        return p2_data[static_cast<std::size_t>(p + ((p2_data.size() - 1u) / 2u))];
                    } else {
                        // Compute and return 2^p.
                        if (p < static_cast<boost::long_long_type>(0)) {
                            return pow2(static_cast<boost::long_long_type>(-p)).calculate_inv();
                        } else {
                            cpp_dec_float<Digits10, ExponentType, Allocator> t;
                            default_ops::detail::pow_imp(t, two(), p, boost::mpl::true_());
                            return t;
                        }
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_add(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                     const cpp_dec_float<Digits10, ExponentType, Allocator>& o) {
                    result += o;
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_subtract(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          const cpp_dec_float<Digits10, ExponentType, Allocator>& o) {
                    result -= o;
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_multiply(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          const cpp_dec_float<Digits10, ExponentType, Allocator>& o) {
                    result *= o;
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_divide(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                        const cpp_dec_float<Digits10, ExponentType, Allocator>& o) {
                    result /= o;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_add(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                     const boost::ulong_long_type& o) {
                    result.add_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_subtract(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          const boost::ulong_long_type& o) {
                    result.sub_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_multiply(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          const boost::ulong_long_type& o) {
                    result.mul_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_divide(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                        const boost::ulong_long_type& o) {
                    result.div_unsigned_long_long(o);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_add(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                     boost::long_long_type o) {
                    if (o < 0)
                        result.sub_unsigned_long_long(nil::crypto3::multiprecision::detail::unsigned_abs(o));
                    else
                        result.add_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_subtract(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          boost::long_long_type o) {
                    if (o < 0)
                        result.add_unsigned_long_long(nil::crypto3::multiprecision::detail::unsigned_abs(o));
                    else
                        result.sub_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_multiply(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                          boost::long_long_type o) {
                    if (o < 0) {
                        result.mul_unsigned_long_long(nil::crypto3::multiprecision::detail::unsigned_abs(o));
                        result.negate();
                    } else
                        result.mul_unsigned_long_long(o);
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_divide(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                        boost::long_long_type o) {
                    if (o < 0) {
                        result.div_unsigned_long_long(nil::crypto3::multiprecision::detail::unsigned_abs(o));
                        result.negate();
                    } else
                        result.div_unsigned_long_long(o);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_convert_to(boost::ulong_long_type* result,
                                            const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    *result = val.extract_unsigned_long_long();
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_convert_to(boost::long_long_type* result,
                                            const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    *result = val.extract_signed_long_long();
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_convert_to(long double* result,
                                            const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    *result = val.extract_long_double();
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_convert_to(double* result,
                                            const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    *result = val.extract_double();
                }

                //
                // Non member function support:
                //
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline int eval_fpclassify(const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    if ((x.isinf)())
                        return FP_INFINITE;
                    if ((x.isnan)())
                        return FP_NAN;
                    if (x.iszero())
                        return FP_ZERO;
                    return FP_NORMAL;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_abs(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                     const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    result = x;
                    if (x.isneg())
                        result.negate();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_fabs(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                      const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    result = x;
                    if (x.isneg())
                        result.negate();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_sqrt(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                      const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    result = x;
                    result.calculate_sqrt();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_floor(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                       const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    result = x;
                    if (!(x.isfinite)() || x.isint()) {
                        if ((x.isnan)())
                            errno = EDOM;
                        return;
                    }

                    if (x.isneg())
                        result -= cpp_dec_float<Digits10, ExponentType, Allocator>::one();
                    result = result.extract_integer_part();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_ceil(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                      const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    result = x;
                    if (!(x.isfinite)() || x.isint()) {
                        if ((x.isnan)())
                            errno = EDOM;
                        return;
                    }

                    if (!x.isneg())
                        result += cpp_dec_float<Digits10, ExponentType, Allocator>::one();
                    result = result.extract_integer_part();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_trunc(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                       const cpp_dec_float<Digits10, ExponentType, Allocator>& x) {
                    if (x.isint() || !(x.isfinite)()) {
                        result = x;
                        if ((x.isnan)())
                            errno = EDOM;
                        return;
                    }
                    result = x.extract_integer_part();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline ExponentType eval_ilogb(const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    if (val.iszero())
                        return (std::numeric_limits<ExponentType>::min)();
                    if ((val.isinf)())
                        return INT_MAX;
                    if ((val.isnan)())
#ifdef FP_ILOGBNAN
                        return FP_ILOGBNAN;
#else
                        return INT_MAX;
#endif
                    // Set result, to the exponent of val:
                    return val.order();
                }
                template<unsigned Digits10, class ExponentType, class Allocator, class ArgType>
                inline void eval_scalbn(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                        const cpp_dec_float<Digits10, ExponentType, Allocator>& val,
                                        ArgType e_) {
                    using default_ops::eval_multiply;
                    const ExponentType e = static_cast<ExponentType>(e_);
                    cpp_dec_float<Digits10, ExponentType, Allocator> t(1.0, e);
                    eval_multiply(result, val, t);
                }

                template<unsigned Digits10, class ExponentType, class Allocator, class ArgType>
                inline void eval_ldexp(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                       const cpp_dec_float<Digits10, ExponentType, Allocator>& x,
                                       ArgType e) {
                    const boost::long_long_type the_exp = static_cast<boost::long_long_type>(e);

                    if ((the_exp > (std::numeric_limits<ExponentType>::max)()) ||
                        (the_exp < (std::numeric_limits<ExponentType>::min)()))
                        BOOST_THROW_EXCEPTION(std::runtime_error(std::string("Exponent value is out of range.")));

                    result = x;

                    if ((the_exp >
                         static_cast<boost::long_long_type>(-std::numeric_limits<boost::long_long_type>::digits)) &&
                        (the_exp < static_cast<boost::long_long_type>(0)))
                        result.div_unsigned_long_long(1ULL << static_cast<boost::long_long_type>(-the_exp));
                    else if ((the_exp <
                              static_cast<boost::long_long_type>(std::numeric_limits<boost::long_long_type>::digits)) &&
                             (the_exp > static_cast<boost::long_long_type>(0)))
                        result.mul_unsigned_long_long(1ULL << the_exp);
                    else if (the_exp != static_cast<boost::long_long_type>(0)) {
                        if ((the_exp < cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp / 2) &&
                            (x.order() > 0)) {
                            boost::long_long_type half_exp = e / 2;
                            cpp_dec_float<Digits10, ExponentType, Allocator> t =
                                cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(half_exp);
                            result *= t;
                            if (2 * half_exp != e)
                                t *= 2;
                            result *= t;
                        } else
                            result *= cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(e);
                    }
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline void eval_frexp(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                                       const cpp_dec_float<Digits10, ExponentType, Allocator>& x,
                                       ExponentType* e) {
                    result = x;

                    if (result.iszero() || (result.isinf)() || (result.isnan)()) {
                        *e = 0;
                        return;
                    }

                    if (result.isneg())
                        result.negate();

                    ExponentType t = result.order();
                    BOOST_MP_USING_ABS
                    if (abs(t) < ((std::numeric_limits<ExponentType>::max)() / 1000)) {
                        t *= 1000;
                        t /= 301;
                    } else {
                        t /= 301;
                        t *= 1000;
                    }

                    result *= cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(-t);

                    if (result.iszero() || (result.isinf)() || (result.isnan)()) {
                        // pow2 overflowed, slip the calculation up:
                        result = x;
                        if (result.isneg())
                            result.negate();
                        t /= 2;
                        result *= cpp_dec_float<Digits10, ExponentType, Allocator>::pow2(-t);
                    }
                    BOOST_MP_USING_ABS
                    if (abs(result.order()) > 5) {
                        // If our first estimate doesn't get close enough then try recursion until we do:
                        ExponentType e2;
                        cpp_dec_float<Digits10, ExponentType, Allocator> r2;
                        eval_frexp(r2, result, &e2);
                        // overflow protection:
                        if ((t > 0) && (e2 > 0) && (t > (std::numeric_limits<ExponentType>::max)() - e2))
                            BOOST_THROW_EXCEPTION(
                                std::runtime_error("Exponent is too large to be represented as a power of 2."));
                        if ((t < 0) && (e2 < 0) && (t < (std::numeric_limits<ExponentType>::min)() - e2))
                            BOOST_THROW_EXCEPTION(
                                std::runtime_error("Exponent is too large to be represented as a power of 2."));
                        t += e2;
                        result = r2;
                    }

                    while (result.compare(cpp_dec_float<Digits10, ExponentType, Allocator>::one()) >= 0) {
                        result /= cpp_dec_float<Digits10, ExponentType, Allocator>::two();
                        ++t;
                    }
                    while (result.compare(cpp_dec_float<Digits10, ExponentType, Allocator>::half()) < 0) {
                        result *= cpp_dec_float<Digits10, ExponentType, Allocator>::two();
                        --t;
                    }
                    *e = t;
                    if (x.isneg())
                        result.negate();
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline typename boost::disable_if<boost::is_same<ExponentType, int>>::type
                    eval_frexp(cpp_dec_float<Digits10, ExponentType, Allocator>& result,
                               const cpp_dec_float<Digits10, ExponentType, Allocator>& x,
                               int* e) {
                    ExponentType t;
                    eval_frexp(result, x, &t);
                    if ((t > (std::numeric_limits<int>::max)()) || (t < (std::numeric_limits<int>::min)()))
                        BOOST_THROW_EXCEPTION(std::runtime_error("Exponent is outside the range of an int"));
                    *e = static_cast<int>(t);
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline bool eval_is_zero(const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    return val.iszero();
                }
                template<unsigned Digits10, class ExponentType, class Allocator>
                inline int eval_get_sign(const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    return val.iszero() ? 0 : val.isneg() ? -1 : 1;
                }

                template<unsigned Digits10, class ExponentType, class Allocator>
                inline std::size_t hash_value(const cpp_dec_float<Digits10, ExponentType, Allocator>& val) {
                    return val.hash();
                }

            }    // namespace backends

            using nil::crypto3::multiprecision::backends::cpp_dec_float;

            typedef number<cpp_dec_float<50>> cpp_dec_float_50;
            typedef number<cpp_dec_float<100>> cpp_dec_float_100;

            namespace detail {

                template<unsigned Digits10, class ExponentType, class Allocator>
                struct transcendental_reduction_type<
                    nil::crypto3::multiprecision::backends::cpp_dec_float<Digits10, ExponentType, Allocator>> {
                    //
                    // The type used for trigonometric reduction needs 3 times the precision of the base type.
                    // This is double the precision of the original type, plus the largest exponent supported.
                    // As a practical measure the largest argument supported is 1/eps, as supporting larger
                    // arguments requires the division of argument by PI/2 to also be done at higher precision,
                    // otherwise the result (an integer) can not be represented exactly.
                    //
                    // See ARGUMENT REDUCTION FOR HUGE ARGUMENTS. K C Ng.
                    //
                    typedef nil::crypto3::multiprecision::backends::cpp_dec_float<Digits10 * 3, ExponentType, Allocator>
                        type;
                };

#ifdef BOOST_NO_SFINAE_EXPR

                template<unsigned D1, class E1, class A1, unsigned D2, class E2, class A2>
                struct is_explicitly_convertible<cpp_dec_float<D1, E1, A1>, cpp_dec_float<D2, E2, A2>>
                    : public boost::mpl::true_ { };

#endif

            }    // namespace detail

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

namespace std {
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    class numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>> {
    public:
        BOOST_STATIC_CONSTEXPR bool is_specialized = true;
        BOOST_STATIC_CONSTEXPR bool is_signed = true;
        BOOST_STATIC_CONSTEXPR bool is_integer = false;
        BOOST_STATIC_CONSTEXPR bool is_exact = false;
        BOOST_STATIC_CONSTEXPR bool is_bounded = true;
        BOOST_STATIC_CONSTEXPR bool is_modulo = false;
        BOOST_STATIC_CONSTEXPR bool is_iec559 = false;
        BOOST_STATIC_CONSTEXPR int digits =
            nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10;
        BOOST_STATIC_CONSTEXPR int digits10 =
            nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10;
        BOOST_STATIC_CONSTEXPR int max_digits10 = nil::crypto3::multiprecision::
            cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_total_digits10;
        BOOST_STATIC_CONSTEXPR ExponentType min_exponent = nil::crypto3::multiprecision::
            cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp;    // Type differs from int.
        BOOST_STATIC_CONSTEXPR ExponentType min_exponent10 = nil::crypto3::multiprecision::
            cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_min_exp10;    // Type differs from int.
        BOOST_STATIC_CONSTEXPR ExponentType max_exponent = nil::crypto3::multiprecision::
            cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_max_exp;    // Type differs from int.
        BOOST_STATIC_CONSTEXPR ExponentType max_exponent10 = nil::crypto3::multiprecision::
            cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_max_exp10;    // Type differs from int.
        BOOST_STATIC_CONSTEXPR int radix =
            nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_radix;
        BOOST_STATIC_CONSTEXPR std::float_round_style round_style = std::round_indeterminate;
        BOOST_STATIC_CONSTEXPR bool has_infinity = true;
        BOOST_STATIC_CONSTEXPR bool has_quiet_NaN = true;
        BOOST_STATIC_CONSTEXPR bool has_signaling_NaN = false;
        BOOST_STATIC_CONSTEXPR std::float_denorm_style has_denorm = std::denorm_absent;
        BOOST_STATIC_CONSTEXPR bool has_denorm_loss = false;
        BOOST_STATIC_CONSTEXPR bool traps = false;
        BOOST_STATIC_CONSTEXPR bool tinyness_before = false;

        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::number<
            nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
            ExpressionTemplates>(min)() {
            return (nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::min)();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::number<
            nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
            ExpressionTemplates>(max)() {
            return (nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::max)();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            lowest() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::zero();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            epsilon() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::eps();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            round_error() {
            return 0.5L;
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            infinity() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::inf();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            quiet_NaN() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::nan();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            signaling_NaN() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::zero();
        }
        BOOST_STATIC_CONSTEXPR
        nil::crypto3::multiprecision::
            number<nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>, ExpressionTemplates>
            denorm_min() {
            return nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>::zero();
        }
    };

#ifndef BOOST_NO_INCLASS_MEMBER_INITIALIZATION

    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST int numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::digits;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST int numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::digits10;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST int numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::max_digits10;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_signed;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_integer;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_exact;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST int numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::radix;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST ExponentType numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::min_exponent;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST ExponentType numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::min_exponent10;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST ExponentType numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::max_exponent;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST ExponentType numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::max_exponent10;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::has_infinity;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::has_quiet_NaN;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::has_signaling_NaN;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST float_denorm_style numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::has_denorm;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::has_denorm_loss;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_iec559;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_bounded;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::is_modulo;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::traps;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST bool numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::tinyness_before;
    template<unsigned Digits10,
             class ExponentType,
             class Allocator,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_CONSTEXPR_OR_CONST float_round_style numeric_limits<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
        ExpressionTemplates>>::round_style;

#endif
}    // namespace std

namespace boost {
    namespace math {

        namespace policies {

            template<unsigned Digits10,
                     class ExponentType,
                     class Allocator,
                     class Policy,
                     nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
            struct precision<nil::crypto3::multiprecision::number<
                                 nil::crypto3::multiprecision::cpp_dec_float<Digits10, ExponentType, Allocator>,
                                 ExpressionTemplates>,
                             Policy> {
                // Define a local copy of cpp_dec_float_digits10 because it might differ
                // from the template parameter Digits10 for small or large digit counts.
                static const boost::int32_t cpp_dec_float_digits10 = nil::crypto3::multiprecision::
                    cpp_dec_float<Digits10, ExponentType, Allocator>::cpp_dec_float_digits10;

                typedef typename Policy::precision_type precision_type;
                typedef digits2<((cpp_dec_float_digits10 + 1LL) * 1000LL) / 301LL> digits_2;
                typedef typename boost::mpl::if_c<((digits_2::value <= precision_type::value) ||
                                                   (Policy::precision_type::value <= 0)),
                                                  // Default case, full precision for RealType:
                                                  digits_2,
                                                  // User customized precision:
                                                  precision_type>::type type;
            };

        }    // namespace policies

    }    // namespace math
}    // namespace boost

#ifdef BOOST_MSVC
#pragma warning(pop)
#endif

#endif
