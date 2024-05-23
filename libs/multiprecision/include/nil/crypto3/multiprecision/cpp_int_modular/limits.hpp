///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_LIM_HPP
#define CRYPTO3_MP_CPP_INT_LIM_HPP

#include <boost/multiprecision/traits/max_digits10.hpp>

namespace std {
    namespace detail {

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4307)
#endif

        template<unsigned Bits,
                 boost::multiprecision::expression_template_option ExpressionTemplates>
        inline BOOST_CXX14_CONSTEXPR_IF_DETECTION boost::multiprecision::number<
            boost::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>
            get_min(const std::integral_constant<bool, true>&, const std::integral_constant<bool, true>&,
                    const std::integral_constant<bool, true>&) {
            // Bounded, signed, and no allocator.
            using result_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
            using ui_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            static
#else
            constexpr
#endif
                const result_type val = -result_type(~ui_type(0));
            return val;
        }

        template<unsigned Bits, boost::multiprecision::expression_template_option ExpressionTemplates>
        inline boost::multiprecision::number<
            boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
            ExpressionTemplates>
            get_min(const std::integral_constant<bool, true>&, const std::integral_constant<bool, true>&,
                    const std::integral_constant<bool, false>&) {
            // Bounded, signed, and an allocator (can't be constexpr).
            using result_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
            using ui_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
            static const result_type val = -result_type(~ui_type(0));
            return val;
        }

        template<unsigned Bits, boost::multiprecision::expression_template_option ExpressionTemplates>
        inline BOOST_CXX14_CONSTEXPR_IF_DETECTION boost::multiprecision::number<
            boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
            ExpressionTemplates>
            get_min() {
            // Bounded, unsigned, no allocator (can be constexpr):
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            static
#else
            constexpr
#endif
                const boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                    ExpressionTemplates>
                    val(0u);
            return val;
        }

        template<unsigned Bits,
                 boost::multiprecision::expression_template_option ExpressionTemplates>
        inline BOOST_CXX14_CONSTEXPR_IF_DETECTION boost::multiprecision::number<
            boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
            ExpressionTemplates>
            get_max() {
            // Bounded and signed, no allocator, can be constexpr.
            using result_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
            using ui_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
                ExpressionTemplates>;
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
            static
#else
            constexpr
#endif
                const result_type val = ~ui_type(0);
            return val;
        }
    }    // namespace detail

    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    class numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>> {
        using backend_type =
            boost::multiprecision::backends::cpp_int_modular_backend<Bits>;
        using number_type = boost::multiprecision::number<backend_type, ExpressionTemplates>;

    public:
        static BOOST_MP_CXX14_CONSTEXPR bool is_specialized = true;
        //
        // Largest and smallest numbers are bounded only by available memory, set
        // to zero:
        //
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type(min)() {
            return detail::get_min<Bits, ExpressionTemplates>();
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type(max)() {
            return detail::get_max<Bits, ExpressionTemplates>();
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type lowest() {
            return (min)();
        }
        static BOOST_MP_CXX14_CONSTEXPR int digits =
            boost::multiprecision::backends::max_precision<backend_type>::value == UINT_MAX ?
                INT_MAX :
                boost::multiprecision::backends::max_precision<backend_type>::value;
        static BOOST_MP_CXX14_CONSTEXPR int digits10 = boost::multiprecision::detail::calc_digits10<digits>::value;
        static BOOST_MP_CXX14_CONSTEXPR int max_digits10 = boost::multiprecision::detail::calc_max_digits10<digits>::value;
        static BOOST_MP_CXX14_CONSTEXPR bool is_signed = false;
        static BOOST_MP_CXX14_CONSTEXPR bool is_integer = true;
        static BOOST_MP_CXX14_CONSTEXPR bool is_exact = true;
        static BOOST_MP_CXX14_CONSTEXPR int radix = 2;
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type epsilon() {
            return 0;
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type round_error() {
            return 0;
        }
        static BOOST_MP_CXX14_CONSTEXPR int min_exponent = 0;
        static BOOST_MP_CXX14_CONSTEXPR int min_exponent10 = 0;
        static BOOST_MP_CXX14_CONSTEXPR int max_exponent = 0;
        static BOOST_MP_CXX14_CONSTEXPR int max_exponent10 = 0;
        static BOOST_MP_CXX14_CONSTEXPR bool has_infinity = false;
        static BOOST_MP_CXX14_CONSTEXPR bool has_quiet_NaN = false;
        static BOOST_MP_CXX14_CONSTEXPR bool has_signaling_NaN = false;
        static BOOST_MP_CXX14_CONSTEXPR float_denorm_style has_denorm = denorm_absent;
        static BOOST_MP_CXX14_CONSTEXPR bool has_denorm_loss = false;
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type infinity() {
            return 0;
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type quiet_NaN() {
            return 0;
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type signaling_NaN() {
            return 0;
        }
        static BOOST_CXX14_CONSTEXPR_IF_DETECTION number_type denorm_min() {
            return 0;
        }
        static BOOST_MP_CXX14_CONSTEXPR bool is_iec559 = false;
        static BOOST_MP_CXX14_CONSTEXPR bool is_bounded =
            boost::multiprecision::backends::is_fixed_precision<backend_type>::value;
        static BOOST_MP_CXX14_CONSTEXPR bool is_modulo = true;
        static BOOST_MP_CXX14_CONSTEXPR bool traps = false;
        static BOOST_MP_CXX14_CONSTEXPR bool tinyness_before = false;
    };

    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::digits;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::digits10;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::max_digits10;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_signed;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_integer;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_exact;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::radix;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::min_exponent;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::min_exponent10;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::max_exponent;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR int numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::max_exponent10;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::has_infinity;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::has_quiet_NaN;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::has_signaling_NaN;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR float_denorm_style numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::has_denorm;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::has_denorm_loss;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_iec559;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_bounded;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::is_modulo;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::traps;
    template<unsigned Bits,
             boost::multiprecision::expression_template_option ExpressionTemplates>
    BOOST_MP_CXX14_CONSTEXPR bool numeric_limits<boost::multiprecision::number<
        boost::multiprecision::backends::cpp_int_modular_backend<Bits>,
        ExpressionTemplates>>::tinyness_before;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

}    // namespace std

#endif
