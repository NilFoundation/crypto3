///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_MP_EIGEN_HPP
#define BOOST_MP_EIGEN_HPP

#include <nil/crypto3/multiprecision/number.hpp>

#include <Eigen/Core>

//
// Generic Eigen support code:
//
namespace Eigen {
    template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
    struct NumTraits<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>> {
        using self_type = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;
        using Real = typename nil::crypto3::multiprecision::scalar_result_from_possible_complex<self_type>::type;
        using NonInteger = self_type;    // Not correct but we can't do much better??
        using Literal = double;
        using Nested = self_type;
        enum {
            IsComplex = nil::crypto3::multiprecision::number_category<self_type>::value ==
                        nil::crypto3::multiprecision::number_kind_complex,
            IsInteger = nil::crypto3::multiprecision::number_category<self_type>::value ==
                        nil::crypto3::multiprecision::number_kind_integer,
            ReadCost = 1,
            AddCost = 4,
            MulCost = 8,
            IsSigned =
                std::numeric_limits<self_type>::is_specialized ? std::numeric_limits<self_type>::is_signed : true,
            RequireInitialization = 1,
        };
        static Real epsilon() {
            return std::numeric_limits<Real>::epsilon();
        }
        static Real dummy_precision() {
            return 1000 * epsilon();
        }
        static Real highest() {
            return (std::numeric_limits<Real>::max)();
        }
        static Real lowest() {
            return (std::numeric_limits<Real>::min)();
        }
        static int digits10_imp(const std::integral_constant<bool, true>&) {
            return std::numeric_limits<Real>::digits10;
        }
        template<bool B>
        static int digits10_imp(const std::integral_constant<bool, B>&) {
            return Real::default_precision();
        }
        static int digits10() {
            return digits10_imp(
                std::integral_constant < bool,
                std::numeric_limits<Real>::digits10 && (std::numeric_limits<Real>::digits10 != INT_MAX) ? true :
                                                                                                          false > ());
        }
    };
    template<class tag, class Arg1, class Arg2, class Arg3, class Arg4>
    struct NumTraits<nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>>
        : public NumTraits<
              typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>::result_type> { };

#define BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(A)                                                                        \
    template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates,           \
             typename BinaryOp>                                                                                     \
    struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, A, BinaryOp> {  \
        /*static_assert(nil::crypto3::multiprecision::is_compatible_arithmetic_type<A,                              \
         * nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> >::value, "Interoperability with this \
         * arithmetic type is not supported.");*/                                                                   \
        using ReturnType = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;                      \
    };                                                                                                              \
    template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates,           \
             typename BinaryOp>                                                                                     \
    struct ScalarBinaryOpTraits<A, nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, BinaryOp> {  \
        /*static_assert(nil::crypto3::multiprecision::is_compatible_arithmetic_type<A,                              \
         * nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> >::value, "Interoperability with this \
         * arithmetic type is not supported.");*/                                                                   \
        using ReturnType = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;                      \
    };

    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(float)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(double)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(long double)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(char)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(unsigned char)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(signed char)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(short)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(unsigned short)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(int)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(unsigned int)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(long)
    BOOST_MP_EIGEN_SCALAR_TRAITS_DECL(unsigned long)

#if 0    
      template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates, class Backend2, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates2, typename BinaryOp>
   struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, nil::crypto3::multiprecision::number<Backend2, ExpressionTemplates2>, BinaryOp>
   {
      static_assert(
         nil::crypto3::multiprecision::is_compatible_arithmetic_type<nil::crypto3::multiprecision::number<Backend2, ExpressionTemplates2>, nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> >::value
         || nil::crypto3::multiprecision::is_compatible_arithmetic_type<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, nil::crypto3::multiprecision::number<Backend2, ExpressionTemplates2> >::value, "Interoperability with this arithmetic type is not supported.");
      using ReturnType = typename std::conditional<std::is_convertible<nil::crypto3::multiprecision::number<Backend2, ExpressionTemplates2>, nil::crypto3::multiprecision::number<Backend, ExpressionTemplates> >::value,
         nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, nil::crypto3::multiprecision::number<Backend2, ExpressionTemplates2> >::type;
   };

   template<unsigned D, typename BinaryOp>
   struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::mpc_complex_backend<D>, nil::crypto3::multiprecision::et_on>, nil::crypto3::multiprecision::mpfr_float, BinaryOp>
   {
      using ReturnType = nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::mpc_complex_backend<D>, nil::crypto3::multiprecision::et_on>;
   };

   template<typename BinaryOp>
   struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::mpfr_float, nil::crypto3::multiprecision::mpc_complex, BinaryOp>
   {
      using ReturnType = nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::mpc_complex_backend<0>, nil::crypto3::multiprecision::et_on>;
   };

   template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates, typename BinaryOp>
   struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, BinaryOp>
   {
      using ReturnType = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;
   };
#endif

    template<class Backend, nil::crypto3::multiprecision::expression_template_option ExpressionTemplates, class tag,
             class Arg1, class Arg2, class Arg3, class Arg4, typename BinaryOp>
    struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>,
                                nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>,
                                BinaryOp> {
        static_assert(
            std::is_convertible<
                typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>::result_type,
                nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>>::value,
            "Interoperability with this arithmetic type is not supported.");
        using ReturnType = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;
    };

    template<class tag, class Arg1, class Arg2, class Arg3, class Arg4, class Backend,
             nil::crypto3::multiprecision::expression_template_option ExpressionTemplates, typename BinaryOp>
    struct ScalarBinaryOpTraits<nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>,
                                nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, BinaryOp> {
        static_assert(
            std::is_convertible<
                typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>::result_type,
                nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>>::value,
            "Interoperability with this arithmetic type is not supported.");
        using ReturnType = nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>;
    };

    namespace internal {
        template<typename Scalar>
        struct conj_retval;

        template<typename Scalar, bool IsComplex>
        struct conj_impl;

        template<class tag, class Arg1, class Arg2, class Arg3, class Arg4>
        struct conj_retval<nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>> {
            using type =
                typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>::result_type;
        };

        template<class tag, class Arg1, class Arg2, class Arg3, class Arg4>
        struct conj_impl<nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>, true> {
            EIGEN_DEVICE_FUNC
            static inline
                typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>::result_type
                run(const typename nil::crypto3::multiprecision::detail::expression<tag, Arg1, Arg2, Arg3, Arg4>& x) {
                return conj(x);
            }
        };

    }    // namespace internal

}    // namespace Eigen

#endif
