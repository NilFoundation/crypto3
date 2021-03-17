///////////////////////////////////////////////////////////////////////////////
//  Copyright Vicente J. Botet Escriba 2009-2011
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_MP_RESTRICTED_CONVERSION_HPP
#define BOOST_MP_RESTRICTED_CONVERSION_HPP

#include <boost/mpl/if.hpp>

#include <nil/crypto3/multiprecision/traits/explicit_conversion.hpp>
#include <nil/crypto3/multiprecision/detail/number_base.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace detail {

                template<class From, class To>
                struct is_lossy_conversion {
                    typedef typename boost::mpl::if_c<((number_category<From>::value == number_kind_floating_point) &&
                                                (number_category<To>::value == number_kind_integer))
                                                   /* || ((number_category<From>::value == number_kind_floating_point)
                                                      && (number_category<To>::value == number_kind_rational))*/
                                                   || ((number_category<From>::value == number_kind_rational) &&
                                                       (number_category<To>::value == number_kind_integer)) ||
                                                   ((number_category<From>::value == number_kind_fixed_point) &&
                                                    (number_category<To>::value == number_kind_integer)) ||
                                                   (number_category<From>::value == number_kind_unknown) ||
                                                   (number_category<To>::value == number_kind_unknown),
                                               boost::mpl::true_,
                                               boost::mpl::false_>::type type;
                    static const bool value = type::value;
                };

                template<typename From, typename To>
                struct is_restricted_conversion {
                    typedef typename boost::mpl::if_c<((is_explicitly_convertible<From, To>::value &&
                                                 !boost::is_convertible<From, To>::value) ||
                                                is_lossy_conversion<From, To>::value),
                                               boost::mpl::true_,
                                               boost::mpl::false_>::type type;
                    static const bool value = type::value;
                };

            }    // namespace detail
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    // BOOST_MP_RESTRICTED_CONVERSION_HPP
