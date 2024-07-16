///////////////////////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef CRYPTO3_MP_IS_BACKEND_HPP
#define CRYPTO3_MP_IS_BACKEND_HPP

#include <boost/multiprecision/traits/is_backend.hpp>

namespace boost {
    namespace multiprecision { 
        namespace backends {
            template<typename Backend, typename StorageType>
            class modular_adaptor;

        }    // namespace backends

        namespace detail {
            // Even though cpp_int_modular_backend doesn't have signed and floating point types, still make boost consider
            // it a backend.
            template<unsigned Bits>
            struct is_backend<boost::multiprecision::backends::cpp_int_modular_backend<Bits>> {
               static BOOST_MP_CXX14_CONSTEXPR bool value = true;
            };

            template<typename Backend, typename StorageType>
            struct is_backend<boost::multiprecision::backends::modular_adaptor<Backend, StorageType>> {
               static BOOST_MP_CXX14_CONSTEXPR bool value = true;
            };

            // If boost wants to convert one cpp_int_modular_backend to another for comparison, make it convert the 
            // shorter one to the longer by adding zeros, not cut the longer one.
            template <unsigned Bits1, unsigned Bits2>
            struct is_first_backend_imp<true, boost::multiprecision::backends::cpp_int_modular_backend<Bits1>,
                                        boost::multiprecision::backends::cpp_int_modular_backend<Bits2>> 
                : public std::integral_constant < bool, Bits1 >= Bits2> {};

        } // namespace detail
    } // multiprecision
} // namespace boost

#endif // CRYPTO3_MP_IS_BACKEND_HPP
