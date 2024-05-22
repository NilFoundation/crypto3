///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains eval_modulus for cpp_int_modular_backend, which uses conversion to cpp_int_backend to actually apply the operation.
//

#ifndef CRYPTO3_MP_CPP_INT_DIV_HPP
#define CRYPTO3_MP_CPP_INT_DIV_HPP

namespace boost {
    namespace multiprecision {
        namespace backends {
            // Functions in this file should be called only for creation of montgomery and Barett params, no during "normal" execution, so we do NOT care about the execution speed, and will just redirect calls to normal boost::cpp_int.

            template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
            inline BOOST_MP_CXX14_CONSTEXPR void 
            eval_modulus(cpp_int_modular_backend<Bits1> &result,
                         const cpp_int_modular_backend<Bits2> &a,
                         const cpp_int_modular_backend<Bits3> &b) noexcept {
                result = a;
                // Call the function below.
                eval_modulus(result, b);
            }

            // Just a call to the upper function, similar to operator*=.
            // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR void 
            eval_modulus(cpp_int_modular_backend<Bits1> &result,
                         const cpp_int_modular_backend<Bits2> &a) noexcept {
                boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int = result.to_cpp_int();
                boost::multiprecision::backends::eval_modulus(result_cpp_int, a.to_cpp_int()); 
                result.from_cpp_int(result_cpp_int);
            }


            // This function should be called only for creation of montgomery and Barett params and calculation of inverse,
            // element, not during "normal" execution. We will use conversion to normal boost::cpp_int here and then
            // convert back.
            template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
            inline BOOST_MP_CXX14_CONSTEXPR void 
            eval_divide(cpp_int_modular_backend<Bits1> &result,
                          const cpp_int_modular_backend<Bits2> &a,
                          const cpp_int_modular_backend<Bits3> &b) noexcept {
                result = a;
                // Just make a call to the lower function.
                eval_divide(result, b);
            }

            // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
            // Covers the case where the second operand is not trivial.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type 
            eval_divide(cpp_int_modular_backend<Bits1> &result,
                         const cpp_int_modular_backend<Bits2> &a) noexcept {
                boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int = result.to_cpp_int();
                boost::multiprecision::backends::eval_divide(result_cpp_int, a.to_cpp_int()); 
                result.from_cpp_int(result_cpp_int);
            }

            // We need to handle this since boost does not handle division of non-trivial cpp_int by a trivial one.
            // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
            // Covers the case where the second operand is trivial while the first operand is not trivial.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type 
            eval_divide(cpp_int_modular_backend<Bits1> &result,
                         const cpp_int_modular_backend<Bits2> &a) noexcept {
                using cpp_int_type = boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>;
                cpp_int_type result_cpp_int = result.to_cpp_int();
                // Here we need cpp_int_type::limb_type to compile, otherwise it's ambiguous which function to call, boost has functions
                // for signed and unsigned.
                boost::multiprecision::backends::eval_divide(result_cpp_int, boost::multiprecision::limb_type(*a.limbs())); 
                result.from_cpp_int(result_cpp_int);
            }

            // It looks to me boost has a bug with handling 'eval_divide' for both arguments being trivial but of
            // different bit length, so we need to specialize this one here. It's around line 636 of divide.hpp in boost.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type
            eval_divide(
                cpp_int_modular_backend<Bits1>& result,
                const cpp_int_modular_backend<Bits2>& o) noexcept
            {
                BOOST_ASSERT(*o.limbs());

                *result.limbs() /= *o.limbs();
            }

        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost


#endif // CRYPTO3_MP_CPP_INT_DIV_HPP
