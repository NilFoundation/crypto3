#ifndef CONDITIONAL_MAKE_UNSIGNED_HPP
#define CONDITIONAL_MAKE_UNSIGNED_HPP

#include <type_traits>
#include <nil/crypto3/multiprecision/traits/std_integer_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace detail {

                template<class T>
                struct conditional_make_unsigned : public make_unsigned<T>{ };

                template<>
                struct conditional_make_unsigned<bool> {
                    using type = bool;
                };

            }    // namespace detail
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    // BOOST_MP_IS_BACKEND_HPP
