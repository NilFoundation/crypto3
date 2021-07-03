//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef MARSHALLING_CONTAINER_TYPE_TRAITS_HPP
#define MARSHALLING_CONTAINER_TYPE_TRAITS_HPP

#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/container/static_string.hpp>

namespace nil {
    namespace marshalling {
        namespace container {

            using namespace boost::mpl::placeholders;

            BOOST_TTI_HAS_TYPE(tag)

            BOOST_TTI_HAS_TYPE(interface_options_type)
            BOOST_TTI_HAS_TYPE(impl_options_type)


            namespace detail {

                template<typename T>
                struct is_static_string {
                    static const bool value = false;
                };

                template<std::size_t TSize>
                struct is_static_string<nil::marshalling::container::static_string<TSize>> {
                    static const bool value = true;
                };

                template<typename T>
                struct is_static_vector {
                    static const bool value = false;
                };

                template<typename T, std::size_t TSize>
                struct is_static_vector<nil::marshalling::container::static_vector<T, TSize>> {
                    static const bool value = true;
                };

            }    // namespace detail

            /// @brief Compile time check whether the provided type is a variant of
            ///     @ref nil::marshalling::container::static_string
            /// @related nil::marshalling::container::static_string
            template<typename T>
            static constexpr bool is_static_string() {
                return detail::is_static_string<T>::value;
            }            

            /// @brief Compile time check whether the provided type is a variant of
            ///     @ref nil::marshalling::container::static_vector
            /// @related nil::marshalling::container::static_vector
            template<typename T>
            static constexpr bool is_static_vector() {
                return detail::is_static_vector<T>::value;
            }
        }        // namespace container
    }        // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_CONTAINER_TYPE_TRAITS_HPP