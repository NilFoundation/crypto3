//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_POLYNOMIAL_HPP
#define CRYPTO3_MARSHALLING_POLYNOMIAL_HPP

#include <limits>
#include <ratio>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/math/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                ///////////////////////////////////////////////
                // math::polynomial marshalling.
                ///////////////////////////////////////////////
                template<typename TTypeBase, typename PolynomialType, typename Enable = void>
                struct polynomial;

                template<typename TTypeBase, typename PolynomialType>
                struct polynomial<TTypeBase, PolynomialType, std::enable_if_t<
                        nil::crypto3::math::is_polynomial<PolynomialType>::value>> {
                    using type = field_element_vector<typename PolynomialType::value_type, TTypeBase>;
                };

                template<typename Endianness, typename PolynomialType>
                typename polynomial<nil::marshalling::field_type<Endianness>, PolynomialType, std::enable_if_t<
                        nil::crypto3::math::is_polynomial<PolynomialType>::value>>::type
                fill_polynomial(const PolynomialType &f) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    std::vector<typename PolynomialType::value_type> val;
                    for( auto it=f.begin(); it != f.end(); it++){ val.push_back(*it); }

                    return nil::crypto3::marshalling::types::fill_field_element_vector<
                        typename PolynomialType::value_type, Endianness>(val);
                }

                template<typename Endianness, typename PolynomialType>
                PolynomialType
                make_polynomial(
                    const typename polynomial<
                        nil::marshalling::field_type<Endianness>,
                        PolynomialType,
                        std::enable_if_t<nil::crypto3::math::is_polynomial<PolynomialType>::value>>::type &filled_polynomial) {
                    auto val = nil::crypto3::marshalling::types::make_field_element_vector<
                        typename PolynomialType::value_type,
                        Endianness
                    >(filled_polynomial);

                    return PolynomialType(val.begin(), val.end());
                }

                ///////////////////////////////////////////////
                // math::polynomial_dfs marshalling.
                ///////////////////////////////////////////////
                template<typename TTypeBase, typename PolynomialDFSType>
                struct polynomial<TTypeBase, PolynomialDFSType, std::enable_if_t<
                        nil::crypto3::math::is_polynomial_dfs<PolynomialDFSType>::value>> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // degree
                            nil::marshalling::types::integral<TTypeBase, std::size_t>,
                            // values
                            field_element_vector<typename PolynomialDFSType::value_type, TTypeBase>
                       >
                    >;
                }; 

                template<typename Endianness, typename PolynomialDFSType>
                typename polynomial<nil::marshalling::field_type<Endianness>, PolynomialDFSType, std::enable_if_t<
                        nil::crypto3::math::is_polynomial_dfs<PolynomialDFSType>::value>>::type
                fill_polynomial(const PolynomialDFSType &f) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = typename polynomial<nil::marshalling::field_type<Endianness>, PolynomialDFSType>::type;

                    std::vector<typename PolynomialDFSType::value_type> val;
                    for( auto it=f.begin(); it != f.end(); it++){ val.push_back(*it); }

                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(f.degree()),
                        nil::crypto3::marshalling::types::fill_field_element_vector<
                            typename PolynomialDFSType::value_type,
                            Endianness
                        >(val)
                    ));
                }

                template<typename Endianness, typename PolynomialDFSType>
                PolynomialDFSType
                make_polynomial(const typename polynomial<
                        nil::marshalling::field_type<Endianness>,
                        PolynomialDFSType,
                        std::enable_if_t<nil::crypto3::math::is_polynomial_dfs<PolynomialDFSType>::value
                        >>::type &filled_polynomial) {
                    auto val = nil::crypto3::marshalling::types::make_field_element_vector<
                        typename PolynomialDFSType::value_type,
                        Endianness>(std::get<1>(filled_polynomial.value()));

                    return PolynomialDFSType(std::get<0>(filled_polynomial.value()).value(), val.begin(), val.end());
                }

                ///////////////////////////////////////////////
                // Polynomial vector marshalling, regardless of the form of the polynomial.
                ///////////////////////////////////////////////
                template<typename TTypeBase, typename PolynomialType>
                using polynomial_vector = nil::marshalling::types::standard_array_list<
                    TTypeBase,
                    typename polynomial<TTypeBase, PolynomialType>::type
                >;

                template<typename Endianness, typename PolynomialType>
                polynomial_vector<nil::marshalling::field_type<Endianness>, PolynomialType>
                fill_polynomial_vector(const std::vector<PolynomialType> &f) {
                    polynomial_vector<nil::marshalling::field_type<Endianness>, PolynomialType> result;
                    for (auto it=f.begin(); it != f.end(); it++) {
                        result.value().push_back(fill_polynomial<Endianness, PolynomialType>(*it));
                    }
                    return result;
                }

                template<typename Endianness, typename PolynomialType>
                std::vector<PolynomialType> make_polynomial_vector(
                        const polynomial_vector<nil::marshalling::field_type<Endianness>, PolynomialType> &filled_polynomial_vector) {
                    std::vector<PolynomialType> result;
                    result.reserve(filled_polynomial_vector.value().size());
                    for (std::size_t i = 0; i < filled_polynomial_vector.value().size(); i++) {
                        result.push_back(make_polynomial<Endianness, PolynomialType>(
                            filled_polynomial_vector.value()[i]));
                    }

                    return result;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_POLYNOMIAL_HPP
