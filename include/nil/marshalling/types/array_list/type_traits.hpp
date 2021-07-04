//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_BASIC_ARRAY_LIST_TYPE_TRAITS_HPP
#define MARSHALLING_BASIC_ARRAY_LIST_TYPE_TRAITS_HPP

#include <type_traits>
#include <algorithm>
#include <limits>
#include <numeric>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/container/static_string.hpp>
#include <nil/marshalling/types/detail/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TElemType, bool TIntegral>
                struct array_list_field_has_var_length_helper;

                template<typename TElemType>
                struct array_list_field_has_var_length_helper<TElemType, true> {
                    static const bool value = false;
                };

                template<typename TElemType>
                struct array_list_field_has_var_length_helper<TElemType, false> {
                    static const bool value = TElemType::min_length() != TElemType::max_length();
                };

                template<typename TElemType>
                struct array_list_field_has_var_length {
                    static const bool value
                        = array_list_field_has_var_length_helper<TElemType,
                                                                 std::is_integral<TElemType>::value>::value;
                };

                template<typename TStorage>
                struct array_list_max_length_retrieve_helper {
                    static const std::size_t value = common_funcs::max_supported_length();
                };

                template<typename T, std::size_t TSize>
                struct array_list_max_length_retrieve_helper<
                    nil::marshalling::container::static_vector<T, TSize>> {
                    static const std::size_t value = TSize;
                };

                template<std::size_t TSize>
                struct array_list_max_length_retrieve_helper<nil::marshalling::container::static_string<TSize>> {
                    static const std::size_t value = TSize - 1;
                };

                template<typename T>
                class vector_has_assign {
                protected:
                    typedef char Yes;
                    typedef unsigned No;

                    template<typename U, U>
                    struct ReallyHas;

                    template<typename C, typename TIt>
                    using Func = void (C::*)(TIt, TIt);

                    template<typename C, typename TIt>
                    static Yes test(ReallyHas<Func<C, TIt>, &C::assign> *);

                    template<typename, typename>
                    static No test(...);

                public:
                    static const bool value = (sizeof(test<T, typename T::const_pointer>(nullptr)) == sizeof(Yes));
                };

                template<typename TVersionType, bool TVersionDependent>
                struct version_storage;

                template<typename TVersionType>
                struct version_storage<TVersionType, true> {
                protected:
                    TVersionType version_ = TVersionType();
                };

                template<typename TVersionType>
                struct version_storage<TVersionType, false> { };

                template<typename TElem, bool TIsIntegral>
                struct array_list_elem_version_dependency_helper;

                template<typename TElem>
                struct array_list_elem_version_dependency_helper<TElem, true> {
                    static const bool value = false;
                };

                template<typename TElem>
                struct array_list_elem_version_dependency_helper<TElem, false> {
                    static const bool value = TElem::is_version_dependent();
                };

                template<typename TElem>
                constexpr bool array_list_element_is_version_dependent() {
                    return array_list_elem_version_dependency_helper<TElem, std::is_integral<TElem>::value>::value;
                }

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_ARRAY_LIST_TYPE_TRAITS_HPP
