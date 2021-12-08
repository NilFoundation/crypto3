//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef NIL_DETAIL_TYPE_TRAITS_HPP
#define NIL_DETAIL_TYPE_TRAITS_HPP

#include <complex>

#include <iterator>
#include <tuple>

#include <boost/tti/tti.hpp>

namespace nil {
    namespace detail {

        BOOST_TTI_HAS_TYPE(iterator)
        BOOST_TTI_HAS_TYPE(const_iterator)

        BOOST_TTI_HAS_FUNCTION(begin);
        BOOST_TTI_HAS_MEMBER_FUNCTION(begin);
        BOOST_TTI_HAS_MEMBER_FUNCTION(end);
        
        template<typename T>
        struct is_iterator {
            static char test(...);

            template<typename U, typename = typename std::iterator_traits<U>::difference_type,
                     typename = typename std::iterator_traits<U>::pointer,
                     typename = typename std::iterator_traits<U>::reference,
                     typename = typename std::iterator_traits<U>::value_type,
                     typename = typename std::iterator_traits<U>::iterator_category>
            static long test(U &&);

            constexpr static bool value = std::is_same<decltype(test(std::declval<T>())), long>::value;
        };

        template <typename T>
        class HasBegin
        {
        private:
            typedef char YesType[1];
            typedef char NoType[2];

            template <typename C> static YesType& test( decltype(&C::begin) ) ;
            template <typename C> static NoType& test(...);


        public:
            enum { value = sizeof(test<T>(0)) == sizeof(YesType) };
        };

        template<typename Range, typename Enabled = void>
        struct is_range {
            static const bool value = false;
        };

        template<typename Range>
        struct is_range<Range, typename std::enable_if<has_type_iterator<Range>::value>::type> {
            static const bool value = has_member_function_begin<Range, typename Range::iterator>::value &&
                                      has_member_function_end<Range, typename Range::iterator>::value;
        };

        template<typename Container, typename Enabled = void>
        struct is_container {
            static const bool value = false;
        };

        template<typename Container>
        struct is_container<Container, typename std::enable_if<has_type_const_iterator<Container>::value>::type> {
            static const bool value = has_member_function_begin<Container>::value && has_member_function_end<Container>::value;
        };

        template<typename Value>
        struct is_std_array {
            static const bool value = false;
        };

        template<typename T, size_t ArraySize>
        struct is_std_array<std::array<T, ArraySize>>{
            static const bool value = true;
        };

        /// @brief Check whether provided type is a variant of
        ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
        /// @tparam TType Type to check.
        template<typename TType>
        struct is_tuple {
            /// @brief By default Value has value false. Will be true for any
            /// variant of <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename... TArgs>
        struct is_tuple<std::tuple<TArgs...>> {
            static const bool value = true;
        };
        /// @endcond

        //----------------------------------------

        /// @brief Check whether TType type is included in the tuple TTuple
        /// @tparam TType Type to check
        /// @tparam TTuple Tuple
        /// @pre @code IsTuple<TTuple>::value == true @endcode
        template<typename TType, typename TTuple>
        class is_in_tuple {
            static_assert(is_tuple<TTuple>::value, "TTuple must be std::tuple");

        public:
            /// @brief By default the value is false, will be set to true if TType
            ///     is found in TTuple.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename TType, typename TFirst, typename... TRest>
        class is_in_tuple<TType, std::tuple<TFirst, TRest...>> {
        public:
            static const bool value
                = std::is_same<TType, TFirst>::value || is_in_tuple<TType, std::tuple<TRest...>>::value;
        };

        template<typename TType>
        class is_in_tuple<TType, std::tuple<>> {
        public:
            static const bool value = false;
        };

        /// @endcond
    }    // namespace detail
}    // namespace nil

#endif    // NIL_DETAIL_TYPE_TRAITS_HPP
