//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_MARSHALL_HPP
#define MARSHALLING_MARSHALL_HPP

#include <type_traits>

#include <boost/spirit/home/support/container.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/inference.hpp>
#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {

        /*!
         * @defgroup marshalling Marshalling
         *
         * @brief Marshalling between two or more defined types
         *
         * @defgroup marshalling_algorithms Algorithms
         * @ingroup marshalling
         * @brief Algorithms are meant to provide marshalling interface similar to STL algorithms' one.
         */

        /*
         * Marshalling with both input and output types, which are marshalling types, not a std
         * iterator of elements with a marshalling type
         */

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam InputWordType
         * @tparam TMarshallingOutnput
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TMarshallingOutnput, typename InputContainer>
        typename std::enable_if<marshalling::is_marshalling_type<TMarshallingOutnput>::value
            && boost::spirit::traits::is_container<InputContainer>::value
                                    && std::is_integral<typename InputContainer::value_type>::value,
                                TMarshallingOutnput>::type
            pack(InputContainer val, status_type &status) {

            TMarshallingOutnput result;
            typename InputContainer::iterator buffer_begin = val.begin();
            status = result.read(buffer_begin, val.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam InputWordType A compatible with std::is_integral type
         * @tparam TOutput std::is_arithmetic type, not a marshalling type. For example, `int`, `uint8_t` or `double`
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TOutput, typename InputContainer>
        typename std::enable_if<
            (!nil::marshalling::is_container<typename is_compatible<TOutput>::template type<>>::value)
                   && boost::spirit::traits::is_container<InputContainer>::value
                && std::is_integral<typename InputContainer::value_type>::value,
            TOutput>::type
            pack(InputContainer val, status_type &status) {

            using marshalling_type = typename is_compatible<TOutput>::template type<TEndian>;

            marshalling_type m_val;
            typename InputContainer::iterator buffer_begin = val.begin();
            status = m_val.read(buffer_begin, val.size());

            return m_val.value();
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam InputWordType A compatible with std::is_integral type
         * @tparam TContainer A compatible with boost::is_container container.
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TContainer, typename InputContainer>
        typename std::enable_if<
                nil::marshalling::is_container<typename is_compatible<TContainer>::template type<>>::value
                && (!nil::marshalling::is_container<
                    typename is_compatible<TContainer>::template type<>::element_type>::value)
                && (!is_compatible<TContainer>::fixed_size)
                   && boost::spirit::traits::is_container<InputContainer>::value
                && std::is_integral<typename InputContainer::value_type>::value,
            TContainer>::type
            pack(InputContainer val, status_type &status) {

            using marshalling_type = typename is_compatible<TContainer>::template type<TEndian>;

            marshalling_type m_val;
            typename InputContainer::iterator buffer_begin = val.begin();

            status = m_val.read(buffer_begin, val.size());

            TContainer result;
            for (const auto &val_i : m_val.value()) {
                result.push_back(val_i.value());
            }

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam InputWordType A compatible with std::is_integral type
         * @tparam TContainer std::array
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TContainer, typename InputContainer>
        typename std::enable_if<
                nil::marshalling::is_container<typename is_compatible<TContainer>::template type<>>::value
                && is_compatible<TContainer>::fixed_size
                   && boost::spirit::traits::is_container<InputContainer>::value
                && std::is_integral<typename InputContainer::value_type>::value,
            TContainer>::type
            pack(InputContainer val, status_type &status) {

            using marshalling_type = typename is_compatible<TContainer>::template type<TEndian>;

            marshalling_type m_val;
            typename InputContainer::iterator buffer_begin = val.begin();

            status = m_val.read(buffer_begin, val.size());
            auto values = m_val.value();

            TContainer result;
            for (std::size_t i = 0; i < values.size(); i++) {
                result[i] = values[i].value();
            }

            return result;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_HPP
