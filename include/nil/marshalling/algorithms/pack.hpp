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
        template<typename TMarshallingOutnput, typename InputWordType>
        typename std::enable_if<marshalling::is_marshalling_type<TMarshallingOutnput>::value
                                    && std::is_integral<InputWordType>::value,
                                TMarshallingOutnput>::type
            pack(std::vector<InputWordType> val, status_type &status) {

            TMarshallingOutnput result;
            typename std::vector<InputWordType>::iterator buffer_begin = val.begin();
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
        template<typename TEndian, typename TOutput, typename InputWordType>
        typename std::enable_if<is_compatible<TOutput>::value
                                    && std::is_arithmetic<TOutput>::value
                                    && std::is_integral<InputWordType>::value,
                                TOutput>::type
            pack(std::vector<InputWordType> val, status_type &status) {

            using marshalling_type = typename is_compatible<TOutput>::template type<TEndian>;

            marshalling_type m_val;
            typename std::vector<InputWordType>::iterator buffer_begin = val.begin();
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
         * @tparam TContainer A compatible with nil::detail::is_container container type.
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TContainer, typename InputWordType>
        typename std::enable_if<is_compatible<TContainer>::value
                                    // && nil::detail::is_container<TContainer>::value
                                    && (!std::is_arithmetic<TContainer>::value)
                                    && std::is_integral<InputWordType>::value,
                                TContainer>::type
            pack(std::vector<InputWordType> val, status_type &status) {

            // static_assert(std::is_arithmetic<typename TContainer::value_type>::value);

            using marshalling_type = typename is_compatible<TContainer>::template type<TEndian>;

            marshalling_type m_val;
            typename std::vector<InputWordType>::iterator buffer_begin = val.begin();

            status = m_val.read(buffer_begin, val.size());

            TContainer result;
            for (const auto &val_i : m_val.value()) {
                result.push_back(val_i.value());
            }

            return result;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_MARSHALL_HPP
