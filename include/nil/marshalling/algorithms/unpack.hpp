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

#ifndef MARSHALLING_DEMARSHALL_HPP
#define MARSHALLING_DEMARSHALL_HPP

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
         * @tparam OutputWordType
         * @tparam TMarshallingInput
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename OutputContainer = std::vector<uint8_t>, typename TMarshallingInput>
        typename std::enable_if<marshalling::is_marshalling_type<TMarshallingInput>::value
                                    && std::is_integral<typename OutputContainer::value_type>::value,
            OutputContainer>::type
            unpack(TMarshallingInput val, status_type &status) {

            OutputContainer result(val.length());
            typename OutputContainer::iterator buffer_begin = result.begin();
            status = val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam OutputWordType A compatible with std::is_integral type
         * @tparam TInput std::is_arithmetic type, not a marshalling type. For example, `int`, `uint8_t` or `double`
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename OutputContainer = std::vector<uint8_t>, typename TInput>
        typename std::enable_if<
            is_compatible<TInput>::value
                && (!nil::marshalling::is_container<typename is_compatible<TInput>::template type<>>::value)
                && std::is_integral<typename OutputContainer::value_type>::value && !std::is_same<bool, typename OutputContainer::value_type>::value,
            OutputContainer>::type
            unpack(TInput val, status_type &status) {

            using marshalling_type = typename is_compatible<TInput>::template type<TEndian>;

            marshalling_type m_val = marshalling_type(val);
            OutputContainer result(m_val.length());
            typename OutputContainer::iterator buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

        template<typename TEndian, typename OutputContainer = std::vector<bool>, typename TInput>
        typename std::enable_if<
            is_compatible<TInput>::value
                && (!nil::marshalling::is_container<typename is_compatible<TInput>::template type<>>::value)
                && std::is_same<bool, typename OutputContainer::value_type>::value,
            OutputContainer>::type
            unpack(TInput val, status_type &status) {

            using marshalling_type = typename is_compatible<TInput>::template type<TEndian>;

            marshalling_type m_val = marshalling_type(val);
            OutputContainer result(m_val.bit_length());
            auto buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam OutputWordType A compatible with std::is_integral type
         * @tparam TContainer std::vector.
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename OutputContainer = std::vector<uint8_t>, typename TContainer>
        typename std::enable_if<
            is_compatible<TContainer>::value
                && nil::marshalling::is_container<typename is_compatible<TContainer>::template type<>>::value
                && (!nil::marshalling::is_container<
                    typename is_compatible<TContainer>::template type<>::element_type>::value)
                && (!is_compatible<TContainer>::fixed_size) && std::is_integral<typename OutputContainer::value_type>::value,
            OutputContainer>::type
            unpack(TContainer val, status_type &status) {

            using marshalling_type = typename is_compatible<TContainer>::template type<TEndian>;
            using marshalling_internal_type = typename marshalling_type::element_type;

            std::vector<marshalling_internal_type> values;
            for (const auto &val_i : val) {
                values.emplace_back(val_i);
            }

            marshalling_type m_val = marshalling_type(values);
            OutputContainer result(m_val.length());
            typename OutputContainer::iterator buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam OutputWordType A compatible with std::is_integral type
         * @tparam TContainer std::array.
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename OutputContainer = std::vector<uint8_t>, typename TContainer>
        typename std::enable_if<
            is_compatible<TContainer>::value
                && nil::marshalling::is_container<typename is_compatible<TContainer>::template type<>>::value
                && is_compatible<TContainer>::fixed_size && std::is_integral<typename OutputContainer::value_type>::value,
            OutputContainer>::type
            unpack(TContainer val, status_type &status) {

            using marshalling_type = typename is_compatible<TContainer>::template type<TEndian>;
            using marshalling_internal_type = typename marshalling_type::element_type;

            nil::marshalling::container::static_vector<marshalling_internal_type, marshalling_type::max_length()>
                values;
            for (const auto &val_i : val) {
                values.emplace_back(val_i);
            }

            marshalling_type m_val = marshalling_type(values);
            OutputContainer result(m_val.length());
            typename OutputContainer::iterator buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_DEMARSHALL_HPP
