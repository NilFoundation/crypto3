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

#include <nil/marshalling/marshalling_state.hpp>
#include <nil/marshalling/accumulators/marshalling.hpp>
#include <nil/marshalling/accumulators/parameters/buffer_length.hpp>
#include <nil/marshalling/accumulators/parameters/expected_status.hpp>
#include <nil/marshalling/type_traits.hpp>
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
         * @tparam TMarshallingInput
         * @tparam OutputWordType
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TMarshallingInput, typename OutputWordType>
        typename std::enable_if<marshalling::is_marshalling_type<TMarshallingInput>::value
                                    && std::is_integral<OutputWordType>::value,
                                std::vector<OutputWordType>>::type
            disperse(TMarshallingInput val, status_type &status) {

            std::vector<OutputWordType> result(val.length());
            typename std::vector<OutputWordType>::iterator buffer_begin = result.begin();
            status = val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam TInput A real type, not a marshalling type. For example, `int` or `uint8_t`
         * @tparam OutputWordType
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TInput, typename OutputWordType>
        typename std::enable_if<std::is_integral<TInput>::value
                                    && std::is_integral<OutputWordType>::value,
                                std::vector<OutputWordType>>::type
            disperse(TInput val, status_type &status) {

            using marhsalling_type = marshalling::types::integral<field_type<TEndian>, 
                TInput>;

            marhsalling_type m_val = marhsalling_type(val);
            std::vector<OutputWordType> result(m_val.length());
            typename std::vector<OutputWordType>::iterator buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam TInput A real type, not a marshalling type. For example, `float` or `double`
         * @tparam OutputWordType
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TInput, typename OutputWordType>
        typename std::enable_if<(std::is_same<float, TInput>::value || 
                                 std::is_same<double, TInput>::value)
                                    && std::is_integral<OutputWordType>::value,
                                std::vector<OutputWordType>>::type
            disperse(TInput val, status_type &status) {

            using marhsalling_type = marshalling::types::float_value<field_type<TEndian>, 
                TInput>;

            marhsalling_type m_val = marhsalling_type(val);
            std::vector<OutputWordType> result(m_val.length());
            typename std::vector<OutputWordType>::iterator buffer_begin = result.begin();
            status = m_val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam TInput A type of container's internal value.
         * @tparam OutputWordType
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TInput, typename OutputWordType>
        typename std::enable_if<std::is_arithmetic<TInput>::value,
                                    && std::is_integral<OutputWordType>::value,
                                std::vector<OutputWordType>>::type
            disperse(std::vector<TInput> val, status_type &status) {

            using marhsalling_type = marshalling::types::array_list<
                field_type<TEndian>,
                types::integral<
                    field_type<TEndian>, 
                    TInput>>;
            
            ...

            marhsalling_type m_val = marhsalling_type(prep_val);
            std::vector<OutputWordType> result(prep_val.length());
            typename std::vector<OutputWordType>::iterator buffer_begin = result.begin();
            status = prep_val.write(buffer_begin, result.size());

            return result;
        }

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TEndian
         * @tparam TInput A type of container's internal value.
         * @tparam TSize Size of the fixed size container's.
         * @tparam OutputWordType
         *
         * @param val
         * @param status
         *
         * @return
         */
        template<typename TEndian, typename TInput, typename TSize, typename OutputWordType>
        typename std::enable_if<std::is_arithmetic<TInput>::value
                                    && std::is_integral<OutputWordType>::value,
                                std::vector<OutputWordType>>::type
            disperse(std::array<TInput, TSize> val, status_type &status) {

            using marhsalling_type = marshalling::types::array_list<
                field_type<TEndian>,
                types::integral<
                    field_type<TEndian>, 
                    TInput>, 
                option::sequence_fixed_size<TSize>
            >;
            
            ...

            marhsalling_type m_val = marhsalling_type(prep_val);
            std::vector<OutputWordType> result(prep_val.length());
            typename std::vector<OutputWordType>::iterator buffer_begin = result.begin();
            status = prep_val.write(buffer_begin, result.size());

            return result;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_DEMARSHALL_HPP
