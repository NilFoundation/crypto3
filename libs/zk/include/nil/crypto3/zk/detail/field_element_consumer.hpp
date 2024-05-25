//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

#ifndef CRYPTO3_ZK_DETAIL_FIELD_ELEMENT_CONSUMER_HPP
#define CRYPTO3_ZK_DETAIL_FIELD_ELEMENT_CONSUMER_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
                namespace detail {

                    /**
                     * @brief Consuming field elements and choose either to serialize field element to vector of bytes
                     *        or to keep field elements as is. Could be used in places, where hash is computed, to
                     *        avoid unnecessary serialization in case of algebraic hashes.
                     *
                    * @tparam Field
                    * @tparam Target A type that determines whether to store Field's value_type directly or as bytes.
                    *         The decision is based on whether Target is identified as a field element by the
                    *         `algebra::is_field_element` trait.
                    * @tparam Marshalling A type of marshalled strucutre to use for serialization in case of keepeng
                    *         serialized values.
                    */
                    template <typename Field, typename Target, typename Marshalling>
                    class field_element_consumer : public std::vector<typename std::conditional_t<
                        algebra::is_field_element<Target>::value,
                        typename Field::value_type,
                        std::uint8_t
                    >> {
                    public: // TODO: make private
                        using base_class = std::vector<typename std::conditional_t<
                            algebra::is_field_element<Target>::value,
                            typename Field::value_type,
                            std::uint8_t
                        >>;
                        using iterator = typename base_class::iterator;

                        /**
                         * @brief Constant expression that determines the size multiplier.
                         *        If the word type is a field element, the size is 1; otherwise,
                         *        it multiplies by the length of the field element representation.
                         */
                        static constexpr std::size_t field_element_holder_size_multiplier = std::conditional_t<
                            algebra::is_field_element<Target>::value,
                            std::integral_constant<std::size_t, 1>,
                            std::integral_constant<std::size_t, Marshalling::length()>
                        >::value;

                        // Default ctor is used for single values
                        field_element_consumer() : field_element_consumer(1) {
                        };

                        field_element_consumer(std::size_t size)
                            : base_class(size * field_element_holder_size_multiplier) {
                            reset_cursor();
                        }

                        explicit field_element_consumer(const typename Field::value_type& field_element)
                            : field_element_consumer() {
                            consume(field_element);
                        }


                        void consume(const typename Field::value_type& field_element) {
                            BOOST_ASSERT(current_iter <= this->end() - field_element_holder_size_multiplier);
                            if constexpr (algebra::is_field_element<Target>::value) {
                                *current_iter++ = field_element;
                            } else {
                                Marshalling field_val(field_element);
                                field_val.write(current_iter, Marshalling::length());
                            }
                        }

                        field_element_consumer& reset_cursor() {
                            current_iter = this->begin();
                            return *this;
                        }

                    private:
                        iterator current_iter;
                    };

                }    // namespace detail
        }    // namespace zk
    }    // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_ZK_DETAIL_FIELD_ELEMENT_CONSUMER_HPP
