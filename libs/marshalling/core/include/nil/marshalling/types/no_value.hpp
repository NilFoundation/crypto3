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

#ifndef MARSHALLING_NO_VALUE_HPP
#define MARSHALLING_NO_VALUE_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/types/no_value/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Dummy field with "do-nothing" read/write operations.
            /// @details Can be used with other classes that require field types.
            /// @tparam TFieldBase Base class for this field, expected to be a variant of
            ///     nil::marshalling::field_type.
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/no_value.hpp
            template<typename TFieldBase>
            class no_value : private detail::adapt_basic_field_type<detail::basic_no_value<TFieldBase>> {
                using base_impl_type = detail::adapt_basic_field_type<detail::basic_no_value<TFieldBase>>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<>;

                /// @brief Tag indicating type of the field
                using tag = tag::no_value;

                /// @brief Type of underlying value.
                /// @details Defined to be "unsigned", not really used
                using value_type = typename base_impl_type::value_type;

                /// @brief Default constructor
                /// @details Initialises internal value to 0.
                no_value() = default;

                /// @brief Constructor
                explicit no_value(value_type val) {
                    base_impl_type::value() = val;
                }

                /// @brief Copy constructor
                no_value(const no_value &) = default;

                /// @brief Copy assignment
                no_value &operator=(const no_value &) = default;

                /// @brief Get access to the value storage.
                /// @details Should not really be used.
                /// @return Reference to a static value. All the independent get/set
                ///     operations on the different @ref no_value fields access the same
                ///     static value.
                static value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get length required to serialise the current field value.
                /// @return Always 0.
                static constexpr std::size_t length() {
                    return base_impl_type::length();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                /// @return Always 0.
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                /// @return Always 0.
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Check validity of the field value.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Read field value from input data sequence.
                /// @details The function does nothing, always reporting success.
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] size Number of bytes available for reading.
                /// @return Status of read operation.
                template<typename TIter>
                static status_type read(TIter &iter, std::size_t size) {
                    return base_impl_type::read(iter, size);
                }

                /// @brief Read field value from input data sequence without error check and status report.
                /// @details Similar to @ref read(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to read the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void read_no_status(TIter &iter) {
                    base_impl_type::read_no_status(iter);
                }

                /// @brief Write current field value to output data sequence
                /// @details The function does nothing, always reporting success.
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] size Maximal number of bytes that can be written.
                /// @return Status of write operation.
                template<typename TIter>
                static status_type write(TIter &iter, std::size_t size) {
                    return base_impl_type::write(iter, size);
                }

                /// @brief Write current field value to output data sequence  without error check and status report.
                /// @details Similar to @ref write(), but doesn't perform any correctness
                ///     checks and doesn't report any failures.
                /// @param[in, out] iter Iterator to write the data.
                /// @post Iterator is advanced.
                template<typename TIter>
                void write_no_status(TIter &iter) const {
                    base_impl_type::write_no_status(iter);
                }

                /// @brief Compile time check if this class is version dependent
                static constexpr bool is_version_dependent() {
                    return parsed_options_type::has_custom_version_update || base_impl_type::is_version_dependent();
                }

                /// @brief Default implementation of version update.
                /// @return @b true in case the field contents have changed, @b false otherwise
                bool set_version(version_type version) {
                    return base_impl_type::set_version(version);
                }

            protected:
                using base_impl_type::read_data;
                using base_impl_type::write_data;

            private:
#ifdef _MSC_VER
                // VS compiler has problems having 0 size objects in tuple.
                int dummy_ = 0;
#endif
            };

            /// @brief Equality comparison operator.
            /// @details To @ref no_value fields are always equal.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Always true.
            /// @related no_value
            template<typename TFieldBase>
            bool operator==(const no_value<TFieldBase> &field1, const no_value<TFieldBase> &field2) {
                static_cast<void>(field1);
                static_cast<void>(field2);
                return true;
            }

            /// @brief Non-equality comparison operator.
            /// @details To @ref no_value fields are always equal.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Always false.
            /// @related no_value
            template<typename TFieldBase>
            bool operator!=(const no_value<TFieldBase> &field1, const no_value<TFieldBase> &field2) {
                return !(field1 == field2);
            }

            /// @brief Equivalence comparison operator.
            /// @details To @ref no_value fields are always equal.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Always false.
            /// @related no_value
            template<typename TFieldBase>
            bool operator<(const no_value<TFieldBase> &field1, const no_value<TFieldBase> &field2) {
                static_cast<void>(field1);
                static_cast<void>(field2);
                return false;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_NO_VALUE_HPP
