//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_CURVE_ELEMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>

#include <nil/crypto3/marshalling/algebra/types/detail/curve_element/basic_type.hpp>
#include <nil/crypto3/marshalling/algebra/inference.hpp>
#include <nil/crypto3/marshalling/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                class curve_element
                    : private ::nil::marshalling::types::detail::adapt_basic_field_type<
                          crypto3::marshalling::types::detail::basic_curve_element<TTypeBase, CurveGroupType>,
                          TOptions...> {

                    using curve_group_type = CurveGroupType;

                    using base_impl_type = ::nil::marshalling::types::detail::adapt_basic_field_type<
                        crypto3::marshalling::types::detail::basic_curve_element<TTypeBase, curve_group_type>,
                        TOptions...>;

                public:
                    /// @brief endian_type used for serialization.
                    using endian_type = typename base_impl_type::endian_type;

                    /// @brief Version type
                    using version_type = typename base_impl_type::version_type;

                    /// @brief All the options provided to this class bundled into struct.
                    using parsed_options_type = ::nil::marshalling::types::detail::options_parser<TOptions...>;

                    /// @brief Type of underlying curve_element value.
                    /// @details Same as template parameter T to this class.
                    using value_type = typename base_impl_type::value_type;

                    /// @brief Default constructor
                    /// @details Initialises internal value to 0.
                    curve_element() = default;

                    /// @brief Constructor
                    explicit curve_element(const value_type &val) : base_impl_type(val) {
                    }

                    /// @brief Copy constructor
                    curve_element(const curve_element &) = default;

                    /// @brief Destructor
                    ~curve_element() noexcept = default;

                    /// @brief Copy assignment
                    curve_element &operator=(const curve_element &) = default;

                    /// @brief Get access to curve_element value storage.
                    const value_type &value() const {
                        return base_impl_type::value();
                    }

                    /// @brief Get access to curve_element value storage.
                    value_type &value() {
                        return base_impl_type::value();
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    static constexpr std::size_t length() {
                        return base_impl_type::length();
                    }

                    /// @brief Get length required to serialise the current field value.
                    /// @return Number of bytes it will take to serialise the field value.
                    static constexpr std::size_t bit_length() {
                        return base_impl_type::bit_length();
                    }

                    /// @brief Get minimal length that is required to serialise field of this type.
                    /// @return Minimal number of bytes required serialise the field value.
                    static constexpr std::size_t min_length() {
                        return base_impl_type::min_length();
                    }

                    /// @brief Get maximal length that is required to serialise field of this type.
                    /// @return Maximal number of bytes required serialise the field value.
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

                    /// @brief Read field value from input data sequence
                    /// @param[in, out] iter Iterator to read the data.
                    /// @param[in] size Number of bytes available for reading.
                    /// @return Status of read operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::marshalling::status_type read(TIter &iter, std::size_t size) {
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
                    /// @param[in, out] iter Iterator to write the data.
                    /// @param[in] size Maximal number of bytes that can be written.
                    /// @return Status of write operation.
                    /// @post Iterator is advanced.
                    template<typename TIter>
                    nil::marshalling::status_type write(TIter &iter, std::size_t size) const {
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

                    /// @brief Get version of the field.
                    /// @details Exists only if @ref nil::marshalling::option::version_storage option has been provided.
                    version_type get_version() const {
                        return base_impl_type::get_version();
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
                    // because such an adapter uses pure byte reading,
                    // incompatible with crypto3::curve_element
                    static_assert(!parsed_options_type::has_fixed_length_limit,
                                  "nil::marshalling::option::fixed_length option is not applicable to "
                                  "crypto3::curve_element type");

                    // because such an adapter uses pure byte reading,
                    // incompatible with crypto3::curve_element
                    static_assert(!parsed_options_type::has_fixed_bit_length_limit,
                                  "nil::marshalling::option::fixed_bit_length option is not applicable to "
                                  "crypto3::curve_element type");

                    static_assert(!parsed_options_type::has_scaling_ratio,
                                  "nil::marshalling::option::scaling_ratio option is not applicable to "
                                  "crypto3::curve_element type");

                    static_assert(
                        !parsed_options_type::has_sequence_elem_length_forcing,
                        "nil::marshalling::option::SequenceElemLengthForcingEnabled option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_sequence_size_forcing,
                                  "nil::marshalling::option::SequenceSizeForcingEnabled option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_sequence_length_forcing,
                                  "nil::marshalling::option::SequenceLengthForcingEnabled option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_sequence_fixed_size,
                                  "nil::marshalling::option::sequence_fixed_size option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_fixed_size_use_fixed_size_storage,
                        "nil::marshalling::option::SequenceFixedSizeUseFixedSizeStorage option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_sequence_size_field_prefix,
                                  "nil::marshalling::option::sequence_size_field_prefix option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_ser_length_field_prefix,
                        "nil::marshalling::option::sequence_ser_length_field_prefix option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_elem_ser_length_field_prefix,
                        "nil::marshalling::option::sequence_elem_ser_length_field_prefix option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_elem_fixed_ser_length_field_prefix,
                        "nil::marshalling::option::SequenceElemSerLengthFixedFieldPrefix option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_trailing_field_suffix,
                        "nil::marshalling::option::sequence_trailing_field_suffix option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_sequence_termination_field_suffix,
                        "nil::marshalling::option::sequence_termination_field_suffix option is not applicable to "
                        "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_fixed_size_storage,
                                  "nil::marshalling::option::fixed_size_storage option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_custom_storage_type,
                                  "nil::marshalling::option::custom_storage_type option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(!parsed_options_type::has_orig_data_view,
                                  "nil::marshalling::option::orig_data_view option is not applicable to "
                                  "crypto3::curve_element type");
                    static_assert(
                        !parsed_options_type::has_versions_range,
                        "nil::marshalling::option::exists_between_versions (or similar) option is not applicable to "
                        "crypto3::curve_element type");
                };

                /// @brief Equality comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case fields are equal, false otherwise.
                /// @related curve_element
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                bool operator==(const curve_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                                const curve_element<TTypeBase, CurveGroupType, TOptions...> &field2) {
                    return field1.value() == field2.value();
                }

                /// @brief Non-equality comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case fields are NOT equal, false otherwise.
                /// @related curve_element
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                bool operator!=(const curve_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                                const curve_element<TTypeBase, CurveGroupType, TOptions...> &field2) {
                    return field1.value() != field2.value();
                }

                template<typename FieldType>
                typename std::enable_if<algebra::is_field<FieldType>::value &&
                                            !(algebra::is_extended_field<FieldType>::value),
                                        int>::type
                    compare_field_data(const typename FieldType::value_type &field_elem1,
                                       const typename FieldType::value_type &field_elem2) {
                    return (field_elem1.data < field_elem2.data) ? -1 : ((field_elem1.data > field_elem2.data) ? 1 : 0);
                }

                template<typename FieldType>
                typename std::enable_if<algebra::is_extended_field<FieldType>::value, bool>::type
                    compare_field_data(const typename FieldType::value_type &field_elem1,
                                       const typename FieldType::value_type &field_elem2) {
                    for (std::size_t i = 0; i < FieldType::arity; i++) {

                        int compare_result = compare_field_data<typename FieldType::underlying_field_type>(
                            field_elem1.data[i], field_elem2.data[i]);
                        if (compare_result != 0) {
                            return compare_result;
                        }
                    }
                }

                /// @brief Equivalence comparison operator.
                /// @param[in] field1 First field.
                /// @param[in] field2 Second field.
                /// @return true in case value of the first field is lower than than the value of the second.
                /// @related curve_element
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                bool operator<(const curve_element<TTypeBase, CurveGroupType, TOptions...> &field1,
                               const curve_element<TTypeBase, CurveGroupType, TOptions...> &field2) {

                    int compared_X =
                        compare_field_data<typename CurveGroupType::field_type>(field1.value().X, field2.value().X);
                    int compared_Y =
                        compare_field_data<typename CurveGroupType::field_type>(field1.value().Y, field2.value().Y);
                    int compared_Z =
                        compare_field_data<typename CurveGroupType::field_type>(field1.value().Z, field2.value().Z);

                    if (compared_X == -1)
                        return true;
                    if (compared_X == 0 && compared_Y == -1)
                        return true;
                    if (compared_X == 0 && compared_Y == 0 && compared_Z == -1)
                        return true;
                    return false;
                }

                /// @brief Upcast type of the field definition to its parent nil::marshalling::types::curve_element type
                ///     in order to have access to its internal types.
                /// @related nil::marshalling::types::curve_element
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                inline curve_element<TTypeBase, CurveGroupType, TOptions...> &
                    to_field_base(curve_element<TTypeBase, CurveGroupType, TOptions...> &field) {
                    return field;
                }

                /// @brief Upcast type of the field definition to its parent nil::marshalling::types::curve_element type
                ///     in order to have access to its internal types.
                /// @related nil::marshalling::types::curve_element
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                inline const curve_element<TTypeBase, CurveGroupType, TOptions...> &
                    to_field_base(const curve_element<TTypeBase, CurveGroupType, TOptions...> &field) {
                    return field;
                }

                template<typename CurveGroupType, typename Endianness>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    fill_curve_element_vector(
                        const std::vector<typename CurveGroupType::value_type> &curve_elem_vector) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_element_type = curve_element<TTypeBase, CurveGroupType>;

                    using curve_element_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        curve_element_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>;

                    curve_element_vector_type result;

                    std::vector<curve_element_type> &val = result.value();
                    for (std::size_t i = 0; i < curve_elem_vector.size(); i++) {
                        val.push_back(curve_element_type(curve_elem_vector[i]));
                    }
                    return result;
                }

                template<typename CurveGroupType, typename Endianness>
                std::vector<typename CurveGroupType::value_type> make_curve_element_vector(
                    const nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                        &curve_elem_vector) {

                    std::vector<typename CurveGroupType::value_type> result;
                    const std::vector<curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>> &values =
                        curve_elem_vector.value();
                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result.push_back(values[i].value());
                    }
                    return result;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_CURVE_ELEMENT_HPP
