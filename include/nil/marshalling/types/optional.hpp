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

#ifndef MARSHALLING_OPTIONAL_HPP
#define MARSHALLING_OPTIONAL_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/detail/options_parser.hpp>
#include <nil/marshalling/types/optional_mode.hpp>
#include <nil/marshalling/types/optional/basic_type.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/types/tag.hpp>

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Adaptor class to any other field, that makes the field optional.
            /// @details When field is optional, it may either exist or not. The behaviour
            ///     of length(), read() and write() operations depends on the current field's mode.
            /// @tparam TField Proper type of the field that needs to be optional.
            /// @tparam TOptions Zero or more options that modify/refine default behaviour
            ///     of the field.@n
            ///     Supported options are:
            ///     @li @ref nil::marshalling::option::default_value_initializer, @ref
            ///     nil::marshalling::option::DefaultOptionalMode,
            ///         @ref nil::marshalling::option::OptionalMissingByDefault, or @ref
            ///         nil::marshalling::option::OptionalExistsByDefault.
            ///     @li @ref nil::marshalling::option::contents_validator.
            ///     @li @ref nil::marshalling::option::contents_refresher
            ///     @li @ref nil::marshalling::option::has_custom_read
            ///     @li @ref nil::marshalling::option::has_custom_refresh
            ///     @li @ref nil::marshalling::option::version_storage
            /// @extends nil::marshalling::field_type
            /// @headerfile nil/marshalling/types/optional.hpp
            template<typename TField, typename... TOptions>
            class optional : private detail::adapt_basic_field_type<detail::basic_optional<TField>, TOptions...> {
                using base_impl_type = detail::adapt_basic_field_type<detail::basic_optional<TField>, TOptions...>;

            public:
                /// @brief endian_type used for serialization.
                using endian_type = typename base_impl_type::endian_type;

                /// @brief Version type
                using version_type = typename base_impl_type::version_type;

                /// @brief All the options provided to this class bundled into struct.
                using parsed_options_type = detail::options_parser<TOptions...>;

                /// @brief Tag indicating type of the field
                using tag = tag::optional;

                /// @brief Type of the field.
                using field_type = TField;

                /// @brief Value type of this field, equal to @ref field_type
                using value_type = field_type;

                /// @brief Mode of the field.
                /// @see optional_mode
                using Mode = optional_mode;

                /// @brief Default constructor
                /// @details The mode it is created in is optional_mode::tentative.
                optional() = default;

                /// @brief Construct the field.
                /// @param[in] fieldSrc field_type to be copied from during construction.
                explicit optional(const field_type &fieldSrc) : base_impl_type(fieldSrc) {
                }

                /// @brief Construct the field.
                /// @param[in] fieldSrc field_type to be moved from during construction.
                explicit optional(field_type &&fieldSrc) : base_impl_type(std::move(fieldSrc)) {
                }

                /// @brief Copy constructor
                optional(const optional &) = default;

                /// @brief Move constructor
                optional(optional &&) = default;

                /// @brief Destructor
                ~optional() noexcept = default;

                /// @brief Copy assignment
                optional &operator=(const optional &) = default;

                /// @brief Move assignment
                optional &operator=(optional &&) = default;

                /// @brief Check whether mode is equivalent to Mode::tentative
                /// @details Convenience wrapper for get_mode(), equivalent to
                ///     @code return get_mode() == Mode::tentative; @endcode
                bool is_tentative() const {
                    return base_impl_type::get_mode() == Mode::tentative;
                }

                /// @brief Set mode to Mode::tentative
                /// @details Convenience wrapper for set_mode(), equivalent to
                ///     @code set_mode(Mode::tentative); @endcode
                void set_tentative() {
                    base_impl_type::set_mode(Mode::tentative);
                }

                /// @brief Check whether mode is equivalent to Mode::missing
                /// @details Convenience wrapper for get_mode(), equivalent to
                ///     @code return get_mode() == Mode::missing; @endcode
                bool is_missing() const {
                    return base_impl_type::get_mode() == Mode::missing;
                }

                /// @brief Set mode to Mode::missing
                /// @details Convenience wrapper for set_mode(), equivalent to
                ///     @code set_mode(Mode::missing); @endcode
                void set_missing() {
                    base_impl_type::set_mode(Mode::missing);
                }

                /// @brief Check whether mode is equivalent to Mode::exists
                /// @details Convenience wrapper for get_mode(), equivalent to
                ///     @code return get_mode() == Mode::exists; @endcode
                bool does_exist() const {
                    return base_impl_type::get_mode() == Mode::exists;
                }

                /// @brief Set mode to Mode::exists
                /// @details Convenience wrapper for set_mode(), equivalent to
                ///     @code set_mode(Mode::exists); @endcode
                void set_exists() {
                    base_impl_type::set_mode(Mode::exists);
                }

                /// @brief Get an access to the wrapped field object
                field_type &field() {
                    return base_impl_type::field();
                }

                /// @brief Get an access to the wrapped field object
                const field_type &field() const {
                    return base_impl_type::field();
                }

                /// @brief Get an access to the wrapped field object
                value_type &value() {
                    return base_impl_type::value();
                }

                /// @brief Get an access to the wrapped field object
                const value_type &value() const {
                    return base_impl_type::value();
                }

                /// @brief Get current optional mode
                Mode get_mode() const {
                    return base_impl_type::get_mode();
                }

                /// @brief Get optional mode
                void set_mode(Mode val) {
                    base_impl_type::set_mode(val);
                }

                /// @brief Get length required to serialise the current field value.
                /// @return If current mode is optional_mode::exists, then the function
                ///     returns whatever length() member function of the wrapped field
                ///     returns. Otherwise (for both optional_mode::missing and
                ///     optional_mode::tentative) 0 is returned.
                std::size_t length() const {
                    return base_impl_type::length();
                }

                /// @brief Get minimal length that is required to serialise field of this type.
                /// @return Same as field_type::min_length()
                static constexpr std::size_t min_length() {
                    return base_impl_type::min_length();
                }

                /// @brief Get maximal length that is required to serialise field of this type.
                /// @return Same as field_type::max_length()
                static constexpr std::size_t max_length() {
                    return base_impl_type::max_length();
                }

                /// @brief Check validity of the field value.
                /// @return If field is marked to be missing (mode is optional_mode::missing),
                ///     "true" is returned, otherwise valid() member function of the wrapped
                ///     field is called.
                bool valid() const {
                    return base_impl_type::valid();
                }

                /// @brief Refresh the field's value
                /// @details Will invoke the refresh() member function of the contained
                ///     field, only if it is marked as "exists", otherwise @b false will be
                ///     returned.
                /// @return @b true if the value has been updated, @b false otherwise
                bool refresh() {
                    return base_impl_type::refresh();
                }

                /// @brief Read field value from input data sequence
                /// @details If field is marked as missing (mode is optional_mode::missing),
                ///     function returns nil::marshalling::ErrorStatus::Success without advancing iterator.@n
                ///     If field is marked as existing (mode is optional_mode::exists) the
                ///     read() member function of the wrapped field object is invoked.@n
                ///     If field is marked to be tentative (mode is optional_mode::tentative),
                ///     the call redirected to wrapped field's read() member function if
                ///     value of the "len" parameter is greater than 0, i.e. there are
                ///     still bytes available for reading, and field itself is marked as
                ///     existing.@n Otherwise, field is marked as missing and
                ///     nil::marshalling::ErrorStatus::Success is returned.
                /// @param[in, out] iter Iterator to read the data.
                /// @param[in] len Number of bytes available for reading.
                /// @return Status of read operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type read(TIter &iter, std::size_t len) {
                    return base_impl_type::read(iter, len);
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
                /// @details If field is marked as missing (mode is optional_mode::missing),
                ///     function returns nil::marshalling::ErrorStatus::Success without advancing iterator.@n
                ///     If field is marked as existing (mode is optional_mode::exists) the
                ///     write() member function of the wrapped field object is invoked.@n
                ///     If field is marked to be tentative (mode is optional_mode::tentative),
                ///     the call redirected to wrapped field's write() member function if
                ///     value of the "len" parameter is greater than 0, i.e. there is
                ///     space available for writing.@n Otherwise, nil::marshalling::ErrorStatus::Success
                ///     is returned.
                /// @param[in, out] iter Iterator to write the data.
                /// @param[in] len Maximal number of bytes that can be written.
                /// @return Status of write operation.
                /// @post Iterator is advanced.
                template<typename TIter>
                status_type write(TIter &iter, std::size_t len) const {
                    return base_impl_type::write(iter, len);
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
                static_assert(
                    !parsed_options_type::has_invalid_by_default,
                    "nil::marshalling::option::invalid_by_default option is not applicable to optional field");
            };

            /// @brief Equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the equality comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator==(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                if (field1.get_mode() != field2.get_mode()) {
                    return false;
                }

                if (field1.is_missing()) {
                    return true;
                }

                return field1.field() == field2.field();
            }

            /// @brief Non-equality comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the non-equality comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator!=(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                return !(field1 == field2);
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the equivalence comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator<(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                if (field1.is_missing()) {
                    return !field2.is_missing();
                }

                if (field2.is_missing()) {
                    return false;
                }

                return false;
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the equivalence comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator>(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                return (field2 < field1);
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the equivalence comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator<=(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                return (field1 < field2) || (field1 == field2);
            }

            /// @brief Equivalence comparison operator.
            /// @param[in] field1 First field.
            /// @param[in] field2 Second field.
            /// @return Result of the equivalence comparison of the contained fields.
            /// @related optional
            template<typename TField, typename... TOptions>
            bool operator>=(const optional<TField, TOptions...> &field1, const optional<TField, TOptions...> &field2) {
                return field2 <= field1;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::optional type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::optional
            template<typename TField, typename... TOptions>
            inline optional<TField, TOptions...> &to_field_base(optional<TField, TOptions...> &field) {
                return field;
            }

            /// @brief Upcast type of the field definition to its parent nil::marshalling::types::optional type
            ///     in order to have access to its internal types.
            /// @related nil::marshalling::types::optional
            template<typename TField, typename... TOptions>
            inline const optional<TField, TOptions...> &to_field_base(const optional<TField, TOptions...> &field) {
                return field;
            }

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_OPTIONAL_HPP
