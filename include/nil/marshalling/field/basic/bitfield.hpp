//---------------------------------------------------------------------------//
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_BASIC_BITFIELD_HPP
#define MARSHALLING_BASIC_BITFIELD_HPP

#include <type_traits>
#include <limits>

#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/processing/size_to_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/marshalling/field/int_value.hpp>
#include <nil/marshalling/field/basic/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace field {
            namespace basic {
                namespace detail {

                    template<typename TField, bool THasFixedBitLength>
                    struct bitfield_member_length_retrieve_helper;

                    template<typename TField>
                    struct bitfield_member_length_retrieve_helper<TField, true> {
                        static const std::size_t value = TField::parsed_options_type::fixed_bit_length;
                    };

                    template<typename TField>
                    struct bitfield_member_length_retrieve_helper<TField, false> {
                        static const std::size_t value = std::numeric_limits<typename TField::value_type>::digits;
                    };

                    template<typename TField>
                    struct bitfield_member_length_retriever {
                        static const std::size_t value = bitfield_member_length_retrieve_helper<
                            TField,
                            TField::parsed_options_type::has_fixed_bit_length_limit>::value;
                    };

                    template<std::size_t TRem, typename TMembers>
                    class bitfield_bit_length_calc_helper {
                        static const std::size_t Idx = std::tuple_size<TMembers>::value - TRem;
                        using field_type = typename std::tuple_element<Idx, TMembers>::type;

                    public:
                        static const std::size_t value = bitfield_bit_length_calc_helper<TRem - 1, TMembers>::value
                                                         + bitfield_member_length_retriever<field_type>::value;
                    };

                    template<typename TMembers>
                    class bitfield_bit_length_calc_helper<0, TMembers> {
                    public:
                        static const std::size_t value = 0;
                    };

                    template<typename TMembers>
                    constexpr std::size_t calc_bit_length() {
                        return bitfield_bit_length_calc_helper<std::tuple_size<TMembers>::value, TMembers>::value;
                    }

                    template<std::size_t TIdx, typename TMembers>
                    struct bitfield_pos_retrieve_helper {
                        static_assert(TIdx < std::tuple_size<TMembers>::value, "Invalid tuple element");
                        using field_type = typename std::tuple_element<TIdx - 1, TMembers>::type;

                        static const std::size_t PrevFieldSize = bitfield_member_length_retriever<field_type>::value;

                    public:
                        static const std::size_t value
                            = bitfield_pos_retrieve_helper<TIdx - 1, TMembers>::value + PrevFieldSize;
                    };

                    template<typename TMembers>
                    struct bitfield_pos_retrieve_helper<0, TMembers> {
                    public:
                        static const std::size_t value = 0;
                    };

                    template<std::size_t TIdx, typename TMembers>
                    constexpr std::size_t get_member_shift_pos() {
                        return bitfield_pos_retrieve_helper<TIdx, TMembers>::value;
                    }

                }    // namespace detail

                template<typename TFieldBase, typename TMembers>
                class bitfield : public TFieldBase {
                    using base_impl_type = TFieldBase;

                    static_assert(nil::marshalling::processing::is_tuple<TMembers>::value,
                                  "TMembers is expected to be a tuple of BitfieldMember<...>");

                    static_assert(1U < std::tuple_size<TMembers>::value,
                                  "Number of members is expected to be at least 2.");

                    static const std::size_t total_bits = detail::calc_bit_length<TMembers>();
                    static_assert((total_bits % std::numeric_limits<std::uint8_t>::digits) == 0,
                                  "Wrong number of total bits");

                    static const std::size_t length_ = total_bits / std::numeric_limits<std::uint8_t>::digits;
                    static_assert(0U < length_, "Serialised length is expected to be greater than 0");
                    using serialized_type = typename nil::marshalling::processing::size_to_type<length_, false>::type;

                    using fixed_int_value_field_type = nil::marshalling::field::
                        int_value<TFieldBase, serialized_type, nil::marshalling::option::fixed_length<length_>>;

                    using simple_int_value_field_type = nil::marshalling::field::int_value<TFieldBase, serialized_type>;

                    using int_value_field_type = typename std::conditional<((length_ & (length_ - 1)) == 0),
                                                                           simple_int_value_field_type,
                                                                           fixed_int_value_field_type>::type;

                public:
                    using endian_type = typename base_impl_type::endian_type;
                    using version_type = typename base_impl_type::version_type;
                    using value_type = TMembers;

                    bitfield() = default;

                    explicit bitfield(const value_type &val) : members_(val) {
                    }

                    explicit bitfield(value_type &&val) : members_(std::move(val)) {
                    }

                    const value_type &value() const {
                        return members_;
                    }

                    value_type &value() {
                        return members_;
                    }

                    static constexpr std::size_t length() {
                        return length_;
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        if (size < length()) {
                            return status_type::not_enough_data;
                        }

                        auto serValue = base_impl_type::template read_data<serialized_type, length_>(iter);
                        status_type es = status_type::success;
                        nil::marshalling::processing::tuple_for_each_with_template_param_idx(members_,
                                                                                            read_helper(serValue, es));
                        return es;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        auto serValue = base_impl_type::template read_data<serialized_type, length_>(iter);
                        nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                            members_, read_no_status_helper(serValue));
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t size) const {
                        if (size < length()) {
                            return status_type::buffer_overflow;
                        }

                        serialized_type serValue = 0;
                        status_type es = status_type::success;
                        nil::marshalling::processing::tuple_for_each_with_template_param_idx(members_,
                                                                                            write_helper(serValue, es));
                        if (es == status_type::success) {
                            nil::marshalling::processing::write_data<length_>(serValue, iter, endian_type());
                        }
                        return es;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        serialized_type serValue = 0;
                        nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                            members_, write_no_status_helper(serValue));
                        nil::marshalling::processing::write_data<length_>(serValue, iter, endian_type());
                    }

                    constexpr bool valid() const {
                        return nil::marshalling::processing::tuple_accumulate(members_, true, valid_helper());
                    }

                    bool refresh() {
                        return nil::marshalling::processing::tuple_accumulate(members_, false, refresh_helper());
                    }

                    template<std::size_t TIdx>
                    static constexpr std::size_t member_bit_length() {
                        static_assert(TIdx < std::tuple_size<value_type>::value, "Index exceeds number of fields");

                        using field_type = typename std::tuple_element<TIdx, value_type>::type;
                        return detail::bitfield_member_length_retriever<field_type>::value;
                    }

                    static constexpr bool is_version_dependent() {
                        return common_funcs::are_members_version_dependent<value_type>();
                    }

                    bool set_version(version_type version) {
                        return common_funcs::set_version_for_members(value(), version);
                    }

                private:
                    class read_helper {
                    public:
                        read_helper(serialized_type val, status_type &es) : value_(val), es_(es) {
                        }

                        template<std::size_t TIdx, typename TFieldParam>
                        void operator()(TFieldParam &&field) {
                            if (es_ != nil::marshalling::status_type::success) {
                                return;
                            }

                            using field_type = typename std::decay<decltype(field)>::type;
                            static const auto Pos = detail::get_member_shift_pos<TIdx, value_type>();
                            static const auto Mask = (static_cast<serialized_type>(1)
                                                      << detail::bitfield_member_length_retriever<field_type>::value)
                                                     - 1;

                            auto fieldSerValue = static_cast<serialized_type>((value_ >> Pos) & Mask);

                            static_assert(field_type::min_length() == field_type::max_length(),
                                          "bitfield doesn't support members with variable length");

                            static const std::size_t max_length = field_type::max_length();
                            std::uint8_t buf[max_length];
                            auto *writeIter = &buf[0];
                            using FieldEndian = typename field_type::endian_type;
                            nil::marshalling::processing::write_data<max_length>(
                                fieldSerValue, writeIter, FieldEndian());

                            const auto *readIter = &buf[0];
                            es_ = field.read(readIter, max_length);
                        }

                    private:
                        serialized_type value_;
                        status_type &es_;
                    };

                    class read_no_status_helper {
                    public:
                        read_no_status_helper(serialized_type val) : value_(val) {
                        }

                        template<std::size_t TIdx, typename TFieldParam>
                        void operator()(TFieldParam &&field) {
                            using field_type = typename std::decay<decltype(field)>::type;
                            using FieldOptions = typename field_type::parsed_options_type;
                            static const auto Pos = detail::get_member_shift_pos<TIdx, value_type>();
                            static const auto Mask
                                = (static_cast<serialized_type>(1) << FieldOptions::fixed_bit_length) - 1;

                            auto fieldSerValue = static_cast<serialized_type>((value_ >> Pos) & Mask);

                            static_assert(field_type::min_length() == field_type::max_length(),
                                          "bitfield doesn't support members with variable length");

                            static const std::size_t max_length = field_type::max_length();
                            std::uint8_t buf[max_length];
                            auto *writeIter = &buf[0];
                            using FieldEndian = typename field_type::endian_type;
                            nil::marshalling::processing::write_data<max_length>(
                                fieldSerValue, writeIter, FieldEndian());

                            const auto *readIter = &buf[0];
                            field.read_no_status(readIter);
                        }

                    private:
                        serialized_type value_;
                    };

                    class write_helper {
                    public:
                        write_helper(serialized_type &val, status_type &es) : value_(val), es_(es) {
                        }

                        template<std::size_t TIdx, typename TFieldParam>
                        void operator()(TFieldParam &&field) {
                            if (es_ != nil::marshalling::status_type::success) {
                                return;
                            }

                            using field_type = typename std::decay<decltype(field)>::type;

                            static_assert(field_type::min_length() == field_type::max_length(),
                                          "bitfield supports fixed length members only.");

                            static const std::size_t max_length = field_type::max_length();
                            std::uint8_t buf[max_length];
                            auto *writeIter = &buf[0];
                            es_ = field.write(writeIter, max_length);
                            if (es_ != nil::marshalling::status_type::success) {
                                return;
                            }

                            using FieldEndian = typename field_type::endian_type;
                            const auto *readIter = &buf[0];
                            auto fieldSerValue = nil::marshalling::processing::read_data<serialized_type, max_length>(
                                readIter, FieldEndian());

                            static const auto Pos = detail::get_member_shift_pos<TIdx, value_type>();
                            static const auto Mask = (static_cast<serialized_type>(1)
                                                      << detail::bitfield_member_length_retriever<field_type>::value)
                                                     - 1;

                            static const auto ClearMask = ~(Mask << Pos);

                            auto valueMask = (static_cast<serialized_type>(fieldSerValue) & Mask) << Pos;

                            value_ &= ClearMask;
                            value_ |= valueMask;
                        }

                    private:
                        serialized_type &value_;
                        status_type &es_;
                    };

                    class write_no_status_helper {
                    public:
                        write_no_status_helper(serialized_type &val) : value_(val) {
                        }

                        template<std::size_t TIdx, typename TFieldParam>
                        void operator()(TFieldParam &&field) {

                            using field_type = typename std::decay<decltype(field)>::type;

                            static_assert(field_type::min_length() == field_type::max_length(),
                                          "bitfield supports fixed length members only.");

                            static const std::size_t max_length = field_type::max_length();
                            std::uint8_t buf[max_length];
                            auto *writeIter = &buf[0];
                            field.write_no_status(writeIter);

                            using FieldEndian = typename field_type::endian_type;
                            const auto *readIter = &buf[0];
                            auto fieldSerValue = nil::marshalling::processing::read_data<serialized_type, max_length>(
                                readIter, FieldEndian());

                            using FieldOptions = typename field_type::parsed_options_type;
                            static const auto Pos = detail::get_member_shift_pos<TIdx, value_type>();
                            static const auto Mask
                                = (static_cast<serialized_type>(1) << FieldOptions::fixed_bit_length) - 1;

                            static const auto ClearMask = ~(Mask << Pos);

                            auto valueMask = (static_cast<serialized_type>(fieldSerValue) & Mask) << Pos;

                            value_ &= ClearMask;
                            value_ |= valueMask;
                        }

                    private:
                        serialized_type &value_;
                    };

                    struct valid_helper {
                        template<typename TFieldParam>
                        bool operator()(bool soFar, const TFieldParam &field) {
                            return soFar && field.valid();
                        }
                    };

                    struct refresh_helper {
                        template<typename TFieldParam>
                        bool operator()(bool soFar, TFieldParam &field) {
                            return field.refresh() || soFar;
                        }
                    };

                    value_type members_;
                };

            }    // namespace basic
        }    // namespace field
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_BITFIELD_HPP
