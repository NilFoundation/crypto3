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

#ifndef MARSHALLING_COMMON_FUNCS_HPP
#define MARSHALLING_COMMON_FUNCS_HPP

#include <type_traits>
#include <iterator>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                struct common_funcs {
                    template<typename TField, typename TIter>
                    static status_type read_sequence(TField &field, TIter &iter, std::size_t len) {
                        field.clear();
                        auto remLen = len;
                        while (0 < remLen) {
                            auto &elem = field.create_back();
                            status_type es = field.read_element(elem, iter, remLen);
                            if (es != status_type::success) {
                                field.value().pop_back();
                                return es;
                            }
                        }

                        return status_type::success;
                    }

                    template<typename TField, typename TIter>
                    static status_type read_sequence_n(TField &field, std::size_t count, TIter &iter,
                                                                         std::size_t &len) {
                        field.clear();
                        while (0 < count) {
                            auto &elem = field.create_back();
                            status_type es = field.read_element(elem, iter, len);
                            if (es != status_type::success) {
                                field.value().pop_back();
                                return es;
                            }
                            --count;
                        }
                        return status_type::success;
                    }

                    template<typename TField, typename TIter>
                    static void read_sequence_no_status_n(TField &field, std::size_t count, TIter &iter) {
                        field.clear();
                        while (0 < count) {
                            auto &elem = field.create_back();
                            field.read_element_no_status(elem, iter);
                            --count;
                        }
                    }

                    template<typename TField, typename TIter>
                    static status_type write_sequence(const TField &field, TIter &iter,
                                                                        std::size_t len) {
                        status_type es = status_type::success;
                        auto remainingLen = len;
                        for (auto &elem : field.value()) {
                            es = field.write_element(elem, iter, remainingLen);
                            if (es != status_type::success) {
                                break;
                            }
                        }

                        return es;
                    }

                    template<typename TField, typename TIter>
                    static void write_sequence_no_status(TField &field, TIter &iter) {
                        for (auto &elem : field.value()) {
                            field.write_element_no_status(elem, iter);
                        }
                    }

                    template<typename TField, typename TIter>
                    static status_type write_sequence_n(const TField &field, std::size_t count,
                                                                          TIter &iter, std::size_t &len) {
                        status_type es = status_type::success;
                        for (auto &elem : field.value()) {
                            if (count == 0) {
                                break;
                            }

                            es = field.write_element(elem, iter, len);
                            if (es != status_type::success) {
                                break;
                            }

                            --count;
                        }

                        return es;
                    }

                    template<typename TField, typename TIter>
                    static void write_sequence_no_status_n(const TField &field, std::size_t count, TIter &iter) {
                        for (auto &elem : field.value()) {
                            if (count == 0) {
                                break;
                            }

                            field.write_element_no_status(elem, iter);
                            --count;
                        }
                    }

                    template<typename TIter>
                    static void advance_write_iterator(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using byte_type = typename std::iterator_traits<IterType>::value_type;
                        while (len > 0U) {
                            *iter = byte_type();
                            ++iter;
                            --len;
                        }
                    }

                    static constexpr std::size_t max_supported_length() {
                        return 0xffff;
                    }

                    template<typename TFields>
                    static constexpr bool are_members_version_dependent() {
                        return processing::tuple_type_accumulate<TFields>(
                            false, version_dependency_checker());
                    }

                    template<typename TFields, typename TVersionType>
                    static bool set_version_for_members(TFields &fields, TVersionType version) {
                        return processing::tuple_accumulate(fields, false,
                                                                              make_version_updater(version));
                    }

                private:
                    struct version_dependency_checker {
                        template<typename TField>
                        constexpr bool operator()(bool soFar) const {
                            return TField::is_version_dependent() || soFar;
                        }
                    };

                    template<typename TVerType>
                    class version_updater {
                    public:
                        explicit version_updater(TVerType val) : version_(val) {
                        }

                        template<typename TField>
                        bool operator()(bool soFar, TField &field) const {
                            return field.set_version(static_cast<typename TField::version_type>(version_)) || soFar;
                        }

                    private:
                        TVerType version_;
                    };

                    template<typename TVerType>
                    static version_updater<TVerType> make_version_updater(TVerType val) {
                        return version_updater<TVerType>(val);
                    }
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_COMMON_FUNCS_HPP
