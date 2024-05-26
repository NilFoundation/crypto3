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

/// @file
/// This file contains all the functions required for proper units conversion.

#ifndef MARSHALLING_UNITS_HPP
#define MARSHALLING_UNITS_HPP

#include <ratio>
#include <type_traits>

#include <nil/marshalling/units_types.hpp>

namespace nil {
    namespace marshalling {
        namespace units {
            namespace detail {

                template<typename TField, bool THasScalingRatio>
                struct scaling_ratio_retriever {
                    using type = std::ratio<1, 1>;
                };

                template<typename TField>
                struct scaling_ratio_retriever<TField, true> {
                    using type = typename TField::parsed_options_type::scaling_ratio_type;
                };

                template<typename TField>
                using scaling_ratio_of =
                    typename scaling_ratio_retriever<TField, TField::parsed_options_type::has_scaling_ratio>::type;

                template<typename TField, typename TConvRatio>
                using full_units_ratio_of = typename std::ratio_divide<
                    typename std::ratio_multiply<scaling_ratio_of<TField>,
                                                 typename TField::parsed_options_type::units_ratio>::type,
                    TConvRatio>::type;

                struct units_value_converter {
                    template<typename TRet, typename TConvRatio, typename TField>
                    static TRet get_value(const TField &field) {
                        using Ratio = full_units_ratio_of<TField, TConvRatio>;
                        using tag = typename std::conditional<std::is_same<Ratio, std::ratio<1, 1>>::value,
                                                              no_conversion_tag,
                                                              has_conversion_tag>::type;

                        return get_value_internal<TRet, Ratio>(field, tag());
                    }

                    template<typename TConvRatio, typename TField, typename TVal>
                    static void set_value(TField &field, TVal &&value) {
                        using Ratio = full_units_ratio_of<TField, TConvRatio>;
                        using tag = typename std::conditional<std::is_same<Ratio, std::ratio<1, 1>>::value,
                                                              no_conversion_tag,
                                                              has_conversion_tag>::type;

                        return set_value_internal<Ratio>(field, std::forward<TVal>(value), tag());
                    }

                private:
                    struct has_conversion_tag { };
                    struct no_conversion_tag { };
                    struct convert_to_fp_tag { };
                    struct convert_to_int_tag { };

                    template<typename TRet, typename TRatio, typename TField>
                    static TRet get_value_internal(const TField &field, no_conversion_tag) {
                        return static_cast<TRet>(field.value());
                    }

                    template<typename TRet, typename TRatio, typename TField>
                    static TRet get_value_internal(const TField &field, has_conversion_tag) {
                        using tag = typename std::conditional<std::is_floating_point<TRet>::value,
                                                              convert_to_fp_tag,
                                                              convert_to_int_tag>::type;

                        return get_value_internal<TRet, TRatio>(field, tag());
                    }

                    template<typename TRet, typename TRatio, typename TField>
                    static TRet get_value_internal(const TField &field, convert_to_fp_tag) {
                        static_assert(std::is_floating_point<TRet>::value,
                                      "TRet is expected to be floating point type");
                        return static_cast<TRet>(field.value())
                               * (static_cast<TRet>(TRatio::num) / static_cast<TRet>(TRatio::den));
                    }

                    template<typename TRet, typename TRatio, typename TField>
                    static TRet get_value_internal(const TField &field, convert_to_int_tag) {
                        static_assert(std::is_integral<TRet>::value, "TRet is expected to be integral type");

                        using field_type = typename std::decay<decltype(field)>::type;
                        using value_type = typename field_type::value_type;

                        static_assert(std::is_integral<value_type>::value || std::is_floating_point<value_type>::value
                                          || std::is_enum<value_type>::value,
                                      "Unexpected field in units conversion");

                        using cast_type = typename std::conditional<
                            std::is_floating_point<value_type>::value,
                            typename std::conditional<std::is_same<value_type, float>::value, double, value_type>::type,
                            typename std::conditional<std::is_signed<TRet>::value, std::intmax_t, std::uintmax_t>::
                                type>::type;

                        return static_cast<TRet>((static_cast<cast_type>(field.value()) * TRatio::num) / TRatio::den);
                    }

                    template<typename TRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&value, no_conversion_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        using value_type = typename field_type::value_type;
                        field.value() = static_cast<value_type>(value);
                    }

                    template<typename TRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&value, has_conversion_tag) {
                        using tag = typename std::conditional<
                            std::is_floating_point<typename std::decay<decltype(value)>::type>::value,
                            convert_to_fp_tag,
                            convert_to_int_tag>::type;

                        set_value_internal<TRatio>(field, std::forward<TVal>(value), tag());
                    }

                    template<typename TRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&value, convert_to_int_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        using value_type = typename field_type::value_type;

                        static_assert(std::is_integral<value_type>::value || std::is_floating_point<value_type>::value
                                          || std::is_enum<value_type>::value,
                                      "Unexpected field in units conversion");

                        using cast_type = typename std::conditional<
                            std::is_floating_point<value_type>::value,
                            typename std::conditional<std::is_same<value_type, float>::value, double, value_type>::type,
                            typename std::conditional<std::is_signed<typename std::decay<decltype(value)>::type>::value,
                                                      std::intmax_t,
                                                      std::uintmax_t>::type>::type;

                        field.value() = static_cast<value_type>((static_cast<cast_type>(value) * TRatio::den)
                                                                / static_cast<cast_type>(TRatio::num));
                    }

                    template<typename TRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&value, convert_to_fp_tag) {
                        using DecayedType = typename std::decay<decltype(value)>::type;
                        using field_type = typename std::decay<decltype(field)>::type;
                        using value_type = typename field_type::value_type;

                        auto epsilon = DecayedType(0);
                        if ((TRatio::num < TRatio::den) && std::is_integral<value_type>::value) {
                            epsilon = static_cast<DecayedType>(TRatio::num) / static_cast<DecayedType>(TRatio::den + 1);
                        }

                        if (epsilon < DecayedType(0)) {
                            epsilon = -epsilon;
                        }

                        if (value < DecayedType(0)) {
                            epsilon = -epsilon;
                        }

                        field.value()
                            = static_cast<value_type>(((value + epsilon) * static_cast<DecayedType>(TRatio::den))
                                                      / static_cast<DecayedType>(TRatio::num));
                    }
                };

                template<typename TField, typename TType, bool THasUnits>
                struct units_checker {
                    static const bool value = false;
                };

                template<typename TField, typename TType>
                struct units_checker<TField, TType, true> {
                    static const bool value
                        = std::is_same<typename TField::parsed_options_type::units_type, TType>::value;
                };

                template<typename TField, typename TType>
                constexpr bool has_expected_units() {
                    return units_checker<TField, TType, TField::parsed_options_type::has_units>::value;
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_time(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::Time>(),
                                  "The field is expected to contain \"time\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_time(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::Time>(),
                                  "The field is expected to contain \"time\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_distance(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::distance>(),
                                  "The field is expected to contain \"distance\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_distance(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::distance>(),
                                  "The field is expected to contain \"distance\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_speed(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::speed>(),
                                  "The field is expected to contain \"speed\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_speed(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::speed>(),
                                  "The field is expected to contain \"speed\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_frequency(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::frequency>(),
                                  "The field is expected to contain \"frequency\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_frequency(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::frequency>(),
                                  "The field is expected to contain \"frequency\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename T>
                struct PI {
                    static constexpr T value = static_cast<T>(
                        3.14159265358979323846264338327950288419716939937510582097494459230781640628620899L);
                };

                struct angle_value_converter {
                    template<typename TRet, typename TConvRatio, typename TField>
                    static TRet get_value(const TField &field) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(detail::has_expected_units<field_type, nil::marshalling::traits::units::angle>(),
                                      "The field is expected to contain \"angle\" units.");

                        using tag = typename std::conditional<
                            std::is_same<TConvRatio, typename field_type::parsed_options_type::units_ratio>::value,
                            same_units_tag,
                            typename ::std::conditional<
                                std::is_same<TConvRatio, nil::marshalling::traits::units::radians_ratio>::value,
                                degrees_to_radians_tag,
                                radians_to_degrees_tag>::type>::type;

                        return get_value_internal<TRet, TConvRatio>(field, tag());
                    }

                    template<typename TConvRatio, typename TField, typename TVal>
                    static void set_value(TField &field, TVal &&val) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(detail::has_expected_units<field_type, nil::marshalling::traits::units::angle>(),
                                      "The field is expected to contain \"angle\" units.");

                        using tag = typename std::conditional<
                            std::is_same<TConvRatio, typename field_type::parsed_options_type::units_ratio>::value,
                            same_units_tag,
                            typename ::std::conditional<
                                std::is_same<TConvRatio,
                                             typename nil::marshalling::traits::units::radians_ratio>::value,
                                radians_to_degrees_tag,
                                degrees_to_radians_tag>::type>::type;

                        set_value_internal<TConvRatio>(field, std::forward<TVal>(val), tag());
                    }

                private:
                    struct same_units_tag { };
                    struct degrees_to_radians_tag { };
                    struct radians_to_degrees_tag { };

                    template<typename TRet, typename TConvRatio, typename TField>
                    static TRet get_value_internal(const TField &field, same_units_tag) {
                        return field.template get_scaled<TRet>();
                    }

                    template<typename TRet, typename TConvRatio, typename TField>
                    static TRet get_value_internal(const TField &field, degrees_to_radians_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(std::is_same<typename field_type::parsed_options_type::units_ratio,
                                                   nil::marshalling::traits::units::degrees_ratio>::value,
                                      "The field is expected to contain degrees.");

                        return PI<TRet>::value * units_value_converter::get_value<TRet, TConvRatio>(field);
                    }

                    template<typename TRet, typename TConvRatio, typename TField>
                    static TRet get_value_internal(const TField &field, radians_to_degrees_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(std::is_same<typename field_type::parsed_options_type::units_ratio,
                                                   nil::marshalling::traits::units::radians_ratio>::value,
                                      "The field is expected to contain radians.");

                        return units_value_converter::get_value<TRet, TConvRatio>(field) / PI<TRet>::value;
                    }

                    template<typename TConvRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&val, same_units_tag) {
                        field.set_scaled(std::forward<TVal>(val));
                    }

                    template<typename TConvRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&val, degrees_to_radians_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(std::is_same<typename field_type::parsed_options_type::units_ratio,
                                                   nil::marshalling::traits::units::radians_ratio>::value,
                                      "The field is expected to contain radians.");

                        using value_type = typename std::decay<decltype(val)>::type;
                        using PiType = typename std::
                            conditional<std::is_floating_point<value_type>::value, value_type, double>::type;

                        units_value_converter::set_value<TConvRatio>(field, val * PI<PiType>::value);
                    }

                    template<typename TConvRatio, typename TField, typename TVal>
                    static void set_value_internal(TField &field, TVal &&val, radians_to_degrees_tag) {
                        using field_type = typename std::decay<decltype(field)>::type;
                        static_assert(std::is_same<typename field_type::parsed_options_type::units_ratio,
                                                   nil::marshalling::traits::units::degrees_ratio>::value,
                                      "The field is expected to contain degrees.");

                        using value_type = typename std::decay<decltype(val)>::type;
                        using PiType = typename std::
                            conditional<std::is_floating_point<value_type>::value, value_type, double>::type;

                        units_value_converter::set_value<TConvRatio>(field,
                                                                     static_cast<PiType>(val) / PI<PiType>::value);
                    }
                };

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_angle(const TField &field) {
                    return angle_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_angle(TField &field, TVal &&val) {
                    angle_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_current(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::current>(),
                                  "The field is expected to contain \"current\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_current(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::current>(),
                                  "The field is expected to contain \"current\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

                template<typename TRet, typename TConvRatio, typename TField>
                TRet get_voltage(const TField &field) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::voltage>(),
                                  "The field is expected to contain \"voltage\" units.");
                    return units_value_converter::get_value<TRet, TConvRatio>(field);
                }

                template<typename TConvRatio, typename TField, typename TVal>
                void set_voltage(TField &field, TVal &&val) {
                    static_assert(detail::has_expected_units<typename std::decay<decltype(field)>::type,
                                                             nil::marshalling::traits::units::voltage>(),
                                  "The field is expected to contain \"voltage\" units.");
                    units_value_converter::set_value<TConvRatio>(field, std::forward<TVal>(val));
                }

            }    // namespace detail

            /// @brief Retrieve field's value as nanoseconds.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to nanoseconds and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_nanoseconds(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::nanoseconds_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing nanoseconds value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided nanoseconds into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_nanoseconds(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::nanoseconds_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as microseconds.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to microseconds and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_microseconds(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::microseconds_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing microseconds value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided microseconds into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_microseconds(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::microseconds_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as milliseconds.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to milliseconds and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_milliseconds(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::milliseconds_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing milliseconds value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided milliseconds into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_milliseconds(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::milliseconds_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as seconds.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to seconds and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_seconds(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::seconds_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing seconds value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided seconds into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_seconds(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::seconds_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as minutes.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to minutes and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_minutes(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::minutes_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing minutes value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided minutes into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_minutes(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::minutes_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as hours.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to hours and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_hours(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::hours_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing hours value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided hours into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_hours(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::hours_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as days.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to days and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_days(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::days_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing days value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided days into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_days(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::days_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as weeks.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to weeks and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TRet, typename TField>
            TRet get_weeks(const TField &field) {
                return detail::get_time<TRet, nil::marshalling::traits::units::weeks_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing weeks value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided weeks into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any time value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliseconds,
            ///     nil::marshalling::option::UnitsSeconds, etc...
            template<typename TField, typename TVal>
            void set_weeks(TField &field, TVal &&val) {
                detail::set_time<nil::marshalling::traits::units::weeks_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as nanometers.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to nanometers and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet get_nanometers(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::nanometers_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing nanometers value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided nanometers into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void set_nanometers(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::nanometers_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as micrometers.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to micrometers and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet get_micrometers(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::micrometers_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing micrometers value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided micrometers into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void set_micrometers(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::micrometers_ratio>(field,
                                                                                         std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as millimeters.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to millimeters and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet get_millimeters(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::millimeters_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing millimeters value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided millimeters into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void set_millimeters(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::millimeters_ratio>(field,
                                                                                         std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as centimeters.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to centimeters and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet get_centimeters(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::centimeters_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing centimeters value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided centimeters into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void setCentimeters(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::centimeters_ratio>(field,
                                                                                         std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as meters.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to meters and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet getMeters(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::meters_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing meters value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided meters into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void setMeters(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::meters_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kilometers.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to kilometers and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TRet, typename TField>
            TRet getKilometers(const TField &field) {
                return detail::get_distance<TRet, nil::marshalling::traits::units::kilometers_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kilometers value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided kilometers into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any distance value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimeters,
            ///     nil::marshalling::option::UnitsMeters, etc...
            template<typename TField, typename TVal>
            void setKilometers(TField &field, TVal &&val) {
                detail::set_distance<nil::marshalling::traits::units::kilometers_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as nanometers per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to nm/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getNanometersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::nanometers_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing nanometers per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided nm/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setNanometersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::nanometers_per_second_ratio>(
                    field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as micrometers per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to um/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getMicrometersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::micrometers_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing micrometers per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided um/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setMicrometersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::micrometers_per_second_ratio>(
                    field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as millimeters per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to mm/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getMillimetersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::millimeters_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing millimeters per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided mm/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setMillimetersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::millimeters_per_second_ratio>(
                    field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as centimeters per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to cm/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getCentimetersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::centimeters_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing centimeters per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided cm/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setCentimetersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::centimeters_per_second_ratio>(
                    field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as meters per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to m/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getMetersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::meters_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing meters per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided m/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setMetersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::meters_per_second_ratio>(field,
                                                                                            std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kilometers per second.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to km/s and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getKilometersPerSecond(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::kilometers_per_second_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kilometers per second value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided km/s into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setKilometersPerSecond(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::kilometers_per_second_ratio>(
                    field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kilometers per hour.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to km/h and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TRet, typename TField>
            TRet getKilometersPerHour(const TField &field) {
                return detail::get_speed<TRet, nil::marshalling::traits::units::kilometers_per_hour_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kilometers per hour value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided km/h into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any speed value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillimetersPerSecond,
            ///     nil::marshalling::option::UnitsMetersPerSecond, etc...
            template<typename TField, typename TVal>
            void setKilometersPerHour(TField &field, TVal &&val) {
                detail::set_speed<nil::marshalling::traits::units::kilometers_per_hour_ratio>(field,
                                                                                              std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as hertz.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to hertz and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TRet, typename TField>
            TRet getHertz(const TField &field) {
                return detail::get_frequency<TRet, nil::marshalling::traits::units::hz_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing hertz value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided hertz into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TField, typename TVal>
            void setHertz(TField &field, TVal &&val) {
                detail::set_frequency<nil::marshalling::traits::units::hz_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kilohertz.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to kilohertz and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TRet, typename TField>
            TRet getKilohertz(const TField &field) {
                return detail::get_frequency<TRet, nil::marshalling::traits::units::kilo_hz_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kilohertz value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided kilohertz into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TField, typename TVal>
            void setKilohertz(TField &field, TVal &&val) {
                detail::set_frequency<nil::marshalling::traits::units::kilo_hz_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as megahertz.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to megahertz and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TRet, typename TField>
            TRet getMegahertz(const TField &field) {
                return detail::get_frequency<TRet, nil::marshalling::traits::units::mega_hz_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing megahertz value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided megahertz into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TField, typename TVal>
            void setMegahertz(TField &field, TVal &&val) {
                detail::set_frequency<nil::marshalling::traits::units::mega_hz_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as gigahertz.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to gigahertz and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TRet, typename TField>
            TRet getGigahertz(const TField &field) {
                return detail::get_frequency<TRet, nil::marshalling::traits::units::giga_hz_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing gigahertz value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided gigahertz into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any frequency value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsHertz,
            ///     nil::marshalling::option::UnitsKilohertz, etc...
            template<typename TField, typename TVal>
            void setGigahertz(TField &field, TVal &&val) {
                detail::set_frequency<nil::marshalling::traits::units::giga_hz_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as degrees.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to degrees and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any angle measurement value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsDegrees or
            ///     nil::marshalling::option::UnitsRadians
            template<typename TRet, typename TField>
            TRet getDegrees(const TField &field) {
                return detail::get_angle<TRet, nil::marshalling::traits::units::degrees_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing degrees value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided degrees into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any angle measurement value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsDegrees or
            ///     nil::marshalling::option::UnitsRadians
            template<typename TField, typename TVal>
            void setDegrees(TField &field, TVal &&val) {
                detail::set_angle<nil::marshalling::traits::units::degrees_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as radians.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to radians and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any angle measurement value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsDegrees or
            ///     nil::marshalling::option::UnitsRadians
            template<typename TRet, typename TField>
            TRet getRadians(const TField &field) {
                return detail::get_angle<TRet, nil::marshalling::traits::units::radians_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing radians value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided radians into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any angle measurement value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsDegrees or
            ///     nil::marshalling::option::UnitsRadians
            template<typename TField, typename TVal>
            void setRadians(TField &field, TVal &&val) {
                detail::set_angle<nil::marshalling::traits::units::radians_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as nanoamps.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to nanoamps and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TRet, typename TField>
            TRet getNanoamps(const TField &field) {
                return detail::get_current<TRet, nil::marshalling::traits::units::nanoamps_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing nanoamps value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided nanoamps into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TField, typename TVal>
            void setNanoamps(TField &field, TVal &&val) {
                detail::set_current<nil::marshalling::traits::units::nanoamps_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as microamps.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to microamps and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TRet, typename TField>
            TRet getMicroamps(const TField &field) {
                return detail::get_current<TRet, nil::marshalling::traits::units::microamps_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing microamps value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided microamps into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TField, typename TVal>
            void setMicroamps(TField &field, TVal &&val) {
                detail::set_current<nil::marshalling::traits::units::microamps_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as milliamps.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to milliamps and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TRet, typename TField>
            TRet getMilliamps(const TField &field) {
                return detail::get_current<TRet, nil::marshalling::traits::units::milliamps_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing milliamps value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided milliamps into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TField, typename TVal>
            void setMilliamps(TField &field, TVal &&val) {
                detail::set_current<nil::marshalling::traits::units::milliamps_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as amps.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to amps and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TRet, typename TField>
            TRet getAmps(const TField &field) {
                return detail::get_current<TRet, nil::marshalling::traits::units::amps_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing amps value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided amps into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TField, typename TVal>
            void setAmps(TField &field, TVal &&val) {
                detail::set_current<nil::marshalling::traits::units::amps_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kiloamps.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to kiloamps and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TRet, typename TField>
            TRet getKiloamps(const TField &field) {
                return detail::get_current<TRet, nil::marshalling::traits::units::kiloamps_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kiloamps value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided kiloamps into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMilliamps,
            ///     nil::marshalling::option::UnitsAmps, etc...
            template<typename TField, typename TVal>
            void setKiloamps(TField &field, TVal &&val) {
                detail::set_current<nil::marshalling::traits::units::kiloamps_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as nanovolts.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to nanovolts and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical current value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TRet, typename TField>
            TRet getNanovolts(const TField &field) {
                return detail::get_voltage<TRet, nil::marshalling::traits::units::nanovolts_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing nanovolts value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided nanovolts into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TField, typename TVal>
            void setNanovolts(TField &field, TVal &&val) {
                detail::set_voltage<nil::marshalling::traits::units::nanovolts_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as microvolts.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to microvolts and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TRet, typename TField>
            TRet getMicrovolts(const TField &field) {
                return detail::get_voltage<TRet, nil::marshalling::traits::units::microvolts_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing microvolts value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided microvolts into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TField, typename TVal>
            void setMicrovolts(TField &field, TVal &&val) {
                detail::set_voltage<nil::marshalling::traits::units::microvolts_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as millivolts.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to millivolts and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TRet, typename TField>
            TRet getMillivolts(const TField &field) {
                return detail::get_voltage<TRet, nil::marshalling::traits::units::millivolts_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing millivolts value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided millivolts into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TField, typename TVal>
            void setMillivolts(TField &field, TVal &&val) {
                detail::set_voltage<nil::marshalling::traits::units::millivolts_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as volts.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to volts and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TRet, typename TField>
            TRet getVolts(const TField &field) {
                return detail::get_voltage<TRet, nil::marshalling::traits::units::volts_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing volts value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided volts into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TField, typename TVal>
            void setVolts(TField &field, TVal &&val) {
                detail::set_voltage<nil::marshalling::traits::units::volts_ratio>(field, std::forward<TVal>(val));
            }

            /// @brief Retrieve field's value as kilovolts.
            /// @details The function will do all the necessary math operations to convert
            ///     stored value to kilovolts and return the result in specified return
            ///     type.
            /// @tparam TRet Return type
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TRet, typename TField>
            TRet getKilovolts(const TField &field) {
                return detail::get_voltage<TRet, nil::marshalling::traits::units::kilovolts_ratio>(field);
            }

            /// @brief Update field's value accordingly, while providing kilovolts value.
            /// @details The function will do all the necessary math operations to convert
            ///     provided kilovolts into the units stored by the field and update the
            ///     internal value of the latter accordingly.
            /// @tparam TField Type of the field, expected to be a field with integral
            ///     internal value, such as a variant of nil::marshalling::types::integral.
            /// @tparam TVal Type of value to assign.
            /// @pre The @b TField type must be defined containing any electrical voltage value, using
            ///     any of the relevant options: nil::marshalling::option::UnitsMillivolts,
            ///     nil::marshalling::option::UnitsVolts, etc...
            template<typename TField, typename TVal>
            void setKilovolts(TField &field, TVal &&val) {
                detail::set_voltage<nil::marshalling::traits::units::kilovolts_ratio>(field, std::forward<TVal>(val));
            }
        }    // namespace units
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_UNITS_HPP
