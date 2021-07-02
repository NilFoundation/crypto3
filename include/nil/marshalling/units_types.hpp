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

/// @file nil/marshalling/units_types.hpp
/// This file contains all the classes necessary to properly
/// define message traits.

#ifndef MARSHALLING_TRAITS_HPP
#define MARSHALLING_TRAITS_HPP

#include <ratio>

#include <nil/marshalling/processing/access.hpp>

namespace nil {
    namespace marshalling {
        namespace traits {
            namespace units {

                /// @brief Tag class used to indicate time value
                struct Time { };

                /// @brief Tag class used to indicate distance value
                struct distance { };

                /// @brief Tag class used to indicate speed value
                struct speed { };

                /// @brief Tag class used to indicate frequency value
                struct frequency { };

                /// @brief Tag class used to indicate angle value
                struct angle { };

                /// @brief Tag class used to indicate electrical current value
                struct current { };

                /// @brief Tag class used to indicate electrical voltage value
                struct voltage { };

                using nanoseconds_ratio = std::nano;
                using microseconds_ratio = std::micro;
                using milliseconds_ratio = std::milli;
                using seconds_ratio = std::ratio<1, 1>;
                using minutes_ratio = std::ratio<60>;
                using hours_ratio = std::ratio<60 * 60>;
                using days_ratio = std::ratio<24L * 60 * 60>;
                using weeks_ratio = std::ratio<7L * 24 * 60 * 60>;

                using nanometers_ratio = std::nano;
                using micrometers_ratio = std::micro;
                using millimeters_ratio = std::milli;
                using centimeters_ratio = std::centi;
                using meters_ratio = std::ratio<1, 1>;
                using kilometers_ratio = std::kilo;

                using nanometers_per_second_ratio = typename std::ratio_divide<nanometers_ratio, seconds_ratio>::type;

                using micrometers_per_second_ratio = typename std::ratio_divide<micrometers_ratio, seconds_ratio>::type;

                using millimeters_per_second_ratio = typename std::ratio_divide<millimeters_ratio, seconds_ratio>::type;

                using centimeters_per_second_ratio = typename std::ratio_divide<centimeters_ratio, seconds_ratio>::type;

                using meters_per_second_ratio = typename std::ratio_divide<meters_ratio, seconds_ratio>::type;

                using kilometers_per_second_ratio = typename std::ratio_divide<kilometers_ratio, seconds_ratio>::type;

                using kilometers_per_hour_ratio = typename std::ratio_divide<kilometers_ratio, hours_ratio>::type;

                using hz_ratio = std::ratio<1, 1>;
                using kilo_hz_ratio = std::kilo;
                using mega_hz_ratio = std::mega;
                using giga_hz_ratio = std::giga;

                using degrees_ratio = std::ratio<1, 1>;
                using radians_ratio = std::ratio<180, 1>;

                using nanoamps_ratio = std::nano;
                using microamps_ratio = std::micro;
                using milliamps_ratio = std::milli;
                using amps_ratio = std::ratio<1, 1>;
                using kiloamps_ratio = std::kilo;

                using nanovolts_ratio = std::nano;
                using microvolts_ratio = std::micro;
                using millivolts_ratio = std::milli;
                using volts_ratio = std::ratio<1, 1>;
                using kilovolts_ratio = std::kilo;

            }    // namespace units
        }        // namespace traits
    }            // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_TRAITS_HPP
