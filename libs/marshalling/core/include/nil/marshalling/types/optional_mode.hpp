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

/// @file nil/marshalling/types/optional_mode.hpp
/// Contains definition of the mode used for nil::marshalling::types::optional fields.

#ifndef MARSHALLING_OPTIONAL_MODE_HPP
#define MARSHALLING_OPTIONAL_MODE_HPP

namespace nil {
    namespace marshalling {
        namespace types {

            /// @brief Mode to be used by nil::marshalling::types::optional
            /// @headerfile nil/marshalling/types/optional_mode.hpp
            enum class optional_mode {
                tentative,      ///< The field existence is tentative, i.e. If there is enough bytes
                                /// to read the field's value, than field exists, if not
                                /// then it doesn't exist.
                exists,         ///< field_type must exist
                missing,        ///< field_type doesn't exist
                modes_amount    ///< Number of possible modes, must be last
            };

        }    // namespace types
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_OPTIONAL_MODE_HPP
