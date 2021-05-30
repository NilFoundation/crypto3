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

/// @file nil/marshalling/status_type.hpp
/// This file contain definition of error statuses used by marshalling module.

#ifndef MARSHALLING_STATUS_TYPE_HPP
#define MARSHALLING_STATUS_TYPE_HPP

namespace nil {
    namespace marshalling {

        /// @brief Error statuses.
        enum class status_type {
            success,             ///< Used to indicate successful outcome of the operation.
            update_required,     ///< Used to indicate that write operation wasn't complete,
                                 /// call to update(...) is required.
            not_enough_data,     ///< Used to indicate that stream buffer didn't contain
                                 /// enough data to complete read operation.
            protocol_error,      ///< Used to indicate that any of the used protocols
                                 /// encountered an error while processing the data.
            buffer_overflow,     ///< Used to indicate that stream buffer was overflowed
                                 /// when attempting to write data.
            invalid_msg_id,      ///< Used to indicate that received message has unknown id
            invalid_msg_data,    ///< Used to indicate that received message has invalid
            /// data.
            msg_alloc_failure,     ///< Used to indicate that message allocation has failed.
            not_supported,         ///< The operation is not supported.
            error_status_amount    ///< Number of supported error statuses, must be last.
        };

        status_type operator|(const status_type &l_status, const status_type &r_status) {
            if (l_status == status_type::success) {
                return r_status;
            }
            if (r_status == status_type::success) {
                return l_status;
            }

            return status_type::not_supported;
        }

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_STATUS_TYPE_HPP
