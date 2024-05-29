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

#include <system_error>

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

        inline status_type operator|(const status_type &l_status, const status_type &r_status) {
            if (l_status == status_type::success) {
                return r_status;
            }
            if (r_status == status_type::success) {
                return l_status;
            }

            return status_type::not_supported;
        }

        // Define a custom error code category derived from std::error_category
        class status_type_category : public ::std::error_category
        {
            public:
                // Return a short descriptive name for the category
                virtual const char *name() const noexcept override final { return "nil::marshalling::status_type"; }
                // Return what each enum means in text
                virtual std::string message(int c) const override final
                {
                    switch (static_cast<status_type>(c))
                    {
                        case status_type::success:
                            return "conversion successful";
                        case status_type::update_required:
                            return "write operation wasn't complete, call to update(...) is required";
                        case status_type::not_enough_data:
                            return "stream buffer didn't contain enough data to complete read operation";
                        case status_type::protocol_error:
                            return "any of the used protocols encountered an error while processing the data";
                        case status_type::buffer_overflow:
                            return "stream buffer was overflowed when attempting to write data";
                        case status_type::invalid_msg_id:
                            return "received message has unknown id";
                        case status_type::invalid_msg_data:
                            return "received message has invalid data";
                        case status_type::msg_alloc_failure:
                            return "message allocation has failed";
                        case status_type::not_supported:
                            return "the operation is not supported";
                        case status_type::error_status_amount:
                            return "unreachable";
                    }
                }
        };
    }    // namespace marshalling
}    // namespace nil

namespace std
{
    template <> struct is_error_code_enum<nil::marshalling::status_type> : true_type
    {
    };
}

inline std::error_code make_error_code(nil::marshalling::status_type e)
{
    static nil::marshalling::status_type_category category;
    return {static_cast<int>(e), category};
}


#endif    // MARSHALLING_STATUS_TYPE_HPP
