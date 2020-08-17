//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Temporary import serialization operators from libff in snark namespace;
//---------------------------------------------------------------------------//

#ifndef LIBSNARK_SERIALIZATION_HPP_
#define LIBSNARK_SERIALIZATION_HPP_

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                using algebra::consume_newline;
                using algebra::consume_OUTPUT_NEWLINE;
                using algebra::consume_OUTPUT_SEPARATOR;

                using algebra::input_bool;
                using algebra::output_bool;

                using algebra::input_bool_vector;
                using algebra::output_bool_vector;
                using algebra::operator<<;
                using algebra::operator>>;
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // LIBSNARK_SERIALIZATION_HPP_
