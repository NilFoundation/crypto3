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

#ifndef MARSHALLING_ADAPTERS_HPP
#define MARSHALLING_ADAPTERS_HPP

#include <nil/marshalling/types/adapter/custom_value_reader.hpp>
#include <nil/marshalling/types/adapter/ser_offset.hpp>
#include <nil/marshalling/types/adapter/fixed_length.hpp>
#include <nil/marshalling/types/adapter/fixed_bit_length.hpp>
#include <nil/marshalling/types/adapter/var_length.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_length_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_size_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_length_forcing.hpp>
#include <nil/marshalling/types/adapter/sequence_fixed_size.hpp>
#include <nil/marshalling/types/adapter/sequence_size_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_elem_fixed_ser_length_field_prefix.hpp>
#include <nil/marshalling/types/adapter/sequence_trailing_field_suffix.hpp>
#include <nil/marshalling/types/adapter/sequence_termination_field_suffix.hpp>
#include <nil/marshalling/types/adapter/default_value_initialiser.hpp>
#include <nil/marshalling/types/adapter/num_value_multi_range_validator.hpp>
#include <nil/marshalling/types/adapter/custom_validator.hpp>
#include <nil/marshalling/types/adapter/custom_refresher.hpp>
#include <nil/marshalling/types/adapter/fail_on_invalid.hpp>
#include <nil/marshalling/types/adapter/ignore_invalid.hpp>
#include <nil/marshalling/types/adapter/empty_serialization.hpp>
#include <nil/marshalling/types/adapter/exists_between_versions.hpp>
#include <nil/marshalling/types/adapter/invalid_by_default.hpp>
#include <nil/marshalling/types/adapter/version_storage.hpp>
#endif    // MARSHALLING_ADAPTERS_HPP
