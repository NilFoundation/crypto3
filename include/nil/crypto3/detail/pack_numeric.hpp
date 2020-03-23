//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PACK_NUMERIC_HPP
#define CRYPTO3_PACK_NUMERIC_HPP

#include <boost/assert.hpp>
#include <boost/static_assert.hpp>

#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            using namespace boost::multiprecision;

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(InputIterator first, InputIterator last, number<Backend, ExpressionTemplates> &out) {
                import_bits(out, first, last);
                BOOST_ASSERT(msb(out) == OutValueBits);
            }

            template<typename Endianness, int OutValueBits, typename InputType, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(const InputType &in, number<Backend, ExpressionTemplates> &out) {
                import_bits(out, in.begin(), in.end());
                BOOST_ASSERT(msb(out) == OutValueBits);
            }

            template<typename Endianness, int OutValueBits, typename OutputType, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(const number<Backend, ExpressionTemplates> &in, OutputType &out) {
                export_bits(in, out);
                BOOST_ASSERT(msb(out) == OutValueBits);
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_PACK_HPP
