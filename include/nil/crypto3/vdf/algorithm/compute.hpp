//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_VDF_COMPUTE_HPP
#define CRYPTO3_VDF_COMPUTE_HPP

#ifdef CRYPTO3_VDF_BOOST
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/detail/number_base.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace vdf {
#ifndef CRYPTO3_VDF_BOOST

            template<typename Vdf, typename NumberType, typename Integer>
            void compute(const NumberType &challenge, Integer difficulty,
                         typename Vdf::template state_type<NumberType> &out) {
                Vdf::compute(out, challenge, difficulty);
            }

#else

            using namespace boost::multiprecision;

            template<typename Vdf,
                     typename SinglePassRange,
                     typename Backend,
                     expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>>
                raw_input(const SinglePassRange &v) {

            }

            template<typename Vdf,
                     typename InputIterator,
                     typename Backend,
                     expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>> raw_input(InputIterator first,
                                                                                              InputIterator last) {
            }

            template<typename Vdf, typename Backend, expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>>
                discriminant_input(const number<Backend, ExpressionTemplates> &v) {
                return Vdf::state_from_discriminant(v);
            }

            template<typename Vdf, typename Backend, expression_template_option ExpressionTemplates, typename Integer>
            void compute(typename Vdf::template state_type<number<Backend, ExpressionTemplates>> &state,
                         Integer difficulty) {
            }

            template<typename Vdf, typename Backend1, expression_template_option ExpressionTemplates1, typename Integer>
            void compute(const number<Backend1, ExpressionTemplates1> &challenge, Integer difficulty) {
                Vdf::compute(challenge, difficulty);
            }
#endif

            template<typename Vdf, typename NumberType>
            typename Vdf::template state_type<NumberType> discriminant_input(const NumberType &v) {
                return Vdf::state_from_discriminant(v);
            }

            template<typename Vdf, typename InputIterator, typename Integer, typename OutputIterator>
            OutputIterator compute(InputIterator first, InputIterator last, Integer difficulty, OutputIterator out) {
            }

            template<typename Vdf, typename SinglePassRange, typename Integer, typename OutputIterator>
            OutputIterator compute(const SinglePassRange &r, Integer difficulty, OutputIterator out) {
            }
        }    // namespace vdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_VDF_COMPUTE_HPP
