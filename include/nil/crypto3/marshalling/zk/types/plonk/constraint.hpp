//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

#include <nil/crypto3/marshalling/zk/types/math/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename PlonkConstraint,
                         typename = typename std::enable_if<
                             std::is_same<PlonkConstraint, nil::crypto3::zk::snark::plonk_constraint<
                                                               typename PlonkConstraint::field_type,
                                                               typename PlonkConstraint::variable_type>>::value>::type>
                using plonk_constraint =
                    typename non_linear_combination<TTypeBase, typename PlonkConstraint::base_type>::type;

                template<typename PlonkConstraint, typename Endianness>
                plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint>
                    fill_plonk_constraint(const PlonkConstraint &constr) {
                    return fill_non_linear_combination<typename PlonkConstraint::base_type, Endianness>(constr);
                }

                template<typename PlonkConstraint, typename Endianness>
                PlonkConstraint make_plonk_constraint(
                    const plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint> &filled_constr) {
                    return make_non_linear_combination<typename PlonkConstraint::base_type, Endianness>(filled_constr);
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
