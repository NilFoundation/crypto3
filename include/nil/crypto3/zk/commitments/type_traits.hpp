//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP
#define CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP

#include <boost/tti/tti.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {

            BOOST_TTI_HAS_TYPE(commitment_type)
            BOOST_TTI_HAS_TYPE(proof_type)

            BOOST_TTI_MEMBER_TYPE(commitment_type)
            // BOOST_TTI_HAS_TYPE(proving_key)
            // BOOST_TTI_HAS_TYPE(verification_key)

            BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(commit)
            BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(proof_eval)
            BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(verify_eval)
            
            template<typename T>
            struct is_commitment {
                using commitment_type = typename member_type_commitment_type<T>::type;

                static const bool value = has_type_commitment_type<T>::value && has_type_proof_type<T>::value &&
                                          has_static_member_function_commit<T, commitment_type>::value;
                typedef T type;
            };

        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP
