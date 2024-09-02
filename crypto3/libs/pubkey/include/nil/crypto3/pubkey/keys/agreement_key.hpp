//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_AGREEMENT_KEY_HPP
#define CRYPTO3_AGREEMENT_KEY_HPP

#include <nil/crypto3/pubkey/keys/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

          /*!
           * @brief 
           * 
           * @ingroup pubkey_algorithms
           * 
           * Key agreement refers to one form of key exchange  in which two or more users 
           * execute a protocol to securely share a resultant key value. As an alternative 
           * to key agreement, a key transport protocol may be used. The distinguishing 
           * feature of a key agreement protocol is that participating users each contribute 
           * an equal portion toward the computation of the resultant shared key value 
           * (as opposed to one user computing and distributing a key value to other users).
           *
           */
          template<typename Scheme>
          struct agreement_key : public private_key<Scheme> {
              typedef typename private_key<Scheme>::scheme_type scheme_type;
              typedef typename Scheme::key_agreement_policy key_policy_type;

              typedef typename private_key<Scheme>::key_type key_type;
              typedef typename private_key<Scheme>::key_schedule_type key_schedule_type;

              agreement_key(const key_type &key) : private_key<Scheme>(key), agrkey(key) {
              }

              key_schedule_type agrkey;
          };
        } // namespace pubkey
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PRIVATE_KEY_HPP
