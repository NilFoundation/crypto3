//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#include <iostream>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/bls.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <vector>
#include <string>
#include <utility>
#include <random>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;

using curve_type = curves::bls12_381;
using hash_type = sha2<256>;
using curve_type = curves::bls12_381;
using scheme_type = bls<bls_default_public_params<>, bls_mss_ro_version, bls_basic_scheme, curve_type>;

using privkey_type = private_key<scheme_type>;
using pubkey_type = public_key<scheme_type>;
using _privkey_type = typename privkey_type::private_key_type;
using _pubkey_type = typename pubkey_type::public_key_type;
using signature_type = typename pubkey_type::signature_type;

int main() {
    std::string msg_str = "hello world";
    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    privkey_type sk = privkey_type(random_element<typename _privkey_type::field_type>());

    signature_type sig = sign(msg, sk);
    pubkey_type &pubkey = sk;
    assert(verify(msg, sig, pubkey));

    return 0;
}