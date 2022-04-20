//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_SPONGE_HPP
#define CRYPTO3_ZK_SPONGE_HPP

#include <vector>
#include <iostream>

// #include <nil/crypto3/multiprecision/number.hpp>
// #include <nil/crypto3/multiprecision/cpp_int.hpp>
// #include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
// #include <nil/crypto3/multiprecision/modular/modular_params_fixed.hpp>

#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace transcript {
                const int CHALLENGE_LENGTH_IN_LIMBS = 2;
                const int HIGH_ENTROPY_LIMBS = 2;

                template<typename curve_type>
                class sponge{
                public:
                    using group_type = typename curve_type::template g1_type<>;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using base_field_type = typename curve_type::base_field_type;
                    using policy_type = hashes::detail::base_poseidon_policy<base_field_type, 2, 1, 7, 55, 0, true>;

                    typename hashes::detail::poseidon_sponge_construction<policy_type> pos_sponge;
                    std::vector<uint64_t> last_squeezed;

                    sponge() : last_squeezed(), pos_sponge() {}

                    void print_state() {
                        std::cout << "STATE: ";
                        for (auto i : this->pos_sponge.state) {
                            std::cout << i.data << ' ';
                        }
                        std::cout << '\n';
                    }

                    typename scalar_field_type::value_type pack(const std::vector<uint64_t>& limbs) {
                        typename scalar_field_type::value_type res(0);
                        typename scalar_field_type::value_type zero(0);
                        typename scalar_field_type::value_type two(2);
                        auto x = zero.data;
                        auto mult = two.data;
                        for (int i = 0; i < 6; ++i) {
                            mult = mult * mult;
                        }
                        for (auto limb : limbs) {
                            typename scalar_field_type::value_type smth(limb);
                            x = x << 64;
                            x = x + smth.data;
                        }
                        res.data = x;
                        return res;
                    }

                    std::vector<uint64_t> unpack(typename base_field_type::value_type elem) {
                        std::vector<uint64_t> res;
                        auto data = elem.data;
                        for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                            // std::cout << "UNPACK: " << (data - (data >> 64 << 64)) << '\n';
                            res.push_back(static_cast<uint64_t>(data - (data >> 64 << 64)));
                            data = data >> 64;
                        }
                        return res;
                    }

                    std::vector<uint64_t> squeeze_limbs(int num_limbs) {
                        if (this->last_squeezed.size() >= num_limbs) {
                            auto copy_last_squeezed = this->last_squeezed;
                            std::vector<uint64_t> limbs = {copy_last_squeezed.begin(), copy_last_squeezed.begin() + num_limbs};
                            std::vector<uint64_t> remaining = {copy_last_squeezed.begin() + num_limbs, copy_last_squeezed.end()};
                            this->last_squeezed = remaining;
                            return limbs;
                        }
                        auto sq = this->pos_sponge.squeeze();
                        std::cout << "CORE_SQUEEZE: " << sq.data << '\n';
                        auto x = unpack(sq);
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            this->last_squeezed.push_back(x[i]);
                        }
                        return this->squeeze_limbs(num_limbs);
                    }

                    typename base_field_type::value_type squeeze_field() {
                        this->last_squeezed = {};
                        return this->pos_sponge.squeeze();
                    }

                    typename scalar_field_type::value_type squeeze(int num_limbs) {
                        typename scalar_field_type::value_type res(0);
                        auto limbs = this->squeeze_limbs(num_limbs);
                        res = pack(limbs);
                        std::cout << "SQUEEZE: " << res.data << '\n';
                        return res;
                    }

                    void absorb_g(const std::vector<typename group_type::value_type>& gs) {
                        std::cout << "ABSORBED\n";
                        this->last_squeezed = {};
                        for (auto g : gs) {
                            // for infinite groups need to check if inf - then absorb [zero, zero]
                            // auto vec = {g.X, g.Y};
                            this->pos_sponge.absorb({g.X});
                            this->pos_sponge.absorb({g.Y});
                        }
                        return;
                    }

                    int from_bits(const std::array<bool, 128>& bits) {
                        int res = 1;
                        // int a = 1;
                        // for (auto bit : bits) {
                        //     if (bit) {res += a;}
                        //     a *= 2;
                        // }
                        return res;
                    }

                    std::array<bool, 128> to_bits(int a) {
                        std::array<bool, 128> bits = {false};
                        // auto integral_b = typename scalar_field_type::integral_type(a);
                        // for (std::size_t i = 0; i < 128; i++) {
                        //     bits[128 - i - 1] = multiprecision::bit_test(integral_b, i);
                        // }
                        return bits;
                    }

                    void absorb_fr(const std::vector<typename scalar_field_type::value_type>& xs) {
                        // this->last_squeezed = {};
                        // for (auto x : xs) {
                        //     auto bits = to_bits(x.data);

                        //     if (scalar_field_type::modulus < base_field_type::modulus) {
                        //         this->pos_sponge.absorb();
                        //     } else {
                        //         typename base_field_type::value_type low_bit = (bits[0] ?
                        //                                         typename base_field_type::value_type::one() :
                        //                                         typename base_field_type::value_type::zero());
                        //         typename base_field_type::value_type high_bits = base_field_type::value_type(
                        //                                         from_bits(newVec(bits.begin() + 1, bits.end())));
                                
                        //         this->pos_sponge.absorb(std::vector<typename base_field_type::value_type>(high_bits));
                        //         this->pos_sponge.absorb(std::vector<typename base_field_type::value_type>(low_bit));
                        //     }
                        // }
                        return;
                    }

                    // static typename scalar_field_type::value_type digest() {}

                    typename scalar_field_type::value_type challenge() {
                        return this->squeeze(CHALLENGE_LENGTH_IN_LIMBS);
                    }

                    typename base_field_type::value_type challenge_fq() {
                        return this->squeeze_field();
                    }
                };
            }    // namespace transcript
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SPONGE_HPP
