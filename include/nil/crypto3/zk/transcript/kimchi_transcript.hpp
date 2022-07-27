#ifndef CRYPTO3_ZK_SPONGE_HPP
#define CRYPTO3_ZK_SPONGE_HPP

#include <vector>
#include <iostream>
#include <cstdint>

#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace transcript {
                const int CHALLENGE_LENGTH_IN_LIMBS = 2;
                const int HIGH_ENTROPY_LIMBS = 2;

                template <typename FieldType>
                typename FieldType::integral_type pack(const std::vector<uint64_t>& limbs_lsb){
                    nil::marshalling::status_type status;
                    typename FieldType::integral_type res = nil::marshalling::pack<nil::marshalling::option::big_endian>(limbs_lsb, status);
                    return res;
                }

                template <typename value_type, typename integral_type>
                std::vector<std::uint64_t> unpack(value_type& value){
                    nil::marshalling::status_type status;
                    integral_type scalar_value = integral_type(value.data);
                    std::vector<bool> limbs_lsb1 = nil::marshalling::pack<nil::marshalling::option::big_endian>(scalar_value, status);
                    std::vector<std::uint64_t> limbs_lsb;
                    return limbs_lsb;
                }

                // template <typename value_type>
                // value_type pack(const std::vector<std::uint64_t>& limbs) {
                //     value_type res(0);
                //     value_type zero(0);
                //     auto x = zero.data;
                //     for (int i = 0; i < limbs.size(); ++i) {
                //         value_type smth(limbs[limbs.size() - 1 - i]);
                //         x = x << 64;
                //         x = x + smth.data;
                //     }
                //     res = value_type(x);
                //     return res;
                // }

                // template <typename value_type, typename integral_type>
                // std::vector<std::uint64_t> unpack(value_type elem) {
                //     std::vector<std::uint64_t> res;
                //     auto data = elem.data;
                //     for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                //         auto delta = data - ((data >> 64) << 64);
                //         res.push_back(static_cast<std::uint64_t>(integral_type(delta)));
                //         data = data >> 64;
                //     }
                //     return res;
                // }

                template <typename value_type>
                std::vector<bool> to_bits(value_type a) {
                    size_t size = 255;
                    std::vector<bool> bits(size, false);
                    auto integral_b = a.data;
                    for (size_t i = 0; i < size; ++i) {
                        bits[i] = multiprecision::bit_test(integral_b, i);
                    }
                    return bits;
                }

                template <typename value_type, typename InputIterator>
                value_type from_bits(InputIterator first, InputIterator last) {
                    value_type value;
                    for(auto iter = last - 1; iter >= first; --iter){
                        if((*iter) == true){
                            multiprecision::bit_set(value, iter - first);
                        }
                    }
                    return value;
                }
                template <typename CurveType>
                struct BaseSponge{
                    typedef typename CurveType::template g1_type<> group_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    using policy_type = nil::crypto3::hashes::detail::base_poseidon_policy<base_field_type, 2, 1, 7, 55, 0, true>;

                    typedef std::uint64_t limb_type;

                    typename nil::crypto3::hashes::detail::poseidon_sponge_construction<policy_type> sponge;
                    std::vector<limb_type> last_squeezed;

                };

                template <typename CurveType>
                struct DefaultFrSponge : public BaseSponge<CurveType> {
                    typedef typename BaseSponge<CurveType>::group_type group_type;
                    typedef typename BaseSponge<CurveType>::base_field_type base_field_type;
                    typedef typename BaseSponge<CurveType>::scalar_field_type scalar_field_type;
                    typedef typename BaseSponge<CurveType>::limb_type limb_type;

                    typename base_field_type::value_type squeeze(std::size_t num_limbs){
                        if(this->last_squeezed.size() >= num_limbs){
                            std::vector<limb_type> limbs(this->last_squeezed.begin(), this->last_squeezed.begin() + limbs);
                            std::vector<limb_type> remaining(this->last_squeezed.begin() + limbs, this->last_squeezed.end());
                            this->last_squeezed = remaining;
                            
                            return pack(limbs);
                        }
                        else{
                            auto sq = this->sponge.squeeze();
                            nil::marshalling::status_type status;
                            std::vector<limb_type> x = unpack<base_field_type::value_type, base_field_type::integral_type>(sq);

                            for(int i = 0; i < HIGH_ENTROPY_LIMBS; ++i){
                                this->last_squeezed.push_back(x[i]);
                            }

                            return squeeze(num_limbs);
                        }
                    }
                };

                template <typename CurveType>
                struct DefaultFqSponge : public BaseSponge<CurveType> {
                    typedef typename BaseSponge<CurveType>::group_type group_type;
                    typedef typename BaseSponge<CurveType>::base_field_type base_field_type;
                    typedef typename BaseSponge<CurveType>::scalar_field_type scalar_field_type;
                    typedef typename BaseSponge<CurveType>::limb_type limb_type;

                    std::vector<limb_type> squeeze_limbs(std::size_t num_limbs){
                        if(this->last_squeezed.size() >= num_limbs){
                            std::vector<limb_type> limbs(this->last_squeezed.begin(), this->last_squeezed.begin() + num_limbs);
                            std::vector<limb_type> remaining(this->last_squeezed.begin() + num_limbs, this->last_squeezed.end());
                            this->last_squeezed = remaining;
                            return limbs;
                        }
                        else{
                            auto sq = this->sponge.squeeze();
                            nil::marshalling::status_type status;

                            std::vector<limb_type> x = unpack<typename base_field_type::value_type, typename base_field_type::integral_type>(sq);

                            for(int i = 0; i < HIGH_ENTROPY_LIMBS; ++i){
                                this->last_squeezed.push_back(x[i]);
                            }

                            return squeeze_limbs(num_limbs);
                        }
                    }

                    typename base_field_type::value_type squeeze_field(){
                        this->last_squeezed.clear();
                        return this->sponge.squeeze();
                    }

                    typename scalar_field_type::value_type squeeze(std::size_t num_limbs){
                        auto limbs = this->squeeze_limbs(num_limbs);
                        nil::marshalling::status_type status;
                        typename scalar_field_type::value_type res = pack<typename scalar_field_type::value_type>(limbs);
                        return res;
                    }

                    void absorb_g(std::vector<typename group_type::value_type>& gs){
                        this->last_squeezed.clear();
                        for(auto &g : gs){
                            absorb_g(g);
                        }
                    }

                    void absorb_g(typename group_type::value_type& g){
                        if(this->last_squeezed.empty())
                            this->last_squeezed.clear();

                        this->sponge.absorb(g.X);
                        this->sponge.absorb(g.Y);
                    }

                    void absorb_fr(typename scalar_field_type::value_type& f){
                        if(this->last_squeezed.empty())
                            this->last_squeezed.clear();

                        if(scalar_field_type::modulus < base_field_type::modulus){
                            typename base_field_type::value_type casted_to_base_value = typename base_field_type::value_type(typename base_field_type::integral_type(f.data));
                            this->sponge.absorb(casted_to_base_value);
                        } else{
                            std::vector<bool> bits = to_bits(f);
                            typename base_field_type::integral_type low_bit = bits[0] ? 
                                    typename base_field_type::integral_type(1) : typename base_field_type::integral_type(0);
                            typename base_field_type::integral_type high_bits = from_bits<typename base_field_type::integral_type>(bits.begin() + 1, bits.end());    
                            typename base_field_type::value_type high_bits_field = typename base_field_type::value_type(high_bits);
                            typename base_field_type::value_type low_bit_field = typename base_field_type::value_type(low_bit);
                            this->sponge.absorb(high_bits_field);
                            this->sponge.absorb(low_bit_field);
                        }
                    }
                    void absorb_fr(const std::vector<typename scalar_field_type::value_type>& fs){
                        this->last_squeezed.clear();

                        for(auto f : fs){
                            absorb_fr(f);
                        }
                    }

                    typename scalar_field_type::value_type challenge() {
                        return this->squeeze(CHALLENGE_LENGTH_IN_LIMBS);
                    }

                    typename base_field_type::value_type challenge_fq() {
                        return this->squeeze_field();
                    }
                };
            }
        }
    }
}

#endif