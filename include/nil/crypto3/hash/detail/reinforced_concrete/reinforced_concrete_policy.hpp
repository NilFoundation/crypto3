#ifndef CRYPTO3_HASH_REINFORCED_CONCRETE_POLICY_HPP
#define CRYPTO3_HASH_REINFORCED_CONCRETE_POLICY_HPP

#include <array>
#include <type_traits>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template <typename FieldType>
                struct base_reinforced_concrete_policy{
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;
                    typedef typename element_type::integral_type integral_type;
                    constexpr static const std::size_t word_bits = field_type::modulus_bits;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = field_type::modulus_bits;
                    typedef element_type digest_type;

                    constexpr static const std::size_t block_words = 2;
                    constexpr static const std::size_t block_bits = block_words * field_type::modulus_bits;
                    typedef std::array<element_type, block_words> block_type;

                    constexpr static const std::size_t state_words = block_words + 1;
                    constexpr static const std::size_t state_bits = state_words * field_type::modulus_bits;
                    typedef std::array<element_type, state_words> state_type;

                    constexpr static const std::size_t part_rounds = 3;
                    constexpr static const std::size_t constant_ab_size = 2;
                    typedef std::array<element_type, constant_ab_size> alphas_type;
                    typedef std::array<element_type, constant_ab_size> betas_type;
                    
                };

                template <typename FieldType>
                struct reinforced_concrete_policy;

                template <>
                struct reinforced_concrete_policy<nil::crypto3::algebra::fields::bls12_fr<381> > : 
                  public base_reinforced_concrete_policy<nil::crypto3::algebra::fields::bls12_fr<381> > {
                    constexpr static const std::size_t bucket_size = 27;
                    typedef std::array<element_type, bucket_size> bucket_type;

                    constexpr static const alphas_type alphas = {element_type(integral_type(1ul)), element_type(integral_type(3ul))};
                    constexpr static const betas_type betas = {element_type(integral_type(2ul)), element_type(integral_type(4ul))};
                    constexpr static const std::size_t d = 5;
                    constexpr static const bucket_type bucket = {element_type(integral_type(693)), element_type(integral_type(696)), element_type(integral_type(694)), 
                                                                element_type(integral_type(668)), element_type(integral_type(679)), element_type(integral_type(695)), 
                                                                element_type(integral_type(691)), element_type(integral_type(693)), element_type(integral_type(700)), 
                                                                element_type(integral_type(688)), element_type(integral_type(700)), element_type(integral_type(694)), 
                                                                element_type(integral_type(701)), element_type(integral_type(694)), element_type(integral_type(699)), 
                                                                element_type(integral_type(701)), element_type(integral_type(701)), element_type(integral_type(701)), 
                                                                element_type(integral_type(695)), element_type(integral_type(698)), element_type(integral_type(697)), 
                                                                element_type(integral_type(703)), element_type(integral_type(702)), element_type(integral_type(691)), 
                                                                element_type(integral_type(688)), element_type(integral_type(703)), element_type(integral_type(679))};
                    constexpr static const element_type p_min = element_type(integral_type(659ul));
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_HASH_REINFORCED_CONCRETE_POLICY_HPP