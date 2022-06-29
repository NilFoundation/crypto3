#ifndef CRYPTO3_ALGEBRA_FIELDS_FP64_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FP64_SCALAR_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/detail/literals.hpp>


namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<std::size_t Version>
                struct FP;

                template<>
                struct FP<64> : public fields::field<64>{
                    typedef field<64> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xFFFFFFFFFFFFFFC5_cppui64; // 18446744073709551557
                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus;
                    typedef nil::crypto3::multiprecision::number<
                        nil::crypto3::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename fields::detail::element_fp<fields::params<FP<64>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };
              }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif 