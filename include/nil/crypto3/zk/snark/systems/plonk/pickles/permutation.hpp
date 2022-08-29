#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_PERMUTATION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_PERMUTATION_HPP

#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                typename FieldType::value_type eval_vanishes_on_last_4_rows(math::basic_radix2_domain<FieldType>& domain, 
                            typename FieldType::value_type& x){
                    typename FieldType::value_type w4 = domain.get_domain_element(domain.size() - (kimchi_constant::ZK_ROWS + 1));
                    typename FieldType::value_type w3 = domain.omega * w4;
                    typename FieldType::value_type w2 = domain.omega * w3;
                    typename FieldType::value_type w1 = domain.omega * w2;

                    return (x - w1) * (x - w2) * (x - w3) * (x - w4);
                }
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
} 

#endif
