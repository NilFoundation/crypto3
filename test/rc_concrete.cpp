#include "nil/crypto3/hash/reinforced_concrete.hpp"
#include "nil/crypto3/algebra/fields/bls12/scalar_field.hpp"
#include <iostream>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
// using namespace nil::crypto3::accumulators;

using rc_default_field_t = fields::bls12_fr<381>;


int main(){
    // std::flu
    using rc_functions_t = hashes::detail::reinforced_concrete_functions<rc_default_field_t>;
    using element_type = rc_functions_t::element_type;
    using integral_type = rc_functions_t::integral_type;
    using state_type = rc_functions_t::state_type;

    state_type temp_state = {element_type(integral_type(0)), element_type(integral_type(0)), element_type(integral_type(0))};
    rc_functions_t::permute(temp_state);
    std::cout << temp_state[0].data << ' ' << temp_state[1].data << ' ' << temp_state[2].data << '\n';
    // element_type a = element_type(integral_type(45));
    // element_type b = element_type(integral_type(10));

    // std::cout << a.data % b.data;
}