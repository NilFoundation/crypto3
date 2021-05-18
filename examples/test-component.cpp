#include <stdlib.h>
#include <iostream>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/policies/r1cs_gg_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/policies/r1cs_gg_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/policies/r1cs_gg_ppzksnark/verifier.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;
using namespace std;

int main(){
  // Initialize the curve parameters

  default_r1cs_ppzksnark_pp::init_public_params();


  using curve_type = curves::bls12<381>;
  using field_type = typename curve_type::scalar_field_type;
  
  // Create blueprint

  blueprint<field_type> bp;
  blueprint_variable<field_type> out;
  blueprint_variable<field_type> x;

  // Allocate variables

  out.allocate(bp);
  x.allocate(bp);

  // This sets up the blueprint variables
  // so that the first one (out) represents the public
  // input and the rest is private input

  bp.set_input_sizes(1);

  // Initialize gadget

  test_gadget<field_type> g(bp, out, x);
  g.generate_r1cs_constraints();
  
  // Add witness values

  bp.val(out) = 35;
  bp.val(x) = 3;

  g.generate_r1cs_witness();
  
  const r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

  const typename r1cs_gg_ppzksnark<curve_type>::keypair_type keypair = generate<r1cs_gg_ppzksnark<curve_type>>(constraint_system);

  const typename r1cs_gg_ppzksnark<curve_type>::proof_type proof = prove<r1cs_gg_ppzksnark<curve_type>>(keypair.pk, bp.primary_input(), bp.auxiliary_input());

  bool verified = verify<r1cs_gg_ppzksnark<curve_type>>(keypair.vk, bp.primary_input(), proof);

  std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
  std::cout << "Verification status: " << verified << std::endl;

  const typename r1cs_gg_ppzksnark<curve_type>::verification_key_type vk = keypair.vk;

  return 0;
}
