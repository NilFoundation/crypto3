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
using namespace std;

int main(){
  // Initialize the curve parameters

  default_r1cs_ppzksnark_pp::init_public_params();

  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
  
  // Create blueprint

  blueprint<FieldT> bp;
  blueprint_variable<FieldT> out;
  blueprint_variable<FieldT> x;

  // Allocate variables

  out.allocate(bp);
  x.allocate(bp);

  // This sets up the blueprint variables
  // so that the first one (out) represents the public
  // input and the rest is private input

  bp.set_input_sizes(1);

  // Initialize gadget

  test_gadget<FieldT> g(bp, out, x);
  g.generate_r1cs_constraints();
  
  // Add witness values

  bp.val(out) = 35;
  bp.val(x) = 3;

  g.generate_r1cs_witness();
  
  const r1cs_constraint_system<FieldT> constraint_system = bp.get_constraint_system();

  const typename r1cs_gg_ppzksnark<bls12<381>>::keypair_type keypair = generate<r1cs_gg_ppzksnark<bls12<381>>>(constraint_system);

  const typename r1cs_gg_ppzksnark<bls12<381>>::proof_type proof = prove<r1cs_gg_ppzksnark<bls12<381>>>(keypair.pk, bp.primary_input(), bp.auxiliary_input());

  bool verified = verify<r1cs_gg_ppzksnark<bls12<381>>>(keypair.vk, bp.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << bp.primary_input() << endl;
  cout << "Auxiliary (private) input: " << bp.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  const typename r1cs_gg_ppzksnark<bls12<381>>::verification_key_type vk = keypair.vk;

  return 0;
}
