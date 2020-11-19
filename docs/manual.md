# Manual # {#zk_manual}

@tableofcontents

## Proving knowledge of a hashed message 

Before you start proving knowledge of a hashed message you need to construct a sha2-256 
circuit on protoboard.

### Usage of SHA2-256 component


### Proving the knowledge

```
std::cout << "Starting generator" << std::endl;
typename r1cs_gg_ppzksnark<CurveType>::keypair_type keypair =
    r1cs_gg_ppzksnark<CurveType>::generator(example.constraint_system);

std::cout << "Starting prover" << std::endl;

typename r1cs_gg_ppzksnark<CurveType>::proof_type proof =
    r1cs_gg_ppzksnark<CurveType>::prover(keypair.pk, example.primary_input, example.auxiliary_input);

/*const bool ans =
    r1cs_gg_ppzksnark<CurveType, policies::r1cs_gg_ppzksnark_verifier_strong_input_consistency<CurveType>>::verifier(keypair.vk, example.primary_input, proof);*/

std::cout << "Starting verifier" << std::endl;

const bool ans =
    r1cs_gg_ppzksnark<CurveType>::verifier(keypair.vk, example.primary_input, proof);

std::cout << "Verifier finished, result: " << ans << std::endl;
```
