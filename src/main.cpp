#include <libff/common/default_types/ec_pp.hpp>
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include "password-circuit.hpp"

using namespace libsnark;


template<typename ppT>
bool run_password_circuit() {

  libff::bit_vector password_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
  libff::bit_vector salt_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
  libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

  libff::print_header("R1CS GG-ppzkSNARK Generator");
  Password_Circuit<ppT> password_circuit;
  r1cs_gg_ppzksnark_keypair<ppT> keypair = password_circuit.get_keypair();
  printf("\n"); libff::print_indent(); libff::print_mem("after generator");

  libff::print_header("R1CS GG-ppzkSNARK Prover");
  r1cs_gg_ppzksnark_proof<ppT> proof = password_circuit.generate_proof(password_bv, salt_bv, hash_bv);
  printf("\n"); libff::print_indent(); libff::print_mem("after prover");

  libff::print_header("R1CS GG-ppzkSNARK Verifier");
  const bool ans = password_circuit.verify_proof(proof, hash_bv);
  printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
  printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
  return ans;
}

int main () {
  default_r1cs_gg_ppzksnark_pp::init_public_params();
  run_password_circuit<default_r1cs_gg_ppzksnark_pp>();
  return 0;
}
