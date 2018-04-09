#ifndef PASSWORD_CIRCUIT_HPP_
#define PASSWORD_CIRCUIT_HPP_
#include <iostream>
#include <string>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.tcc>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

using namespace libsnark;

template<typename ppT>
class Password_Circuit {
  public:
    Password_Circuit();
    r1cs_gg_ppzksnark_keypair<ppT> get_keypair();
    r1cs_gg_ppzksnark_proof<ppT> generate_proof(libff::bit_vector& password_v, libff::bit_vector& salt_v, libff::bit_vector& hash_v);
    bool verify_proof(r1cs_gg_ppzksnark_proof<ppT>& password, libff::bit_vector& hash_v);
  private:
    protoboard<libff::Fr<ppT>> pb;
    r1cs_gg_ppzksnark_keypair<ppT> keypair;
    digest_variable<libff::Fr<ppT>> hash_out;
    digest_variable<libff::Fr<ppT>> salt;
    digest_variable<libff::Fr<ppT>> password;
    sha256_two_to_one_hash_gadget<libff::Fr<ppT>> hash_func;
};

template<typename ppT>
Password_Circuit<ppT>::Password_Circuit(): 
  pb(),
  keypair(),
  hash_out(pb, SHA256_digest_size, "out"),
  salt(pb, SHA256_digest_size, "salt"), 
  password(pb, SHA256_digest_size, "password"), 
  hash_func(pb, password, salt, hash_out, "hashF") {
    pb.set_input_sizes(SHA256_digest_size);
    hash_func.generate_r1cs_constraints();
    r1cs_gg_ppzksnark_keypair<ppT> tmp = r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
    keypair.pk = tmp.pk;
    keypair.vk = tmp.vk;
}

template<typename ppT> 
r1cs_gg_ppzksnark_keypair<ppT> Password_Circuit<ppT>::get_keypair() {
  return keypair;
}

template<typename ppT> 
r1cs_gg_ppzksnark_proof<ppT> Password_Circuit<ppT>::generate_proof(libff::bit_vector& password_v, libff::bit_vector& salt_v, libff::bit_vector& hash_v) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  hash_out.generate_r1cs_witness(hash_v);
  password.generate_r1cs_witness(password_v);
  salt.generate_r1cs_witness(salt_v);
  hash_func.generate_r1cs_witness();
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();
  return r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppT> 
bool Password_Circuit<ppT>::verify_proof(r1cs_gg_ppzksnark_proof<ppT>& password_salt_proof, libff::bit_vector& hash_v) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
  hash_out.generate_r1cs_witness(hash_v);
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  return r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, prim_input, password_salt_proof);
}
#endif
