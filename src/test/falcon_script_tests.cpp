// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <script/interpreter.h>
#include <script/script.h>
#include <key.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <falcon/falcon.h>
#include <chrono>
#include <iostream>

BOOST_FIXTURE_TEST_SUITE(falcon_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(falcon_p2wpkh_verify)
{
    // Use Falcon-512 (logn = 9)
    constexpr unsigned logn = 9;
    constexpr size_t FALCON_PUBKEY_SIZE = FALCON_PUBKEY_SIZE(logn);
    constexpr size_t FALCON_PRIVKEY_SIZE = FALCON_PRIVKEY_SIZE(logn);
    constexpr size_t FALCON_SIG_COMPRESSED_MAXSIZE = FALCON_SIG_COMPRESSED_MAXSIZE(logn);
    constexpr size_t FALCON_TMPSIZE_KEYGEN = FALCON_TMPSIZE_KEYGEN(logn);
    constexpr size_t FALCON_TMPSIZE_SIGNDYN = FALCON_TMPSIZE_SIGNDYN(logn);

    // FALCON KEYPAIR GENERATION
    std::vector<unsigned char> falcon_pubkey(FALCON_PUBKEY_SIZE);
    std::vector<unsigned char> falcon_privkey(FALCON_PRIVKEY_SIZE);
    std::vector<unsigned char> tmp_keygen(FALCON_TMPSIZE_KEYGEN);
    // Falcon needs a SHAKE256 context for randomness
    shake256_context rng;
    int ret = shake256_init_prng_from_system(&rng);
    BOOST_CHECK_EQUAL(ret, 0);
    ret = falcon_keygen_make(
        &rng, logn,
        falcon_privkey.data(), falcon_privkey.size(),
        falcon_pubkey.data(), falcon_pubkey.size(),
        tmp_keygen.data(), tmp_keygen.size()
    );
    BOOST_CHECK_EQUAL(ret, 0);

    // FALCON TRANSACTION HASH SIGNING (from signature scheme, message is the transaction hash)

	// building dummy transaction context
	// classic P2PKH script template..
	// this will be added as scriptCode to the transaction by VerifyWitnessProgram function
	CScript scriptCode = CScript() << OP_DUP << OP_HASH160 << ToByteVector(Hash160(falcon_pubkey)) << OP_EQUALVERIFY << OP_CHECKSIG;
	unsigned int nIn = 0;	// input index
	int32_t nHashType = SIGHASH_ALL; // hash type
	SigVersion sigversion = SigVersion::WITNESS_V0;
	const CAmount& amount = 0;
	SigHashCache m_sighash_cache;
	CMutableTransaction dummyTx;
	dummyTx.vin.push_back(CTxIn()); // adding at least one input to the dummy transaction (see nIn assertion in SignatureHash function)
	PrecomputedTransactionData txdata(dummyTx);
	GenericTransactionSignatureChecker<CMutableTransaction> checker(&dummyTx, nIn, amount, txdata, MissingDataBehavior::FAIL);
	ScriptError serror;

	// hashing the dummy transaction
	uint256 sighash = SignatureHash(scriptCode, dummyTx, nIn, nHashType, amount, sigversion, &txdata, &m_sighash_cache);

	// computing signature over the transaction hash
	std::vector<unsigned char> falcon_sig(FALCON_SIG_COMPRESSED_MAXSIZE);
    size_t siglen = falcon_sig.size();
    std::vector<unsigned char> tmp_sig(FALCON_TMPSIZE_SIGNDYN);
    // New randomness for signing
    shake256_context rng2;
    ret = shake256_init_prng_from_system(&rng2);
    BOOST_CHECK_EQUAL(ret, 0);
    ret = falcon_sign_dyn(
        &rng2,
        falcon_sig.data(), &siglen, FALCON_SIG_COMPRESSED,
        falcon_privkey.data(), falcon_privkey.size(),
        sighash.begin(), sizeof(uint256),
        tmp_sig.data(), tmp_sig.size()
    );
    BOOST_CHECK_EQUAL(ret, 0);
    falcon_sig.resize(siglen);
    // Append SIGHASH_ALL byte to the end of the signature
	// This is to comply with bitcoin convention of having the hash type as a byte at the end of the signature
    falcon_sig.push_back(SIGHASH_ALL);
	// Build the scriptPubKey for P2WPKH AKA To who I want to pay
	CScript scriptPubKey = CScript() << OP_0 << ToByteVector(Hash160(falcon_pubkey));
	// Construct the witness stack: [signature] [pubkey]
    CScriptWitness witness;
    witness.stack.push_back(falcon_sig);
    witness.stack.push_back(falcon_pubkey);
    // Empty scriptSig for P2WPKH
    CScript scriptSig;
    // Set script flags to enable Falcon
    script_verify_flags flags = (script_verify_flags)(SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_FALCON);
	
	
	// VERIFY THE SIGNATURE VIA SCRIPT INTERPRETER
	// THIS IS GOING TO RUN THE FALCON SIGNATURE VERIFICATION PATH
    bool verified = VerifyScript(scriptSig, scriptPubKey, &witness, flags, checker, &serror);
    BOOST_CHECK(verified);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);

    // Print Falcon public key size
    std::cout << "Falcon pubkey size: " << falcon_pubkey.size() << std::endl;

    // Print Falcon signature size
    std::cout << "Falcon signature size: " << falcon_sig.size() << std::endl;

    // Measure time for VerifyScript
    auto start = std::chrono::high_resolution_clock::now();
    verified = VerifyScript(scriptSig, scriptPubKey, &witness, flags, checker, &serror);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "VerifyScript (Falcon) time: " << duration_us << " us" << std::endl;

    BOOST_CHECK(verified);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(ecdsa_p2wpkh_verify)
{
    // ECDSA keypair generation
    CKey ecdsa_privkey;
    ecdsa_privkey.MakeNewKey(true); // compressed
    CPubKey ecdsa_pubkey = ecdsa_privkey.GetPubKey();

    // Print public key size
    std::cout << "ECDSA pubkey size: " << ecdsa_pubkey.size() << std::endl;

    // Build dummy transaction context
    CScript scriptCode = CScript() << OP_DUP << OP_HASH160 << ToByteVector(Hash160(ecdsa_pubkey)) << OP_EQUALVERIFY << OP_CHECKSIG;
    unsigned int nIn = 0;
    int32_t nHashType = SIGHASH_ALL;
    SigVersion sigversion = SigVersion::WITNESS_V0;
    const CAmount& amount = 0;
    SigHashCache m_sighash_cache;
    CMutableTransaction dummyTx;
    dummyTx.vin.push_back(CTxIn());
    PrecomputedTransactionData txdata(dummyTx);
    GenericTransactionSignatureChecker<CMutableTransaction> checker(&dummyTx, nIn, amount, txdata, MissingDataBehavior::FAIL);
    ScriptError serror;

    // Hash the dummy transaction
    uint256 sighash = SignatureHash(scriptCode, dummyTx, nIn, nHashType, amount, sigversion, &txdata, &m_sighash_cache);

    // Sign the transaction hash
    std::vector<unsigned char> ecdsa_sig;
    ecdsa_privkey.Sign(sighash, ecdsa_sig);
    ecdsa_sig.push_back(SIGHASH_ALL);

    // Print signature size
    std::cout << "ECDSA signature size: " << ecdsa_sig.size() << std::endl;

    // Build scriptPubKey for P2WPKH
    CScript scriptPubKey = CScript() << OP_0 << ToByteVector(Hash160(ecdsa_pubkey));
    // Construct the witness stack: [signature] [pubkey]
    CScriptWitness witness;
    witness.stack.push_back(ecdsa_sig);
    witness.stack.push_back(ToByteVector(ecdsa_pubkey));
    // Empty scriptSig for P2WPKH
    CScript scriptSig;
    // Set script flags to enable ECDSA
    script_verify_flags flags = (script_verify_flags)(SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);

    // Measure time for VerifyScript
    auto start = std::chrono::high_resolution_clock::now();
    bool verified = VerifyScript(scriptSig, scriptPubKey, &witness, flags, checker, &serror);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "VerifyScript (ECDSA) time: " << duration_us << " us" << std::endl;

    BOOST_CHECK(verified);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
