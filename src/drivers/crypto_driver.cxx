#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params() {
  AutoSeededRandomPool prg;
  PrimeAndGenerator pgen;
  pgen.Generate(1, prg, 512, 511);

  Integer p = pgen.Prime();
  Integer q = pgen.SubPrime();
  Integer g = pgen.Generator();

  DHParams_Message message;
  message.p = p;
  message.q = q;
  message.g = g;

  return message;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params) {
  // TODO: implement me!
  AutoSeededRandomPool prng;
  DH DH_obj(DH_params.p, DH_params.q, DH_params.g);
  SecByteBlock sk(DH_obj.PrivateKeyLength()), pk(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, sk, pk);
  return std::make_tuple(DH_obj, sk, pk);
}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw a `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  // TODO: implement me!
  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  if(!DH_obj.Agree(shared_key,DH_private_value, DH_other_public_value))
	  throw std::runtime_error("Failed to reach shared secret");
  return shared_key;
}

/**
 * @brief Generates AES key using HKDR with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for AES using the provided
 * salt. See the `DeriveKey` function. (Use NULL for the "info" argument)
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // TODO: implement me!
  SecByteBlock aes_key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(aes_key, aes_key.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);
  return aes_key;
}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size AES::BLOCKSIZE
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * `AES_encryptor`.
 * 3) Return ciphertext and iv used in encryption or throw a
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // TODO: implement me!
    AutoSeededRandomPool prng;
    SecByteBlock iv(AES::BLOCKSIZE);

    CBC_Mode<AES>::Encryption enc;
    enc.GetNextIV(prng, iv);
    enc.SetKeyWithIV(key, key.size(), iv);
    std::string ciphertext;
    StringSource s(plaintext, true, 
          new StreamTransformationFilter(enc,
              new StringSink(ciphertext)
          ) // StreamTransformationFilter
      ); // StringSource
      return std::make_pair(ciphertext, iv);

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using SetKeyWithIV on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using `AES_decryptor`.
 * 3) Return the plaintext or throw a `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    // TODO: implement me!
    CBC_Mode<AES>::Decryption dec;
    std::string plaintext;

    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(dec,
            new StringSink(plaintext)
        ) // StreamTransformationFilter
    ); // StringSource
    return plaintext;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!
  SecByteBlock hmac_key(SHA256::BLOCKSIZE);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(hmac_key, hmac_key.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);
  return hmac_key;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    // TODO: implement me!
    HMAC<SHA256> hmac(key, key.size());
    std::string mac;
    StringSource ss2(ciphertext, true, 
        new HashFilter(hmac,
            new StringSink(mac)
        ) // HashFilter      
    ); // StringSource
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the message through a `HashVerificationFilter` to verify the HMAC.
 * 3) Return false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  // TODO: implement me!
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true, 
          new HashVerificationFilter(hmac, NULL, flags)
      ); // StringSource
    return true;
  } catch (const CryptoPP::Exception &e) {
    return false;
  }
}

/*
 * With public key pk, encrypt m.
 */
std::pair<Integer, Integer>
CryptoDriver::EG_encrypt(Integer pk, Integer m, std::optional<Integer> rand) {
  Integer y;
  if (rand.has_value()) {
    y = rand.value();
  } else {
    AutoSeededRandomPool rng;
    y = Integer(rng, Integer::One(), DL_P);
  }
  Integer c1 = a_exp_b_mod_c(DL_G, y, DL_P);
  Integer c2 = m * a_exp_b_mod_c(pk, y, DL_P);
  return std::make_pair(c1, c2);
}

/*
 * With private key sk, decrypt (c1, c2)
 */
Integer CryptoDriver::EG_decrypt(Integer sk, std::pair<Integer, Integer> c) {
  Integer m;
  Integer c1 = c.first;
  Integer c2 = c.second;
  m = (c2 * EuclideanMultiplicativeInverse(a_exp_b_mod_c(c1, sk, DL_P), DL_P)) % DL_P;
  return m;
}

/**
 * @brief Generates a pair of El Gamal keys. This function should:
 * 1) Generate a random `a` value using an CryptoPP::AutoSeededRandomPool
 * 2) Exponentiate the base DL_G to get the public value, 
 *    then return (private key, public key)
 */
std::pair<Integer, Integer> CryptoDriver::EG_generate() {
  AutoSeededRandomPool rng;
  Integer sk = Integer(rng, Integer::Zero(), DL_P - 1);
  Integer pk = a_exp_b_mod_c(DL_G, sk, DL_P);
  return std::make_pair(sk, pk);
}

/**
 * @brief Generates a SHA-256 hash of msg.
 */
std::string CryptoDriver::hash(std::string msg) {
  SHA256 hash;
  std::string encodedHex;
  HexEncoder encoder(new StringSink(encodedHex));

  // Compute hash
  StringSource(msg, true, new HashFilter(hash, new StringSink(encodedHex)));
  return encodedHex;
}

// Kyber implementation modified to work with ElGamal
// from https://cryptosith.org/papers/kyber-20170627.pdf

void CryptoDriver::split_hash_three(std::string h, SecByteBlock &i1, SecByteBlock &i2, SecByteBlock &i3) {
  int sublen = h.length()/3;
  i1 = string_to_byteblock(h.substr(0, sublen));
  i2 = string_to_byteblock(h.substr(sublen, sublen*2));
  i2 = string_to_byteblock(h.substr(sublen*2, sublen*3));
}

std::pair<std::tuple<SecByteBlock, SecByteBlock, SecByteBlock>, SecByteBlock> CryptoDriver::encaps(SecByteBlock pk) {
  AutoSeededRandomPool rng;
  SecByteBlock m_bytes(256/8); // 256 bits
  rng.GenerateBlock(m_bytes, m_bytes.size());
  std::string pk_str = byteblock_to_string(pk);
  std::string m_str = byteblock_to_string(m_bytes);
  std::string Khrd = hash(pk_str + m_str); // 256 bits
  SecByteBlock K_hat;
  SecByteBlock r;
  SecByteBlock d;
  split_hash_three(Khrd, K_hat, r, d);
  std::string K_hat_str = byteblock_to_string(K_hat);
  std::pair<Integer, Integer> uv = EG_encrypt(byteblock_to_integer(pk),
                                byteblock_to_integer(m_bytes),
                                std::optional<Integer>{byteblock_to_integer(r)});
  std::tuple<SecByteBlock, SecByteBlock, SecByteBlock> c = std::make_tuple(
    integer_to_byteblock(uv.first),
    integer_to_byteblock(uv.second),
    d
  );
  std::string c_str = byteblock_to_string(std::get<0>(c)) +
                        byteblock_to_string(std::get<1>(c)) +
                        byteblock_to_string(std::get<2>(c));
  std::string K_str = hash(K_hat_str + c_str);
  SecByteBlock K = string_to_byteblock(K_str);
  return std::make_pair(c, K);
}