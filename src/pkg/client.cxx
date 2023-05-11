#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->DH_switched = true;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  // TODO: implement me!
  CryptoPP::SecByteBlock dh_shared_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = this->crypto_driver->AES_generate_key(dh_shared_key);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(dh_shared_key);
  this->DH_current_private_value = DH_private_value;
  this->DH_last_other_public_value = DH_other_public_value;
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // TODO: implement me!
  Message_Message msg;

  if(this->DH_switched) {
    this->DH_switched = false;
    std::tuple<DH, SecByteBlock, SecByteBlock> keys = this->crypto_driver->DH_initialize(this->DH_params);
    this->prepare_keys(std::get<0>(keys), std::get<1>(keys) , this->DH_last_other_public_value);
    this->DH_current_public_value = std::get<2>(keys);
  }
  std::pair<std::string, SecByteBlock> c_iv = this->crypto_driver->AES_encrypt(this->AES_key, plaintext);
  
  msg.iv = std::get<1>(c_iv);
  msg.ciphertext = std::get<0>(c_iv);
  msg.public_value = this->DH_current_public_value;
  msg.mac = this->crypto_driver->HMAC_generate(this->HMAC_key, concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext));
  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message ciphertext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  if(ciphertext.public_value != this->DH_last_other_public_value) {
    std::tuple<DH, SecByteBlock, SecByteBlock> keys = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_last_other_public_value = ciphertext.public_value;
    this->prepare_keys(std::get<0>(keys), this->DH_current_private_value, this->DH_last_other_public_value);
  }
  this->DH_switched = true;
  return std::make_pair<std::string, bool>(this->crypto_driver->AES_decrypt(this->AES_key, ciphertext.iv, ciphertext.ciphertext), this->crypto_driver->HMAC_verify(this->HMAC_key, concat_msg_fields(ciphertext.iv, ciphertext.public_value, ciphertext.ciphertext), ciphertext.mac));
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  // TODO: implement me!
  if(command == "listen") {
    std::vector<unsigned char> dh_params = this->network_driver->read();
    this->DH_params.deserialize(dh_params);
  } else if (command == "connect"){
    this->DH_params = this->crypto_driver->DH_generate_params();
    std::vector<unsigned char> dh_params;
    this->DH_params.serialize(dh_params);
    this->network_driver->send(dh_params);
  }

  std::tuple<DH, SecByteBlock, SecByteBlock> keys = this->crypto_driver->DH_initialize(this->DH_params);

  PublicValue_Message pvm;
  pvm.public_value = std::get<2>(keys);
  std::vector<unsigned char> pkey_to_send; 
  pvm.serialize(pkey_to_send);

  this->network_driver->send(pkey_to_send);

  std::vector<unsigned char> other_pkey = this->network_driver->read();
  pvm.deserialize(other_pkey);

  this->prepare_keys(std::get<0>(keys),std::get<1>(keys),pvm.public_value);
  this->DH_current_public_value = std::get<2>(keys);
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}