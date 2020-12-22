//
// Created by Anat Samohi on 23/10/2020.
//

#ifndef SEAL_CREATOR_SERVER_H
#define SEAL_CREATOR_SERVER_H

#include "../../../examples.h"
#include "client.h"
#include "serv_func.h"

class creator_server
{
private:
    std::shared_ptr<SEALContext> context;
    std::shared_ptr<CKKSEncoder> encoder;
    Decryptor* decryptor;

    /*  decrypted_result_q - represents an unsecure one-way channel between decryption sever and clients.  */
    std::queue<Decrypted_Result>* decrypted_result_q;

    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;

public:
    creator_server(std::shared_ptr<SEALContext> context_, std::shared_ptr<CKKSEncoder> encoder_,
                   std::queue<Decrypted_Result>* decrypted_result_q_)
    {
        context = context_;
        encoder = encoder_;
        decrypted_result_q = decrypted_result_q_;

        /*  Init the keys   */
        create_all_keys();

        /*  Create a Decryptor object.
         *  Decryptor object is used in the Online Phase of the protocol   */
        decryptor = new Decryptor(context, secret_key);
    }

    ~creator_server()
    {
        delete decryptor;
    }

    void create_all_keys()
    {
        KeyGenerator keygen(context);
        public_key = keygen.public_key();
        secret_key = keygen.secret_key();
        relin_keys = keygen.relin_keys_local();
    }

    PublicKey get_public_key()
    {
        return public_key;
    }

    RelinKeys get_relin_keys()
    {
        return relin_keys;
    }

    void decrypt_msg(Encrypted_Result encryptedResult)
    {
        /*  1. Decryption: */
        Plaintext D_plain;
        Plaintext U_plain;

        decryptor->decrypt(encryptedResult.D_encrypted, D_plain);
        decryptor->decrypt(encryptedResult.U_encrypted, U_plain);

        /*  2. Decode: */
        vector <double> D_result, U_result;
        encoder->decode(D_plain, D_result);
        encoder->decode(U_plain, U_result);

        /*  3. Print part of the decoded vectors, for sainety-check.
         *     All values in a vector should be equal  */
        print_vector(D_result, 3, 7);
        print_vector(U_result, 3, 7);

        /*  4. Copy one element, they are all the same... */
        double d = D_result[0];
        double u = U_result[0];

        Decrypted_Result result;
        result.D = d;
        result.U = u;

        /*  5. The creator server is responsible to empty the decrypted_result_q.
         *      For simplicity, we empty the queue at the just before pushing a new msg.
         *      After cleaning the queue, the server can use it to send the result to the clients */
        while(!decrypted_result_q->empty())
        {
            decrypted_result_q->pop();
        }

        decrypted_result_q->push(result);
    }
};

#endif // SEAL_CREATOR_SERVER_H
