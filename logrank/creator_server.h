//
// Created by Anat Samohi on 23/10/2020.
//

#ifndef SEAL_CREATOR_SERVER_H
#define SEAL_CREATOR_SERVER_H

#include "../../examples.h"
#include "client.h"
#include "serv_func.h"

extern std::queue<Decrypted_Result> decrypted_result_q;

class creator_server
{
private:
    std::shared_ptr<SEALContext> context;
    std::shared_ptr<CKKSEncoder> encoder;
    Decryptor* decryptor;

    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;

public:
    creator_server(std::shared_ptr<SEALContext> context_, std::shared_ptr<CKKSEncoder> encoder_)
    {
        context = context_;
        encoder = encoder_;
        create_all_keys();
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
        /*
        Decrypt, decode, and print the result.
        */
        Plaintext D_plain;
        Plaintext U_plain;

        decryptor->decrypt(encryptedResult.D_encrypted, D_plain);
        decryptor->decrypt(encryptedResult.U_encrypted, U_plain);
        vector <double> D_result, U_result;
        encoder->decode(D_plain, D_result);
        encoder->decode(U_plain, U_result);

        print_vector(D_result, 3, 7);
        print_vector(U_result, 3, 7);
        double d, u;
        d=D_result[0];
        u=U_result[0];

        //Clean queue and put the msg there:
        while(!decrypted_result_q.empty())
        {
            decrypted_result_q.pop();
        }
        Decrypted_Result result;
        result.D = d;
        result.U = u;

        decrypted_result_q.push(result);
    }
};

#endif // SEAL_CREATOR_SERVER_H
