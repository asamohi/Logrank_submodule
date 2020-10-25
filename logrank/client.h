//
// Created by Anat Samohi on 24/10/2020.
//

#ifndef SEAL_CLIENT_H
#define SEAL_CLIENT_H

#include <queue>
#include "../../examples.h"
#include "serv_func.h"

extern std::queue<Cipher_Msg> enc_msg_q;
extern std::queue<Decrypted_Result> decrypted_result_q;

class client
{
private:
    std::shared_ptr<SEALContext> context;
    std::shared_ptr<CKKSEncoder> encoder;
    Encryptor* encryptor;
    PublicKey public_key;
    double scale;

public:
    client(std::shared_ptr<SEALContext> context_, std::shared_ptr<CKKSEncoder> encoder_, PublicKey public_key, double scale_)
    {
        context = context_;
        encoder = encoder_;
        scale = scale_;
        encryptor = new Encryptor(context, public_key);
    }

    void get_encryped_msg(double O, double E, double V, double r)
    {
        Plaintext plain_O_minus_E, plain_V, plain_r;
        encoder->encode(O - E, scale, plain_O_minus_E);
        encoder->encode(V, scale, plain_V);
        encoder->encode(r, scale, plain_r);

        Cipher_Msg cipher;

        encryptor->encrypt(plain_O_minus_E, cipher.enc_O_minus_E);
        encryptor->encrypt(plain_V, cipher.enc_V);
        encryptor->encrypt(plain_r, cipher.enc_r);

        enc_msg_q.push(cipher);
    }

    void print_result()
    {
        Decrypted_Result decryptedResult = decrypted_result_q.front();
        cout << "U=" << decryptedResult.U << " D=" << decryptedResult.D << endl;
        cout << "The calculated result is : " << (decryptedResult.D / sqrt(decryptedResult.U)) << endl;
    }
    double get_result()
    {
        Decrypted_Result decryptedResult = decrypted_result_q.front();
        return(decryptedResult.D / sqrt(decryptedResult.U));
    }
};

#endif // SEAL_CLIENT_H
