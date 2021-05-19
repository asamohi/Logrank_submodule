//
// Created by Anat Samohi on 24/10/2020.
//

#ifndef SEAL_CLIENT_H
#define SEAL_CLIENT_H

#include <queue>
#include <tgmath.h>
#include "../../../examples.h"
#include "serv_func.h"

struct Client_Input
{
    double O;
    double E;
    double V;
    double r;
};

class client
{
private:
    std::shared_ptr<SEALContext> context;
    std::shared_ptr<CKKSEncoder> encoder;
    Encryptor* encryptor;
    PublicKey public_key;
    double scale;
    Client_Input input;

    /*  enc_msg_q - represents a secure one-way channel between client and evaluation server.
     *  Must be secure in case the creator server is corrupted. Assume an HTTPS connection. */
    std::queue<Cipher_Msg>* enc_msg_q;

    /*  decrypted_result_q - represents an unsecure one-way channel between decryption sever and clients.  */
    std::queue<Decrypted_Result>* decrypted_result_q;


public:
    client(std::shared_ptr<SEALContext> context_, std::shared_ptr<CKKSEncoder> encoder_, PublicKey public_key,
           std::queue<Cipher_Msg>* enc_msg_q_, std::queue<Decrypted_Result>* decrypted_result_q_,
           double scale_, double O, double E, double V, double r)
    {
        context = context_;
        encoder = encoder_;
        scale = scale_;
        encryptor = new Encryptor(context, public_key);

        enc_msg_q = enc_msg_q_;
        decrypted_result_q = decrypted_result_q_;

        /*  Get the experiment results which are the input: */
        input.E = E;
        input.O = O;
        input.V = V;
        input.r = r;
    }

    void get_encryped_msg()
    {
        /*  The client encodes the input    */
        Plaintext plain_O_minus_E, plain_V, plain_r;
        encoder->encode((input.O - input.E), scale, plain_O_minus_E);
        encoder->encode(input.V, scale, plain_V);

        /*  The client uses the public key to encrypt the input into a cipher msg   */
        Cipher_Msg cipher;
        encryptor->encrypt(plain_O_minus_E, cipher.enc_O_minus_E);
        encryptor->encrypt(plain_V, cipher.enc_V);
        //encryptor->encrypt(plain_r, cipher.enc_r);

        /* Put the ciphertext objects in exteral files - for future use
         * The file path: /SEAL/bin/fatut.txt */

        std::ofstream outfile;
        outfile.open("fatut.txt",std::ofstream::binary);
        streampos begin,end;

        /* begin - the position of the write ptr in the file before the write */
        begin = outfile.tellp();

        cipher.enc_O_minus_E.save(outfile); //366,219
        cipher.enc_V.save(outfile);
        //cipher.enc_r.save(outfile);

        /* end - the position of the write ptr in the file before the write */
        end = outfile.tellp();
        cout << "ecryoted inputs size is: " << (end-begin) << " bytes.\n"; // The size is ~1.1M


        /*  The client uses the channel to send the cipher msg to the evaluation server  */
        enc_msg_q->push(cipher);
    }

    void print_result()
    {
        /*  Print the calculated Z */
        Decrypted_Result decryptedResult = decrypted_result_q->front();
        cout << "U=" << decryptedResult.U << " D=" << decryptedResult.D << endl;
        cout << "The calculated Z is : " << (decryptedResult.D / sqrt(decryptedResult.U)) << endl;
    }

    double get_result()
    {
        /*  Return the calculated Z */
        Decrypted_Result decryptedResult = decrypted_result_q->front();
        return(decryptedResult.D / sqrt(decryptedResult.U));
    }
};

#endif // SEAL_CLIENT_H
