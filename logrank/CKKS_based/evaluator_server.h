//
// Created by Anat Samohi on 24/10/2020.
//

#ifndef SEAL_EVALUATOR_SERVER_H
#define SEAL_EVALUATOR_SERVER_H

#include <queue>
#include "../../../examples.h"
#include "serv_func.h"

class evaluator_server
{
private:
    RelinKeys relin_keys;
    std::shared_ptr<SEALContext> context;
    Evaluator* evaluator;
    double scale;

    /*  enc_msg_q - represents a secure one-way channel between client and evaluation server.
     *  Must be secure in case the creator server is corrupted. Assume an HTTPS connection. */
    std::queue<Cipher_Msg>* enc_msg_q;

public:
    evaluator_server(std::shared_ptr<SEALContext> context_, RelinKeys relin_keys_,
                     std::queue<Cipher_Msg>* enc_msg_q_, double scale_)
    {
        relin_keys = relin_keys_;
        context = context_;
        scale = scale_;
        enc_msg_q = enc_msg_q_;

        /*  Create a Evaluator object.
         *  Evaluator object is used in the Online Phase of the protocol   */
        evaluator = new Evaluator(context);
    }
    ~evaluator_server()
    {
        delete evaluator;
    }

    Encrypted_Result evaluate_with_random()
    {
        /*  Read all the cipher msgs from all clients.
         *  We assume that when this method is called all the clients already put their msgs in the queue  */
        vector<Cipher_Msg> msg_vec;
        while(!enc_msg_q->empty())
        {
            msg_vec.push_back(enc_msg_q->front());
            enc_msg_q->pop();
        }

        /*  Reorder the cipher elements  */
        Basic_Vectors basicVectors = create_basic_vectors(msg_vec);

        /*  Compute R  */
        Ciphertext sigma_r_encrypted;
        calculate_R(*evaluator, basicVectors, sigma_r_encrypted);

        /*  Compute T0  */
        Ciphertext sigma_T0_encrypted;
        calculate_T0(*evaluator, basicVectors, sigma_T0_encrypted);

        /*  Compute T1  */
        Ciphertext sigma_T1_encrypted;
        calculate_T1(*evaluator, basicVectors, sigma_T1_encrypted);

        /*  Compute D = T0 x R  . Then relinearize and rescale. */
        Encrypted_Result output;
        multiply_relinearize_and_rescale(*evaluator, sigma_T0_encrypted, sigma_r_encrypted,
                                                   output.D_encrypted, "D", relin_keys);

        /*  Compute R x R . Then relinearize and rescale.  */
        Ciphertext R_sq_encrypted;
        square_relinearize_and_rescale(*evaluator, sigma_r_encrypted,
                                                 R_sq_encrypted, "R", relin_keys);

        /*  Now R_sq_encrypted is at a different level than sigma_T1_encrypted, which prevents us
            from multiplying them to compute U = T1*R*R.    */

        print_line(__LINE__);
        cout << "Parameters used by all three terms are different." << endl;
        cout << "    + Modulus chain index for sigma_T1_encrypted: "
             << context->get_context_data(sigma_T1_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Modulus chain index for R_sq_encrypted: "
             << context->get_context_data(R_sq_encrypted.parms_id())->chain_index() << endl;
        cout << "    + R_sq_encrypted::save_size: "
             << R_sq_encrypted.save_size() << endl;
        cout << "    + sigma_T1_encrypted::save_size: "
             << sigma_T1_encrypted.save_size() << endl;
        cout << endl;

        /*  We could simply switch sigma_T1_encrypted to the next parameters in the modulus switching chain.
            However, we need to make sure the scale are the same for both of them (they both are very close to 30,
            but not exactly 30). So we align the scale by  using the SEAL function .scale() */

        print_line(__LINE__);
        cout << "Normalize scales to 2^30." << endl;
        sigma_T1_encrypted.scale() = scale;
        R_sq_encrypted.scale() = scale;
        cout << "    + R_sq_encrypted::save_size: "
             << R_sq_encrypted.save_size() << endl;

        /*  " We still have a problem with mismatching encryption parameters. This is easy
            to fix by using traditional modulus switching (no rescaling). CKKS supports
            modulus switching just like the BFV scheme, allowing us to switch away parts
            of the coefficient modulus when it is simply not needed. " (SEAL comment)   */

        print_line(__LINE__);
        cout << "Normalize encryption parameters to the lowest level." << endl;
        parms_id_type last_parms_id = R_sq_encrypted.parms_id();
        evaluator->mod_switch_to_inplace(sigma_T1_encrypted, last_parms_id);

        /*  Now, when the scale and the Modulus chain index are equal for  sigma_T1_encrypted
         *  and R_sq_encrypted, we can multiply them. */
        print_line(__LINE__);
        cout << "Compute and rescale U = T1*R*R." << endl;
        multiply_relinearize_and_rescale(*evaluator, sigma_T1_encrypted, R_sq_encrypted,
                                                   output.U_encrypted, "U", relin_keys);

        /*  Now D and U are ready. However, there is a problem:
            the encryption parameters used by D and U are different due to modulus switching from rescaling.

            Before decryption we want to align the scales and the encryption parameters (parms_id) match,
            to avoid unexpected consequences.   */

        last_parms_id = output.U_encrypted.parms_id();
        evaluator->mod_switch_to_inplace(output.D_encrypted, last_parms_id);

        cout << endl;
        print_line(__LINE__);
        cout << "Parameters used by all three terms are different." << endl;
        cout << "    + Modulus chain index for D_encrypted: "
             << context->get_context_data(output.D_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Modulus chain index for U_encrypted: "
             << context->get_context_data(output.U_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Exact scale in D_encrypted: " << output.D_encrypted.scale() << endl;
        cout << "    + Exact scale in  U_encrypted: " << output.U_encrypted.scale() << endl;
        cout << endl;

        return output;
    }

    Encrypted_Result evaluate()
    {
        /*  Read all the cipher msgs from all clients.
         *  We assume that when this method is called all the clients already put their msgs in the queue  */
        vector<Cipher_Msg> msg_vec;
        while(!enc_msg_q->empty())
        {
            msg_vec.push_back(enc_msg_q->front());
            enc_msg_q->pop();
        }

        /*  Reorder the cipher elements  */
        Basic_Vectors basicVectors = create_basic_vectors(msg_vec);

        Encrypted_Result output;

        /*  Compute T0  */
        Ciphertext sigma_T0_encrypted;
        calculate_T0(*evaluator, basicVectors, output.D_encrypted);

        /*  Compute T1  */
        Ciphertext sigma_T1_encrypted;
        calculate_T1(*evaluator, basicVectors, output.U_encrypted);

        cout << endl;
        print_line(__LINE__);
        cout << "Parameters used by all three terms are different." << endl;
        cout << "    + Modulus chain index for D_encrypted: "
             << context->get_context_data(output.D_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Modulus chain index for U_encrypted: "
             << context->get_context_data(output.U_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Exact scale in D_encrypted: " << output.D_encrypted.scale() << endl;
        cout << "    + Exact scale in  U_encrypted: " << output.U_encrypted.scale() << endl;
        cout << endl;

        std::ofstream outfile;
        outfile.open("fatut.txt",std::ofstream::binary);
        streampos begin,end;

        /* begin - the position of the write ptr in the file before the write */
        begin = outfile.tellp();

        output.U_encrypted.save(outfile); //366,219
        output.D_encrypted.save(outfile);
        //cipher.enc_r.save(outfile);

        /* end - the position of the write ptr in the file before the write */
        end = outfile.tellp();
        cout << "encrypted result size is: " << (end-begin) << " bytes.\n"; // The size is ~1.1M

        return output;
    }

};
#endif // SEAL_EVALUATOR_SERVER_H
