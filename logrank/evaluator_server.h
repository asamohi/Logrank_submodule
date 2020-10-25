//
// Created by Anat Samohi on 24/10/2020.
//

#ifndef SEAL_EVALUATOR_SERVER_H
#define SEAL_EVALUATOR_SERVER_H

#include <queue>
#include "../../examples.h"
#include "serv_func.h"

extern std::queue<Cipher_Msg> enc_msg_q;

class evaluator_server
{
private:
    RelinKeys relin_keys;
    std::shared_ptr<SEALContext> context;
    Evaluator* evaluator;
    double scale;


public:
    evaluator_server(std::shared_ptr<SEALContext> context_, RelinKeys relin_keys_, double scale_)
    {
        relin_keys = relin_keys_;
        context = context_;
        scale = scale_;
        evaluator = new Evaluator(context);
    }
    ~evaluator_server()
    {
        delete evaluator;
    }

    Encrypted_Result evaluate()
    {
        vector<Cipher_Msg> msg_vec;
        while(!enc_msg_q.empty())
        {
            msg_vec.push_back(enc_msg_q.front());
            enc_msg_q.pop();
        }

        //Arage the msgs in vectors:
        Basic_Vectors basicVectors = create_basic_vectors(msg_vec);

        /*
        To compute R scale has now grown to 2^30+3 ?....
        */
        Ciphertext sigma_r_encrypted;
        calculate_R(*evaluator, basicVectors, sigma_r_encrypted);

        /*
        To compute T0 scale has now grown to 2^30 + log(3)?....
        */
        Ciphertext sigma_T0_encrypted;
        calculate_T0(*evaluator, basicVectors, sigma_T0_encrypted);

        /*
        To compute T1 scale has now grown to 2^30 + log(3)?....
        */
        Ciphertext sigma_T1_encrypted;
        calculate_T1(*evaluator, basicVectors, sigma_T1_encrypted);

        /*
        Compute D = T0 * R  and relinearize and rescale
        */
        Encrypted_Result output;
        calculate_multiply_relinearize_and_rescale(*evaluator, sigma_T0_encrypted, sigma_r_encrypted,
                                                   output.D_encrypted, "D", relin_keys);

        /*
        Compute R * R  and relinearize and rescale
        */
        Ciphertext R_sq_encrypted;
        calculate_square_relinearize_and_rescale(*evaluator, sigma_r_encrypted,
                                                 R_sq_encrypted, "R", relin_keys);


        /*
        Now R_sq_encrypted is at a different level than sigma_T1_encrypted, which prevents us
        from multiplying them to compute U = T1*R*R. We could simply switch sigma_T1_encrypted to
        the next parameters in the modulus switching chain. However, since we still
        need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
        first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
        PI*x and rescale it back from scale 2^60 to something close to 2^30.
        */

        print_line(__LINE__);
        cout << "Parameters used by all three terms are different." << endl;
        cout << "    + Modulus chain index for sigma_T1_encrypted: "
             << context->get_context_data(sigma_T1_encrypted.parms_id())->chain_index() << endl;
        cout << "    + Modulus chain index for R_sq_encrypted: "
             << context->get_context_data(R_sq_encrypted.parms_id())->chain_index() << endl;
        cout << endl;

        print_line(__LINE__);
        cout << "Normalize scales to 2^30." << endl;

        //here we saw we don;t
        sigma_T1_encrypted.scale() = scale;
        R_sq_encrypted.scale() = scale;

        /*
        We still have a problem with mismatching encryption parameters. This is easy
        to fix by using traditional modulus switching (no rescaling). CKKS supports
        modulus switching just like the BFV scheme, allowing us to switch away parts
        of the coefficient modulus when it is simply not needed.
        */
        print_line(__LINE__);
        cout << "Normalize encryption parameters to the lowest level." << endl;
        parms_id_type last_parms_id = R_sq_encrypted.parms_id();
        evaluator->mod_switch_to_inplace(sigma_T1_encrypted, last_parms_id);

        print_line(__LINE__);
        cout << "Compute and rescale U = T1*R*R." << endl;

        calculate_multiply_relinearize_and_rescale(*evaluator, sigma_T1_encrypted, R_sq_encrypted,
                                                   output.U_encrypted, "U", relin_keys);

        /*
        Now we would hope to compute the sum of all three terms. However, there is
        a serious problem: the encryption parameters used by all three terms are
        different due to modulus switching from rescaling.

        Encrypted addition and subtraction require that the scales of the inputs are
        the same, and also that the encryption parameters (parms_id) match. If there
        is a mismatch, Evaluator will throw an exception.
        */

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

};
#endif // SEAL_EVALUATOR_SERVER_H
