//
// Created by Anat Samohi on 23/10/2020.
//

#include <exception>
#include <queue>
#include "../../examples.h"

using namespace std;
using namespace seal;

#include "serv_func.h"
#include "creator_server.h"
#include "client.h"
#include "evaluator_server.h"
#include "logrank_simulation.h"

/*---Global Resources---*/

/*  enc_msg_q - represents a secure one-way channel between client and evaluation server.
 *  Must be secure in case the creator server is corrupted. Assume an HTTPS connection. */
std::queue<Cipher_Msg> enc_msg_q;

/*  decrypted_result_q - represents an unsecure one-way channel between decryption sever and clients.  */
std::queue<Decrypted_Result> decrypted_result_q;

void Logrank_protocol_sim () {

    cout << " ------------------------------" << endl;
    cout << " ---START LOGRANK SIMULATION---" << endl;
    cout << " ------------------------------" << endl;

    /* ------------------------------------------ */
    /* --------------- OFFLINE PHASE -------------*/
    /* ------------------------------------------ */

    /*  The scale sets the resolution of the real number. Each real number is transform to integer when encoded */
    const int scale_cost_param = 30;
    double scale = pow(2.0, scale_cost_param);

    /*  The context and the encoder are resources that are shared by all entities   */
    std::__1::shared_ptr<seal::SEALContext> context = create_context(scale_cost_param);
    std::shared_ptr<CKKSEncoder> encoder = create_encoder(context);

    /*  Init values - sample random numbers to be clients' inputs   */
    Inputs inputs = sample_imputs();

    /*  Calculate the protocol correct output, for verification only  */
    double trueResult =
        (((inputs.O1 + inputs.O2 + inputs.O3) - (inputs.E1 + inputs.E2 + inputs.E3)) / sqrt(inputs.V1 + inputs.V2 + inputs.V3));
    cout << " True value: " << trueResult << endl;

    /*  creator_server entity: the creator_server creates the keys and performs the decryption  */
    creator_server key_server(context, encoder);

    /*  evaluator_server entity: performs all the evaluation on the encrypted data
     *  relin keys are needed for the evaluation*/
    evaluator_server eval_server(context, key_server.get_relin_keys(), scale);

    /* ------------------------------------------ */
    /* --------------- SETTING PHASE ------------ */
    /* ------------------------------------------ */

    /*  client entities: perform the experiment and wait for the decrypted output.
     *  In this simulation the experiment results are given to the object */
    client client1(context, encoder, key_server.get_public_key(), scale, inputs.O1, inputs.E1, inputs.V1, inputs.r1);
    client client2(context, encoder, key_server.get_public_key(), scale, inputs.O2, inputs.E2, inputs.V2, inputs.r2);
    client client3(context, encoder, key_server.get_public_key(), scale, inputs.O3, inputs.E3, inputs.V3, inputs.r3);

    /* ------------------------------------------ */
    /* --------------- ONLINE PHASE --------------*/
    /* ------------------------------------------ */

    /*  1. The clients encrypts their results and send over secure channel to the evaluator server  */
    client1.get_encryped_msg();
    client2.get_encryped_msg();
    client3.get_encryped_msg();

    /*  2. Evaluation over encrypted data   */
    Encrypted_Result encryptedResult = eval_server.evaluate();

    /*  3. Decryption   */
    key_server.decrypt_msg(encryptedResult);

    /*  4. The clients receive the output   */
    client1.print_result();
    client2.print_result();

    /*  5. Simulation verification  */
    double calculatedResult = client3.get_result();
    cout << "True result : " << trueResult << endl;
    if(std::abs ((double)(calculatedResult - trueResult)/calculatedResult) > 0.001)
    {
        cout << std::abs((double)(calculatedResult - trueResult)/calculatedResult) << endl;
        throw;
    }
}

void example_logrank_test()
{
    /*  Run 10 times with random inputs   */
    for (int i=0; i<50; i++)
    {
        Logrank_protocol_sim();
    }
}


