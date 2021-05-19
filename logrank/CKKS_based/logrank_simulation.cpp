//
// Created by Anat Samohi on 23/10/2020.
//

#include <exception>
#include <queue>
#include "../../../examples.h"
#include "client.h"
#include "logrank_simulation.h"
#include "creator_server.h"
#include "evaluator_server.h"
#include "serv_func.h"

using namespace std;
using namespace seal;

/*---Global Resources---*/

void Logrank_protocol_sim (int num_of_clients) {

    cout << " ------------------------------" << endl;
    cout << " ---START LOGRANK SIMULATION---" << endl;
    cout << " ------------------------------" << endl;

    /* ------------------------------------------ */
    /* --------------- OFFLINE PHASE -------------*/
    /* ------------------------------------------ */

    /*  enc_msg_q - represents a secure one-way channel between client and evaluation server.
     *  Must be secure in case the creator server is corrupted. Assume an HTTPS connection. */
    std::queue<Cipher_Msg> enc_msg_q;

    /*  decrypted_result_q - represents an unsecure one-way channel between decryption sever and clients.  */
    std::queue<Decrypted_Result> decrypted_result_q;

    /*  The scale sets the resolution of the real number. Each real number is transform to integer when encoded */
    const int scale_cost_param = 30;
    double scale = pow(2.0, scale_cost_param);

    /*  The context and the encoder are resources that are shared by all entities   */
    std::__1::shared_ptr<seal::SEALContext> context = create_context(scale_cost_param);
    std::shared_ptr<CKKSEncoder> encoder = create_encoder(context);

    /*  Init values - sample random numbers to be clients' inputs   */
    ClientsInput inputs[num_of_clients];
    sample_inputs_clients(inputs, num_of_clients);

    /*  Calculate the protocol correct output, for verification only  */
    double sigma_O = 0, sigma_E = 0, sigma_V = 0;
    for (int i=0; i<num_of_clients; i++)
    {
        sigma_O += inputs[i].O;
        sigma_E += inputs[i].E;
        sigma_V += inputs[i].V;
    }
    double trueResult =
        ((sigma_O - sigma_E) / sqrt(sigma_V));
    cout << " True value: " << trueResult << endl;

    /*  creator_server entity: the creator_server creates the keys and performs the decryption  */
    creator_server key_server(context, encoder, &decrypted_result_q);

    /*  evaluator_server entity: performs all the evaluation on the encrypted data
     *  relin keys are needed for the evaluation*/
    evaluator_server eval_server(context, key_server.get_relin_keys(), &enc_msg_q, scale);

    /* ------------------------------------------ */
    /* --------------- SETTING PHASE ------------ */
    /* ------------------------------------------ */

    /*  client entities: perform the experiment and wait for the decrypted output.
     *  In this simulation the experiment results are given to the object */
    client* clients[num_of_clients];
    for (int i=0; i<num_of_clients; i++)
    {
        clients[i] = new client(context, encoder, key_server.get_public_key(), &enc_msg_q, &decrypted_result_q, scale,
                                         inputs[i].O, inputs[i].E, inputs[i].V, inputs[i].r);
    }

    /* ------------------------------------------ */
    /* --------------- ONLINE PHASE --------------*/
    /* ------------------------------------------ */

    /*  0. setting the timer    */
    chrono::high_resolution_clock::time_point time_start = chrono::high_resolution_clock::now();

    /*  1. The clients encrypts their results and send over secure channel to the evaluator server  */
    for (int i=0; i<num_of_clients; i++)
    {
        clients[i]->get_encryped_msg();
    }

    /*  2. Evaluation over encrypted data   */
    Encrypted_Result encryptedResult = eval_server.evaluate();

    /*  3. Decryption   */
    key_server.decrypt_msg(encryptedResult);

    /*  4. The clients receive the output   */
    clients[0]->print_result();

    /*  5. Simulation verification  */
    verify_result(clients[2], trueResult);

    /*  6. Measure performance of the online phase */
    measure_test_time(time_start);

    /* delete */
    for (int i=0; i<num_of_clients; i++)
    {
        delete clients[i];
    }
}

void example_logrank_test()
{
    int num_of_clients = 0;
    cout << endl << "> type number of cliets: ";
    cin >> num_of_clients;
    /*  Run 10 times with random inputs   */
    for (int i=0; i<1; i++)
    {
        Logrank_protocol_sim(num_of_clients);
    }

    example_logrank_5_clients_test();
}


