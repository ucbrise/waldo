# dorydb

Install gRPC using instructions here: https://grpc.io/docs/languages/cpp/quickstart/

## Running benchmarks

Run `scripts/runExperiment.py` with the options for setup and/or running the experiment (provisioning and cleaning up new ec2 instances not fully ported from azure yet). Set the experiment config file at the top of `runExperiment.py`, and make sure that the experiment config file has the right IP addresses (using elastic IPs so this should be fine). After you've pulled and run `make` at the client and servers (this can be automated, just haven't fixed scripts for this yet), run `python runExperiment.py` at the coordinator. The output will be in `experiments/results` in the directory corresponding to the experiment and the particular time. See `processed_results.dat` for final benchmark numbers (look in `runExperiment.py` for how to parse), and you can see logs for individual runs in the directory for each parameter setting.

## Testing locally

To run locally, start server X as `./build/bin/query_server config/serverX.config`. Start the client with `./build/bin/bench config/client.config`. Alternatively, start the client with `./build/bin/correctness_tests` to run the correctness tests.
