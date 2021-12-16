# Waldo: A Private Time-Series Database from Function Secret Sharing

This implementation accompanies our paper by Emma Dauterman, Mayank Rathee, Raluca Ada Popa and Ion Stoica to appear at Oakland'22.

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

This prototype is released under the Apache v2 license (see [License](#license)).

## Setup

Install gRPC using the instructions [here](https://grpc.io/docs/languages/cpp/quickstart/).

Download the [Boost](https://www.boost.org/) library (version 1.76).

To install the dependencies to run benchmarking scripts, `cd scripts` and run `pip install -r requirements.txt`.

Note that the [libPSI](https://github.com/osu-crypto/libPSI) and [libOTe](https://github.com/osu-crypto/libOTe) libraries, which build on [cryptoTools](https://github.com/ladnir/cryptoTools/tree/master), are already included in `fss-core` and will build with the rest of the project.

## Building

Run
```
cd network
cmake .
make
cd ..
cmake .
make
```

## Running benchmarks

Run `scripts/runExperiment.py` with the options for setup ('-s') and/or running the experiment ('-r').

Set the experiment config file at the top of `runExperiment.py`, and make sure that the experiment config file has the right IP addresses.

After you've pulled and run `make` at the client and servers, run `python runExperiment.py` at the coordinator machine (machine running the experiments, not the client or servers).

The output will be in `experiments/results` in the directory corresponding to the experiment and the particular time. See `processed_results.dat` for final benchmark numbers (look in `runExperiment.py` for how to parse), and you can see logs for individual executions in the directory for each parameter setting.

## Testing locally

To run the entire system locally, start server X as `./build/bin/query_server config/serverX.config`. Start the client with `./build/bin/bench config/client.config`.
Alternatively, start the client with `./build/bin/correctness_tests` to run the correctness tests. Modify the parameters in the corresponding config files to run with different settings (e.g. number of cores, malicious security).
Make sure to start the servers within 10 seconds of each other and wait until each has printed "DONE WITH SETUP" before starting the client (this means initialization has completed).

The following unit tests can also be run locally:
```
./build/bin/AggTreeUnitTest
./build/bin/DCFTableICUnitTest
./build/bin/DCFTableParallelICUnitTest
./build/bin/DCFTableUnitTest
./build/bin/DCFTableParallelUnitTest
./build/bin/DCF_unit_test
./build/bin/DPFTableUnitTest
./build/bin/DPF_unit_test
```

## Limitations

The rollup functionality suggested as an extension for the WaldoTree construction in the
paper is not fully implemented. Also, the node values for WaldoTree are directly
returned without aggregating by the user-defined aggregation function.

## Acknowledgements

Thanks to Natacha Crooks and Vivian Fang for contributing to the framework used for the benchmarking in `scripts/`.
