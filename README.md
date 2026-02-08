# README

## Launching the Experimental Environment

Download the RPKI validator source packages and the DynamoRIO installation package into the `tmp` directory located at the project root.
```shell
mkdir tmp && cd tmp
wget https://github.com/NLnetLabs/routinator/archive/refs/tags/v0.15.1.tar.gz
wget https://github.com/cloudflare/cfrpki/archive/refs/tags/v1.5.10.tar.gz
wget https://github.com/rpki-client/rpki-client-portable/releases/download/9.6/rpki-client-9.6.tar.gz
wget https://github.com/NICMx/FORT-validator/releases/download/1.6.7/fort-1.6.7.tar.gz
wget https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.90.20482/DynamoRIO-Linux-11.90.20482.tar.gz
wget https://go.dev/dl/go1.25.7.linux-amd64.tar.gz
cd ..
```

Create the local cache and output directories for the RPKI validators.
```shell
mkdir -p rp_cache/{fort_cache,octorpki_cache,routinator_cache,rpki-client_cache,rpki-client_output}
```

Initialize the Docker container for the experiment:

```shell
./docker-run.sh
```

## RQ1 Effectiveness of CFG-guided Mutation

**Generating Repositories with Diverse Structures**

Execute the `run_parallel_batch.sh` script. All results will be output to the `output` directory.


**Measuring Basic Block Counts during RPKI Validation across Different Structures**

Run the `repo_structure_mutator.py` script. The results will be exported to the `drcov_output` directory.

## RQ2 Effectiveness of Dependency Repair

**Measuring Multi-stage Pass Rates before and after Mutation Repair**

Run the `mutation/test_coverage.py` script to calculate the pass rates across multiple validation stages.

## RQ3 Efficiency of Grammar-Guided and Dependency Repair Mutator

**Measuring Validator Parsing Latency**

Execute the `mutation/main.py` script to record the time required by different RPKI validators to parse the repositories.

**Measuring repositories Generation Time under Different Threading**

Run the `mutation/test_mutate_times_3.py` script to measure repositories generation time under different multi-threading configurations.

