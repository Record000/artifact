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

**Generating Certificate Repositories with Diverse Structures**

Execute the `run_parallel_batch.sh` script. All results will be output to the `output` directory.


**Measuring Basic Block Counts during RPKI Validation across Different Structures**

Run the `repo_structure_mutator.py` script. The results will be exported to the `drcov_output` directory.