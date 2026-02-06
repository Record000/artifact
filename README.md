# RQ1: How effectively does structure mutation diversify validator execution behaviors and repository structures?

## 1. Launching the Experimental Environment

Initialize the Docker container for the experiment:

```shell
./docker-run.sh
```

## 2. Generating Certificate Repositories with Diverse Structures

We conducted a total of 5 experimental rounds. In each round, 1,000 certificate repositories were generated using 5 concurrent threads. A timeout of 60 seconds was enforced for the generation of each repository. The tree depth was configured to range from 1 to 100, and the branching factor (width) ranged from 1 to 2. All results were output to the `output` directory.

```shell
./run_parallel_batch.sh --runs 5 --threads 5 --num-repos 1000 --timeout 60 --depth-range 1 100 --branch-range 1 2 
```

## 3. Measuring Basic Block Counts during RPKI Validation across Different Structures

In this step, we generated certificate repositories with varying structures and gathered the basic block counts triggered during the validation process by the RPKI validator.

**Baseline Configuration:**
We generated 1,000 repository variants using 20 concurrent threads. The parameters were fixed at 100 ROAs, a maximum depth of 1, and a total of 10 CA nodes. The results were exported to the `drcov_output` directory with the filename prefix `baseline`.

```shell
python3 repo_structure_mutator.py --mode concurrent --roa-count 100 --min-depth 1 --max-depth 1 --min-ca 10 --max-ca 10 --num-variants 1000 --gen-threads 20 --experiment-csv drcov_output/baseline
```

**Experimental Group:**
We generated 1,000 repository variants using 20 concurrent threads. While maintaining a total of 100 ROAs, we varied the maximum depth between 1 and 100, and the total number of CA nodes between 1 and 100. The results were exported to the `drcov_output` directory with the filename prefix `100depth_100ca`.

```shell
python3 repo_structure_mutator.py --mode concurrent --roa-count 100 --min-depth 1 --max-depth 100 --min-ca 1 --max-ca 100 --num-variants 1000 --gen-threads 20 --experiment-csv drcov_output/100depth_100ca
```