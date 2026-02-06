#!/usr/bin/env python3
"""
Run batch_diversity_generator.py in parallel and aggregate statistics

Usage:
    python run_parallel_batch.py --runs 5 --threads 3 --num-repos 1000 --depth-range 1 100 --branch-range 1 2 --timeout 60
"""

import os
import sys
import json
import argparse
import subprocess
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


class ParallelBatchRunner:
    """Multi-threaded batch executor"""

    def __init__(self, args):
        self.args = args
        self.results: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.start_time = time.time()

    def _get_command(self, run_id: int) -> List[str]:
        """Build command line"""
        # Get the script's directory to build correct path to batch_diversity_generator.py
        script_dir = Path(__file__).parent
        generator_path = script_dir / "batch_diversity_generator.py"

        cmd = [
            "python3", str(generator_path),
            "--num-repos", str(self.args.num_repos),
            "--timeout", str(self.args.timeout),
            "--depth-range", str(self.args.depth_range[0]), str(self.args.depth_range[1]),
            "--branch-range", str(self.args.branch_range[0]), str(self.args.branch_range[1]),
            "--seed", str(self.args.seed + run_id),  # Use different seed for each run
        ]

        # Add optional parameters
        if self.args.tree_types:
            cmd.extend(["--tree-types"] + self.args.tree_types)

        if self.args.roa_range:
            cmd.extend(["--roa-range", str(self.args.roa_range[0]), str(self.args.roa_range[1])])

        # Create independent output directory for each run
        output_dir = f"{self.args.output_dir}/run_{run_id:03d}"
        cmd.extend(["--output-dir", output_dir])

        if self.args.keep_repos:
            cmd.append("--keep-repos")

        if self.args.quiet:
            cmd.append("--quiet")

        return cmd

    def _run_single_batch(self, run_id: int) -> Tuple[int, bool, Dict[str, Any]]:
        """Execute a single batch run"""
        cmd = self._get_command(run_id)
        output_dir = f"{self.args.output_dir}/run_{run_id:03d}"

        print(f"\n[Run {run_id + 1}/{self.args.runs}] Starting...")
        print(f"  Output directory: {output_dir}")
        sys.stdout.flush()

        start = time.time()

        try:
            # Use Popen to display output in real-time
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Print output in real-time
            for line in process.stdout:
                print(line, end='', flush=True)

            # Wait for process to complete
            return_code = process.wait(timeout=self.args.run_timeout)
            elapsed = time.time() - start

            if return_code != 0:
                print(f"\n  [FAILED] Return code: {return_code}")
                return run_id, False, {"error": f"Return code: {return_code}", "elapsed": elapsed}

            print(f"\n  [DONE] Elapsed: {elapsed:.1f}s")
            sys.stdout.flush()

            # Read generated JSON summary file
            summary_file = None
            output_path = Path(output_dir)
            if output_path.exists():
                # Find the latest summary file
                summary_files = list(output_path.glob("diversity_summary_*.json"))
                if summary_files:
                    summary_file = max(summary_files, key=os.path.getctime)

            if not summary_file:
                return run_id, False, {"error": "Summary file not found", "elapsed": elapsed}

            with open(summary_file, 'r', encoding='utf-8') as f:
                summary_data = json.load(f)

            summary_data["elapsed"] = elapsed
            return run_id, True, summary_data

        except subprocess.TimeoutExpired:
            print(f"  [TIMEOUT] Execution exceeded {self.args.run_timeout} seconds")
            process.kill()
            return run_id, False, {"error": "Execution timeout", "elapsed": time.time() - start}
        except Exception as e:
            print(f"  [ERROR] {str(e)}")
            return run_id, False, {"error": str(e), "elapsed": time.time() - start}

    def run_all(self):
        """Execute all batches"""
        print(f"\n{'='*70}")
        print(f"Parallel Batch Execution Configuration")
        print(f"{'='*70}")
        print(f"Total runs:        {self.args.runs}")
        print(f"Threads:           {self.args.threads}")
        print(f"Repos per batch:   {self.args.num_repos}")
        print(f"Parameter range:   depth={self.args.depth_range}, branch={self.args.branch_range}")
        print(f"Timeout:           {self.args.timeout}s/repo, {self.args.run_timeout}s/batch")
        print(f"Output directory:  {self.args.output_dir}")
        print(f"{'='*70}\n")

        os.makedirs(self.args.output_dir, exist_ok=True)

        success_count = 0
        fail_count = 0

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            # Submit all tasks
            future_to_run = {
                executor.submit(self._run_single_batch, run_id): run_id
                for run_id in range(self.args.runs)
            }

            # Process completed tasks
            for future in as_completed(future_to_run):
                run_id = future_to_run[future]
                try:
                    rid, success, data = future.result()

                    with self.lock:
                        if success:
                            self.results.append(data)
                            success_count += 1
                        else:
                            fail_count += 1

                        # Progress display
                        total_done = success_count + fail_count
                        elapsed_total = time.time() - self.start_time
                        avg_time = elapsed_total / total_done
                        remaining = self.args.runs - total_done
                        eta = avg_time * remaining

                        print(f"\n[PROGRESS] Success: {success_count}, Failed: {fail_count}/{self.args.runs} | "
                              f"ETA: {eta:.0f}s")

                except Exception as e:
                    print(f"[Run {run_id}] Error processing result: {e}")
                    fail_count += 1

        total_elapsed = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"All batch runs completed!")
        print(f"Total elapsed: {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
        print(f"Success: {success_count}/{self.args.runs}, Failed: {fail_count}/{self.args.runs}")
        print(f"{'='*70}\n")

    def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate statistics from all batches"""
        if not self.results:
            print("No successful batches to aggregate")
            return {}

        print("Aggregating statistics...")

        # List of metrics to aggregate
        metrics_to_aggregate = [
            "depth", "num_ca", "max_branch", "leaf_count",
            "num_roa", "num_mft", "num_crl", "num_cert",
        ]

        aggregated = {
            "num_runs": len(self.results),
            "total_repos": sum(r.get("total_repos", 0) for r in self.results),
            "total_failures": sum(r.get("total_failures", 0) for r in self.results),
            "total_timeouts": sum(r.get("total_timeouts", 0) for r in self.results),
            "total_generation_time_sec": sum(r.get("total_generation_time_sec", 0) for r in self.results),
            "runs_data": self.results,  # Save original data
        }

        # Calculate cross-batch statistics for each metric
        for metric in metrics_to_aggregate:
            values = []
            for r in self.results:
                mean_val = r.get(f"{metric}_mean", 0)
                if mean_val:
                    values.append(mean_val)

            if values:
                aggregated[f"{metric}_mean_across_runs"] = sum(values) / len(values)
                aggregated[f"{metric}_min_across_runs"] = min(values)
                aggregated[f"{metric}_max_across_runs"] = max(values)

                # Calculate standard deviation
                mean_val = sum(values) / len(values)
                variance = sum((v - mean_val) ** 2 for v in values) / len(values)
                aggregated[f"{metric}_std_across_runs"] = variance ** 0.5

        return aggregated

    def save_aggregated_results(self, aggregated: Dict[str, Any]):
        """Save aggregated results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(self.args.output_dir)

        # Save JSON summary
        summary_file = output_path / f"aggregated_summary_{timestamp}.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated, f, indent=2, ensure_ascii=False)

        # Save CSV (cross-batch statistics)
        csv_file = output_path / f"aggregated_summary_{timestamp}.csv"
        self._save_aggregated_csv(aggregated, csv_file)

        print(f"\nAggregated results saved:")
        print(f"  JSON: {summary_file}")
        print(f"  CSV:  {csv_file}")

    def _save_aggregated_csv(self, aggregated: Dict[str, Any], filepath):
        """Save aggregated statistics to CSV"""
        import csv

        metrics = [
            "depth", "num_ca", "max_branch", "leaf_count",
            "num_roa", "num_mft", "num_crl", "num_cert",
        ]

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Min Across Runs", "Max Across Runs",
                           "Mean Across Runs", "Std Across Runs"])

            for metric in metrics:
                writer.writerow([
                    metric,
                    aggregated.get(f"{metric}_min_across_runs", "N/A"),
                    aggregated.get(f"{metric}_max_across_runs", "N/A"),
                    aggregated.get(f"{metric}_mean_across_runs", "N/A"),
                    aggregated.get(f"{metric}_std_across_runs", "N/A"),
                ])

    def print_aggregated_report(self, aggregated: Dict[str, Any]):
        """Print aggregated report"""
        if not aggregated:
            return

        print(f"\n{'='*70}")
        print("Cross-Batch Aggregated Statistics Report")
        print(f"{'='*70}")
        print(f"Successful batches:   {aggregated['num_runs']}")
        print(f"Total repos:          {aggregated['total_repos']}")
        print(f"Total failures:       {aggregated['total_failures']} (timeouts: {aggregated['total_timeouts']})")
        print(f"Total generation time: {aggregated['total_generation_time_sec']:.1f}s")

        if aggregated['total_repos'] > 0:
            print(f"Average time:         {aggregated['total_generation_time_sec']/aggregated['total_repos']:.2f}s/repo")
        print()

        metrics = ["depth", "num_ca", "max_branch", "leaf_count", "num_roa", "num_mft", "num_crl", "num_cert"]

        print("Cross-Batch Metric Statistics (based on batch means):")
        print("-" * 70)
        print(f"{'Metric':<12} {'Min':<12} {'Max':<12} {'Mean':<12} {'Std Dev':<12}")
        print("-" * 70)

        for metric in metrics:
            print(f"{metric:<12} "
                  f"{aggregated.get(f'{metric}_min_across_runs', 0):<12.2f} "
                  f"{aggregated.get(f'{metric}_max_across_runs', 0):<12.2f} "
                  f"{aggregated.get(f'{metric}_mean_across_runs', 0):<12.2f} "
                  f"{aggregated.get(f'{metric}_std_across_runs', 0):<12.2f}")
        print("-" * 70)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Run batch_diversity_generator.py in parallel and aggregate statistics",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Execution control parameters
    parser.add_argument("--runs", type=int, default=5,
                       help="Number of batch runs (default: 5)")
    parser.add_argument("--threads", type=int, default=3,
                       help="Number of parallel threads (default: 3)")
    parser.add_argument("--run-timeout", type=int, default=7200,
                       help="Timeout per batch run in seconds, default 7200 (2 hours)")

    # Parameters passed to batch_diversity_generator.py
    parser.add_argument("--num-repos", type=int, default=1000,
                       help="Number of repos per batch (default: 1000)")
    parser.add_argument("--timeout", type=int, default=60,
                       help="Timeout per repo in seconds (default: 60)")
    parser.add_argument("--depth-range", type=int, nargs=2, default=[1, 100],
                       help="Depth range (default: 1 100)")
    parser.add_argument("--branch-range", type=int, nargs=2, default=[1, 2],
                       help="Branch range (default: 1 2)")
    parser.add_argument("--tree-types", type=str, nargs="+",
                       default=["full", "random", "sparse"],
                       help="Tree types (default: full random sparse)")
    parser.add_argument("--roa-range", type=int, nargs=2, default=None,
                       help="ROA count range (optional)")
    parser.add_argument("--seed", type=int, default=42,
                       help="Random seed base value (default: 42)")

    # Output control
    parser.add_argument("--output-dir", type=str, default="output",
                       help="Output directory (default: output)")
    parser.add_argument("--keep-repos", action="store_true",
                       help="Keep repository files")
    parser.add_argument("--quiet", action="store_true",
                       help="Quiet mode")

    args = parser.parse_args()

    runner = ParallelBatchRunner(args)
    runner.run_all()

    aggregated = runner.aggregate_results()
    if aggregated:
        runner.save_aggregated_results(aggregated)
        runner.print_aggregated_report(aggregated)


if __name__ == "__main__":
    main()
