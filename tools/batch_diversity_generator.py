#!/usr/bin/env python3
"""
RPKI Certificate Repository Batch Generation and Diversity Statistics Tool

Features:
1. Batch generate RPKI certificate repositories with random structures
2. Collect diversity metrics for each repository
3. Output statistical reports (CSV format)
4. Support timeout control to ensure target number of successful generations

Usage:
    python batch_diversity_generator.py --num-repos 1000
    python batch_diversity_generator.py --num-repos 100 --timeout 30
    python batch_diversity_generator.py --num-repos 50 --keep-repos --output-dir my_batch
"""

import os
import sys
import csv
import json
import time
import shutil
import random
import argparse
import tempfile
import multiprocessing
import traceback
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime

# Import existing modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.cfg_generator import GeneratorConfig, RPKICFGGenerator
from tools.visualize_repo import DirectRepoScanner


# ============================================================================
# Configuration Classes
# ============================================================================

@dataclass
class BatchConfig:
    """Simplified configuration for batch generation"""

    # ===== Structure range parameters =====
    depth_range: Tuple[int, int] = (1, 5)
    branch_range: Tuple[int, int] = (1, 4)
    tree_types: List[str] = field(default_factory=lambda: ["full", "random", "sparse"])
    roa_range: Tuple[int, int] = (1, 3)

    # ===== Batch control parameters =====
    num_repos: int = 1000
    """Target number of successfully generated repositories"""

    seed_base: int = 42

    timeout: int = 60
    """Timeout in seconds for each repository generation"""

    # ===== Output control parameters =====
    output_dir: str = "batch_output"
    keep_repos: bool = False
    repos_subdir: str = "repos"

    # ===== Performance parameters =====
    reuse_keys: bool = True
    key_size: int = 2048

    def __post_init__(self):
        """Validate configuration parameters"""
        if self.depth_range[0] < 1:
            self.depth_range = (1, self.depth_range[1])
        if self.depth_range[0] > self.depth_range[1]:
            self.depth_range = (self.depth_range[1], self.depth_range[1])

        if self.branch_range[0] < 1:
            self.branch_range = (1, self.branch_range[1])
        if self.branch_range[0] > self.branch_range[1]:
            self.branch_range = (self.branch_range[1], self.branch_range[1])

        if self.roa_range[0] < 0:
            self.roa_range = (0, self.roa_range[1])
        if self.roa_range[0] > self.roa_range[1]:
            self.roa_range = (self.roa_range[1], self.roa_range[1])

        valid_types = {"full", "random", "sparse", "skeleton"}
        self.tree_types = [t for t in self.tree_types if t in valid_types]
        if not self.tree_types:
            self.tree_types = ["full"]

        if self.timeout <= 0:
            self.timeout = 60

    def sample_structure_params(self, seed: int) -> Dict[str, Any]:
        """Randomly sample a set of structure parameters based on seed"""
        rng = random.Random(seed)

        depth = rng.randint(self.depth_range[0], self.depth_range[1])
        max_branch = rng.randint(self.branch_range[0], self.branch_range[1])
        min_branch = rng.randint(1, max_branch)  # min_branch <= max_branch
        tree_type = rng.choice(self.tree_types)
        num_roa = rng.randint(self.roa_range[0], self.roa_range[1])

        return {
            "depth": depth,
            "max_branch": max_branch,
            "min_branch": min_branch,
            "tree_type": tree_type,
            "num_roa": num_roa,
            "seed": seed
        }


# ============================================================================
# Statistics Aggregator
# ============================================================================

class StatisticsAggregator:
    """Diversity metrics aggregator"""

    METRICS = [
        "depth", "num_ca", "max_branch", "leaf_count",
        "num_roa", "num_mft", "num_crl", "num_cert",
    ]

    INPUT_PARAMS = [
        "input_depth", "input_max_branch", "input_min_branch",
        "input_tree_type", "input_num_roa", "input_seed",
    ]

    def __init__(self):
        self.records: List[Dict[str, Any]] = []
        self.failures: int = 0
        self.timeouts: int = 0

    def add_record(self, repo_index: int, input_params: Dict[str, Any], stats: Dict[str, Any],
                   generation_time: float) -> None:
        """Add a successful record"""
        record: Dict[str, Any] = {
            "repo_index": repo_index,
            "generation_time_sec": round(generation_time, 3),
            "input_depth": input_params.get("depth"),
            "input_max_branch": input_params.get("max_branch"),
            "input_min_branch": input_params.get("min_branch"),
            "input_tree_type": input_params.get("tree_type"),
            "input_num_roa": input_params.get("num_roa"),
            "input_seed": input_params.get("seed"),
        }

        # Add statistical metrics
        for k in self.METRICS:
            record[k] = stats.get(k, 0)

        self.records.append(record)

    def add_failure(self, is_timeout: bool = False):
        """Record a failure"""
        self.failures += 1
        if is_timeout:
            self.timeouts += 1

    def get_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics"""
        if not self.records:
            return {
                "total_repos": 0,
                "total_failures": self.failures,
                "total_timeouts": self.timeouts
            }

        summary = {
            "total_repos": len(self.records),
            "total_failures": self.failures,
            "total_timeouts": self.timeouts,
            "total_generation_time_sec": sum(r["generation_time_sec"] for r in self.records),
        }

        for metric in self.METRICS:
            values = [r[metric] for r in self.records]
            n = len(values)
            mean_val = sum(values) / n
            variance = sum((v - mean_val) ** 2 for v in values) / n
            std_val = variance ** 0.5

            summary[f"{metric}_min"] = min(values)
            summary[f"{metric}_max"] = max(values)
            summary[f"{metric}_mean"] = round(mean_val, 2)
            summary[f"{metric}_std"] = round(std_val, 2)

        return summary

    def get_distribution(self, metric: str) -> Dict[int, int]:
        """Get metric distribution"""
        if metric not in self.METRICS:
            return {}
        dist: Dict[int, int] = {}
        for r in self.records:
            val = r[metric]
            dist[val] = dist.get(val, 0) + 1
        return dict(sorted(dist.items()))

    def save_csv(self, filepath: str) -> None:
        """Save detailed records to CSV"""
        if not self.records:
            return
        fieldnames = ["repo_index", "generation_time_sec"] + self.INPUT_PARAMS + self.METRICS
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.records)

    def save_summary(self, filepath: str) -> None:
        """Save summary statistics to JSON"""
        summary = self.get_summary()
        summary["distributions"] = {}
        for metric in self.METRICS:
            summary["distributions"][metric] = self.get_distribution(metric)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)


# ============================================================================
# Batch Generator
# ============================================================================

def _generate_safe_wrapper(config_kwargs: Dict, result_dict: Dict):
    """
    Subprocess worker function to run generation.
    Must be top-level for pickling support on some platforms.
    """
    try:
        # Reconstruct config
        config = GeneratorConfig(**config_kwargs)
        generator = RPKICFGGenerator(config)
        generator.generate()
        result_dict['success'] = True
    except Exception as e:
        result_dict['success'] = False
        result_dict['error'] = str(e)
        # traceback.print_exc() # Optional: print for debugging

class BatchGenerator:
    """Batch repository generator"""

    def __init__(self, config: BatchConfig):
        self.config = config
        self.aggregator = StatisticsAggregator()
        self._temp_dir: Optional[str] = None

    def _get_repo_dir(self, index: int) -> str:
        """Get output directory for a repository"""
        if self.config.keep_repos:
            return os.path.join(
                self.config.output_dir,
                self.config.repos_subdir,
                f"repo_{index:05d}"
            )
        else:
            if self._temp_dir is None:
                self._temp_dir = tempfile.mkdtemp(prefix="rpki_batch_")
            return os.path.join(self._temp_dir, f"repo_{index}")

    def generate_single_with_timeout(self, index: int, attempt_seed: int) -> Tuple[bool, Dict, Dict, float]:
        """
        Generate a single repository with timeout control

        Returns:
            (success, params, stats, generation_time)
        """
        params = self.config.sample_structure_params(attempt_seed)
        repo_dir = self._get_repo_dir(index)

        # Prepare kwargs for subprocess
        gen_config_kwargs = {
            'depth': params["depth"],
            'max_branch': params["max_branch"],
            'min_branch': params["min_branch"],
            'tree_type': params["tree_type"],
            'random_seed': attempt_seed,
            'num_roa': params["num_roa"],
            'num_mft': 1,
            'num_crl': 1,
            'reuse_keys': self.config.reuse_keys,
            'key_size': self.config.key_size,
            'output_dir': repo_dir,
            'clean_output': True
        }

        print(f"\n[{index + 1}/{self.config.num_repos}] Starting generation (Seed: {attempt_seed})")
        print(f"  Config: depth={params['depth']}, branch={params['max_branch']}, type={params['tree_type']}")

        start_time = time.time()

        # Use multiprocessing to implement timeout
        manager = multiprocessing.Manager()
        result_dict = manager.dict()

        p = multiprocessing.Process(
            target=_generate_safe_wrapper,
            args=(gen_config_kwargs, result_dict)
        )
        p.start()
        p.join(self.config.timeout)

        success = False
        generation_time: float = 0.0
        if p.is_alive():
            print(f"  [TIMEOUT] Generation exceeded {self.config.timeout}s, terminating...")
            p.terminate()
            p.join()
            self.aggregator.add_failure(is_timeout=True)
            generation_time = float(self.config.timeout)
        else:
            if result_dict.get('success', False):
                success = True
                generation_time = time.time() - start_time
            else:
                print(f"  [FAILED] Generation error: {result_dict.get('error', 'Unknown')}")
                self.aggregator.add_failure(is_timeout=False)
                generation_time = time.time() - start_time

        results = {}
        if success:
            try:
                # Collect statistics
                cache_dir = os.path.join(repo_dir, "cache", "localhost", "repo")
                scanner = DirectRepoScanner(cache_dir)
                results = scanner.scan()

                print(f"  [SUCCESS] Time {generation_time:.2f}s | "
                      f"CA={results['num_ca']}, ROA={results['num_roa']}, Depth={results['depth']}")
            except Exception as e:
                print(f"  [ERROR] Statistics scan failed: {e}")
                success = False
                self.aggregator.add_failure(is_timeout=False)

        # Cleanup
        if (not success) or (not self.config.keep_repos):
            try:
                if os.path.exists(repo_dir):
                    shutil.rmtree(repo_dir)
            except Exception:
                pass

        return success, params, results, generation_time

    def run(self) -> StatisticsAggregator:
        """Execute batch generation"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        if self.config.keep_repos:
            os.makedirs(
                os.path.join(self.config.output_dir, self.config.repos_subdir),
                exist_ok=True
            )

        print(f"Target: Successfully generate {self.config.num_repos} repositories")
        print(f"Timeout: {self.config.timeout} seconds per repository")
        print(f"Parameter range: D:{self.config.depth_range} B:{self.config.branch_range} "
              f"T:{len(self.config.tree_types)} types R:{self.config.roa_range}")
        print()

        success_count = 0
        attempt_count = 0
        total_start = time.time()

        try:
            while success_count < self.config.num_repos:
                # Seed strategy: base + attempt_count, ensures each attempt (even after retry) uses different seed
                current_seed = self.config.seed_base + attempt_count

                is_success, params, stats, gen_time = self.generate_single_with_timeout(
                    success_count, current_seed
                )

                attempt_count += 1

                if is_success:
                    self.aggregator.add_record(success_count, params, stats, gen_time)
                    success_count += 1

                    # Progress display
                    elapsed = time.time() - total_start
                    avg_time = elapsed / success_count
                    remaining = self.config.num_repos - success_count
                    eta = avg_time * remaining

                    print(f"  Progress: {success_count}/{self.config.num_repos} "
                          f"({100*success_count/self.config.num_repos:.1f}%) | "
                          f"Fails/Timeouts: {self.aggregator.failures}/{self.aggregator.timeouts} | "
                          f"ETA: {eta:.0f}s")
                else:
                    print(f"  Retry... (failed so far: {self.aggregator.failures})")

        except KeyboardInterrupt:
            print("\nUser interrupted generation process")
        finally:
            if self._temp_dir and os.path.exists(self._temp_dir):
                try:
                    shutil.rmtree(self._temp_dir)
                except Exception:
                    pass

        total_time = time.time() - total_start
        print(f"\nDone! Total time: {total_time:.1f}s")
        print(f"Success: {success_count}, Failures: {self.aggregator.failures} (timeouts: {self.aggregator.timeouts})")

        return self.aggregator

    def save_results(self) -> Tuple[str, str]:
        """Save results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(self.config.output_dir, f"diversity_stats_{timestamp}.csv")
        summary_path = os.path.join(self.config.output_dir, f"diversity_summary_{timestamp}.json")
        self.aggregator.save_csv(csv_path)
        self.aggregator.save_summary(summary_path)
        return csv_path, summary_path


# ============================================================================
# Report Printing
# ============================================================================

def print_summary_report(aggregator: StatisticsAggregator) -> None:
    """Print summary report"""
    summary = aggregator.get_summary()
    if not summary or summary['total_repos'] == 0:
        print("No valid data")
        return

    print()
    print("=" * 60)
    print("Diversity Statistics Summary Report")
    print("=" * 60)
    print(f"Successful repositories: {summary['total_repos']}")
    print(f"Failures:                 {summary['total_failures']} (timeouts: {summary['total_timeouts']})")
    print(f"Success rate:             {100*summary['total_repos']/(summary['total_repos']+summary['total_failures']):.1f}%")
    print(f"Average time:             {summary['total_generation_time_sec']/summary['total_repos']:.2f} sec/repo")
    print()

    print("Structure metrics (successful samples only):")
    print("-" * 60)
    print(f"{'Metric':<12} {'Min':<10} {'Max':<10} {'Mean':<10} {'Std Dev':<10}")
    print("-" * 60)

    for metric in StatisticsAggregator.METRICS:
        print(f"{metric:<12} {summary.get(f'{metric}_min',0):<10} "
              f"{summary.get(f'{metric}_max',0):<10} "
              f"{summary.get(f'{metric}_mean',0):<10.2f} "
              f"{summary.get(f'{metric}_std',0):<10.2f}")
    print("-" * 60)
    print()


def print_distribution(aggregator: StatisticsAggregator, metric: str) -> None:
    """Print distribution"""
    dist = aggregator.get_distribution(metric)
    if not dist:
        return
    total = sum(dist.values())
    print(f"\n{metric} distribution:")
    print("-" * 40)
    max_count = max(dist.values())
    for val, count in dist.items():
        pct = 100 * count / total
        bar_len = int(30 * count / max_count)
        print(f"  {val:>4}: {'#'*bar_len:<30} {count:>5} ({pct:>5.1f}%)")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="RPKI Certificate Repository Batch Generation and Diversity Statistics Tool (with timeout retry)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--num-repos", type=int, default=1000, help="Target number of successful repositories")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout per repo in seconds, default 60")

    parser.add_argument("--depth-range", type=int, nargs=2, default=[1, 5], help="Depth range")
    parser.add_argument("--branch-range", type=int, nargs=2, default=[1, 4], help="Branch range")
    parser.add_argument("--tree-types", type=str, nargs="+", default=["full", "random", "sparse"], help="Tree types")
    parser.add_argument("--roa-range", type=int, nargs=2, default=[1, 3], help="ROA count range")

    parser.add_argument("--seed", type=int, default=42, help="Random seed base")
    parser.add_argument("--output-dir", type=str, default="batch_output", help="Output directory")
    parser.add_argument("--keep-repos", action="store_true", help="Keep repository files")
    parser.add_argument("--show-distribution", action="store_true", help="Show distributions")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")

    args = parser.parse_args()

    # Windows requires freeze_support for multiprocessing
    if sys.platform.startswith('win'):
        multiprocessing.freeze_support()

    config = BatchConfig(
        depth_range=tuple(args.depth_range),
        branch_range=tuple(args.branch_range),
        tree_types=args.tree_types,
        roa_range=tuple(args.roa_range),
        num_repos=args.num_repos,
        seed_base=args.seed,
        timeout=args.timeout,
        output_dir=args.output_dir,
        keep_repos=args.keep_repos,
    )

    generator = BatchGenerator(config)
    aggregator = generator.run()

    csv_path, summary_path = generator.save_results()

    if not args.quiet:
        print(f"\nResults saved to:\n  CSV: {csv_path}\n  JSON: {summary_path}")
        print_summary_report(aggregator)

    if args.show_distribution:
        for metric in ["depth", "num_ca", "max_branch", "leaf_count"]:
            print_distribution(aggregator, metric)

if __name__ == "__main__":
    main()
