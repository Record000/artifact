#!/usr/bin/env python3


import os
import sys
import json
import shutil
import argparse
import random
import re
import subprocess
import time
import glob
import tempfile
import multiprocessing
import queue
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, NamedTuple
from datetime import datetime
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod

# Import the CFG generator
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from tools.cfg_generator import GeneratorConfig, RPKICFGGenerator


@dataclass
class RPSoftwareConfig:
    """
    Configuration for a specific RP software.

    Attributes:
        name: Software identifier (e.g., 'routinator', 'fort')
        display_name: Human-readable name
        requires_pre_validation: Whether to run run_<name>.sh before drcov
        log_pattern: Glob pattern to match relevant log files
        log_exclude_pattern: Pattern to exclude from log matching (optional)
        cache_dir: Path to cache directory relative to project root
        validate_script: Path to validation script (run_<name>.sh)
        drcov_script: Path to drcov script (drcov_<name>.sh)
    """
    name: str
    display_name: str
    requires_pre_validation: bool
    log_pattern: str
    log_exclude_pattern: Optional[str] = None
    cache_dir: str = ""
    validate_script: str = ""
    drcov_script: str = ""

    def __post_init__(self):
        """Set default script paths if not provided."""
        if not self.cache_dir:
            self.cache_dir = f"./rp_cache/{self.name}_cache"
        if not self.validate_script:
            self.validate_script = f"./run/run_{self.name}.sh"
        if not self.drcov_script:
            self.drcov_script = f"./run/drcov_{self.name}.sh"


# RP Software Configuration Registry
RP_SOFTWARE_CONFIGS: Dict[str, RPSoftwareConfig] = {
    'routinator': RPSoftwareConfig(
        name='routinator',
        display_name='Routinator',
        requires_pre_validation=True,
        log_pattern='drcov.routinator.*.proc.log',
        log_exclude_pattern=None,
        cache_dir='./rp_cache/routinator_cache',
    ),
    'rpki-client': RPSoftwareConfig(
        name='rpki-client',
        display_name='rpki-client',
        requires_pre_validation=True,
        log_pattern='drcov.rpki-client*',
        log_exclude_pattern=None,
        cache_dir='./rp_cache/rpki-client_cache',
    ),
    'fort': RPSoftwareConfig(
        name='fort',
        display_name='Fort',
        requires_pre_validation=False,
        log_pattern='drcov.fort*',
        log_exclude_pattern='*rsync*',
        cache_dir='./rp_cache/fort_cache',
    ),
    'octorpki': RPSoftwareConfig(
        name='octorpki',
        display_name='OctoRPKI',
        requires_pre_validation=False,
        log_pattern='drcov.octorpki*',
        log_exclude_pattern='*rsync*',
        cache_dir='./rp_cache/octorpki_cache',
    ),
}


def get_rp_config(name: str) -> RPSoftwareConfig:
    """Get RP software configuration by name."""
    name_lower = name.lower()
    if name_lower not in RP_SOFTWARE_CONFIGS:
        raise ValueError(f"Unknown RP software: {name}. "
                        f"Supported: {list(RP_SOFTWARE_CONFIGS.keys())}")
    return RP_SOFTWARE_CONFIGS[name_lower]


def parse_target_rps(arg_value: str) -> Set[str]:
    """
    Parse the --target-rps argument.

    Accepts comma-separated list or 'all' for all supported software.
    """
    if arg_value.lower() == 'all':
        return set(RP_SOFTWARE_CONFIGS.keys())

    rps = set()
    for name in arg_value.split(','):
        name = name.strip().lower()
        if name not in RP_SOFTWARE_CONFIGS:
            raise ValueError(f"Unknown RP software: {name}. "
                           f"Supported: {list(RP_SOFTWARE_CONFIGS.keys())}")
        rps.add(name)
    return rps


# ============================================================================
# Shared Data Structures for Producer-Consumer
# ============================================================================

class GeneratedRepo(NamedTuple):
    """Data package passed from producer to consumer."""
    round_num: int
    depth: int
    ca_count: int
    temp_dir: str
    stats: Dict


# Sentinel value to signal end of work (None works across processes)
SENTINEL = None


# ============================================================================
# Configuration Classes
# ============================================================================

@dataclass
class MutationConfig:
    """Configuration for repository structure mutation."""
    # Fixed parameter
    target_roa_count: int = 100  # Total number of ROAs to maintain

    # Variable parameters (ranges for mutation)
    min_depth: int = 1
    max_depth: int = 10
    min_ca_count: int = 5
    max_ca_count: int = 50

    # Generation settings
    num_variants: int = 10  # Number of different structures to generate
    output_base_dir: str = "mutation_results"
    random_seed: Optional[int] = None
    clean_before: bool = True

    # Repository generation settings
    reuse_keys: bool = False
    key_size: int = 2048
    base_uri: str = "rsync://localhost:8730/repo"

    def __post_init__(self):
        """Validate configuration parameters."""
        if self.target_roa_count <= 0:
            raise ValueError("target_roa_count must be positive")
        if self.min_depth < 1:
            self.min_depth = 1
        if self.max_depth < self.min_depth:
            self.max_depth = self.min_depth
        if self.min_ca_count < 0:
            self.min_ca_count = 0
        if self.max_ca_count < self.min_ca_count:
            self.max_ca_count = self.min_ca_count
        if self.num_variants < 1:
            self.num_variants = 1


@dataclass
class VariantResult:
    """Result of a single repository generation variant."""
    variant_id: int
    depth: int
    ca_count: int
    roa_count: int
    actual_ca_count: int
    actual_roa_count: int
    actual_max_depth: int
    output_dir: str
    timestamp: str
    tree_structure: Dict = field(default_factory=dict)


# ============================================================================
# Repository Structure Mutator
# ============================================================================

class RepositoryMutator:
    """
    Generates multiple RPKI repository structures with varying parameters.

    The mutator explores different (depth, ca_count) combinations while
    keeping the total ROA count constant. This allows studying how
    repository structure affects RPKI validator performance.
    """

    def __init__(self, config: MutationConfig):
        self.config = config
        self.results: List[VariantResult] = []
        self.start_time = datetime.now()

        # Setup output directory
        self.output_base_dir = Path(config.output_base_dir)
        if config.clean_before and self.output_base_dir.exists():
            shutil.rmtree(self.output_base_dir)
        self.output_base_dir.mkdir(parents=True, exist_ok=True)

        # Initialize random seed
        if config.random_seed is not None:
            random.seed(config.random_seed)

    def _generate_parameter_set(self) -> List[Tuple[int, int]]:
        """
        Generate a list of (depth, ca_count) parameter pairs to test.

        Strategy:
        1. Grid sampling: Cover the parameter space evenly
        2. Random sampling: Add random combinations for exploration
        3. Edge cases: Include boundary values
        """
        param_sets = []

        # Grid sampling - divide ranges into bins
        depth_bins = max(1, min(5, self.config.max_depth - self.config.min_depth + 1))
        ca_bins = max(1, min(5, self.config.max_ca_count - self.config.min_ca_count + 1))

        for d in range(depth_bins):
            depth = self.config.min_depth + int(
                (self.config.max_depth - self.config.min_depth) * d / max(1, depth_bins - 1)
            )
            for c in range(ca_bins):
                ca_count = self.config.min_ca_count + int(
                    (self.config.max_ca_count - self.config.min_ca_count) * c / max(1, ca_bins - 1)
                )
                param_sets.append((depth, ca_count))

        # Random sampling - add variety
        num_random = max(0, self.config.num_variants - len(param_sets))
        for _ in range(num_random):
            depth = random.randint(self.config.min_depth, self.config.max_depth)
            ca_count = random.randint(self.config.min_ca_count, self.config.max_ca_count)
            param_sets.append((depth, ca_count))

        # Deduplicate while preserving order
        seen = set()
        unique_sets = []
        for params in param_sets:
            if params not in seen:
                seen.add(params)
                unique_sets.append(params)

        # Limit to num_variants
        return unique_sets[:self.config.num_variants]

    def _generate_tree_structure_info(self, generator: RPKICFGGenerator) -> Dict:
        """Extract tree structure information from the generator."""
        if generator.root_ca is None:
            return {}

        def build_tree_info(ca) -> Dict:
            info = {
                'name': ca.name,
                'depth': ca.depth,
                'num_roas': ca.roa_set.count(),
                'num_children': ca.child_set.count(),
                'children': []
            }
            for child in ca.child_set.children:
                info['children'].append(build_tree_info(child))
            return info

        return build_tree_info(generator.root_ca)

    def generate_variant(self, variant_id: int, depth: int, ca_count: int) -> VariantResult:
        """
        Generate a single repository variant.

        Args:
            variant_id: Unique identifier for this variant
            depth: Maximum depth of CA hierarchy
            ca_count: Target number of CA nodes

        Returns:
            VariantResult with generation details
        """
        timestamp = datetime.now().isoformat()
        output_dir = str(self.output_base_dir / f"variant_{variant_id:03d}_d{depth}_c{ca_count}")

        print(f"\n{'='*60}")
        print(f"Variant {variant_id}: depth={depth}, ca_count={ca_count}")
        print(f"{'='*60}")

        # Create generator config
        gen_config = GeneratorConfig(
            depth=depth,
            max_branch=min(10, ca_count),  # Reasonable branching factor
            min_branch=1,
            tree_type="sparse",
            random_seed=None,
            num_roa=1,  # Will be adjusted by generate_with_limits
            reuse_keys=self.config.reuse_keys,
            key_size=self.config.key_size,
            output_dir=output_dir,
            base_uri=self.config.base_uri,
            clean_output=True,
        )

        # Generate repository with precise limits
        generator = RPKICFGGenerator(gen_config)
        generator.generate_with_limits(
            target_ca_count=ca_count,
            target_roa_count=self.config.target_roa_count,
            max_depth=depth
        )

        # Get actual statistics
        stats = generator.get_stats()
        actual_ca = stats['total_ca'] - 1  # Exclude root
        actual_roa = stats['total_roa']
        actual_max_depth = stats['max_depth']

        print(f"  Generated: {actual_ca} CAs, {actual_roa} ROAs, max_depth={actual_max_depth}")

        # Extract tree structure
        tree_structure = self._generate_tree_structure_info(generator)

        result = VariantResult(
            variant_id=variant_id,
            depth=depth,
            ca_count=ca_count,
            roa_count=self.config.target_roa_count,
            actual_ca_count=actual_ca,
            actual_roa_count=actual_roa,
            actual_max_depth=actual_max_depth,
            output_dir=output_dir,
            timestamp=timestamp,
            tree_structure=tree_structure
        )

        return result

    def run_mutation_campaign(self) -> List[VariantResult]:
        """
        Run the complete mutation campaign, generating all variants.

        Returns:
            List of VariantResult objects
        """
        print(f"\n{'#'*60}")
        print(f"# RPKI Repository Structure Mutation Campaign")
        print(f"# Target ROA Count: {self.config.target_roa_count}")
        print(f"# Depth Range: [{self.config.min_depth}, {self.config.max_depth}]")
        print(f"# CA Count Range: [{self.config.min_ca_count}, {self.config.max_ca_count}]")
        print(f"# Number of Variants: {self.config.num_variants}")
        print(f"{'#'*60}")

        # Generate parameter sets
        param_sets = self._generate_parameter_set()
        print(f"\nGenerated {len(param_sets)} parameter sets to test")

        # Generate each variant
        results = []
        for i, (depth, ca_count) in enumerate(param_sets, 1):
            try:
                result = self.generate_variant(i, depth, ca_count)
                results.append(result)
            except Exception as e:
                print(f"  [ERROR] Variant {i} failed: {e}")
                import traceback
                traceback.print_exc()

        self.results = results
        return results

    def save_summary(self, filename: str = "mutation_summary.json") -> None:
        """Save mutation results summary to JSON file."""
        summary = {
            'config': asdict(self.config),
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'num_variants': len(self.results),
            'results': []
        }

        for result in self.results:
            result_dict = asdict(result)
            # Exclude tree_structure from summary to keep it manageable
            result_dict.pop('tree_structure', None)
            summary['results'].append(result_dict)

        output_path = self.output_base_dir / filename
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n[SAVE] Summary saved to: {output_path}")

    def save_tree_structures(self, filename: str = "tree_structures.json") -> None:
        """Save detailed tree structures to JSON file."""
        trees = {
            'target_roa_count': self.config.target_roa_count,
            'variants': []
        }

        for result in self.results:
            trees['variants'].append({
                'variant_id': result.variant_id,
                'depth': result.depth,
                'ca_count': result.ca_count,
                'actual_ca_count': result.actual_ca_count,
                'actual_roa_count': result.actual_roa_count,
                'actual_max_depth': result.actual_max_depth,
                'tree_structure': result.tree_structure
            })

        output_path = self.output_base_dir / filename
        with open(output_path, 'w') as f:
            json.dump(trees, f, indent=2)

        print(f"[SAVE] Tree structures saved to: {output_path}")

    def print_summary(self) -> None:
        """Print a summary of all generated variants."""
        print(f"\n{'='*80}")
        print(f"MUTATION CAMPAIGN SUMMARY")
        print(f"{'='*80}\n")

        print(f"Target ROA Count: {self.config.target_roa_count}")
        print(f"Variants Generated: {len(self.results)}")
        print(f"Output Directory: {self.output_base_dir}")
        print()

        # Table header
        header = f"{'ID':<6} {'Depth':<8} {'CA Count':<10} {'Actual CA':<12} {'Actual ROA':<12} {'Max Depth':<10}"
        print(header)
        print("-" * 80)

        # Data rows
        for result in self.results:
            row = (f"{result.variant_id:<6} "
                   f"{result.depth:<8} "
                   f"{result.ca_count:<10} "
                   f"{result.actual_ca_count:<12} "
                   f"{result.actual_roa_count:<12} "
                   f"{result.actual_max_depth:<10}")
            print(row)

        print("\n" + "="*80)


# ============================================================================
# Coverage Experiment Runner
# ============================================================================

@dataclass
class ExperimentResult:
    """Result of a single coverage experiment round for a specific RP software."""
    round_num: int
    timestamp: str
    target_depth: int
    target_ca_count: int
    actual_ca_count: int
    actual_roa_count: int
    rp_software: str
    bb_count: Optional[int] = None
    line_coverage: Optional[float] = None
    validation_success: bool = False
    coverage_success: bool = False
    error_message: str = ""


class LogParser:
    """
    Parses drcov log files and extracts coverage information.

    Handles different log patterns for various RP software.
    """

    BB_PATTERN = re.compile(r'BB Table:\s+(\d+)\s+bbs')
    LINE_COV_PATTERN = re.compile(r'lines\.*:\s+([\d\.]+)%')

    def __init__(self, enable_line_cov: bool = False):
        """
        Initialize log parser.

        Args:
            enable_line_cov: Whether to extract line coverage (requires drcov2lcov)
        """
        self.enable_line_cov = enable_line_cov

    @staticmethod
    def read_log_file(log_file: Path) -> Optional[str]:
        """Read log file with multiple encoding fallbacks."""
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
            try:
                with open(log_file, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue

        # Fallback: read as binary and decode with errors='ignore'
        try:
            with open(log_file, 'rb') as f:
                raw_content = f.read()
            return raw_content.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def extract_bb_count(self, content: str) -> Optional[int]:
        """Extract BB count from log content."""
        match = self.BB_PATTERN.search(content)
        if match:
            return int(match.group(1))
        return None

    def parse_log_files(
        self,
        log_dir: Path,
        rp_config: RPSoftwareConfig
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        Parse log files for a specific RP software and extract BB count.

        Returns the maximum BB count found across matching log files.

        Args:
            log_dir: Directory containing log files
            rp_config: Configuration for the RP software

        Returns:
            Tuple of (max_bb_count, primary_log_file_path)
        """
        try:
            # Get all matching log files
            pattern = os.path.join(log_dir, rp_config.log_pattern)
            log_files = glob.glob(pattern)

            # Filter out excluded patterns
            if rp_config.log_exclude_pattern:
                exclude_pattern = os.path.join(log_dir, rp_config.log_exclude_pattern)
                excluded = set(glob.glob(exclude_pattern))
                log_files = [f for f in log_files if f not in excluded]

            if not log_files:
                return None, None

            # Parse each log file and find max BB count
            max_bb_count = None
            primary_log = None

            for log_file_str in log_files:
                log_file = Path(log_file_str)
                content = self.read_log_file(log_file)
                if content is None:
                    continue

                bb_count = self.extract_bb_count(content)
                if bb_count is not None:
                    if max_bb_count is None or bb_count > max_bb_count:
                        max_bb_count = bb_count
                        primary_log = str(log_file)

            return max_bb_count, primary_log

        except Exception as e:
            print(f"  [ERROR] Log parsing failed: {e}")
            return None, None

    def extract_line_coverage(
        self,
        log_dir: Path,
        log_file: Path
    ) -> Optional[float]:
        """
        Extract line coverage percentage from drcov log file.

        Process:
        1. Convert drcov log to lcov format using drcov2lcov
        2. Run lcov --summary to get coverage statistics
        3. Parse output to extract line coverage percentage

        Args:
            log_dir: Directory containing the log files
            log_file: Path to the drcov log file

        Returns:
            Line coverage percentage, or None if extraction failed.
        """
        if not self.enable_line_cov:
            return None

        # Get DR_ROOT environment variable
        dr_root = os.environ.get('DR_ROOT')
        if not dr_root:
            print(f"  [WARN] DR_ROOT not set, skipping line coverage")
            return None

        drcov2lcov_path = Path(dr_root) / "tools" / "bin64" / "drcov2lcov"
        if not drcov2lcov_path.exists():
            print(f"  [WARN] drcov2lcov not found, skipping line coverage")
            return None

        coverage_info_path = log_dir / "coverage.info"

        # Step 1: Convert drcov log to lcov format
        try:
            convert_result = subprocess.run(
                [str(drcov2lcov_path), "-input", str(log_file),
                 "-output", str(coverage_info_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if convert_result.returncode != 0 or not coverage_info_path.exists():
                return None

        except (subprocess.TimeoutExpired, Exception):
            return None

        # Step 2: Run lcov --summary
        try:
            summary_result = subprocess.run(
                ["lcov", "--summary", str(coverage_info_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            # lcov outputs to stderr
            output = summary_result.stderr + summary_result.stdout

            # Step 3: Parse line coverage percentage
            match = self.LINE_COV_PATTERN.search(output)
            if match:
                return float(match.group(1))

        except (subprocess.TimeoutExpired, Exception):
            pass

        return None


class CoverageExperiment:
    """
    Runs automated experiments to measure code coverage of multiple RP software
    under different RPKI repository structures.

    Workflow for each round:
    1. Generate repository with random depth/ca_count
    2. For each target RP software:
       a. Clean cache
       b. Pre-validate if required
       c. Collect coverage with drcov
       d. Parse BB Count and optionally line coverage
       e. Record results to per-RP CSV file
    """

    REPO_DIR = "./my_repo"
    DRCOV_OUTPUT_BASE = "./drcov_output"

    def __init__(
        self,
        total_roas: int,
        min_depth: int,
        max_depth: int,
        min_ca_count: int,
        max_ca_count: int,
        num_rounds: int = 100,
        output_csv: str = "experiment_results",
        project_root: str = ".",
        target_rps: Optional[Set[str]] = None,
        enable_line_cov: bool = False,
        keep_drcov_logs: bool = False,
    ):
        self.total_roas = total_roas
        self.min_depth = min_depth
        self.max_depth = max_depth
        self.min_ca_count = min_ca_count
        self.max_ca_count = max_ca_count
        self.num_rounds = num_rounds
        # Store base output path (without extension) for per-RP CSV generation
        self.output_csv_base = str(Path(output_csv).with_suffix(''))
        self.project_root = Path(project_root).resolve()
        self.enable_line_cov = enable_line_cov
        self.keep_drcov_logs = keep_drcov_logs

        # Set target RP software (default: all)
        if target_rps is None:
            self.target_rps = set(RP_SOFTWARE_CONFIGS.keys())
        else:
            self.target_rps = target_rps

        # Get configurations for target RP software
        self.rp_configs = {
            name: get_rp_config(name) for name in self.target_rps
        }

        self.results: List[ExperimentResult] = []
        self.start_time = datetime.now()
        self.log_parser = LogParser(enable_line_cov=enable_line_cov)

        # Track log directories for potential cleanup
        self.drcov_log_dirs: List[Path] = []

    def _log(self, message: str) -> None:
        """Print log message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def _generate_repository(self, depth: int, ca_count: int, output_dir: str) -> Optional[Dict]:
        """
        Generate a new RPKI repository to specified directory.

        Returns:
            Dict with actual statistics, or None if generation failed.
        """
        self._log(f"Generating repository: depth={depth}, ca={ca_count}, roas={self.total_roas}")

        try:
            # Create generator config
            gen_config = GeneratorConfig(
                depth=depth,
                max_branch=min(10, ca_count),
                min_branch=1,
                tree_type="sparse",
                random_seed=None,
                num_roa=1,
                reuse_keys=False,
                output_dir=output_dir,
                base_uri="rsync://localhost:8730/repo",
                clean_output=True,
            )

            # Generate repository
            generator = RPKICFGGenerator(gen_config)
            generator.generate_with_limits(
                target_ca_count=ca_count,
                target_roa_count=self.total_roas,
                max_depth=depth
            )

            # Get statistics
            stats = generator.get_stats()
            return {
                'actual_ca_count': stats['total_ca'] - 1,  # Exclude root
                'actual_roa_count': stats['total_roa'],
                'actual_max_depth': stats['max_depth']
            }

        except Exception as e:
            self._log(f"  [ERROR] Generation failed: {e}")
            return None

    def _clean_cache(self, rp_config: RPSoftwareConfig) -> bool:
        """Remove RP software cache directory."""
        cache_path = self.project_root / rp_config.cache_dir

        try:
            if cache_path.exists():
                shutil.rmtree(cache_path)
            cache_path.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self._log(f"  [ERROR] Failed to clean cache for {rp_config.name}: {e}")
            return False

    def _validate_repository(self, rp_config: RPSoftwareConfig) -> bool:
        """
        Run RP software validation using run_<name>.sh.

        This ensures the repository is valid and triggers rsync download.
        Only called for software that requires pre-validation.
        """
        script_path = self.project_root / rp_config.validate_script
        if not script_path.exists():
            self._log(f"  [ERROR] Script not found: {script_path}")
            return False

        try:
            result = subprocess.run(
                ["bash", str(script_path)],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                return True
            else:
                self._log(f"  [ERROR] Validation failed for {rp_config.name} (exit={result.returncode})")
                return False

        except subprocess.TimeoutExpired:
            self._log(f"  [ERROR] Validation timeout for {rp_config.name}")
            return False
        except Exception as e:
            self._log(f"  [ERROR] Validation exception for {rp_config.name}: {e}")
            return False

    def _collect_coverage(
        self,
        round_num: int,
        rp_config: RPSoftwareConfig
    ) -> Tuple[Optional[int], Optional[float], Optional[Path]]:
        """
        Run drcov and extract BB Count and optionally line coverage.

        Args:
            round_num: Current round number for output directory naming
            rp_config: Configuration for the RP software

        Returns:
            Tuple of (bb_count, line_coverage, log_dir)
        """
        log_dir = self.project_root / self.DRCOV_OUTPUT_BASE / f"round_{round_num:04d}_{rp_config.name}"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Track log directory for potential cleanup
        self.drcov_log_dirs.append(log_dir)

        script_path = self.project_root / rp_config.drcov_script
        if not script_path.exists():
            self._log(f"  [ERROR] Script not found: {script_path}")
            return None, None, log_dir

        try:
            result = subprocess.run(
                ["bash", str(script_path), str(log_dir)],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=180
            )

            # Parse drcov log files for BB count
            # Create LogParser per-process if not exists (needed for multiprocessing)
            if not hasattr(self, 'log_parser'):
                self.log_parser = LogParser(enable_line_cov=self.enable_line_cov)
            bb_count, primary_log = self.log_parser.parse_log_files(log_dir, rp_config)

            if bb_count is not None:
                self._log(f"  [{rp_config.name.upper()}] BB Count: {bb_count}")
            else:
                self._log(f"  [{rp_config.name.upper()}] No BB Count found")

            # Extract line coverage if enabled
            line_coverage = None
            if self.enable_line_cov and primary_log:
                log_file = Path(primary_log)
                line_coverage = self.log_parser.extract_line_coverage(log_dir, log_file)
                if line_coverage is not None:
                    self._log(f"  [{rp_config.name.upper()}] Line Coverage: {line_coverage}%")

            return bb_count, line_coverage, log_dir

        except subprocess.TimeoutExpired:
            self._log(f"  [ERROR] Coverage collection timeout for {rp_config.name}")
            return None, None, log_dir
        except Exception as e:
            self._log(f"  [ERROR] Coverage exception for {rp_config.name}: {e}")
            return None, None, log_dir

    def _save_result(self, result: ExperimentResult) -> None:
        """Append result to per-RP software CSV file."""
        # Generate per-RP CSV file path: <base>_<rp_name>.csv
        csv_path = self.project_root / f"{self.output_csv_base}_{result.rp_software}.csv"

        # Write header if file doesn't exist
        if not csv_path.exists():
            header = ("Round,Timestamp,Depth,CA_Count,ROA_Count,"
                     "BB_Count,Line_Cov_Percent\n")
            with open(csv_path, 'w') as f:
                f.write(header)

        # Append result (without RP_Software column since it's in the filename)
        csv_row = (f"{result.round_num},{result.timestamp},"
                   f"{result.target_depth},{result.target_ca_count},{result.actual_roa_count},"
                   f"{result.bb_count if result.bb_count else 'N/A'},"
                   f"{f'{result.line_coverage:.2f}' if result.line_coverage is not None else 'N/A'}\n")
        with open(csv_path, 'a') as f:
            f.write(csv_row)

    def run_single_round_for_rp(
        self,
        round_num: int,
        depth: int,
        ca_count: int,
        gen_stats: Dict,
        rp_config: RPSoftwareConfig
    ) -> ExperimentResult:
        """
        Execute a single experiment round for a specific RP software.

        Args:
            round_num: Round number
            depth: Target repository depth
            ca_count: Target CA count
            gen_stats: Actual generation statistics
            rp_config: Configuration for the RP software

        Returns:
            ExperimentResult with collected data.
        """
        result = ExperimentResult(
            round_num=round_num,
            timestamp=datetime.now().isoformat(),
            target_depth=depth,
            target_ca_count=ca_count,
            actual_ca_count=gen_stats['actual_ca_count'],
            actual_roa_count=gen_stats['actual_roa_count'],
            rp_software=rp_config.name,
            bb_count=None,
            line_coverage=None,
            validation_success=False,
            coverage_success=False,
            error_message=""
        )

        # Step 1: Clean cache
        if not self._clean_cache(rp_config):
            result.error_message = "Cache cleanup failed"
            self._save_result(result)
            return result

        # Step 2: Pre-validate if required
        if rp_config.requires_pre_validation:
            if not self._validate_repository(rp_config):
                result.error_message = "Pre-validation failed"
                self._save_result(result)
                return result
            result.validation_success = True

        # Step 3: Collect coverage
        bb_count, line_coverage, log_dir = self._collect_coverage(round_num, rp_config)

        result.bb_count = bb_count
        result.line_coverage = line_coverage
        result.coverage_success = (bb_count is not None)

        if not result.coverage_success:
            result.error_message = "Coverage collection failed"

        # Step 4: Save result
        self._save_result(result)

        # Print summary
        status = "OK" if result.coverage_success else "FAIL"
        bb_str = f"BBs={result.bb_count}" if result.bb_count else "BBs=N/A"
        lc_str = f", Cov={result.line_coverage:.1f}%" if result.line_coverage is not None else ", Cov=N/A"
        self._log(f"  [{rp_config.name.upper()}] {status} | {bb_str}{lc_str}")

        return result

    def run_single_round(
        self,
        round_num: int,
        depth: int,
        ca_count: int
    ) -> List[ExperimentResult]:
        """
        Execute a single experiment round for all target RP software.

        Args:
            round_num: Round number (1-indexed)
            depth: Target repository depth
            ca_count: Target CA count

        Returns:
            List of ExperimentResult objects, one per RP software.
        """
        self._log(f"\n{'='*60}")
        self._log(f"Round {round_num}/{self.num_rounds}")
        self._log(f"Parameters: depth={depth}, ca={ca_count}")
        self._log(f"Target RPs: {', '.join(sorted(self.target_rps))}")
        self._log(f"{'='*60}")

        # Step 1: Generate repository (shared by all RP software)
        gen_stats = self._generate_repository(depth, ca_count, str(self.project_root / self.REPO_DIR))
        if gen_stats is None:
            # Create failed results for all RP software
            results = []
            for rp_name in self.target_rps:
                rp_config = self.rp_configs[rp_name]
                result = ExperimentResult(
                    round_num=round_num,
                    timestamp=datetime.now().isoformat(),
                    target_depth=depth,
                    target_ca_count=ca_count,
                    actual_ca_count=0,
                    actual_roa_count=0,
                    rp_software=rp_name,
                    bb_count=None,
                    line_coverage=None,
                    validation_success=False,
                    coverage_success=False,
                    error_message="Repository generation failed"
                )
                self._save_result(result)
                results.append(result)
            return results

        # Step 2: Run for each RP software
        results = []
        for rp_name in sorted(self.target_rps):
            rp_config = self.rp_configs[rp_name]
            result = self.run_single_round_for_rp(
                round_num, depth, ca_count, gen_stats, rp_config
            )
            results.append(result)

        # Step 3: Clean up drcov logs if not keeping them
        if not self.keep_drcov_logs:
            self._cleanup_drcov_logs()

        return results

    def _cleanup_drcov_logs(self) -> None:
        """Remove drcov log directories after processing."""
        if not self.drcov_log_dirs:
            return

        cleaned = 0
        for log_dir in self.drcov_log_dirs:
            try:
                if log_dir.exists():
                    shutil.rmtree(log_dir)
                    cleaned += 1
            except Exception as e:
                self._log_val(f"  [WARN] Failed to clean {log_dir}: {e}")

        if cleaned > 0:
            self._log_val(f"  [CLEAN] Removed {cleaned} drcov log directories")
        self.drcov_log_dirs.clear()

    def run_experiment(self) -> List[ExperimentResult]:
        """
        Run the complete experiment campaign (single-threaded).

        Returns:
            List of ExperimentResult objects.
        """
        line_cov_status = "enabled" if self.enable_line_cov else "disabled"
        log_cache_status = "kept" if self.keep_drcov_logs else "cleaned after each round"

        self._log(f"\n{'#'*60}")
        self._log(f"# Coverage Experiment Campaign (Single-threaded)")
        self._log(f"# Target ROAs: {self.total_roas}")
        self._log(f"# Depth Range: [{self.min_depth}, {self.max_depth}]")
        self._log(f"# CA Range: [{self.min_ca_count}, {self.max_ca_count}]")
        self._log(f"# Rounds: {self.num_rounds}")
        self._log(f"# Target RP Software: {', '.join(sorted(self.target_rps))}")
        self._log(f"# Line Coverage: {line_cov_status}")
        self._log(f"# Drcov Logs: {log_cache_status}")
        self._log(f"# Output CSV Base: {self.output_csv_base}")
        self._log(f"{'#'*60}\n")

        all_results = []
        successful = 0
        failed = 0

        try:
            for round_num in range(1, self.num_rounds + 1):
                # Generate random parameters
                depth = random.randint(self.min_depth, self.max_depth)
                ca_count = random.randint(self.min_ca_count, self.max_ca_count)

                # Run single round
                results = self.run_single_round(round_num, depth, ca_count)
                all_results.extend(results)

                for result in results:
                    if result.coverage_success:
                        successful += 1
                    else:
                        failed += 1

                # Brief pause between rounds
                if round_num < self.num_rounds:
                    time.sleep(0.5)

        except KeyboardInterrupt:
            self._log(f"\n[INTERRUPTED] Experiment stopped by user")
            self._log(f"Completed {len(all_results)} data points")

        # Final cleanup if any logs remain
        if not self.keep_drcov_logs and self.drcov_log_dirs:
            self._cleanup_drcov_logs()

        # Print final summary
        self._print_summary(all_results, successful, failed)

        self.results = all_results
        return all_results

    def _print_summary(self, all_results: List[ExperimentResult], successful: int, failed: int) -> None:
        """Print experiment summary."""
        self._log(f"\n{'='*60}")
        self._log(f"EXPERIMENT COMPLETE")
        self._log(f"{'='*60}")
        self._log(f"Total data points: {len(all_results)}")
        self._log(f"Successful: {successful}")
        self._log(f"Failed: {failed}")

        # List generated CSV files
        csv_files = []
        for rp_name in sorted(self.target_rps):
            csv_path = self.project_root / f"{self.output_csv_base}_{rp_name}.csv"
            if csv_path.exists():
                csv_files.append(str(csv_path))

        if csv_files:
            self._log(f"\nGenerated CSV files:")
            for csv_file in csv_files:
                self._log(f"  - {csv_file}")

        # Calculate statistics per RP software
        if successful > 0:
            self._log(f"\nPer-RP Statistics:")
            for rp_name in sorted(self.target_rps):
                rp_results = [r for r in all_results if r.rp_software == rp_name]
                rp_successful = [r for r in rp_results if r.bb_count is not None]
                rp_failed = len(rp_results) - len(rp_successful)

                self._log(f"  {rp_name}:")
                self._log(f"    Total: {len(rp_results)}, OK: {len(rp_successful)}, Fail: {rp_failed}")

                if rp_successful:
                    bb_counts = [r.bb_count for r in rp_successful]
                    self._log(f"    BB Count - Min: {min(bb_counts)}, "
                             f"Max: {max(bb_counts)}, "
                             f"Avg: {sum(bb_counts) / len(bb_counts):.2f}")


# ============================================================================
# Multi-threaded Producer-Consumer Experiment
# ============================================================================

class ConcurrentCoverageExperiment:
    """
    Multi-threaded producer-consumer experiment for improved throughput.

    Producers: Multiple threads generating repositories in parallel to temp directories.
    Consumer: Single thread validating and collecting coverage data.
    """

    REPO_DIR = "./my_repo"
    DRCOV_OUTPUT_BASE = "./drcov_output"
    TEMP_GEN_BASE = "./tmp/temp_gen"

    def __init__(
        self,
        total_roas: int,
        min_depth: int,
        max_depth: int,
        min_ca_count: int,
        max_ca_count: int,
        num_rounds: int = 100,
        output_csv: str = "experiment_results",
        project_root: str = ".",
        target_rps: Optional[Set[str]] = None,
        enable_line_cov: bool = False,
        keep_drcov_logs: bool = False,
        num_producers: int = None,
    ):
        self.total_roas = total_roas
        self.min_depth = min_depth
        self.max_depth = max_depth
        self.min_ca_count = min_ca_count
        self.max_ca_count = max_ca_count
        self.num_rounds = num_rounds
        self.output_csv_base = str(Path(output_csv).with_suffix(''))
        self.project_root = Path(project_root).resolve()
        self.enable_line_cov = enable_line_cov
        self.keep_drcov_logs = keep_drcov_logs

        # Set number of producer processes
        if num_producers is None:
            self.num_producers = max(1, os.cpu_count() - 1)
        else:
            self.num_producers = max(1, num_producers)

        # Set target RP software (default: all)
        if target_rps is None:
            self.target_rps = set(RP_SOFTWARE_CONFIGS.keys())
        else:
            self.target_rps = target_rps

        # Get configurations for target RP software
        self.rp_configs = {
            name: get_rp_config(name) for name in self.target_rps
        }

        self.start_time = datetime.now()
        # Note: LogParser cannot be shared across processes, will be created in each process
        self.enable_line_cov = enable_line_cov

        # Shared state using multiprocessing Manager
        self.manager = multiprocessing.Manager()
        self.generated_count = self.manager.Value('i', 0)
        self.generated_count_lock = multiprocessing.Lock()
        self.results: List[ExperimentResult] = self.manager.list()
        self.results_lock = multiprocessing.Lock()
        self.drcov_log_dirs: List[Path] = []

        # Create temp generation base directory
        self.temp_gen_base = self.project_root / self.TEMP_GEN_BASE
        self.temp_gen_base.mkdir(parents=True, exist_ok=True)

        # Setup log files
        log_dir = self.project_root / "drcov_output" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.gen_log_path = log_dir / f"generation_{timestamp_str}.log"
        self.val_log_path = log_dir / f"validation_{timestamp_str}.log"

        # Initialize log file locks (for multiprocessing-safe writes)
        self.gen_log_lock = multiprocessing.Lock()
        self.val_log_lock = multiprocessing.Lock()

        # Write headers to log files
        self._write_log(self.gen_log_path, "# Generation Log - Certificate/ROA Generation")
        self._write_log(self.val_log_path, "# Validation Log - RP Software Validation & Coverage")

    def _write_log(self, log_path: Path, message: str) -> None:
        """Write message to log file with timestamp (multiprocessing-safe)."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")

    def _log_gen(self, message: str, print_console: bool = False) -> None:
        """Log generation message to file and optionally console."""
        self._write_log(self.gen_log_path, message)
        if print_console:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [GEN] {message}")

    def _log_val(self, message: str, print_console: bool = True) -> None:
        """Log validation message to file and optionally console."""
        self._write_log(self.val_log_path, message)
        if print_console:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [VAL] {message}")

    def _log(self, message: str) -> None:
        """Print log message with timestamp to console only (for general status)."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def _generate_to_temp_dir(self, depth: int, ca_count: int, producer_id: int, round_num: int) -> Optional[Tuple[str, Dict]]:
        """
        Generate repository to a temporary directory.

        Args:
            depth: Target tree depth
            ca_count: Target CA count
            producer_id: ID of the producer process
            round_num: Round number for logging

        Returns:
            Tuple of (temp_dir_path, stats_dict) or None on failure.
        """
        try:
            # Create unique temp directory for this generation
            temp_dir = tempfile.mkdtemp(prefix="repo_gen_", dir=str(self.temp_gen_base))

            self._log_gen(f"[PRODUCER-{producer_id}] Round {round_num}: Starting generation to {temp_dir}")
            self._log_gen(f"[PRODUCER-{producer_id}] Round {round_num}: Target - depth={depth}, ca={ca_count}, roas={self.total_roas}")

            # Create generator config
            gen_config = GeneratorConfig(
                depth=depth,
                max_branch=min(10, ca_count),
                min_branch=1,
                tree_type="sparse",
                random_seed=None,
                num_roa=1,
                reuse_keys=False,
                output_dir=temp_dir,
                base_uri="rsync://localhost:8730/repo",
                clean_output=True,
            )

            # Generate repository
            import time
            start_time = time.time()
            generator = RPKICFGGenerator(gen_config)
            generator.generate_with_limits(
                target_ca_count=ca_count,
                target_roa_count=self.total_roas,
                max_depth=depth
            )
            elapsed = time.time() - start_time

            # Get statistics
            stats = generator.get_stats()
            self._log_gen(f"[PRODUCER-{producer_id}] Round {round_num}: Generation complete in {elapsed:.2f}s")
            self._log_gen(f"[PRODUCER-{producer_id}] Round {round_num}: Actual - ca={stats['total_ca']-1}, "
                         f"roa={stats['total_roa']}, depth={stats['max_depth']}")

            return temp_dir, {
                'actual_ca_count': stats['total_ca'] - 1,
                'actual_roa_count': stats['total_roa'],
                'actual_max_depth': stats['max_depth']
            }

        except Exception as e:
            self._log_gen(f"[PRODUCER-{producer_id}] Round {round_num}: Generation failed - {e}", print_console=True)
            return None

    def _move_temp_to_repo(self, temp_dir: str) -> bool:
        """
        Move contents from temp directory to my_repo.

        This is a critical operation that must ensure my_repo is complete
        before the validator starts.
        """
        repo_path = self.project_root / self.REPO_DIR
        temp_path = Path(temp_dir)

        try:
            # Remove existing my_repo
            if repo_path.exists():
                shutil.rmtree(repo_path)

            # Create my_repo parent directory if needed
            repo_path.parent.mkdir(parents=True, exist_ok=True)

            # Move temp directory to my_repo
            # Using shutil.move for atomic-like operation
            shutil.move(str(temp_path), str(repo_path))

            # Fix permissions for rpki-client (drops privileges to _rpki-client user)
            # Make all files readable and directories accessible by all users
            for root, dirs, files in os.walk(repo_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o666)

            return True

        except Exception as e:
            self._log(f"  [ERROR] Failed to move temp to repo: {e}")
            # Try to clean up temp dir if move failed
            try:
                if temp_path.exists():
                    shutil.rmtree(temp_path)
            except:
                pass
            return False

    def _clean_cache(self, rp_config: RPSoftwareConfig) -> bool:
        """Remove RP software cache directory."""
        cache_path = self.project_root / rp_config.cache_dir

        try:
            if cache_path.exists():
                shutil.rmtree(cache_path)
            cache_path.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self._log(f"  [ERROR] Failed to clean cache for {rp_config.name}: {e}")
            return False

    def _validate_repository(self, rp_config: RPSoftwareConfig) -> bool:
        """Run RP software validation using run_<name>.sh."""
        script_path = self.project_root / rp_config.validate_script
        if not script_path.exists():
            self._log_val(f"  [ERROR] Script not found: {script_path}")
            return False

        self._log_val(f"  [{rp_config.name.upper()}] Starting validation...")

        try:
            result = subprocess.run(
                ["bash", str(script_path)],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                self._log_val(f"  [{rp_config.name.upper()}] Validation successful")
                return True
            else:
                self._log_val(f"  [ERROR] Validation failed for {rp_config.name} (exit={result.returncode})")
                if result.stderr:
                    self._log_val(f"  [{rp_config.name.upper()}] STDERR: {result.stderr[:200]}")
                return False

        except subprocess.TimeoutExpired:
            self._log_val(f"  [ERROR] Validation timeout for {rp_config.name}")
            return False
        except Exception as e:
            self._log_val(f"  [ERROR] Validation exception for {rp_config.name}: {e}")
            return False

    def _collect_coverage(
        self,
        round_num: int,
        rp_config: RPSoftwareConfig
    ) -> Tuple[Optional[int], Optional[float]]:
        """
        Run drcov and extract BB Count and optionally line coverage.

        Returns:
            Tuple of (bb_count, line_coverage)
        """
        log_dir = self.project_root / self.DRCOV_OUTPUT_BASE / f"round_{round_num:04d}_{rp_config.name}"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Track log directory for potential cleanup
        self.drcov_log_dirs.append(log_dir)

        script_path = self.project_root / rp_config.drcov_script
        if not script_path.exists():
            self._log_val(f"  [ERROR] Script not found: {script_path}")
            return None, None

        self._log_val(f"  [{rp_config.name.upper()}] Starting coverage collection...")

        try:
            result = subprocess.run(
                ["bash", str(script_path), str(log_dir)],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=180
            )

            # Parse drcov log files for BB count
            # Create LogParser per-process if not exists (needed for multiprocessing)
            if not hasattr(self, 'log_parser'):
                self.log_parser = LogParser(enable_line_cov=self.enable_line_cov)
            bb_count, primary_log = self.log_parser.parse_log_files(log_dir, rp_config)

            if bb_count is not None:
                self._log_val(f"  [{rp_config.name.upper()}] BB Count: {bb_count}")
            else:
                self._log_val(f"  [{rp_config.name.upper()}] No BB Count found")

            # Extract line coverage if enabled
            line_coverage = None
            if self.enable_line_cov and primary_log:
                log_file = Path(primary_log)
                line_coverage = self.log_parser.extract_line_coverage(log_dir, log_file)
                if line_coverage is not None:
                    self._log_val(f"  [{rp_config.name.upper()}] Line Coverage: {line_coverage}%")

            return bb_count, line_coverage

        except subprocess.TimeoutExpired:
            self._log_val(f"  [ERROR] Coverage collection timeout for {rp_config.name}")
            return None, None
        except Exception as e:
            self._log_val(f"  [ERROR] Coverage exception for {rp_config.name}: {e}")
            return None, None

    def _save_result(self, result: ExperimentResult) -> None:
        """Thread-safe append result to per-RP software CSV file."""
        # Generate per-RP CSV file path: <base>_<rp_name>.csv
        csv_path = self.project_root / f"{self.output_csv_base}_{result.rp_software}.csv"

        # Thread-safe file write
        with self.results_lock:
            # Write header if file doesn't exist
            if not csv_path.exists():
                header = ("Round,Timestamp,Depth,CA_Count,ROA_Count,"
                         "BB_Count,Line_Cov_Percent\n")
                with open(csv_path, 'w') as f:
                    f.write(header)

            # Append result
            csv_row = (f"{result.round_num},{result.timestamp},"
                       f"{result.target_depth},{result.target_ca_count},{result.actual_roa_count},"
                       f"{result.bb_count if result.bb_count else 'N/A'},"
                       f"{f'{result.line_coverage:.2f}' if result.line_coverage is not None else 'N/A'}\n")
            with open(csv_path, 'a') as f:
                f.write(csv_row)

    def _process_round_for_rp(
        self,
        round_num: int,
        depth: int,
        ca_count: int,
        gen_stats: Dict,
        rp_config: RPSoftwareConfig
    ) -> ExperimentResult:
        """Process a single round for a specific RP software."""
        result = ExperimentResult(
            round_num=round_num,
            timestamp=datetime.now().isoformat(),
            target_depth=depth,
            target_ca_count=ca_count,
            actual_ca_count=gen_stats['actual_ca_count'],
            actual_roa_count=gen_stats['actual_roa_count'],
            rp_software=rp_config.name,
            bb_count=None,
            line_coverage=None,
            validation_success=False,
            coverage_success=False,
            error_message=""
        )

        # Step 1: Clean cache
        if not self._clean_cache(rp_config):
            result.error_message = "Cache cleanup failed"
            self._save_result(result)
            return result

        # Step 2: Pre-validate if required
        if rp_config.requires_pre_validation:
            if not self._validate_repository(rp_config):
                result.error_message = "Pre-validation failed"
                self._save_result(result)
                return result
            result.validation_success = True

        # Step 3: Collect coverage
        bb_count, line_coverage = self._collect_coverage(round_num, rp_config)

        result.bb_count = bb_count
        result.line_coverage = line_coverage
        result.coverage_success = (bb_count is not None)

        if not result.coverage_success:
            result.error_message = "Coverage collection failed"

        # Step 4: Save result
        self._save_result(result)

        # Print summary
        status = "OK" if result.coverage_success else "FAIL"
        bb_str = f"BBs={result.bb_count}" if result.bb_count else "BBs=N/A"
        lc_str = f", Cov={result.line_coverage:.1f}%" if result.line_coverage is not None else ", Cov=N/A"
        summary_msg = f"[{rp_config.name.upper()}] {status} | {bb_str}{lc_str}"
        self._log_val(summary_msg)

        return result

    def _consumer_task(self, task_queue: multiprocessing.Queue) -> None:
        """
        Consumer task: processes generated repositories from the queue.

        Args:
            task_queue: Queue containing GeneratedRepo objects or SENTINEL
        """
        processed_count = 0

        while True:
            try:
                # Get task from queue with timeout to allow checking for interruption
                item = task_queue.get(timeout=1)

                # Check for sentinel (end of work signal)
                if item is SENTINEL:
                    # Put sentinel back for other consumers (if any)
                    task_queue.put(SENTINEL)
                    break

                if item is None:
                    # Invalid item, skip
                    continue

                repo = item  # GeneratedRepo

                self._log_val(f"\n{'='*60}")
                self._log_val(f"Processing Round {repo.round_num}/{self.num_rounds}")
                self._log_val(f"Parameters: depth={repo.depth}, ca={repo.ca_count}")
                self._log_val(f"From temp dir: {repo.temp_dir}")
                self._log_val(f"{'='*60}")

                # Step 1: Move temp directory to my_repo
                if not self._move_temp_to_repo(repo.temp_dir):
                    # Create failed results for all RP software
                    for rp_name in self.target_rps:
                        rp_config = self.rp_configs[rp_name]
                        result = ExperimentResult(
                            round_num=repo.round_num,
                            timestamp=datetime.now().isoformat(),
                            target_depth=repo.depth,
                            target_ca_count=repo.ca_count,
                            actual_ca_count=0,
                            actual_roa_count=0,
                            rp_software=rp_name,
                            bb_count=None,
                            line_coverage=None,
                            validation_success=False,
                            coverage_success=False,
                            error_message="Failed to move temp repo to my_repo"
                        )
                        self._save_result(result)
                        with self.results_lock:
                            self.results.append(result)
                    continue

                # Step 2: Process for each RP software
                for rp_name in sorted(self.target_rps):
                    rp_config = self.rp_configs[rp_name]
                    result = self._process_round_for_rp(
                        repo.round_num, repo.depth, repo.ca_count,
                        repo.stats, rp_config
                    )
                    with self.results_lock:
                        self.results.append(result)

                # Step 3: Clean up drcov logs if not keeping them
                if not self.keep_drcov_logs:
                    self._cleanup_drcov_logs()

                processed_count += 1

            except queue.Empty:
                # Timeout - check if we should continue
                with self.generated_count_lock:
                    if self.generated_count.value >= self.num_rounds:
                        break
                continue
            except Exception as e:
                self._log(f"  [ERROR] Consumer task exception: {e}")
                import traceback
                self._log(f"  [TRACE] {traceback.format_exc()}")
                continue

        self._log(f"[CONSUMER] Processed {processed_count} rounds")

    def _producer_task(
        self,
        task_queue: multiprocessing.Queue,
        producer_id: int,
        local_random: random.Random
    ) -> None:
        """
        Producer task: generates repositories and puts them in the queue.

        Args:
            task_queue: Queue to put GeneratedRepo objects into
            producer_id: Identifier for this producer process
            local_random: Process-local random number generator
        """
        produced = 0

        while True:
            # Check if we've reached the target number of rounds
            with self.generated_count_lock:
                if self.generated_count.value >= self.num_rounds:
                    break
                # Get current round number
                current_round = self.generated_count.value + 1
                self.generated_count.value += 1

            # Generate random parameters (using thread-local RNG)
            depth = local_random.randint(self.min_depth, self.max_depth)
            ca_count = local_random.randint(self.min_ca_count, self.max_ca_count)

            self._log_gen(f"[PRODUCER-{producer_id}] Generating round {current_round}/{self.num_rounds}: "
                         f"depth={depth}, ca={ca_count}", print_console=True)

            # Generate repository to temp directory
            result = self._generate_to_temp_dir(depth, ca_count, producer_id, current_round)

            if result is None:
                # Generation failed - put None in queue to signal error
                task_queue.put(None)
                continue

            temp_dir, stats = result

            # Create GeneratedRepo and put in queue
            repo = GeneratedRepo(
                round_num=current_round,
                depth=depth,
                ca_count=ca_count,
                temp_dir=temp_dir,
                stats=stats
            )
            task_queue.put(repo)
            produced += 1

        self._log(f"[PRODUCER-{producer_id}] Finished, generated {produced} repos")

    def _cleanup_drcov_logs(self) -> None:
        """Remove drcov log directories after processing."""
        if not self.drcov_log_dirs:
            return

        cleaned = 0
        for log_dir in self.drcov_log_dirs:
            try:
                if log_dir.exists():
                    shutil.rmtree(log_dir)
                    cleaned += 1
            except Exception as e:
                self._log_val(f"  [WARN] Failed to clean {log_dir}: {e}")

        if cleaned > 0:
            self._log_val(f"  [CLEAN] Removed {cleaned} drcov log directories")
        self.drcov_log_dirs.clear()

    def run_experiment(self) -> List[ExperimentResult]:
        """
        Run the multi-threaded producer-consumer experiment campaign.

        Returns:
            List of ExperimentResult objects.
        """
        line_cov_status = "enabled" if self.enable_line_cov else "disabled"
        log_cache_status = "kept" if self.keep_drcov_logs else "cleaned after each round"

        self._log(f"\n{'#'*60}")
        self._log(f"# Multi-threaded Coverage Experiment Campaign")
        self._log(f"# Producer-Consumer Mode")
        self._log(f"# Producer Threads: {self.num_producers}")
        self._log(f"# Consumer Threads: 1")
        self._log(f"# Target ROAs: {self.total_roas}")
        self._log(f"# Depth Range: [{self.min_depth}, {self.max_depth}]")
        self._log(f"# CA Range: [{self.min_ca_count}, {self.max_ca_count}]")
        self._log(f"# Rounds: {self.num_rounds}")
        self._log(f"# Target RP Software: {', '.join(sorted(self.target_rps))}")
        self._log(f"# Line Coverage: {line_cov_status}")
        self._log(f"# Drcov Logs: {log_cache_status}")
        self._log(f"# Output CSV Base: {self.output_csv_base}")
        self._log(f"{'#'*60}\n")

        # Create queue
        task_queue = multiprocessing.Queue(maxsize=self.num_producers * 2)

        # Create and start producer processes
        producer_processes = []
        seed = int(time.time() * 1000) % (2**32)

        for i in range(self.num_producers):
            # Each producer gets its own RNG with a different seed
            local_random = random.Random(seed + i)
            process = multiprocessing.Process(
                target=self._producer_task,
                args=(task_queue, i, local_random),
                name=f"Producer-{i}",
                daemon=True
            )
            process.start()
            producer_processes.append(process)

        # Create and start consumer process
        consumer_process = multiprocessing.Process(
            target=self._consumer_task,
            args=(task_queue,),
            name="Consumer",
            daemon=False
        )
        consumer_process.start()

        # Wait for all producers to finish
        for process in producer_processes:
            process.join()

        # Signal consumer to stop
        task_queue.put(SENTINEL)

        # Wait for consumer to finish
        consumer_process.join()

        # Clean up temp gen directory
        try:
            if self.temp_gen_base.exists():
                shutil.rmtree(self.temp_gen_base)
        except:
            pass

        # Print final summary
        successful = sum(1 for r in self.results if r.coverage_success)
        failed = len(self.results) - successful
        self._print_summary(self.results, successful, failed)

        self.results
        return self.results

    def _print_summary(self, all_results: List[ExperimentResult], successful: int, failed: int) -> None:
        """Print experiment summary."""
        elapsed = datetime.now() - self.start_time

        self._log(f"\n{'='*60}")
        self._log(f"EXPERIMENT COMPLETE")
        self._log(f"{'='*60}")
        self._log(f"Total elapsed time: {elapsed}")
        self._log(f"Total data points: {len(all_results)}")
        self._log(f"Successful: {successful}")
        self._log(f"Failed: {failed}")

        if len(all_results) > 0:
            throughput = len(all_results) / elapsed.total_seconds()
            self._log(f"Throughput: {throughput:.2f} data points/second")

        # List generated CSV files
        csv_files = []
        for rp_name in sorted(self.target_rps):
            csv_path = self.project_root / f"{self.output_csv_base}_{rp_name}.csv"
            if csv_path.exists():
                csv_files.append(str(csv_path))

        if csv_files:
            self._log(f"\nGenerated CSV files:")
            for csv_file in csv_files:
                self._log(f"  - {csv_file}")

        # Calculate statistics per RP software
        if successful > 0:
            self._log(f"\nPer-RP Statistics:")
            for rp_name in sorted(self.target_rps):
                rp_results = [r for r in all_results if r.rp_software == rp_name]
                rp_successful = [r for r in rp_results if r.bb_count is not None]
                rp_failed = len(rp_results) - len(rp_successful)

                self._log(f"  {rp_name}:")
                self._log(f"    Total: {len(rp_results)}, OK: {len(rp_successful)}, Fail: {rp_failed}")

                if rp_successful:
                    bb_counts = [r.bb_count for r in rp_successful]
                    self._log(f"    BB Count - Min: {min(bb_counts)}, "
                             f"Max: {max(bb_counts)}, "
                             f"Avg: {sum(bb_counts) / len(bb_counts):.2f}")


# ============================================================================
# Incremental Mutator (Continuous Generation)
# ============================================================================

class IncrementalMutator:
    """
    Continuously generates repository structures with varying parameters.

    This class provides an iterator interface for generating an infinite
    sequence of repository structures with random parameters within
    the specified ranges.
    """

    def __init__(
        self,
        target_roa_count: int,
        min_depth: int = 1,
        max_depth: int = 10,
        min_ca_count: int = 5,
        max_ca_count: int = 50,
        output_base_dir: str = "mutation_results",
        reuse_keys: bool = False,
        base_uri: str = "rsync://localhost:8730/repo"
    ):
        self.target_roa_count = target_roa_count
        self.min_depth = min_depth
        self.max_depth = max_depth
        self.min_ca_count = min_ca_count
        self.max_ca_count = max_ca_count
        self.output_base_dir = Path(output_base_dir)
        self.reuse_keys = reuse_keys
        self.base_uri = base_uri
        self.counter = 0

        # Create output directory
        self.output_base_dir.mkdir(parents=True, exist_ok=True)

    def generate_next(self) -> Tuple[RPKICFGGenerator, Dict]:
        """
        Generate the next repository variant.

        Returns:
            Tuple of (generator, metadata_dict)
        """
        self.counter += 1

        # Random parameters within ranges
        depth = random.randint(self.min_depth, self.max_depth)
        ca_count = random.randint(self.min_ca_count, self.max_ca_count)

        output_dir = str(self.output_base_dir / f"variant_{self.counter:05d}")

        # Create generator config
        gen_config = GeneratorConfig(
            depth=depth,
            max_branch=min(10, ca_count),
            min_branch=1,
            tree_type="sparse",
            random_seed=None,
            num_roa=1,
            reuse_keys=self.reuse_keys,
            output_dir=output_dir,
            base_uri=self.base_uri,
            clean_output=True,
        )

        # Generate repository
        generator = RPKICFGGenerator(gen_config)
        generator.generate_with_limits(
            target_ca_count=ca_count,
            target_roa_count=self.target_roa_count,
            max_depth=depth
        )

        stats = generator.get_stats()

        metadata = {
            'variant_id': self.counter,
            'depth': depth,
            'ca_count': ca_count,
            'target_roa_count': self.target_roa_count,
            'actual_ca_count': stats['total_ca'] - 1,
            'actual_roa_count': stats['total_roa'],
            'actual_max_depth': stats['max_depth'],
            'output_dir': output_dir
        }

        return generator, metadata

    def __iter__(self):
        """Return self as an iterator."""
        return self

    def __next__(self) -> Tuple[RPKICFGGenerator, Dict]:
        """Generate the next variant."""
        return self.generate_next()


# ============================================================================
# Main Entry Point
# ============================================================================

def generate_single_repository(
    roa_count: int,
    depth: int,
    ca_count: int,
    output_dir: str,
    base_uri: str = "rsync://localhost:8730/repo",
    reuse_keys: bool = False
) -> RPKICFGGenerator:
    """
    Generate a single RPKI repository with specified parameters.

    Args:
        roa_count: Target total number of ROAs
        depth: Maximum depth of CA hierarchy
        ca_count: Target number of CA nodes (excluding root)
        output_dir: Output directory path
        base_uri: Base rsync URI for the repository
        reuse_keys: Whether to reuse EE keys for performance

    Returns:
        RPKICFGGenerator with the generated repository
    """
    print(f"\n{'='*60}")
    print(f"Generating Single Repository")
    print(f"{'='*60}")
    print(f"  ROA Count: {roa_count}")
    print(f"  Depth: {depth}")
    print(f"  CA Count: {ca_count}")
    print(f"  Output: {output_dir}")
    print(f"  Base URI: {base_uri}")

    # Create generator config
    gen_config = GeneratorConfig(
        depth=depth,
        max_branch=min(10, ca_count),
        min_branch=1,
        tree_type="sparse",
        random_seed=None,
        num_roa=1,
        reuse_keys=reuse_keys,
        output_dir=output_dir,
        base_uri=base_uri,
        clean_output=True,
    )

    # Generate repository
    generator = RPKICFGGenerator(gen_config)
    generator.generate_with_limits(
        target_ca_count=ca_count,
        target_roa_count=roa_count,
        max_depth=depth
    )

    # Print statistics
    stats = generator.get_stats()
    print(f"\n[GENERATION COMPLETE]")
    print(f"  Actual CAs: {stats['total_ca'] - 1} (excluding root)")
    print(f"  Actual ROAs: {stats['total_roa']}")
    print(f"  Actual Max Depth: {stats['max_depth']}")
    print(f"  TAL: {generator.tal_path}")

    return generator


def main():
    """Main entry point for the repository mutator."""

    parser = argparse.ArgumentParser(
        description="Generate RPKI repository structures with varying depth and CA counts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a single repository
  python repo_structure_mutator.py --mode single --roa-count 50 --depth 5 --ca-count 10 -o my_repo

  # Generate 20 variants with 100 ROAs each
  python repo_structure_mutator.py --mode batch --roa-count 100 --num-variants 20

  # Run coverage experiment (single-threaded, 100 rounds)
  python repo_structure_mutator.py --mode experiment --roa-count 100 --num-variants 100

  # Run multi-threaded experiment for improved throughput
  python repo_structure_mutator.py --mode concurrent --roa-count 100 --num-variants 100

  # Run concurrent experiment with custom producer process count
  python repo_structure_mutator.py --mode concurrent --gen-threads 4 --num-variants 100

  # Run experiment for specific RP software only (generates per-RP CSV files)
  python repo_structure_mutator.py --mode concurrent --roa-count 100 --num-variants 50 --target-rps routinator,fort

  # Run experiment with line coverage enabled
  python repo_structure_mutator.py --mode concurrent --roa-count 100 --num-variants 50 --enable-line-cov

  # Run experiment and keep drcov log files for debugging
  python repo_structure_mutator.py --mode concurrent --roa-count 100 --num-variants 50 --keep-drcov-logs

  # Experiment with custom ranges and CSV output base path
  python repo_structure_mutator.py --mode concurrent --roa-count 50 --min-depth 2 --max-depth 8 --min-ca 10 --max-ca 40 --num-variants 50 --experiment-csv results/my_experiment

  # Use incremental mode for continuous generation
  python repo_structure_mutator.py --mode incremental --roa-count 100 --num-variants 100

Supported RP Software:
  routinator   - Requires pre-validation
  rpki-client  - Requires pre-validation
  fort         - Direct drcov (no pre-validation)
  octorpki     - Direct drcov (no pre-validation)

CSV Output:
  Each RP software gets its own CSV file: <base>_<rp_name>.csv
  Example: experiment_results_routinator.csv, experiment_results_fort.csv

Concurrent Mode:
  Uses producer-consumer architecture with multiple generator threads
  and a single validator thread for optimal throughput.
        """
    )

    parser.add_argument(
        "--mode",
        type=str,
        choices=["single", "batch", "incremental", "experiment", "concurrent"],
        default="batch",
        help="Generation mode: single (one repository), batch (generate all at once), "
             "incremental (iterator), experiment (single-threaded coverage collection), "
             "concurrent (multi-threaded producer-consumer coverage collection)"
    )

    # Single mode specific arguments
    parser.add_argument(
        "--depth",
        type=int,
        default=5,
        help="Depth of CA hierarchy (for single mode, default: 5)"
    )

    parser.add_argument(
        "--ca-count",
        type=int,
        default=10,
        help="Number of CA nodes (for single mode, default: 10)"
    )

    parser.add_argument(
        "--roa-count",
        type=int,
        default=100,
        help="Target total number of ROAs (default: 100)"
    )

    parser.add_argument(
        "--min-depth",
        type=int,
        default=1,
        help="Minimum depth of CA hierarchy (for batch/incremental/experiment mode, default: 1)"
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum depth of CA hierarchy (for batch/incremental/experiment mode, default: 10)"
    )

    parser.add_argument(
        "--min-ca",
        type=int,
        default=5,
        help="Minimum number of CA nodes (for batch/incremental/experiment mode, default: 5)"
    )

    parser.add_argument(
        "--max-ca",
        type=int,
        default=50,
        help="Maximum number of CA nodes (for batch/incremental/experiment mode, default: 50)"
    )

    parser.add_argument(
        "-n", "--num-variants",
        type=int,
        default=10,
        help="Number of variants to generate (for batch/incremental/experiment mode, default: 10)"
    )

    parser.add_argument(
        "--experiment-csv",
        type=str,
        default="experiment_results",
        help="Output CSV base path for experiment mode (default: experiment_results). "
             "Separate CSV files will be generated per RP software: <base>_<rp_name>.csv"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default="mutation_results",
        help="Output directory (default: mutation_results)"
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )

    parser.add_argument(
        "--save-trees",
        action="store_true",
        help="Save detailed tree structures to JSON (batch mode)"
    )

    parser.add_argument(
        "--base-uri",
        type=str,
        default="rsync://localhost:8730/repo",
        help="Base rsync URI for the repository (default: rsync://localhost:8730/repo)"
    )

    parser.add_argument(
        "--reuse-keys",
        action="store_true",
        default=False,
        dest="reuse_keys",
        help="Reuse EE keys for performance (default: False)"
    )

    parser.add_argument(
        "--no-reuse-keys",
        action="store_false",
        dest="reuse_keys",
        help="Don't reuse EE keys (default)"
    )

    # Experiment mode specific arguments
    parser.add_argument(
        "--target-rps",
        type=str,
        default="all",
        help="Comma-separated list of RP software to test, or 'all' for all supported (default: all). "
             "Supported: routinator, rpki-client, fort, octorpki"
    )

    parser.add_argument(
        "--enable-line-cov",
        action="store_true",
        default=False,
        help="Enable line coverage calculation using drcov2lcov and lcov (default: disabled). "
             "When disabled, only BB Count is collected."
    )

    parser.add_argument(
        "--keep-drcov-logs",
        action="store_true",
        default=False,
        help="Keep drcov log files after processing (default: disabled). "
             "When disabled, log files are cleaned up after each round to save disk space."
    )

    # Concurrent mode specific arguments
    parser.add_argument(
        "--gen-threads",
        type=int,
        default=None,
        help="Number of producer (generator) threads for concurrent mode (default: CPU count - 1). "
             "Consumer is always single-threaded due to RP software constraints."
    )

    args = parser.parse_args()

    # Validate arguments
    if args.roa_count <= 0:
        print("Error: roa-count must be positive")
        return 1

    # Single mode - generate one repository
    if args.mode == "single":
        if args.depth <= 0:
            print("Error: depth must be positive")
            return 1
        if args.ca_count < 0:
            print("Error: ca-count must be non-negative")
            return 1

        generate_single_repository(
            roa_count=args.roa_count,
            depth=args.depth,
            ca_count=args.ca_count,
            output_dir=args.output,
            base_uri=args.base_uri,
            reuse_keys=args.reuse_keys
        )
        return 0

    # Batch mode
    if args.mode == "batch":
        if args.min_depth > args.max_depth:
            print("Error: min-depth cannot be greater than max-depth")
            return 1

        if args.min_ca > args.max_ca:
            print("Error: min-ca cannot be greater than max-ca")
            return 1

        config = MutationConfig(
            target_roa_count=args.roa_count,
            min_depth=args.min_depth,
            max_depth=args.max_depth,
            min_ca_count=args.min_ca,
            max_ca_count=args.max_ca,
            num_variants=args.num_variants,
            output_base_dir=args.output,
            random_seed=args.seed,
            reuse_keys=args.reuse_keys,
            base_uri=args.base_uri
        )

        mutator = RepositoryMutator(config)
        mutator.run_mutation_campaign()
        mutator.print_summary()
        mutator.save_summary()

        if args.save_trees:
            mutator.save_tree_structures()

        print(f"\n[COMPLETE] Generated {len(mutator.results)} variants")
        return 0

    # Experiment mode - single-threaded coverage collection
    if args.mode == "experiment":
        if args.min_depth > args.max_depth:
            print("Error: min-depth cannot be greater than max-depth")
            return 1

        if args.min_ca > args.max_ca:
            print("Error: min-ca cannot be greater than max-ca")
            return 1

        # Parse target RP software
        try:
            target_rps = parse_target_rps(args.target_rps)
        except ValueError as e:
            print(f"Error: {e}")
            return 1

        experiment = CoverageExperiment(
            total_roas=args.roa_count,
            min_depth=args.min_depth,
            max_depth=args.max_depth,
            min_ca_count=args.min_ca,
            max_ca_count=args.max_ca,
            num_rounds=args.num_variants,
            output_csv=args.experiment_csv,
            project_root=".",
            target_rps=target_rps,
            enable_line_cov=args.enable_line_cov,
            keep_drcov_logs=args.keep_drcov_logs,
        )

        results = experiment.run_experiment()
        return 0 if all(r.coverage_success for r in results) or len(results) == 0 else 1

    # Concurrent mode - multi-threaded producer-consumer coverage collection
    if args.mode == "concurrent":
        if args.min_depth > args.max_depth:
            print("Error: min-depth cannot be greater than max-depth")
            return 1

        if args.min_ca > args.max_ca:
            print("Error: min-ca cannot be greater than max-ca")
            return 1

        # Validate gen-threads
        if args.gen_threads is not None and args.gen_threads < 1:
            print("Error: gen-threads must be at least 1")
            return 1

        # Parse target RP software
        try:
            target_rps = parse_target_rps(args.target_rps)
        except ValueError as e:
            print(f"Error: {e}")
            return 1

        experiment = ConcurrentCoverageExperiment(
            total_roas=args.roa_count,
            min_depth=args.min_depth,
            max_depth=args.max_depth,
            min_ca_count=args.min_ca,
            max_ca_count=args.max_ca,
            num_rounds=args.num_variants,
            output_csv=args.experiment_csv,
            project_root=".",
            target_rps=target_rps,
            enable_line_cov=args.enable_line_cov,
            keep_drcov_logs=args.keep_drcov_logs,
            num_producers=args.gen_threads,
        )

        results = experiment.run_experiment()
        return 0 if all(r.coverage_success for r in results) or len(results) == 0 else 1

    # Incremental mode
    if args.mode == "incremental":
        if args.min_depth > args.max_depth:
            print("Error: min-depth cannot be greater than max-depth")
            return 1

        if args.min_ca > args.max_ca:
            print("Error: min-ca cannot be greater than max-ca")
            return 1

        mutator = IncrementalMutator(
            target_roa_count=args.roa_count,
            min_depth=args.min_depth,
            max_depth=args.max_depth,
            min_ca_count=args.min_ca,
            max_ca_count=args.max_ca,
            output_base_dir=args.output,
            reuse_keys=args.reuse_keys,
            base_uri=args.base_uri
        )

        print(f"\n[*] Incremental mode: generating variants...")
        print(f"    Press Ctrl+C to stop\n")

        count = 0
        try:
            for generator, metadata in mutator:
                count += 1
                if count > args.num_variants:
                    break

                print(f"Variant {metadata['variant_id']}: "
                      f"depth={metadata['depth']}, "
                      f"ca={metadata['actual_ca_count']}, "
                      f"roa={metadata['actual_roa_count']}, "
                      f"max_depth={metadata['actual_max_depth']}")

        except KeyboardInterrupt:
            print(f"\n\n[INTERRUPTED] Stopped after {count} variants")

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
