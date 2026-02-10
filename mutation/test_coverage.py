import subprocess
import re
import statistics
from collections import defaultdict
import os
import argparse

# Default config
DEFAULT_TOTAL_RUNS = 5
DEFAULT_MODE = "fix"
RP_NAMES = ["Routinator", "Fort", "Octorpki", "RPKI Client"]
COVERAGE_OUTPUT_DIR = "./mutation/out/coverage"

# Mode to script mapping
MODE_COMMANDS = {
    "fix": ["python3", "mutation/main.py"],
    "nofix": ["python3", "mutation/test_noDep.py"]
}

# Patterns
METRIC_PATTERN = re.compile(r"FUZZ_METRIC: STAGE_(\d)_")

def run_experiment(command, total_runs, mode):
    stats = {}
    for name in RP_NAMES:
        stats[name] = {
            'total_hits': [],
            'stage_hits': {1: [], 2: [], 3: [], 4: [], 5: []},
            'final_stages': []
        }

    # Mode-specific output directory
    mode_output_dir = os.path.join(COVERAGE_OUTPUT_DIR, mode)
    os.makedirs(mode_output_dir, exist_ok=True)

    for i in range(1, total_runs + 1):
        print(f"Progress: {i}/{total_runs}", end='\r')

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr

            # Save debug output to mode-specific directory
            debug_file = os.path.join(mode_output_dir, f"debug_run_{i}.txt")
            with open(debug_file, 'w') as f:
                f.write(f"=== Run {i} Output ===\n")
                f.write(f"Total length: {len(output)}\n")
                f.write(f"FUZZ_METRIC count: {len(METRIC_PATTERN.findall(output))}\n")
                f.write("\n=== Full Output ===\n")
                f.write(output)
        except subprocess.TimeoutExpired as e:
            print(f"\nTimeout at run {i}")
            continue
        except Exception as e:
            print(f"\nError at run {i}: {e}")
            continue

        # Assign FUZZ_METRIC to validators based on path prefixes
        all_metrics = list(METRIC_PATTERN.finditer(output))

        # Separate metrics by path pattern
        rpki_client_metrics = []
        fort_octopki_metrics = []

        for metric_match in all_metrics:
            # Get the line containing this FUZZ_METRIC
            line_start = output.rfind('\n', 0, metric_match.start())
            line_end = output.find('\n', metric_match.start())
            if line_start == -1:
                line_start = 0
            if line_end == -1:
                line_end = len(output)
            line = output[line_start:line_end]

            # RPKI Client uses .rsync/ or .ta/ta/ paths (note: no // after .rsync)
            if '.rsync/' in line or '.ta/ta/' in line:
                rpki_client_metrics.append(metric_match)
            # Fort/Octorpki use rsync://localhost paths (with ://)
            elif 'rsync://localhost' in line:
                fort_octopki_metrics.append(metric_match)

        # Split fort_octopki_metrics between Fort and Octorpki (roughly half each)
        fort_metrics = fort_octopki_metrics[:len(fort_octopki_metrics)//2] or []
        octorpki_metrics = fort_octopki_metrics[len(fort_octopki_metrics)//2:] or []

        for rp_name in RP_NAMES:
            if rp_name == "RPKI Client":
                hits = [int(m.group(1)) for m in rpki_client_metrics]

            elif rp_name == "Fort":
                hits = [int(m.group(1)) for m in fort_metrics]

            elif rp_name == "Octorpki":
                hits = [int(m.group(1)) for m in octorpki_metrics]

            else:  # Routinator
                hits = []

            stats[rp_name]['total_hits'].append(len(hits))

            current_run_stages = {1:0, 2:0, 3:0, 4:0, 5:0}
            for s in hits:
                if s in current_run_stages:
                    current_run_stages[s] += 1

            for s in range(1, 6):
                stats[rp_name]['stage_hits'][s].append(current_run_stages[s])

            if hits:
                stats[rp_name]['final_stages'].append(max(hits))
            else:
                stats[rp_name]['final_stages'].append(0)

    return stats

def print_report(stats, mode):
    # Mode-specific output directory
    mode_output_dir = os.path.join(COVERAGE_OUTPUT_DIR, mode)
    os.makedirs(mode_output_dir, exist_ok=True)

    report_file = os.path.join(mode_output_dir, "coverage_report.txt")
    with open(report_file, 'w') as f:
        import builtins
        original_print = builtins.print
        def tee_print(*args, **kwargs):
            original_print(*args, **kwargs)
            original_print(*args, **kwargs, file=f)

        print = tee_print

        print("\n\n" + "="*30 + " FINAL REPORT " + "="*30)

        for rp in RP_NAMES:
            data = stats[rp]
            if not data['total_hits']:
                print(f"\n[RP: {rp}] No data collected.")
                continue

            total_runs = len(data['total_hits'])
            avg_hits = sum(data['total_hits']) / total_runs
            max_hits = max(data['total_hits'])

            print(f"\n[RP: {rp}] (Runs: {total_runs})")
            print(f"  - Overall Total Hits:  Avg={avg_hits:.2f}, Max={max_hits}")

            print("  - Hits Per Stage (Average per run):")
            for s in range(1, 6):
                s_avg = sum(data['stage_hits'][s]) / total_runs
                print(f"    Stage {s}: {s_avg:.2f}")

            print("  - Final Reached Stage Distribution (Which stage it finished at):")
            dist = defaultdict(int)
            for fs in data['final_stages']:
                dist[fs] += 1

            for s in sorted(dist.keys()):
                percentage = (dist[s] / total_runs) * 100
                print(f"    Reached Stage {s}: {dist[s]} times ({percentage:.1f}%)")

        print = original_print
        print(f"\nCoverage report saved to: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='RPKI Coverage Testing Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mutation/test_coverage.py --mode fix --run 10
  python mutation/test_coverage.py --mode nofix --run 20
        """
    )
    parser.add_argument(
        '--mode',
        type=str,
        choices=['fix', 'nofix'],
        default=DEFAULT_MODE,
        help='Test mode: "fix" for mutation with repair (main.py), "nofix" for mutation without repair (test_noDep.py)'
    )
    parser.add_argument(
        '--run',
        type=int,
        default=DEFAULT_TOTAL_RUNS,
        help=f'Number of runs to execute (default: {DEFAULT_TOTAL_RUNS})'
    )

    args = parser.parse_args()

    # Get command based on mode
    command = MODE_COMMANDS[args.mode]

    print(f"Mode: {args.mode}")
    print(f"Command: {' '.join(command)}")
    print(f"Total runs: {args.run}")
    print("-" * 50)

    results = run_experiment(command, args.run, args.mode)
    print_report(results, args.mode)
