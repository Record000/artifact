import subprocess
import re
import statistics
from collections import defaultdict

# config
COMMAND = ["python3", "test_noDep.py"]
TOTAL_RUNS = 500
RP_NAMES = ["Routinator", "Fort", "Octorpki", "RPKI Client"]

RP_BANNER_PATTERN = re.compile(r"==================== RUNNING (.*?) ====================")
METRIC_PATTERN = re.compile(r"FUZZ_METRIC: STAGE_(\d)_")

def run_experiment():
    # stats[rp_name] = { 'total_hits': [times 1, times 2...], 'stages': {1: [times 1, times 2...], 2: [...]}, 'final_stages': [1, 4, 3...] }
    stats = {}
    for name in RP_NAMES:
        stats[name] = {
            'total_hits': [],
            'stage_hits': {1: [], 2: [], 3: [], 4: [], 5: []},
            'final_stages': []
        }

    for i in range(1, TOTAL_RUNS + 1):
        print(f"Progress: {i}/{TOTAL_RUNS}", end='\r')
        
        try:
            result = subprocess.run(COMMAND, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
        except Exception as e:
            print(f"\nError at run {i}: {e}")
            continue

        parts = RP_BANNER_PATTERN.split(output)
        
        for j in range(1, len(parts), 2):
            rp_name = parts[j].strip()
            content = parts[j+1]
            
            if rp_name in stats:
                matches = METRIC_PATTERN.findall(content)
                hit_counts = [int(m) for m in matches]
                
                stats[rp_name]['total_hits'].append(len(hit_counts))
                
                current_run_stages = {1:0, 2:0, 3:0, 4:0, 5:0}
                for s in hit_counts:
                    if s in current_run_stages:
                        current_run_stages[s] += 1
                
                for s in range(1, 6):
                    stats[rp_name]['stage_hits'][s].append(current_run_stages[s])
                
                if hit_counts:
                    stats[rp_name]['final_stages'].append(max(hit_counts))
                else:
                    stats[rp_name]['final_stages'].append(0)

    return stats

def print_report(stats):
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

if __name__ == "__main__":
    results = run_experiment()
    print_report(results)
