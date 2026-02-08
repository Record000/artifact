import subprocess
import psutil
import time
import statistics
import matplotlib.pyplot as plt
import platform
import matplotlib
from matplotlib import font_manager

# config
NUM_REPOS = 1000
LOGICAL_CORES = psutil.cpu_count(logical=True)

all_times = []
cpu_usages = []
mem_usages = []

for i in range(NUM_REPOS):
    start_time = time.time()

    process = subprocess.Popen(["python3", "oneset.py"])
    ps_proc = psutil.Process(process.pid)

    cpu_samples = []
    mem_samples = []

    while process.poll() is None:
        try:
            cpu_percent = ps_proc.cpu_percent(interval=0.1)
            mem_info = ps_proc.memory_info()
            cpu_samples.append(cpu_percent / LOGICAL_CORES * 100)
            mem_samples.append(mem_info.rss / 1024 / 1024)  
        except psutil.NoSuchProcess:
            break

    end_time = time.time()

    elapsed = end_time - start_time
    all_times.append(elapsed)
    if cpu_samples:
        cpu_usages.append(max(cpu_samples))
    if mem_samples:
        mem_usages.append(max(mem_samples))

print("\n=== Single-threaded Generation Performance Summary ===")
print(f"Total duration: {sum(all_times):.2f} seconds")
print(f"Average time per repository: {statistics.mean(all_times):.3f} seconds")
print(f"Minimum generation time: {min(all_times):.3f} seconds")
print(f"Maximum generation time: {max(all_times):.3f} seconds")

print(f"\nCPU Usage (Max): {max(cpu_usages):.1f}%")
print(f"CPU Usage (Avg): {statistics.mean(cpu_usages):.1f}%")
print(f"Peak Memory (Max): {max(mem_usages):.1f} MB")
print(f"Peak Memory (Avg): {statistics.mean(mem_usages):.1f} MB")

plt.figure(figsize=(15, 5))
font_path = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
font_prop = font_manager.FontProperties(fname=font_path)

matplotlib.rcParams['font.family'] = font_prop.get_name()
matplotlib.rcParams['axes.unicode_minus'] = False 

plt.subplot(1, 2, 1)
plt.hist(cpu_usages, bins=30, color='steelblue', edgecolor='black')
plt.title("CPU Usage Distribution")
plt.xlabel("CPU Usage (%)")
plt.ylabel("Frequency")

plt.subplot(1, 2, 2)
plt.hist(mem_usages, bins=30, color='steelblue', edgecolor='black')
plt.title("Memory Usage Distribution")
plt.xlabel("Memory Usage (MB)")
plt.ylabel("Frequency")

plt.tight_layout()
plt.savefig("resource_usage_distribution.png", dpi=300)
plt.show()
