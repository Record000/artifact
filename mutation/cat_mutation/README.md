# cat_mutation 实验脚本快照

来源：`/home/xyf/research/RPKI/exp_cureasn1` 当前文件。保留原目录，未覆盖 artifact 既有脚本。
这是当前源码快照，不保证与历史 fix_cure_v2（现名 cat_mutation）运行时源码逐字一致。历史说明放在 historical_notes，其中 FIX_ARM.md 描述较早版本，修复行为以当前代码为准。

## 文件
- harness/run_experiment.py：生成、cure_asn1 变异、修复、发布重建、四验证器分进程采集。
- harness/mutation/gen_repo.py：基础仓库生成；main.py、rpki/、data/ 为该实验使用的生成器快照，避免导入 artifact 中不同版本。
- harness/mutation/fix_repair.py：基于 tree/label 的修复与故意变异保护。
- harness/mutation/post_rebuild.py：TAL 与 manifest 发布重建。
- harness/stage_stats.py：从 result.json 统计最高阶段分布及累计到达率。
- batch_mutator/：Rust 变异器源代码和 Cargo.lock。
- vendor/cure_asn1/：本机实际使用的依赖源码（不含 target）；Cargo 路径已改为相对路径。
- requirements.snapshot.txt：原虚拟环境安装包版本快照。
- SOURCE_MANIFEST.json：原始来源和复制时 SHA256；Cargo.toml 路径调整是唯一原始文件内容变更。

不复制历史结果、缓存、虚拟环境、验证器二进制或 glibc。prepare_workspace.py 在新工作区引用原实验的这些运行依赖，故本包并非独立运行环境。

## 在 artifact 外准备工作区

```bash
python3 /home/xyf/research/RPKI/artifact/mutation/cat_mutation/prepare_workspace.py /home/xyf/research/RPKI/cat_mutation_runs/run_01
cd /home/xyf/research/RPKI/cat_mutation_runs/run_01/harness
```

工作区必须不存在；准备脚本不会启动服务或实验。运行脚本依赖当前目录，务必在上述 harness 中执行。

原协议地址固定为 localhost:8730/myrpki。运行前确认 8730 没有被其他实验占用，并确认 rsync 服务发布的是本工作区，而不是旧目录。不要并发运行两个仓库生成实验，不要直接结束其他任务的服务。

端口空闲后：
```bash
rsync --daemon --config="$PWD/rsyncd.exp.conf"
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python run_experiment.py --repos 1000 --start 1 --rounds 7 --ta-rounds 3 --include-ta --types cer --repair --post-rebuild --tag cat_mutation
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python stage_stats.py ../results/cat_mutation --csv ../results/cat_mutation_stats.csv
```

该命令表达 cert-only fix 修复分支设置；随机密钥、secrets 随机数等未被 seed 完全固定，不承诺逐项复现历史数值。生成或变异失败可能重试，修复失败记录为结果；具体口径见 run_experiment.py。每仓库按每个验证器日志中的最高 stage 统计，不是逐对象通过率。

默认复用原 batch_mutator 可执行文件。如需重编译，在外部工作区删除该可执行文件的符号链接（仅链接），然后运行 `cargo build --release --locked --manifest-path ../batch_mutator/Cargo.toml`；勿覆盖链接指向的原实验二进制。运行仍依赖原脚本硬编码的 `/home/xyf/research/RPKI/local-libs/root/usr/lib/x86_64-linux-gnu`。

## 检查范围
整理时进行 Python 语法检查、来源哈希比对、CLI 帮助检查和历史结果只读聚合；不启动新实验，不改动 rsync 服务，不修改历史结果。
