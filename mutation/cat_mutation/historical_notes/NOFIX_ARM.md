# cure_asn1 版 nofix 臂(与 test_noDep.py 对齐)

## 与 test_noDep.py 的对齐关系

| 维度 | test_noDep.py(论文 nofix) | 本臂 |
|---|---|---|
| 变异对象 | **所有 CA 证书,含 TA**(TA:subject/SPKI/SKI 三目标;子 CA:1 随机值字段 + 6 依赖字段) | **同一对象集**:`--include-ta --types cer`,TA 与全部子 CA |
| 变异预算 | TA 3 个字段、子 CA 7 个字段(构建期注入) | TA 3 轮、子 CA 7 轮(`--ta-rounds 3 --rounds 7`,DER 级随机节点) |
| 对象可解析性 | 永远严格可解析(pyasn1 构建期编码) | cure_asn1 宽松可解析;**严格解析失败的样本经重试被排除**(见偏差说明) |
| manifest 哈希 | 一致(证书先变异、manifest 后构建) | 一致(post_rebuild.py 变异后重建,按磁盘实时字节算哈希) |
| TAL | 从变异后 TA 证书公钥导出 | 相同(post_rebuild.py 重导出) |
| 依赖修复 | 无(AKI/SKI/SPKI/AIA/name 引用全部断裂) | 无(相同) |
| 对象自身签名 | 有效(变异后 TBS 正常签名) | **失效**(DER 后处理,不重签)——与 test_noDep 的关键语义差异 |

## 运行方式

```bash
cd exp_cureasn1/harness
rsync --daemon --config=rsyncd.exp.conf     # 若 8730 未监听
.venv/bin/python run_experiment.py --repos 1000 --start 1 \
    --rounds 7 --ta-rounds 3 --include-ta --types cer --post-rebuild --tag nofix_cure
.venv/bin/python stage_stats.py ../results/nofix_cure --csv ../results/nofix_cure_stats.csv
```

## 组件

- `batch_mutator`:新增 `--ta-rounds`;**per-object `catch_unwind`**——cure_asn1
  `labeling.rs` 对部分证书会 panic(库 bug,不修改原库),panic 降级为该对象跳过
  (meta 记 `library_panic_skipped`);**TA panic → 退出码 2** → 上层重生成。
- `mutation/post_rebuild.py`(新):读 gen_repo 落盘的 `topology.json`,
  重导出 TAL + 重建全部 manifest(复用原 build_mft/export_tal,仅哈希一致性,
  不修复任何引用)。
- `mutation/gen_repo.py`:生成后落盘拓扑元数据。
- `run_experiment.py`:生成/变异 panic/严格解析失败 → 组合重试(最多 6 个偏移
  种子);result.json 记录 `gen_ok / mut_ok / rebuild_ok / gen_seed`。

## 冒烟结果(10 仓库,nofix_smoke4)

- **严格型验证器(Routinator/Fort/rpki-client)~90% 死于 STAGE_1**:变异后 TA
  通不过它们的严格 RPKI profile 解析(例:DataRemoval+ByteFlipping 后
  `STAGE_1_PARSE: FAIL: TA_CERT`);
- **宽松型 OctoRPKI 半数到达 STAGE_3/4**:TA 可解析,死在链/签名——即
  test_noDep 的经典 nofix 画像;
- ~10% 全过(变异为中性/no-op);
- 1/10 仓库因生成器自身缺陷(非法 PrintableString)重试耗尽,标记排除。

## 需在论文中声明的两个偏差

1. **幸存者偏差**:重试机制排除了"变异后证书无法通过 cryptography 严格解析"
   的样本(否则 TAL 无法重导出)。被排除比例见各仓库 attempts 记录;
2. **签名语义差异**:test_noDep 的对象自身签名有效(本臂失效),因此本臂的
   STAGE_3 死因混合了"链断裂"与"签名失配"两种,而 test_noDep 仅有前者。

这两点本身就是"构建期定向变异 vs 对象级随机变异"的方法学差异的体现,
属于实验结论的一部分而非缺陷。
