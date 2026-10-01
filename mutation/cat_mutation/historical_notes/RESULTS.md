# cure_asn1 变异 vs 未变异基线:验证阶段到达概率对比实验

日期:2026-09-20 · 两臂各 1000 个证书仓库 · 生成成功率 100%(带重试)

## 实验设置

- **基座仓库**:论文原生成管线(拷贝于 artifact/mutation),每仓库 = TA + 子 CA 层级 +
  manifest/CRL/ROA,TAL 指向 rsync://localhost:8730/myrpki/,种子 = 仓库编号。
- **变异臂(cureasn1)**:batch_mutator(cure_asn1 path 依赖,未改原库)对每仓库全部
  非 TA 的 .cer 各施加 1 轮 `mutate_tree`(结构感知,自动修复长度,不修复密码学依赖)。
- **基线臂(baseline)**:同一生成器同种子,不做任何变异。
- **验证与测量**:4 个打补丁验证器(artifact/RP/instruct 副本)独立子进程运行,
  解析各自日志的 `FUZZ_METRIC: STAGE_<1-5>_<PARSE/HASH/CRYPTO/POLICY/VALID>` 标记;
  每仓库取最大阶段。Routinator 经独立 glibc 2.39 loader 运行;OctoRPKI 加
  `-allow.root` 并预填充缓存(其单文件 rsync 抓取在 instruct 二进制中未修复)。

## 结果:P(仓库到达阶段 k),%

| 验证器 | 臂 | P≥1 | P≥2 | P≥3 | P≥4 | P≥5 |
|---|---|---|---|---|---|---|
| Fort | 基线 | 100 | 100 | 100 | 100 | **40.0** |
| Fort | cure_asn1 | 100 | 100 | 100 | 100 | **9.0** |
| Octorpki | 基线 | 100 | 100 | 100 | 100 | **52.3** |
| Octorpki | cure_asn1 | 100 | 100 | 100 | 100 | **11.1** |
| RPKI Client | 基线 | 100 | 100 | 100 | 90.7 | **35.7** |
| RPKI Client | cure_asn1 | 100 | 100 | 100 | 20.8 | **8.0** |
| Routinator | 基线 | 100 | 100 | 100 | 47.1 | **47.1** |
| Routinator | cure_asn1 | 100 | 100 | 100 | 10.0 | **10.0** |

完整分布(最终停留阶段直方图、每阶段平均标记数)见
`results/cureasn1_stats.txt` 与 `results/baseline_stats.txt`。

## 解读

1. **STAGE_1-3 两臂均为 100%**:变异只作用于子 CA 证书,仓库其余对象(TA、根
   manifest/CRL)仍在浅阶段全部通过;cure_asn1 的 `fix_sizes` 保证变异后 DER 仍可
   解析(STAGE_1 不挂),变异对象本身死于 manifest 哈希失配(STAGE_2,针对该对象)。
2. **STAGE_4/5 显著塌缩**:变异臂完全通过率(STAGE_5)从基线 35.7-52.3% 跌至
   8.0-11.1%,约 4-5 倍下降。原因:子 CA 证书字节改变 → manifest 哈希失配 →
   其下整棵子树(含 ROA)无法产出有效 VRP。这正是"无密码学修复的结构变异"
   的系统性天花板(与 CAT 论文对无修复 fuzzer 的论断一致)。
3. **变异臂 STAGE_5 残留 ~9-11% 的来源**(数据自洽):
   - 166/1000 个仓库拓扑中无非 TA 证书(候选=0,实际未变异);
   - 834 个被变异对象中 63 个(7.6%)为字节级 no-op;
   两者合计 229 个等效未变异仓库 × 基线通过率 40%(Fort)≈ 92 ≈ 观测 90。
4. **验证器差异**:Routinator/rpki-client 更严(基线下也有 47-53%/9.3% 停在
   STAGE_3),其补丁的阶段标记语义与 Fort/Octo 略有不同(如 stage_4 标记仅在
   特定检查路径输出)。跨验证器只做同臂内对比,不做绝对值横比。

## 与论文实验的对接

论文的 fix/nofix 两条件(test_coverage.py 口径)与本实验共享同一阶段定义与
标记机制。本实验新增的第三臂(cure_asn1 对象级结构变异,无修复)可直接与论文
nofix(配置级字段变异,构建期签名)对照:nofix 的证书自身签名仍有效(仅链上
引用断裂),cure_asn1 则连对象签名/哈希一并破坏,故天花板更低、更早。

## 复现

```bash
cd exp_cureasn1/harness
rsync --daemon --config=rsyncd.exp.conf          # 127.0.0.1:8730
.venv/bin/python run_experiment.py --repos 1000 --start 1 --rounds 1 --types cer --tag cureasn1
.venv/bin/python run_experiment.py --repos 1000 --start 1 --no-mutate --tag baseline
.venv/bin/python stage_stats.py ../results/cureasn1 --csv ../results/cureasn1_stats.csv
```

每仓库原始数据:`results/<tag>/repo_XXXXXX/`(result.json、四验证器日志、
变异元数据 mutations.jsonl、生成日志)。运行总时长约 60 分钟(两臂)。

## 已知限制

- OctoRPKI 缓存预填充绕过其损坏的 rsync 抓取(下载不属于五阶段);
- Routinator 需独立 glibc 2.39(instruct 二进制为 Docker 环境编译);
- 变异预算为每对象 1 轮、仅 .cer;`--rounds/--types/--num-objects` 可扩展;
- 阶段判定依赖各验证器补丁的标记输出语义,已按验证器分别统计。

---

# 第三臂:fix(cure_asn1 变异 + CAT 论文点名的修复规则,1000 仓库,2026-09-21)

变异对象与 nofix 对齐(所有 CA 证书含 TA,TA 3 轮/子 CA 7 轮),修复只含
论文 §6.3/§4.1 点名的规则(R1 长度自动、R2 重签、R3 SKI 重算、R4 AKI 同步、
R5/R6 manifest 哈希+重签、flag 保护),无任何结果门控。细节见 FIX_ARM.md。

## P(仓库到达阶段 k),%

| 阶段 | Fort | Octorpki | RPKI Client | Routinator |
|---|---|---|---|---|
| STAGE_1 | 100 | 96.8 | 90.6 | 92.0 |
| STAGE_2 | 26.7 | 39.5 | 20.8 | 25.7 |
| STAGE_3 | 26.7 | 39.5 | 20.8 | 25.7 |
| STAGE_4 | 26.7 | 35.2 | 5.6 | 3.9 |
| STAGE_5 | 2.9 | 4.7 | 2.0 | 3.9 |

## 最终停留阶段分布,%

| 停在 | Fort | Octorpki | RPKI Client | Routinator |
|---|---|---|---|---|
| 0 | 0 | 3.2 | 9.4 | 8.0 |
| 1 | 73.3 | 57.3 | 69.8 | 66.3 |
| 3 | 0 | 4.3 | 15.2 | 21.8 |
| 4 | 23.8 | 30.5 | 3.6 | 0 |
| 5 | 2.9 | 4.7 | 2.0 | 3.9 |

修复统计:997/1000 仓库执行过修复;重签 1630 次、AKI 同步 906 次、
SKI 重算 235 次;按 flag 协议跳过 467 次(签名故意变异 343 居首)。

## 与前两臂对照(P≥5)

| 臂 | 变异 | 修复 | Fort | Octo | RC | Rout |
|---|---|---|---|---|---|---|
| baseline | 无 | - | 40.0 | 52.3 | 35.7 | 47.1 |
| cure_asn1 裸 | 仅子 CA,1 轮 | 无 | 9.0 | 11.1 | 8.0 | 10.0 |
| fix | 全 CA 含 TA,3/7 轮 | 论文规则 | 2.9 | 4.7 | 2.0 | 3.9 |

## 解读

1. **S2 停留数为 0(四验证器一致)**——manifest 哈希修复生效的直接签名;
2. **~70% 仓库死于 S1**:TA 上的随机内容变异破坏严格 RPKI profile 解析,
   flag 协议按设计不修复故意变异 → 整仓被解析关截断;
3. **修复把 ~25% 仓库推入 S4(策略层)**:Fort 23.8%/Octo 30.5% 死于政策
   检查而非哈希/签名——死亡点从"发布一致性"(S2)转移到"语义策略"(S4),
   与 CAT 设计目标一致;
4. P≥5 低于裸变异臂的原因是对象集不同(裸臂不含 TA 变异,TA 恒有效保底);
   同对象集的无修复对照见 NOFIX_ARM.md 冒烟(严格型 ~90% 死于 S1、无人到 S4)。
