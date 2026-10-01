# fix 臂:cure_asn1 变异 + 复现 CAT 论文点名的修复规则

## 设计原则(与 nofix 臂的区别)

**只实现论文明确说明的修复,不做任何结果向好干预**:无幸存者门控、无
重采样——修不动的对象如实记录并照常投喂验证器,验证器的判定就是测量
本身。变异对象集与预算与 nofix 臂/test_noDep 完全一致(所有 CA 证书
含 TA;TA 3 轮、子 CA 7 轮)。

## 论文修复规则 → 实现对照

| 论文条目(原文) | 实现 |
|---|---|
| R1 长度修复(污点传播,§6.3) | cure_asn1 `fix_sizes` 自动完成(变异时已生效) |
| R2 对象签名重算(§4.1"re-computing signatures on the changed object content") | `fix_repair.py` pass 3:对最终 TBS 用签发者私钥重签(TA 自签;子 CA 用父密钥);签名算法仅支持 sha256WithRSA |
| R3 对象内哈希(§4.1"the key fingerprint needs to match the hash of the contained key") | pass 1:SPKI 被变异且 SKI 未被变异时,SKI := SHA-1(新公钥 DER)(与生成器同规则) |
| R4 跨对象依赖(§4.1"the parent fingerprint matching the hash of the parent key") | pass 2:子 CA 的 AKI := 父证书当前 SKI(AKI 未被变异时) |
| R5/R6 manifest 哈希与重签(§6.3 Nesting) | `post_rebuild.py`:按磁盘实时字节重建 manifest 并重签(每轮) |
| R7 RRDP snapshot 哈希(§6.3) | **不适用**:本实验仅 rsync 发布(如实声明,非省略) |
| Flag 保护协议(§6.3"intentionally manipulated fields are flagged") | batch_mutator `--backup-dir` 保存变异前原件;字段级 diff = 故意变异集(含删除),**绝不覆盖**;签名字段/算法被变异时跳过重签并记录 |

**论文未点名、因而不实现的**:issuer/subject 名字链同步、CRL 重签、
EE 证书处理、RRDP delta。TAL 重导出用宽松 TLV 提取 SPKI(RFC 8630 格式),
几乎总能成功;失败则保留旧 TAL 并记录。

## 修复语义的正确性证据

- 重签后的 TA 自签名经 `openssl verify` 验证 **OK**(密码学有效);
- SPKI 被故意变异时:SKI 重算到新值、TA 照常重签,但 TAL 携带的新公钥
  无对应私钥 → 子树验证必然失败——这是 flag 协议下"故意无效"的正确语义;
- 每仓库 `repair.json` 记录:每证书的被追踪变异字段、执行的修复、跳过原因。

## 已知边界(如实记录,非缺陷)

- `mutated_fields` 只追踪修复相关字段(sigalg/sigval/spki/ski/aki);
  落在其他字段(subject/validity/扩展内容等)的变异不进列表,但同样
  被保留(不修复);
- cure_asn1 `labeling.rs` 的库 panic 由 batch_mutator 逐对象捕获并记录
  (`library_panic_skipped`),被跳过的对象保持原样继续投喂;
- 子 CA 内容变异可能使其无法通过 openssl 严格解析——修复不消除故意
  变异,此类对象由验证器裁决。

## 运行

```bash
cd exp_cureasn1/harness
.venv/bin/python run_experiment.py --repos 1000 --start 1 \
    --rounds 7 --ta-rounds 3 --include-ta --types cer \
    --repair --post-rebuild --tag fix_cure
.venv/bin/python stage_stats.py ../results/fix_cure --csv ../results/fix_cure_stats.csv
```

冒烟(10 仓库,fix_smoke5):修复动作共 30 次;阶段分布为诚实的混合
——多数仓库因保留的内容变异死在 STAGE_1(严格型验证器),少数冲到
STAGE_3/4(链修复生效后死于策略/语义)。
