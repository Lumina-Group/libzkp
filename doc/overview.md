# 概要

本ライブラリはゼロ知識証明(ZKP)を学習・検証するためのサンプル実装です。
`sekkei.md` に記載された設計方針に沿い、以下のモジュールを提供します。

- `range_proof` 範囲証明
- `equality_proof` 等価性証明
- `threshold_proof` 閾値証明
- `set_membership` 集合メンバーシップ証明
- `improvement_proof` 改善証明
- `consistency_proof` 一貫性証明

Rust側ではそれぞれ `prove_*` と `verify_*` 関数を実装し、
Python から呼び出せるよう PyO3 で公開しています。

## ディレクトリ構成
`sekkei.md` では以下のような構成例を示しています。
```text
libzkp/
  src/
    lib.rs                 # ルートモジュール（PyO3バインディング含む）
    range_proof.rs         # 範囲証明
    equality_proof.rs      # 等価性証明
    threshold_proof.rs     # 閾値証明
    set_membership.rs      # 集合メンバーシップ証明
    improvement_proof.rs   # 改善証明
    consistency_proof.rs   # 一貫性証明
    backend/               # ZKPバックエンド抽象化
  tests/                   # Rustのテスト
```
