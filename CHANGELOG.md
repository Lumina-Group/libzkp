# Changelog

このプロジェクトのすべての注目すべき変更は、このファイルに記録されます。

フォーマットは[Keep a Changelog](https://keepachangelog.com/ja/1.0.0/)に基づいており、
このプロジェクトは[Semantic Versioning](https://semver.org/spec/v2.0.0.html)に準拠しています。

## [Unreleased]

### Added
- STARKバックエンドの本実装（winterfellフレームワーク使用）
- バッチ処理機能の本実装
  - `batch_add_equality_proof`: 等価性証明のバッチ追加
  - `batch_add_threshold_proof`: しきい値証明のバッチ追加
  - `get_batch_status`: バッチステータスの確認
  - `clear_batch`: 特定バッチのクリア
- 並列証明検証の本実装
  - 各証明タイプに対応した検証ロジック
  - バッチ検証での早期終了機能
  - 並列証明生成機能
- 拡張されたエラーハンドリング
  - 新しいエラータイプ（IntegerOverflow、CryptoError、ConfigError）
  - エラーコンテキストのサポート
  - より詳細なエラーメッセージ
- 整数オーバーフロー保護機能
- APIリファレンスドキュメント（`docs/api.md`）
- テストスクリプト（`test_improvements.py`）

### Changed
- STARKバックエンドがモック実装から本格的な証明システムに変更
- 並列処理がプレースホルダーから実際の並列検証に変更
- バッチ処理が簡易実装から完全な機能実装に変更
- エラーメッセージがより詳細で有用な情報を提供するように改善
- README.mdが新機能と改善点を反映するように更新
- docs/overview.mdが新しいアーキテクチャを反映するように更新

### Fixed
- 整数オーバーフローの可能性がある箇所に保護を追加
- バッチ処理でのメモリリークの可能性を修正

### Dependencies
- `lazy_static = "1.4"` を追加（グローバル状態管理のため）

## [0.1.0] - 2024-01-01

### Added
- 初期リリース
- 6種類のゼロ知識証明のサポート
  - 範囲証明（Range Proof）
  - 等価性証明（Equality Proof）
  - しきい値証明（Threshold Proof）
  - 集合所属証明（Set Membership Proof）
  - 向上証明（Improvement Proof）
  - 整合性証明（Consistency Proof）
- 3つの暗号学的バックエンド
  - Bulletproofs
  - SNARK (Groth16)
  - STARK（簡易実装）
- Python バインディング（PyO3使用）
- 基本的なキャッシング機能
- 複合証明のサポート
- メタデータ付き証明