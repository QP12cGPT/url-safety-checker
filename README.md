# URL Safety Checker

このプロジェクトは、WebサイトやURLの安全性を簡単にチェックするためのPythonスクリプトです。
Google Safe Browsing APIと独自の基本的な検査機能を組み合わせています。

## 機能
- 軽量版 (`url_guard.py`): Google Safe Browsingや簡易ドメイン検査
- 挙動観測版 (`behavior_check.py`): HTTPヘッダーや挙動の確認

## 必要なもの
- Python 3.8以上
- Google Safe Browsing APIキー（`.env`に `GSB_API_KEY=...` を設定）

## インストール
```bash
pip install -r requirements.txt
```

## 使用例
```bash
python url_guard.py https://example.com
python behavior_check.py https://example.com
```

## 注意事項
- 本ツールは100%の安全性を保証するものではありません。
- 判定は参考情報として使用し、最終的な判断は自己責任で行ってください。
