# Ruby `iptables` Generator

このプログラムは`iptables`用の設定ファイルを生成します。

このプログラムではRuby 1.9以上を利用してください。
必要なファイルは[`src/iptables.rb`](src/iptables.rb)のみであり、
他のファイルはテストコードやサンプルコード、ドキュメントになります。

## 使い方

このリポジトリをクローンした後、以下のコマンドを実行してください。
標準出力にHTTPサーバー用の設定が表示されます。
```sh
ruby src/http_server_sample.rb
```

後は適時、[`http_server_sample.rb`](src/http_server_sample.rb)を修正するなり、新規ファイルを作成するなりしてください。

### 使い方の詳細

APIドキュメントはありません。[テストコード](spec/iptables_spec.rb)を参考にしてください。

## 最後に

バグや要望があれば、Issueに登録するかPull Requestを出してください。
このプログラムが便利だと思えたら、このリポジトリにStarするかTwitterで宣伝してくれると嬉しいです。
