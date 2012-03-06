簡単なビルド方法
================

## 目標

単純に、ローカルでのビルドをします。

## ダウンロード、インストール

まず、[Visual C++ 2010 Express](http://go.microsoft.com/fwlink/?LinkId=190491&clcid=0x411)
をインストールしてください。

次に、以下の URL から xyzzy マルチフレーム版の zip ファイルをダウンロードします

 - https://github.com/mumurik/xyzzy/zipball/master

ダウンロードした zip ファイルを展開した後、
`mumurik-xyzzy-ほにゃらら` というディレクトリの下にある
`xyzzy.sln` という Visual Studio 2010 のソリューションファイル開きます。

## ビルドする

Visual Studio 2010 が起動したら、以下の操作でリリース版のビルドが行えます

 - 「ビルド(B)」＞「構成マネージャー(O)」を選択
 - 「構成マネージャー」ダイアログの「アクティブ ソリューション構成」から「Release」を選択し、「閉じる」を押す
 - 「表示(V)」＞「ソリューション エクスプローラー(P)」を選択
 - 「ソリューション エクスプローラー」のツリービューに出ている「xyzzy_mak」を右クリックし、「ビルド(U)」を実行
 - C:\github\xyzzy\xyzzy.exe が更新される

同様に、以下の操作でデバッグ版のビルドが行えます

 - 「ビルド(B)」＞「構成マネージャー(O)」を選択
 - 「構成マネージャー」ダイアログの「アクティブ ソリューション構成」から「Debug」を選択し、「閉じる」を押す
 - 「表示(V)」＞「ソリューション エクスプローラー(P)」を選択
 - 「ソリューション エクスプローラー」のツリービューに出ている「xyzzy_mak」を右クリックし、「ビルド(U)」を実行
 - C:\github\xyzzy\src\d\xyzzy.exe が更新される



---------------------------------------


GitHub を使った開発方法
=======================

マルチフレーム版 xyzzy はバージョン管理システムとして Git (ぎっと) を用いた開発をしています。

また、ホスティングサービスとして GitHub (ぎっとはぶ) を使用しており、
メールアドレスとパスワードのみの、簡単なアカウント登録を行うだけで、直接開発への参加が可能です。


## 目標

 - GitHub でのマルチフレーム版 xyzzy の開発に参加できる環境を作ります


## GitHub で操作をする前に

GitHub および git コマンドによる、全ての操作は **あなたのアカウント、あなたのリポジトリ** に対してのみ実行されます

 - GitHub での操作が、他の人に対して悪影響を与えることはありません
 - ローカルでの git コマンドが、他の人に対して悪影響を与えることもありません

安心して試行錯誤しましょう :-)


## 必要なもの

以下のツール類を、デフォルト設定のままインストールしてください

 - [Visual C++ 2010 Express](http://go.microsoft.com/fwlink/?LinkId=190491&clcid=0x411)
 - [TortoiseGit](http://code.google.com/p/tortoisegit/downloads/list) (とーたすぎっと)
 - [MSysGit](http://code.google.com/p/msysgit/downloads/list)  (えむしすぎっと)


## GitHub のアカウントを作る

 - [GitHub](http://github.com/) へ行き、アカウントを作成してください


## OpenSSH の鍵を作り、公開鍵を GitHub に登録する

MSysGit をインストールすることによって追加された、Git GUI を実行し、鍵を作ります

 - 「スタート」＞「Git」＞「Git GUI」を実行
 - Git GUI の「ヘルプ」＞「SSH キーを表示」を選択
   - 「キーがありません」と表示されたなら
     - 右側にある「鍵を生成」を押す
     - 「Enter passphrase」というダイアログが出るので、空欄のまま「OK」を押す
     - 「Enter same passphrase again」というダイアログが出るので、空欄のまま「OK」を押す
     - 「あなたの鍵は … にあります」という表示に変わる
     - 左下にある「クリップボードにコピー」を押す
   - 「公開鍵がありました : …」と表示されたなら
     - 左下にある「クリップボードにコピー」を押す

Git GUI はそのままにして、ブラウザを開き、GitHub に公開鍵を登録します

 - [GitHubにログイン](https://github.com/settings/emails)する (ログインすると、右上に自分のアカウント名が出る)
 - https://github.com/settings/ssh を開く
 - 「Add New SSH Key」というボタンを押す
 - Git GUI からコピーしたテキスト全体を「Key」欄にペーストする。「Title」は空のままにしておく
 - 「Add key」を押す
   - 押した結果、「SSH Keys」に自分の「コンピュータ名」が追加される

Git GUI での作業は完了したので、閉じましょう。


## マルチフレーム版 xyzzy のリポジトリを Fork する

マルチフレーム版 xyzzy のリポジトリを、GitHub 上の自分のアカウントに Fork (履歴情報付きのコピー) します

 - [GitHubにログイン](https://github.com/settings/emails)する (右上に自分のアカウント名が出る)
 - https://github.com/mumurik/xyzzy を開く
   - 画面の右上にある「`Fork`」を押す
 - Fork が実行され、`https://github.com/ＧｉｔＨｕｂでのユーザ名/xyzzy` という新しいURLに自動的に移動する
   - 「`mirror of https://bitbucket.org/mumurik/xyzzy`」と書かれている下にある「`SSH`」というボタンを押す
   - 「`SSH`」の右のほうにあるエディットボックスの内容「`git@github.com:ＧｉｔＨｕｂでのユーザ名/xyzzy.git`」という文字列をコピーして、どこかに置いておく


## ローカルにファイルを持ってくる

「スタート」＞「Git」＞「Git Bash」を実行して Git Bash を立ち上げ、
以下のコマンドを実行してください

    $ mkdir /c/github
    $ cd /c/github
    $ git clone git@github.com:ＧｉｔＨｕｂでのユーザ名/xyzzy.git
    Cloning into xyzzy...
    remote: Counting objects: XXXX, done.
    remote: Compressing objects: 100% (XXXX/XXXX), done.
    
    Receiving objects: 100% (XXXX/XXXX), X.XX MiB | XXX KiB/s, done.
    Resolving deltas: 100% (XXXX/XXXX), done.

以上で、GitHub 上にあるリポジトリの内容が、ローカル (`C:\github\xyzzy`) にコピーされました。

初期設定として、ユーザ名、メールアドレス、Fork 元のリポジトリを設定します

    $ cd /c/github/xyzzy
    $ git config user.name "ＧｉｔＨｕｂでのユーザ名"
    $ git config user.email "ＧｉｔＨｕｂに登録したメールアドレス"
    $ git remote add upstream https://github.com/mumurik/xyzzy.git
    $ git fetch upstream


## ビルドする

`C:\github\xyzzy\xyzzy.sln` を開き、Visual Studio 2010 を起動します。

Visual Studio 2010 が起動したら、以下の操作でリリース版のビルドが行えます

 - 「ビルド(B)」＞「構成マネージャー(O)」を選択
 - 「構成マネージャー」ダイアログの「アクティブ ソリューション構成」から「Release」を選択し、「閉じる」を押す
 - 「表示(V)」＞「ソリューション エクスプローラー(P)」を選択
 - 「ソリューション エクスプローラー」のツリービューに出ている「xyzzy_mak」を右クリックし、「ビルド(U)」を実行
 - C:\github\xyzzy\xyzzy.exe が更新される

同様に、以下の操作でデバッグ版のビルドが行えます

 - 「ビルド(B)」＞「構成マネージャー(O)」を選択
 - 「構成マネージャー」ダイアログの「アクティブ ソリューション構成」から「Debug」を選択し、「閉じる」を押す
 - 「表示(V)」＞「ソリューション エクスプローラー(P)」を選択
 - 「ソリューション エクスプローラー」のツリービューに出ている「xyzzy_mak」を右クリックし、「ビルド(U)」を実行
 - C:\github\xyzzy\src\d\xyzzy.exe が更新される


## 編集、commit、push する

変更したい点がある場合、以下の繰り返しで作業を行いましょう

 - `C:\github\xyzzy\` 下にあるファイルを編集する
 - ビルド、テスト等を行う
 - 変更点をローカルのリポジトリに追記する
   - xyzzy フォルダを右クリックし、「Git Commit -> "XXX"」を実行する
 - 間違えて `Git Commit` したのを戻したい場合
   - xyzzy フォルダを右クリックし、「TortoiseGit」＞「Show log」を実行する
   - ログダイアログが出るので、戻したい状態の commit を右クリックし、「Reset "XXX" to this...」を実行する
   - Reset ダイアログが出るので、ラジオボタンから「Hard」を選択し、「OK」を押す

ある程度作業がまとまったら、
GitHub サーバにある自分のリポジトリに、変更点をアップロードしましょう

    $ cd /c/github/xyzzy
    $ git push origin

あなたが作業している間に、
[Fork 元のコード](https://github.com/mumurik/xyzzy)が更新されているかもしれません。
更新に追いつきたい場合は、以下の操作を行います

    $ cd /c/github/xyzzy
    $ git stash
    $ git fetch upstream
    $ git rebase upstream/master
    $ git stash pop

以上の操作を繰り返して、作業を行いましょう。


## Pull Request で変更点を作者に提案する

GitHub サーバにあなたのコードがある場合、
マルチフレーム版 xyzzy の作者に対して、変更点の提案を行うことができます。

提案の前に、以下の点を確認しましょう

 - 動作する状態で、提案する
 - 一度にたくさんの提案をするのは避ける

変更点の提案を送信するには、GitHub の Pull Request という機能を使用します

 - 自分のリポジトリが見える URL `https://github.com/ＧｉｔＨｕｂでのユーザ名/xyzzy` に移動する
 - 右上にある「Pull Request」というボタンを押す
 - どのような変更を提案したいのか、フォームに書き入れる
 - 右下にある緑色の「Send pull request」ボタンを押す

以上で、Pull Request が送信されました。
しばらくすると、GitHub に登録したメールアドレスや、
[ダッシュボード](https://github.com/)に返答が来るはずです。
