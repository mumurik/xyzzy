xyzzy Ver.0.2.3.6 - readme

------------------------------------------------------------------------
目次
  ■ xyzzy について
  ■ インストール
     ● はじめて xyzzy を使う場合
     ● もともと xyzzy（オリジナルのもの）を使っていた場合
  ■ アンインストール
  ■ 0.2.3 系列の特徴
     ● マルチフレーム
     ● USB からの起動
     ● アップデータ
  ■ 更新履歴
  ■ 配布ライセンス
  ■ 参考サイト
------------------------------------------------------------------------

■ xyzzy について

xyzzy はテキストエディタです。といっても、ファイル操作をエディタの内部で
行えたり、電卓が使えたり、五目並べができたり（！）、さらに、必要なものを
整えればもっと多彩な機能をエディタ上で実現でき、自分の環境に最適な文章作
成ツールとしてカスタマイズすることができます。

xyzzy はもともと亀井哲弥さんによって開発されたものです。

亀井さんのページ
http://www.jsdlab.co.jp/~kamei/

2005 年に公開された Ver.0.2.2.235 が長らく最新版でしたが、2012 年になっ
て、新しいバージョン番号のもと mumurik によって新たに開発が始められまし
た（0.2.3系列）。開発の状況を知りたいという方は、以下のページを参照して
ください。

Bitbuckets - mumurik
https://bitbucket.org/mumurik/xyzzy/overview


■ インストール

  Windows をお使いであれば、おそらくどのような環境でも動きます。

  ● はじめて xyzzy を使う場合

  普通のテキストエディタとして使うだけなら、展開されてできたフォルダのな
  かにある xyzzy.exe を起動するだけです。適当な場所にフォルダを置いて使
  用してください。ほかに面倒な手続きは必要ありません。

  「もっといろんなことができるんだったらやってみたい」という方は、もう少
  し準備が必要になります。以下のページを参照してください。xyzzy そのもの
  や使い方などがわかりやすく紹介・説明されています。

  Xyzzy Wiki - Quick Tour
  http://xyzzy.s53.xrea.com/wiki/index.php?QuickTour

  ● もともと xyzzy（オリジナルのもの）を使っていた場合

  オリジナルの xyzzy（0.2.2.235 もしくはそれ以前）で動いていた拡張 lisp 
  のなかには、少なくともそのままでは（そして現時点では）0.2.3 系列で動か
  ないものがあります。0.2.3 系列のカスタムパッケージが存在している場合に
  は、それを代わりに使うことができます。以下でご確認ください。

  動かない lisp パッケージ一覧
  https://bitbucket.org/mumurik/xyzzy/wiki/%E5%8B%95%E3%81%8B%E3%81%AA%E3%81%84lisp%E3%83%91%E3%83%83%E3%82%B1%E3%83%BC%E3%82%B8%E4%B8%80%E8%A6%A7

  既存のフォルダにそのまま上書きする場合は、お使いの拡張 lisp がそのまま
  使えるかどうか、カスタムパッケージが存在するかどうか、動くように自分で
  対応することができるかどうかといった点を十分考慮してください。わからな
  いけどとりあえず試してみるというのであれば、上書きせずに別フォルダを用
  意するのがよいでしょう。

  また、あえて上書きする場合はダンプファイルの削除も行ってください。


■ アンインストール

xyzzy の置かれているフォルダを削除するだけです。環境変数 XYZZYHOME を設定し
ていた場合は、それを手動で削除してください。


■ 0.2.3 系列の特徴

  ● マルチフレーム

  0.2.3 系列には、マルチフレームの機能が実装されています。「マルチフレー
  ムって何？」って方は、以下の解説をお読みください。

  マルチフレームとは？
  https://bitbucket.org/mumurik/xyzzy/wiki/%E3%83%9E%E3%83%AB%E3%83%81%E3%83%95%E3%83%AC%E3%83%BC%E3%83%A0%E3%81%A8%E3%81%AF

  M-x make-frame（もしくはC-x 5 2）で新しいフレームが開けます。C-x 5 o 
  で別のフレームに移動します（M-x other-frame）。新しいフレームのサイズ
  は *frame-init-width* *frame-init-height* という二つの変数を使ってカス
  タマイズできます。

  ● USB からの起動

  USB に入れて設定や拡張ごと持ち運んで利用することも容易にできるようにな
  っています。基本的な使い方を以下に示します。

  1. xyzzy.exe があるフォルダに（例えば）data というフォルダを作り、その
     なかに home と config というフォルダを作ってください。
  2. xyzzy.exe と同じ場所に xyzzy.ini というファイルを作り、そのファイル
     に以下を記述してください。

     [USBInit]
     usbHomeDir=data\home
     usbConfigDir=data\config

    （1で "data" の代わりに別の名前のフォルダを作成した場合は、上の記述の
     うち、"data" の部分をそのフォルダの名前に置き換えてください。）
  3. archiver で使っているものがあれば、xyzzy.exe と同じ場所に lib とい
     うフォルダを作って、そのなかに置いてください。
  4. 初期設定ファイル .xyzzy は、先に作成した home のなかに置いてくださ
     い。上の設定が済んでいれば、以後 USB から起動する際、home フォルダ
     のなかに置かれた .xyzzy ファイルが参照されるようになります。また、
     history ファイルは config フォルダのなかに作られます。
  5. xyzzy.exe を起動します。

  以下のページも参考にしてください。

  USB 起動
  https://bitbucket.org/mumurik/xyzzy/wiki/USB%E8%B5%B7%E5%8B%95

  ● アップデータ

  Ver.0.2.3.6 から、メニューから xyzzy のアップデートが自動でできるよう
  になりました。「ツール」＞「アップデートの確認」から、ダイアログに従っ
  て自動更新できます。いろんな手間が省けて便利です。


■ 更新履歴

次をご覧ください。

更新履歴
https://bitbucket.org/mumurik/xyzzy/wiki/%E6%9B%B4%E6%96%B0%E5%B1%A5%E6%AD%B4


■ 配布ライセンス

lisp/ni 下だけは修正 BSD ライセンスとなっています。

------------------------------------------------------------------------
NetInstaller for xyzzy

Copyright (C) 2003-2006 Masashi Hattori
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are 
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. The name of the author may not be used to endorse or promote
   products derived from this software without specific prior
   written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY 
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.
------------------------------------------------------------------------

それ以外は LICENSE ファイルに従います。

------------------------------------------------------------------------
Copyright (C) 1996-2005 Tetsuya Kamei

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without 
limitation the rights to use, copy, modify, merge, publish, distribute, 
sublicense, and/or sell copies of the Software, and to permit persons to 
whom the Software is furnished to do so, subject to the following 
conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------------------


■ 参考サイト

開発サイト
https://bitbucket.org/mumurik/xyzzy/overview

  0.2.3 系 xyzzy の開発に関する情報はこちらから。

オリジナル版 xyzzy の readme
http://www.jsdlab.co.jp/~kei/download/00README.html

  コマンドラインオプションなどについての説明があります（htmlフォルダにも
  同じものがあります）。

Xyzzy Wiki
http://xyzzy.s53.xrea.com/wiki/index.php?FrontPage

  オリジナルの xyzzy を対象としていますが、xyzzy を使ううえで役に立つ情
  報が集約されています。

2ch - xyzzy Part17
http://toro.2ch.net/test/read.cgi/win/1303662374/

  xyzzy や xyzzy lisp に関する情報交換の場として機能しています。わからな
  いことなどがあれば、書き込んでみると何か解決策を示してくれる人がいるか
  もしれません。

