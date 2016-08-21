# CryptHash - シンプルなファイルダイジェストの生成

## 概要

CryptHashは指定されたファイルの SHA-1 / SHA-256 / SHA-384 / SHA-512 を生成するソフトウエアです。Cryptography APIを使用しています。

## 想定使用環境

- Windows
- Visual C++ 2015

## ライセンス

MITライセンス

[http://opensource.org/licenses/mit-license.php](http://opensource.org/licenses/mit-license.php)

## 使い方

    > CryptHash [-sha1|-sha256|-sha384|-sha512] filename

## その他

- MinGWでの利用は想定していません、多分wmainからして厄介なことになるはずです。
- 特殊なことはやっていませんので巨大なファイルには向きません。ご注意ください。
