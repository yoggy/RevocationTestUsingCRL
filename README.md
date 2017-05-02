RevocationTestUsingCRL
====
HTTPS接続時にSSLサーバ証明書が失効しているかどうかをCRLを使って検証するテスト。Android向け。

[Bouncy Castle](https://www.bouncycastle.org/java.html)を使用しています。

![img01.png](img01.png)

メモ
----
AndroidでHttpsURLConnectionクラスを使って通信を行うと、

  - 証明書の有効期限
  - ホスト名とCNの一致
  - 自己署名証明書かどうか
  - 信頼できないルート証明書かどうか

のチェックは行われるが、revokeされているかどうかのチェックは行われない。

* [https://github.com/google/conscrypt/blob/master/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L692](https://github.com/google/conscrypt/blob/master/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L692) より

    // Validate the untrusted part of the chain
    try {
        Set<TrustAnchor> anchorSet = new HashSet<TrustAnchor>();
        // We know that untrusted chains to the first trust anchor, only add that.
        anchorSet.add(trustAnchorChain.get(0));
        PKIXParameters params = new PKIXParameters(anchorSet);
        params.setRevocationEnabled(false);       ← ここで無効にされているっぽい？

[ここ](https://issuetracker.google.com/issues/36993981)とか[ここ](https://bugs.chromium.org/p/chromium/issues/detail?id=362710)などを見ていると、以下の理由でAndroidではrevokeのチェックは行わない方針？

  - モバイル通信環境でいちいちrevocation checkingを行っていると遅い
    - 特にCRLが巨大な場合は顕著？

「失効検証はセキュリティ的にうまく機能しない…」という趣旨の文が書かれているのは、どういう理由なのかしら…？

Copyright and license
----
Copyright (c) 2017 yoggy

Released under the [MIT license](LICENSE.txt)
