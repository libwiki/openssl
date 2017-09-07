# php openssl 加密、签名




### 对称加密 

~~~
$token='需要加密的内容';	// array | string
$key='秘钥';	// array | string

string $crypted=Rsa::encode($token,$key); //加密

string|array Rsa::decode($crypted,$key); //解密
~~~





### 非对称加密 

~~~
$token='需要加密的内容';	// array | string

string $crypted=Rsa::ssl_encode($token); //加密

string|array Rsa::ssl_decode($crypted); //解密

~~~

---
[https://github.com/wschat/openssl](https://github.com/wschat/openssl)
