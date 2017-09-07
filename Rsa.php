<?php 
namespace openssl;

class Rsa{
	private static $conf=[
		'rsa_private_key'=>'./pem/rsa_private_key.pem',
		'rsa_private_key_pkcs8'=>'./pem/rsa_private_key_pkcs8.pem',
		'rsa_public_key'=>'./pem/rsa_public_key.pem',
	];
	/**
	 * openssl 对称加密
	 * @param  array|string 	$token 	加密内容
	 * @param  array|string 	$key 	秘钥
	 * @param  integer|string  	$method 
	 * @param  string    		$iv 	非空 && 16字节 
	 * @return string
	 */
	static function encode($token,$key,$method=0,$iv='1234567812345678'){
		$token=json_encode($token);	
		$key=md5(json_encode($key));
		$methods=openssl_get_cipher_methods();
		if(is_integer($method)){
			$method=array_key_exists($method,$methods)?$methods[$method]:$methods[0];
		}elseif(is_string($method)){
			$method=in_array($method,$methods)?$method:$methods[0];
		}else{
			$method=$methods[0];
		}
		return openssl_encrypt($token, $method, $key,0,$iv);
	}
	/**
	 * openssl 对称解密
	 * @param  array|string 	$crypted 	解密内容
	 * @param  array|string 	$key 		秘钥
	 * @param  integer|string  	$method 
	 * @param  string    		$iv  		非空 && 16字节 
	 * @return string
	 */
	static function decode($crypted,$key,$method=0,$iv='1234567812345678'){
		$key=md5(json_encode($key));
		$methods=openssl_get_cipher_methods();
		if(is_integer($method)){
			$method=array_key_exists($method,$methods)?$methods[$method]:$methods[0];
		}elseif(is_string($method)){
			$method=in_array($method,$methods)?$method:$methods[0];
		}else{
			$method=$methods[0];
		}
		$token=openssl_decrypt($crypted, $method, $key,0,$iv);
		return json_decode($token,true);
	}
	/**
	 * openssl 非对称 公钥加密
	 * @param  array|string 	$token 		加密内容
	 * @param  string 			$key_path 	公钥路径
	 * @return string
	 */
	static function ssl_encode($token,$key_path=''){
		$token=json_encode($token);	
		$public_key_path=empty($key_path)?self::$conf['rsa_public_key']:$key_path;
		$crypted=[];
		openssl_public_encrypt($token,$crypted, self::getKey($public_key_path,false));
		return base64_encode($crypted);
	}
	/**
	 * openssl 非对称 秘钥解密
	 * @param  array|string 	$crypted 	解密内容
	 * @param  string 			$key_path 	秘钥路径
	 * @return string
	 */
	static function ssl_decode($crypted,$key_path=''){
		$crypted=base64_decode($crypted);
		$private_key_path=empty($key_path)?self::$conf['rsa_private_key']:$key_path;
		$token=[];
		openssl_private_decrypt($crypted,$token, self::getKey($private_key_path));
		return json_decode($token,true);
	}
	private static function getKey($path='',$isPrivateKey=true){
		$key=file_get_contents($path);
		if($isPrivateKey){
			return openssl_get_privatekey($key);
		}
		return openssl_get_publickey($key);
	}
}