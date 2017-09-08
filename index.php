<?php 
namespace openssl;
header('Content-type:text/html;charset=utf-8');
include './Rsa.php';
$method='aes-192-ctr';
$iv='1234567812345678';
$token1='需要加密的内容';
$token2=[
	'a'=>'aaa',
	'b'=>'bbb',
	'c'=>'cc',
	'd'=>'d',
];
$key1='This is a key1';
$key2='秘钥';
$de=Rsa::sign_encode($token2);
p($de);
$rs=Rsa::sign_decode($token2,$de);
p($rs);
function p($arr=[]){
	echo "<pre>";
	print_r($arr);
	echo "</pre>";
}