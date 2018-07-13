---------------------------------------------------------------------
キーワード1
$http_cookie_vars $$http_post_files $http_server_vars $http_post_vars $http_get_vars $http_env_vars $php_self $argv $argc $this __file__ __line__ __wakeup __sleep and break continue class case default die do endforeach endswitch e_warning endwhile extends e_parse e_error elseif endfor empty endif e_all else echo exit function foreach false for global include_once include if list null new not or php_version parent php_os print require_once require return stdclass switch static true virtual var while xor 

キーワード2


対応括弧
半角
(qqwwqq)
<>（HTMLのみ）
｢｣ 
[ffffffffffffff]
{}

全角
（）
〈〉
《》
『』
［］
｛｝
【】


URL/メールアドレス
test@megasoft.co.jp
https://www.megasoft.co.jp
---------------------------------------------------------------------

<?php

abs

    //-->

<!-- HTMLコメント-->
<%-- JSPのコメント --%>
"文字列定数"
'文字列定数'
"文字列定数の中の\"文字列"　文字
'文字列定数の中の\'文字列'　文字
// コメント while  "文字列定数"
本文本文本文本文　/* コメント '文字列定数' */  

本文のURL http://www.test.com
本文のMail test@test.com




/*
◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆
pcounter-x(画像連結式カウンター改良版)

  abs

Copyright 2002- Akihiro Asai. All rights reserved.

http://aki.adam.ne.jp
aki@mx3.adam.ne.jp

◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆

2003. 3.26 正常に書き込みがされたかどうかの判定を追加。
　　　　　 １日以上アクセスがなかった際の処理を改善。
2003. 4. 5 キリ番時にログデータをリセットする処理を追加
2003.11.14 キリ番時に別画像を表示させる処理を追加

daydata.datの形式
書き込み日付,ダミー、昨日のカウント数,一昨日のカウント数,昨日までのカウント数

today.dat
当日の訪問者数

*/

//イメージへのパス
define ("img1","image1/");
define ("img2","image2/");

//重複カウントしない時間（分）
define ("BlockTime", 10);

# キリ番設定
# 設定した数値の倍数でログがリセットされます。
# 同じ番号が出現する可能性がなくなります。
# （厳密には発生する可能性はありますが、かなり低い確率です。）
define ("ResetCount", 100); # 設定しない場合は0
define ("ResetImage","resetimage.gif"); # 別画像を表示する場合は、画像のパスを設定

//------------------------------------------------------------

$REFERER = $_SERVER["REMOTE_ADDR"];

define ("log","./log.dat");
define ("count","./daydata.dat");
define ("today","./today.dat");

$count_up = 0;

$dg = $_GET["dg"]; //桁数
if($dg < 1 || $dg >10 || !$dg) $dg = 5 ;

$ct = $_GET["ct"]; //表示項目
if($ct < 1 || $ct > 4 || !$ct ) $ct = 4;

$image = img1;
if($_GET["im"] == 2) $image = img2;

$TimeStamp = time();

//総カウント数表示時のみカウント処理
if($ct == 4)
{
	$fp = fopen(log,"r") or die("logが開けません。");
	flock($fp, LOCK_SH);
	$log = file(log);
	flock($fp, LOCK_UN);
	fclose($fp); 

	foreach($log as $value)
	{
		list($old_time , $ip) = explode(",",rtrim($value));
		//IPのリストを作成
		if($old_time + BlockTime * 60 > $TimeStamp)
		{
			$IpData[$ip] = $old_time;
			$LogIp[$ip] = $value;
		}
	} 

	if(!$IpData[$REFERER])
	{
		$TmpCount = filesize(today);
		$LogIp[$REFERER] = $TimeStamp.",".$REFERER.",".$TmpCount."\n";

		//重複カウント防止ログ書き込み
		$fp = fopen(log,"r+") or die("logが開けません。");
		flock($fp, LOCK_EX);
		ftruncate($fp,0);
		rewind($fp);
		fputs($fp,implode('',$LogIp));    
		flock($fp, LOCK_UN);
		fclose($fp);
		
	    $WriteFlg = 1; //書き込み判定用フラグ
	}
	
}
else
{
	sleep(1);
}

//カウントデータ読み出し処理
function ReadCount()
{
	$fp = fopen(count,"r") or die("count.datが開けません。");
	flock($fp, LOCK_SH);
	$dt = fgets($fp,filesize(count));
	flock($fp, LOCK_UN);
	fclose($fp);
	
	return $dt;
}

	$CountDt = explode(",",rtrim(ReadCount()));
	$TodayCount = filesize(today);

//count.dat書き込み処理（ログの日付と違う場合にカウントファイルに書き込み））
if(date("Y/n/j",$TimeStamp) != date("Y/n/j",$CountDt[0]))
{ 

	$tmp = date("w",$TimeStamp) - date("w",$CountDt[0]);
	if($tmp < 0) $tmp = $tmp + 7;
	
	$CountDt[0] = $TimeStamp;

	$CountDt[4] = $CountDt[4] + $TodayCount; //総カウント
	$CountDt[3] = $CountDt[2]; //一昨日
	$CountDt[2] = $TodayCount; //昨日

	while($tmp > 1)
	{
		$tmp = $tmp - 1 ;
		$CountDt[3] = $CountDt[2];
		$CountDt[2] = 0;
	}
	
	//書き込み処理
	Do
	{ 
		$fp = fopen(count,"r+") or die("countが開けません。");
		flock($fp, LOCK_EX);
		ftruncate($fp,0);
		rewind($fp);
		fputs($fp,"$CountDt[0],$CountDt[1],$CountDt[2],$CountDt[3],$CountDt[4]\n");
		flock($fp, LOCK_UN);
		fclose($fp);
		
		$TmpCountDt = explode(",",rtrim(ReadCount()));
	} while ($TmpCountDt[0] < $CountDt[0]); //書き込まれた値が、変数よりも小さい場合は再書き込み

	//当日カウンタ初期化処理
	$fp = fopen(today, "a");
	flock($fp,LOCK_EX);
	ftruncate($fp,0);
	flock($fp , LOCK_UN);
	fclose($fp);
}

//当日のカウント処理
if($ct == 4 && $WriteFlg == 1)
{
	$fp = fopen(today, "a");
	flock($fp , LOCK_EX);
	fputs($fp,"x");
	flock($fp , LOCK_UN);
	fclose($fp);
}

clearstatcache(today);
$CountDt[1] = filesize(today);
$CountDt[4] = $CountDt[4] + $CountDt[1];
$ResetFlg = 0;
$images = Array();

if(ResetCount)
{
	if(!($CountDt[4] % ResetCount))
	{
		//ログファイルをリセット
		$fp = fopen(log,"r+") or die("logが開けません。");
		flock($fp, LOCK_EX);
		ftruncate($fp,0);
		rewind($fp);
		flock($fp, LOCK_UN);
		fclose($fp);
		
		$ResetFlg = 1;
	}
}

//連結画像ライブラリより画像出力
require("./gifcat.phps");
if (function_exists("i18n_http_output")) i18n_http_output("pass");
$gifcat = new gifcat;

if(!$ResetFlg || !ResetImage)
{
//データ整形処理
	$CountDt[$ct] = sprintf("%0".$dg."d",$CountDt[$ct]);

	for ($i = 0;$i < strlen($CountDt[$ct]);$i++)
	{
		$num = substr($CountDt[$ct],$i,1);
		$images[$i] = $image.$num.".gif";
	}
}
else
{
	$images[0] = ResetImage;
}

header("Content-Type: image/gif");
echo @$gifcat->output($images);

?>