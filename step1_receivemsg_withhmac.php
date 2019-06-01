<?php
    $json_str = file_get_contents('php://input'); //接收request的body
    $json_obj = json_decode($json_str); //轉成json格式
	
	$channel_secret = "ba0a6ea215e7493db7417484933b6075"; //channel secret
	$cal_signature = hash_hmac('sha256', $json_str, $channel_secret, true); //request的body加上channel secret做HMAC-SHA256
	$cal_signature = base64_encode($cal_signature); //base64 encode 得到signature
	
	$headers = apache_request_headers();
	$line_signature = "";
	foreach ($headers as $header => $value) {
		if($header == 'X-Line-Signature') {
			$line_signature = $value; //request header中的X-Line-Signature
		}
	}
	
	if ($line_signature != $cal_signature) {
		return;
	}

    $myfile = fopen("log.txt", "w+") or die("Unable to open file!"); //設定一個log.txt來印訊息
    fwrite($myfile, "\xEF\xBB\xBF".$json_str); //在字串前面加上\xEF\xBB\xBF轉成utf8格式
?>
