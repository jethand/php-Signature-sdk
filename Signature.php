<?php

    // SignatureNonce
    private function getSignatureNonce(){
        $chars  = md5(uniqid(mt_rand(), true));
        $uuid  = substr($chars,0,8) . '-';
        $uuid .= substr($chars,8,4) . '-';
        $uuid .= substr($chars,12,4) . '-';
        $uuid .= substr($chars,16,4) . '-';
        $uuid .= substr($chars,20,12);
        return $uuid;
    }
    
    // percentEncode
    protected function percentEncode($str){
        $res = urlencode($str);
        $res = preg_replace('/\+/', '%20', $res);
        $res = preg_replace('/\*/', '%2A', $res);
        $res = preg_replace('/%7E/', '~', $res);
        return $res;
    }

    // getSignature
    private function getSignature($str, $key){  
        $signature = "";  
        if(function_exists('hash_hmac')){  
            $signature = base64_encode(hash_hmac("sha1", $str, $key, true));  
        }else{  
            $blocksize = 64;  
            $hashfunc = 'sha1';  
            if(strlen($key) > $blocksize){  
                $key = pack('H*', $hashfunc($key));  
            }  
            $key = str_pad($key, $blocksize, chr(0x00));  
            $ipad = str_repeat(chr(0x36), $blocksize);  
            $opad = str_repeat(chr(0x5c), $blocksize);  
            $hmac = pack(  
                'H*', $hashfunc(  
                    ($key ^ $opad) . pack(  
                        'H*', $hashfunc(  
                                ($key ^ $ipad) . $str  
                        )  
                    )  
                )  
            );  
            $signature = base64_encode($hmac);  
        }  
        return $signature;  
    }

    // computeSignature
    $parameters = array(
        "AccessKeyId" => $AccessKeyId,
        "Timestamp" => gmdate('Y-m-d\TH:i:s\Z'),
        "Action" => $ActionType,
        "Format" => "JSON",
        "Version" => "2017-03-21",
        "SignatureMethod" => "HMAC-SHA1",
        "SignatureNonce" => $this->getSignatureNonce(),
        "SignatureVersion" => "1.0",
        "PageNo" => $PageNo,
        "PageSize" => $PageSize,
        "BizDate" => $DateNow
    );
    private function computeSignature($parameters, $accessKeySecret){
        ksort($parameters);
        $canonicalizedQueryString = '';
        foreach($parameters as $key => $value){
            $canonicalizedQueryString .= '&' . $this->percentEncode($key) . '=' . $this->percentEncode($value);
        }
        $stringToSign = "GET&" . $this->percentencode("/") . "&" . $this->percentencode(substr($canonicalizedQueryString,1));
        $signature = $this->getSignature($stringToSign, $accessKeySecret . '&');
        return $signature;
    }

    // totalCurlRequest
    private function totalCurlRequest($url){
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  
        curl_setopt ($curl, CURLOPT_TIMEOUT, 10 );
        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }
?>