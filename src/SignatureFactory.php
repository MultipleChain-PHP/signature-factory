<?php 

namespace Beycan\SignatureFactory;

use \Beycan\SignatureFactory\Dependencies\Keccak\Keccak256;
use \Beycan\SignatureFactory\Dependencies\Elliptic\EC;

class SignatureFactory
{
    /**
     * @param string $address
     * @param string $siteKey
     * @return string
     */
    public static function createHash(string $address, string $siteKey = 'sf') : string
    {
        return "SF" . hash_hmac('md5', $address, $siteKey);
    }

    /**
     * @param string $message
     * @param string $signature
     * @return string|null
     */
    public static function extractAddress(string $message, string $signature) : ?string
    {
        if (extension_loaded('mbstring') && extension_loaded('gmp') || extension_loaded('bcmath')) {
            return self::extractAddressWithPhp($message, $signature);
        } else {
            return self::extractAddressWithApi($message, $signature);
        }
    }

    /**
     * @param string $message
     * @param string $signature
     * @return string
     */
	private static function extractAddressWithPhp(string $message, string $signature) : string
    {
        $message = "\31Ethereum Signed Message:\n" . strlen($message) . $message;

        $messageHash = Keccak256::hash($message, 256);
        $ec = new EC('secp256k1');

        $sign = [
            'r' => substr($signature, 2, 64),
            's' => substr($signature, 66, 64),
        ];

        $recid = ord(hex2bin(substr($signature, 130, 2))) - 27;

        $pubKey = $ec->recoverPubKey($messageHash, $sign, $recid);

        return '0x' . substr(Keccak256::hash(substr(hex2bin($pubKey->encode('hex')), 1), 256), 24);
    }

    /**
     * @param string $message
     * @param string $signature
     * @return string|null
     */
	private static function extractAddressWithApi(string $message, string $signature) : ?string
    {
        $data = [
            'message'   => $message,
            'signature' => $signature,
        ];
		
		$curl = curl_init('https://extract-address.herokuapp.com/');
		curl_setopt_array($curl, [
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => $data,
			CURLOPT_RETURNTRANSFER => true
		]);
		
		$result = curl_exec($curl);
		curl_close($curl);
        
        if (!empty($result) ) {
            return json_decode($result)->data->address;
        } else {
            return null;
        }
    }

}