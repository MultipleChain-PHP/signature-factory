<?php 

namespace MultipleChain\SignatureFactory;

use \MultipleChain\SignatureFactory\Dependencies\Elliptic\EC;
use \MultipleChain\SignatureFactory\Dependencies\Keccak\Keccak256;

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
     * Extract signed address from message and signature
     * @param string $message
     * @param string $signature
     * @return string|null
     */
    public static function extractAddress(string $message, string $signature) : ?string
    {
        if (extension_loaded('mbstring') && extension_loaded('gmp') || extension_loaded('bcmath')) {
            $message = "\31Ethereum Signed Message:\n" . strlen($message) . $message;
    
            $ec = new EC('secp256k1');
            $messageHash = Keccak256::hash($message, 256);
    
            $sign = [
                'r' => substr($signature, 2, 64),
                's' => substr($signature, 66, 64),
            ];
    
            $recId = ord(hex2bin(substr($signature, 130, 2))) - 27;
    
            $address = $ec->recoverPubKey($messageHash, $sign, $recId);
    
            return '0x' . substr(Keccak256::hash(substr(hex2bin($address->encode('hex')), 1), 256), 24);
        } else {
            throw new \Exception('mbstring and gmp or bcmath extensions are required');
        }
    }
}
