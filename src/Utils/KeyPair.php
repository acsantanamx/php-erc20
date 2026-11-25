<?php
/**
 * User: Lessmore92
 * Date: 11/22/2020
 * Time: 5:26 AM
 */

namespace Lessmore92\Ethereum\Utils;


use InvalidArgumentException;
use kornrunner\Keccak;
use Elliptic\EC;

class KeyPair
{
    /**
     * SHA3_NULL_HASH
     *
     * @const string
     */
    const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    protected static ?EC $secp256k1 = null;

    private static function secp256k1(): EC
    {
        if (self::$secp256k1 === null) {
            self::$secp256k1 = new EC('secp256k1');
        }
        return self::$secp256k1;
    }

    public static function privateKeyToAddress(string $privateKey): string
    {
        $publicKey = self::privateKeyToPublicKey($privateKey);
        return self::publicKeyToAddress($publicKey);
    }

    /**
     * publicKeyToAddress
     *
     * @param string $publicKey
     * @throws InvalidArgumentException
     * @return string
     */
    public static function publicKeyToAddress(string $publicKey): string
    {
        if (!preg_match('/^(0x)?[a-fA-F0-9]+$/', $publicKey)) {
            throw new InvalidArgumentException('Invalid public key format.');
        }
        $publicKey = self::stripZero($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new InvalidArgumentException('Invalid public key length.');
        }
        return '0x' . substr(self::sha3(substr(hex2bin($publicKey), 1)), 24);
    }

    /**
     * privateKeyToPublicKey
     *
     * @param string $privateKey
     * @throws InvalidArgumentException
     * @return string
     */
    public static function privateKeyToPublicKey(string $privateKey): string
    {
        if (!preg_match('/^(0x)?[a-fA-F0-9]+$/', $privateKey)) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKey = self::stripZero($privateKey);

        if (strlen($privateKey) !== 64) {
            throw new InvalidArgumentException('Invalid private key length.');
        }
        $key = self::secp256k1()->keyFromPrivate($privateKey, 'hex');
        $publicKey = $key->getPublic(false, 'hex');

        return '0x' . $publicKey;
    }

    /**
     * sha3 / keccak256
     *
     * @param string $value
     * @return null|string
     */
    protected static function sha3(string $value): ?string
    {
        $hash = Keccak::hash($value, 256);

        if ($hash === self::SHA3_NULL_HASH) {
            return null;
        }
        return $hash;
    }

    protected static function stripZero(string $value): string
    {
        if (strpos($value, '0x') === 0) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }
}
