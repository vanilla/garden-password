<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2014 Vanilla Forums Inc.
 * @license MIT
 */

namespace Garden\Password;

/**
 * Implements the password hashing algorithm of Xenforo.
 */
class XenforoPassword implements PasswordInterface {

    /**
     * @var string The name of the hashing function to use.
     */
    private $hashFunction;

    /**
     * Initialize an instance of this class.
     *
     * @param string $hashFunction The name of the hash function to use.
     * This is an function name that can be passed to {@link hash()}.
     * @see hash()
     */
    public function __construct($hashFunction = '') {
        if (!$hashFunction) {
            $hashFunction = 'sha256';
        }
        $this->hashFunction = $hashFunction;
    }

    /**
     * {@inheritdoc}
     */
    public function hash($password) {
        $salt = base64_encode(openssl_random_pseudo_bytes(12));
        $result = [
            'hashFunc' => $this->hashFunction,
            'hash' => $this->hashRaw($password, $salt, $this->hashFunction),
            'salt' => $salt
        ];

        return serialize($result);
    }

    /**
     * Hashes a password with a given salt.
     *
     * @param string $password The password to hash.
     * @param string $salt The password salt.
     * @param string $function The hashing function to use.
     * @return string Returns the password hash.
     */
    private function hashRaw($password, $salt, $function = '', $stored_hash = null) {
        if ($function == '') {
            $function = $this->hashFunction;
        }

        if($function !== 'crypt') {
            $calc_hash = hash($function, hash($function, $password).$salt);
        } else if(!is_null($stored_hash)){
            $calc_hash = crypt($password, $stored_hash);
        } else {
            throw new Gdn_UserException(t('Unknown hashing method.'));
        }


        return $calc_hash;
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash($hash) {
        list($stored_hash, $stored_salt) = $this->splitHash($hash);

        // Unsalted hashes should be rehashed.
        return $stored_hash === false || $stored_salt === false;
    }

    /**
     * {@inheritdoc}
     */
    public function verify($password, $hash) {
        list($stored_hash, $function, $stored_salt) = $this->splitHash($hash);

        $calc_hash = $this->hashRaw($password, $stored_salt, $function, $stored_hash);
        $result = $calc_hash === $stored_hash;

        return $result;
    }

    /**
     * Split the hash into its calculated hash and salt.
     *
     * @param string $hash The hash to split.
     * @return string[] An array in the form [$hash, $hashFunc, $salt].
     */
    private function splitHash($hash) {
        $parts = @unserialize($hash);

        if (!is_array($parts)) {
            $result = ['', '', ''];
        } else {
            $parts += ['hash' => '', 'hashFunc' => '', 'salt' => ''];

            if (!$parts['hashFunc']) {
                switch (strlen($parts['hash'])) {
                    //xf11, XenForo_Authentication_Core11
                    case 32:
                        $parts['hashFunc'] = 'md5';
                        break;
                    case 40:
                        $parts['hashFunc'] = 'sha1';
                        break;
                    //xf12, XenForo_Authentication_Core12
                    default:
                        $parts['hashFunc'] = 'crypt';
                        break;
                }
            }

            $result = [$parts['hash'], $parts['hashFunc'], $parts['salt']];
        }
        return $result;
    }

    /**
     * Get the hash function.
     *
     * @return string Returns the name of hash function.
     */
    public function getHashFunction() {
        return $this->hashFunction;
    }

    /**
     * Set the hash function.
     *
     * @param string $hashFunction The name of the new hash function. Some examples would be: crypt, sha256, sha1.
     * @return XenforoPassword Returns `$this` for fluent calls.
     */
    public function setHashFunction($hashFunction) {
        $this->hashFunction = $hashFunction;
        return $this;
    }
}
