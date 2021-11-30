<?php
/**
 * @author Olivier Lamy-Canuel <olamy-canuel@higherlogic.com>
 * @copyright 2006 Drupal (Original source code)
 * @copyright 2021 Higher Logic (Source code changes)
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 *
 */

namespace Garden\Password;

use Mdespeuilles\DrupalPasswordEncoderBundle\Services\DrupalPasswordEncoder;
use Mdespeuilles\DrupalPasswordEncoderBundle\Services\Password\PhpassHashedPassword;

/**
 * Implements Drupal's password hashing algorithm. Valid for Drupal 7 and 8.
 */
class DrupalPassword implements PasswordInterface {

    /**
     * Check for a correct password.
     *
     * @param string $password The password in plain text.
     * @param string $hash The stored password hash.
     * @return bool Returns true if the password is correct, false if not.
     */
    public function verify($password, $hash) {
        return DrupalPasswordEncoder::isPasswordValid($hash, $password, NULL);
    }

    /**
     * Hashes a plaintext password.
     *
     * @param string $password The password to hash.
     * @return string Returns the hashed password.
     */
    public function hash($password) {
        return DrupalPasswordEncoder::encodePassword($password);
    }

    /**
     * Checks if a given password hash needs to be re-hashed to a stronger algorithm.
     *
     * @param string $hash The hash to check.
     * @return bool Returns `true`
     */
    public function needsRehash($hash) {
        return PhpassHashedPassword::needsRehash($hash);
    }
}
