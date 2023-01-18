Garden Password
===============

[![CI](https://github.com/vanilla/garden-password/actions/workflows/ci.yml/badge.svg)](https://github.com/vanilla/garden-password/actions/workflows/ci.yml)
[![Packagist Version](https://img.shields.io/packagist/v/vanilla/garden-password.svg?style=flat-square)](https://packagist.org/packages/vanilla/garden-password)
![MIT License](https://img.shields.io/packagist/l/vanilla/garden-password.svg?style=flat-square)

Garden Password implements a common interface for various password hashing algorithms.

Why we made Garden Password
---------------------------

Although the industry seems to be settling on [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) as a standard for secure password hashes there are still a lot of legacy systems out there. When you want to import data from one of these legacy systems you will need some way to bridge the password hashes so that users can sign in without resetting their passwords.

Installation
------------

*Garden Password requires PHP 5.4 or higher. If you want to use the PhpPassword object prior to PHP 5.5 you can require the [password-compat](https://packagist.org/packages/ircmaxell/password-compat) package.*

Garden Password is [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md) compliant and can be installed using [composer](//getcomposer.org). Just add `vanilla/garden-password` to your composer.json.

```json
{
    "require": {
        "vanilla/garden-password": "~1.0"
    }
}
```

The PasswordInterface
---------------------

The **PasswordInterface** is the basic interface that all of the password algorithms adhere to. You should type hint to this interface and then choose an appropriate implementation for your application. We recommend using **PhpPassword** for new applications. The **PasswordInterface** is a very simple interface with only three methods.

### hash()

```php
public string hash(string $password)
```

Hash a plaintext password. This will return a one-way, salted hash that is appropriate to store in the database. Once you have this hash you should throw the plaintext password away.

### needsRehash()

```php
public string needsRehash(string $hash)
```

Check to see if an existing password hash needs to be re-hashed. A password needs to be re-hashed when the algorithm had a security concern that was later fixed. You usually call this method when a user signs in and you have their plaintext password. First check to see if their password verifies against the existing hash and then check to see if it needs to be updated. If you need to re-hash then hash the plaintext password again and store the new hash in the database. In this way you can gradually improve the security of your system.

### verify()

```php
public bool verify(string $password, string $hash)
```

Verify a password against a stored hash. This is the method you call to check a user's password when they sign in.

Contributing
------------

If you want to help build out this library we'd really appreciate it. Here are some great ways you can help:

1. Send pull requests with new hashing algorithms. If you know another system and know how its passwords work then send us an implementation.

2. If you know a password hashing algorithm that you want added, but don't want to make a pull-request that's okay. Create an issue and give us the details of the algorithm and we'll implement the algorithm if we can.

3. Send some example password/hash pairs for existing algorithms. If you are running a system with legacy passwords then you can send us some example passwords with their associated hashes. We can then add these to our unit tests. *Don't send us passwords you actually use! Just make a temporary password and send it along with its hash.*

**Note: We cannot reverse engineer a password hashing algorithm from example passwords and hashes.**
