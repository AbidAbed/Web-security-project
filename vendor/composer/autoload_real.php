<?php

// autoload_real.php @generated by Composer

class ComposerAutoloaderInitf6f76aa70fe9e977bf3cd44f4d5e5f0a
{
    private static $loader;

    public static function loadClassLoader($class)
    {
        if ('Composer\Autoload\ClassLoader' === $class) {
            require __DIR__ . '/ClassLoader.php';
        }
    }

    /**
     * @return \Composer\Autoload\ClassLoader
     */
    public static function getLoader()
    {
        if (null !== self::$loader) {
            return self::$loader;
        }

        require __DIR__ . '/platform_check.php';

        spl_autoload_register(array('ComposerAutoloaderInitf6f76aa70fe9e977bf3cd44f4d5e5f0a', 'loadClassLoader'), true, true);
        self::$loader = $loader = new \Composer\Autoload\ClassLoader(\dirname(__DIR__));
        spl_autoload_unregister(array('ComposerAutoloaderInitf6f76aa70fe9e977bf3cd44f4d5e5f0a', 'loadClassLoader'));

        require __DIR__ . '/autoload_static.php';
        call_user_func(\Composer\Autoload\ComposerStaticInitf6f76aa70fe9e977bf3cd44f4d5e5f0a::getInitializer($loader));

        $loader->register(true);

        return $loader;
    }
}
