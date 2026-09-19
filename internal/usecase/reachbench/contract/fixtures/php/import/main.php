<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

\Reachbench\Direct\Entry::run();
$opaqueClass = implode('\\', ['Reachbench', 'Dynamic', 'Entry']);
if (class_exists($opaqueClass)) {
    $opaqueClass::run();
}
