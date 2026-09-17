<?php
declare(strict_types=1);

function entry(): void
{
    controlPositive();
    symbolPositive();
    opaqueDispatch((string) getenv("REACHBENCH_CONTROL"));
}

function controlPositive(): void {}
function controlUnreachable(): void {}

function opaqueDispatch(string $name): void
{
    $handlers = ["opaque" => "controlOpaque"];
    if (isset($handlers[$name])) {
        $handlers[$name]();
    }
}

function controlOpaque(): void {}
function controlNoCoverage(): void {}

function symbolPositive(): void {}

entry();
