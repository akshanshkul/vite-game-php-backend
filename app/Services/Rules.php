<?php
namespace App\Services;
use InvalidArgumentException;
final class Rules
{
    const EPS = 0.0000001;
    private static function overlap(float $a, float $b): bool
    {
        return min($a + 2, $b + 2) - max($a, $b) > self::EPS;
    }
    public static function free(array $tiles, string $id): bool
    {
        $t = null;
        foreach ($tiles as $v) {
            if ($v["id"] === $id) {
                $t = $v;
            }
        }
        if (!$t || $t["removed"]) {
            return false;
        }
        $left = false;
        $right = false;
        foreach ($tiles as $o) {
            if ($o["removed"] || $o["id"] === $id) {
                continue;
            }
            if (
                $o["z"] > $t["z"] &&
                self::overlap($o["x"], $t["x"]) &&
                self::overlap($o["y"], $t["y"])
            ) {
                return false;
            }
            if (
                (float) $o["z"] === (float) $t["z"] &&
                self::overlap($o["y"], $t["y"])
            ) {
                if (abs($o["x"] - $t["x"] + 2) < self::EPS) {
                    $left = true;
                }
                if (abs($o["x"] - $t["x"] - 2) < self::EPS) {
                    $right = true;
                }
            }
        }
        return !$left || !$right;
    }
    public static function replay(array $tiles, array $moves): array
    {
        if (count($moves) > 500) {
            throw new InvalidArgumentException("Too many moves");
        }
        foreach ($moves as $pair) {
            if (
                !is_array($pair) ||
                count($pair) !== 2 ||
                !is_string($pair[0]) ||
                !is_string($pair[1]) ||
                $pair[0] === $pair[1]
            ) {
                throw new InvalidArgumentException("Invalid pair");
            }
            $a = null;
            $b = null;
            foreach ($tiles as $t) {
                if ($t["id"] === $pair[0]) {
                    $a = $t;
                }
                if ($t["id"] === $pair[1]) {
                    $b = $t;
                }
            }
            if (
                !$a ||
                !$b ||
                $a["matchGroup"] !== $b["matchGroup"] ||
                !self::free($tiles, $a["id"]) ||
                !self::free($tiles, $b["id"])
            ) {
                throw new InvalidArgumentException("Illegal move");
            }
            foreach ($tiles as &$t) {
                if (in_array($t["id"], $pair, true)) {
                    $t["removed"] = true;
                }
            }
            unset($t);
        }
        if (count(array_filter($tiles, fn($t) => !$t["removed"]))) {
            throw new InvalidArgumentException("Incomplete game");
        }
        return ["score" => count($moves) * 100, "pairs" => count($moves)];
    }
    public static function validate(array $p): void
    {
        if (
            !isset($p["tiles"], $p["solution"]) ||
            !is_array($p["tiles"]) ||
            !is_array($p["solution"]) ||
            count($p["tiles"]) < 2 ||
            count($p["tiles"]) > 144 ||
            count($p["tiles"]) % 2
        ) {
            throw new InvalidArgumentException("Invalid tile count");
        }
        $ids = [];
        foreach ($p["tiles"] as $t) {
            if (!is_array($t)) {
                throw new InvalidArgumentException("Invalid tile");
            }
            foreach (
                ["id", "x", "y", "z", "suit", "rank", "matchGroup", "removed"]
                as $k
            ) {
                if (!array_key_exists($k, $t)) {
                    throw new InvalidArgumentException("Missing tile field");
                }
            }
            if (
                !is_string($t["id"]) ||
                isset($ids[$t["id"]]) ||
                $t["removed"] !== false
            ) {
                throw new InvalidArgumentException("Invalid tile");
            }
            $ids[$t["id"]] = true;
            foreach (["x", "y", "z"] as $k) {
                if (
                    (!is_int($t[$k]) && !is_float($t[$k])) ||
                    !is_finite((float) $t[$k])
                ) {
                    throw new InvalidArgumentException("Invalid geometry");
                }
            }
            if ($t["z"] < 0 || floor($t["z"]) != $t["z"]) {
                throw new InvalidArgumentException("Invalid layer");
            }
            if (
                !in_array(
                    $t["suit"],
                    [
                        "bamboo",
                        "dots",
                        "characters",
                        "winds",
                        "dragons",
                        "flowers",
                        "seasons",
                    ],
                    true,
                )
            ) {
                throw new InvalidArgumentException("Invalid suit");
            }
            $max = in_array($t["suit"], ["flowers", "seasons", "winds"])
                ? 4
                : ($t["suit"] === "dragons"
                    ? 3
                    : 9);
            if (
                !is_string($t["rank"]) ||
                !preg_match('/^[1-9]$/', $t["rank"]) ||
                (int) $t["rank"] > $max
            ) {
                throw new InvalidArgumentException("Invalid rank");
            }
            $expected = in_array($t["suit"], ["flowers", "seasons"])
                ? $t["suit"]
                : $t["suit"] . ":" . $t["rank"];
            if ($t["matchGroup"] !== $expected) {
                throw new InvalidArgumentException("Invalid match group");
            }
        }
        foreach ($p["tiles"] as $i => $t) {
            foreach (array_slice($p["tiles"], $i + 1) as $o) {
                if (
                    (float) $o["z"] === (float) $t["z"] &&
                    self::overlap($o["x"], $t["x"]) &&
                    self::overlap($o["y"], $t["y"])
                ) {
                    throw new InvalidArgumentException("Overlapping slots");
                }
            }
        }
        self::replay($p["tiles"], $p["solution"]);
    }
}
