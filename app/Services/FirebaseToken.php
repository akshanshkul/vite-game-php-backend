<?php
namespace App\Services;

/**
 * Verifies Firebase Authentication ID tokens (RS256 JWTs signed by Google)
 * without third-party libraries. See
 * https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
 */
class FirebaseToken
{
    private const CERTS = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
    private const SKEW = 60;

    /** @return array<string,mixed> verified claims, or null when invalid */
    public static function verify(string $jwt, string $projectId): ?array
    {
        $parts = explode(".", $jwt);
        if (count($parts) !== 3 || $projectId === "") {
            return null;
        }
        [$h, $p, $s] = $parts;
        $header = json_decode(self::b64($h), true);
        $claims = json_decode(self::b64($p), true);
        if (
            !is_array($header) ||
            !is_array($claims) ||
            ($header["alg"] ?? "") !== "RS256" ||
            !is_string($header["kid"] ?? null)
        ) {
            return null;
        }
        $cert = self::certs()[$header["kid"]] ?? null;
        if (
            !$cert ||
            openssl_verify("$h.$p", self::b64($s), $cert, OPENSSL_ALGO_SHA256) !== 1
        ) {
            return null;
        }
        $now = time();
        $ok =
            ($claims["aud"] ?? null) === $projectId &&
            ($claims["iss"] ?? null) === "https://securetoken.google.com/$projectId" &&
            is_string($claims["sub"] ?? null) &&
            $claims["sub"] !== "" &&
            is_int($claims["exp"] ?? null) &&
            $claims["exp"] > $now - self::SKEW &&
            is_int($claims["iat"] ?? null) &&
            $claims["iat"] <= $now + self::SKEW &&
            is_int($claims["auth_time"] ?? null) &&
            $claims["auth_time"] <= $now + self::SKEW;
        return $ok ? $claims : null;
    }

    private static function b64(string $v): string
    {
        return (string) base64_decode(strtr($v, "-_", "+/") . str_repeat("=", (4 - (strlen($v) % 4)) % 4));
    }

    /** Google's signing certificates, cached for as long as Google allows. */
    private static function certs(): array
    {
        $cache = cache();
        $certs = $cache->get("firebase_certs");
        if (is_array($certs)) {
            return $certs;
        }
        $res = service("curlrequest")->get(self::CERTS, [
            "timeout" => 5,
            "http_errors" => false,
        ]);
        $certs = json_decode($res->getBody(), true);
        if ($res->getStatusCode() !== 200 || !is_array($certs)) {
            return [];
        }
        $control = implode(",", array_map(
            fn($h) => $h->getValueLine(),
            (array) ($res->header("Cache-Control") ?? []),
        ));
        preg_match("/max-age=(\d+)/", $control, $m);
        $cache->save("firebase_certs", $certs, max(60, (int) ($m[1] ?? 3600)));
        return $certs;
    }
}
