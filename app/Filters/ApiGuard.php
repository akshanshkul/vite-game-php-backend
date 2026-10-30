<?php
namespace App\Filters;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
class ApiGuard implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        $response = service("response");
        $session = session();
        if (strlen($request->getBody()) > 262144) {
            return $response
                ->setStatusCode(413)
                ->setJSON([
                    "code" => "PAYLOAD_TOO_LARGE",
                    "message" => "Payload exceeds limit",
                    "requestId" => bin2hex(random_bytes(8)),
                ]);
        }
        if (
            !service("throttler")->check(
                "api-" . hash("sha256", $request->getIPAddress()),
                180,
                60,
            )
        ) {
            return $response
                ->setStatusCode(429)
                ->setJSON([
                    "code" => "RATE_LIMIT",
                    "message" => "Please try again later",
                    "requestId" => bin2hex(random_bytes(8)),
                ]);
        }
        if (
            !in_array(
                strtoupper($request->getMethod()),
                ["GET", "HEAD", "OPTIONS"],
                true,
            )
        ) {
            try {
                $decoded = json_decode(
                    $request->getBody(),
                    true,
                    512,
                    JSON_THROW_ON_ERROR,
                );
                if (!is_array($decoded)) {
                    throw new \JsonException();
                }
            } catch (\JsonException $e) {
                return $response
                    ->setStatusCode(400)
                    ->setJSON([
                        "code" => "INVALID_JSON",
                        "message" => "Send a JSON object",
                        "requestId" => bin2hex(random_bytes(8)),
                    ]);
            }
            $origin = $request->getHeaderLine("Origin");
            $base = rtrim(config("App")->baseURL, "/");
            $allowed = [$base];
            if (ENVIRONMENT === "development") {
                $allowed = array_merge($allowed, [
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://127.0.0.1:4174",
                ]);
                // The Vite dev server on any local port (it moves off 5173
                // when that port is busy), or opened from a phone on the
                // local network, e.g. http://192.168.x.x:5173.
                if (
                    preg_match(
                        '#^http://((localhost|127\.0\.0\.1)|(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)[\d.]+):\d+$#',
                        $origin,
                    )
                ) {
                    $allowed[] = $origin;
                }
            }
            if (
                ($origin && !in_array($origin, $allowed, true)) ||
                !$session->get("csrf") ||
                !hash_equals(
                    $session->get("csrf"),
                    $request->getHeaderLine("X-CSRF-Token"),
                )
            ) {
                return $response
                    ->setStatusCode(403)
                    ->setJSON([
                        "code" => "CSRF",
                        "message" => "Refresh your session and try again",
                        "requestId" => bin2hex(random_bytes(8)),
                    ]);
            }
        }
    }
    public function after(
        RequestInterface $request,
        ResponseInterface $response,
        $arguments = null,
    ) {
        $response
            ->setHeader("Cache-Control", "no-store")
            ->setHeader("X-Content-Type-Options", "nosniff")
            ->setHeader("Referrer-Policy", "same-origin")
            ->setHeader("X-Frame-Options", "DENY");
    }
}
