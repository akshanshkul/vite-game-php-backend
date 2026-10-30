<?php
namespace App\Controllers\Api;
use CodeIgniter\RESTful\ResourceController;
use App\Services\Rules;
class Game extends ResourceController
{
    protected $format = "json";
    private function db()
    {
        return db_connect();
    }
    private function id(): string
    {
        return bin2hex(random_bytes(16));
    }
    private function now(): string
    {
        return gmdate("c");
    }
    private function body(): array
    {
        return $this->request->getJSON(true) ?? [];
    }
    private function error(string $code, string $message, int $status = 400)
    {
        return $this->response
            ->setStatusCode($status)
            ->setJSON([
                "code" => $code,
                "message" => $message,
                "requestId" => $this->id(),
            ]);
    }
    private function user(): ?array
    {
        $id = session()->get("user_id");
        return $id
            ? $this->db()
                ->table("users")
                ->where(["id" => $id, "status" => "active"])
                ->get()
                ->getRowArray()
            : null;
    }
    private function admin(): ?array
    {
        $u = $this->user();
        return $u && $u["role"] === "admin" ? $u : null;
    }
    private function publicUser(array $u): array
    {
        return array_intersect_key(
            $u,
            array_flip(["id", "email", "display_name", "role"]),
        );
    }
    private function lockWallet(string $uid): void
    {
        if ($this->db()->DBDriver === "MySQLi") {
            $this->db()->query(
                "SELECT id FROM wallets WHERE user_id = ? FOR UPDATE",
                [$uid],
            );
        }
    }
    public function health()
    {
        return $this->respond(["status" => "ok", "rulesVersion" => "1"]);
    }
    public function csrf()
    {
        if (!session()->get("csrf")) {
            session()->set("csrf", bin2hex(random_bytes(32)));
        }
        return $this->respond(["token" => session()->get("csrf")]);
    }
    public function register()
    {
        $b = $this->body();
        $email = strtolower(
            trim(is_string($b["email"] ?? null) ? $b["email"] : ""),
        );
        $password = $b["password"] ?? "";
        $name = trim(
            is_string($b["displayName"] ?? null)
                ? $b["displayName"]
                : "Gardener",
        );
        if (
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            strlen($email) > 254 ||
            !is_string($password) ||
            strlen($password) < 12 ||
            strlen($password) > 128 ||
            mb_strlen($name) < 1 ||
            mb_strlen($name) > 40
        ) {
            return $this->error(
                "VALIDATION",
                "Use a valid email, a 12–128 character password and a name under 40 characters.",
            );
        }
        if (
            !service("throttler")->check(
                "register-" . hash("sha256", $this->request->getIPAddress()),
                10,
                3600,
            )
        ) {
            return $this->error("RATE_LIMIT", "Please try later.", 429);
        }
        if (
            $this->db()
                ->table("users")
                ->where("email", $email)
                ->countAllResults()
        ) {
            return $this->error(
                "ACCOUNT_UNAVAILABLE",
                "Unable to create this account.",
                409,
            );
        }
        $id = $this->createUser(
            $email,
            password_hash($password, PASSWORD_ARGON2ID),
            $name,
        );
        if (!$id) {
            return $this->error(
                "ACCOUNT_UNAVAILABLE",
                "Unable to create account.",
                409,
            );
        }
        session()->regenerate(true);
        session()->set("user_id", $id);
        return $this->respondCreated([
            "user" => $this->publicUser($this->user()),
        ]);
    }
    /** Inserts a player and their wallet; returns the new id or null. */
    private function createUser(string $email, string $hash, string $name): ?string
    {
        $id = $this->id();
        $this->db()->transStart();
        $this->db()
            ->table("users")
            ->insert([
                "id" => $id,
                "email" => $email,
                "password_hash" => $hash,
                "display_name" => $name,
                "role" => "player",
                "status" => "active",
                "created_at" => $this->now(),
                "updated_at" => $this->now(),
            ]);
        $this->db()
            ->table("wallets")
            ->insert([
                "id" => $id,
                "user_id" => $id,
                "coin_balance" => 0,
                "version" => 1,
                "created_at" => $this->now(),
            ]);
        $this->db()->transComplete();
        return $this->db()->transStatus() ? $id : null;
    }
    /**
     * Google sign-in: the browser signs in with Firebase and sends its ID
     * token. A verified Google email signs into the matching account, or
     * creates one. Google-only accounts have no usable password hash.
     */
    public function google()
    {
        if (
            !service("throttler")->check(
                "google-" . hash("sha256", $this->request->getIPAddress()),
                20,
                900,
            )
        ) {
            return $this->error("RATE_LIMIT", "Too many sign-in attempts.", 429);
        }
        $token = $this->body()["idToken"] ?? null;
        $claims = is_string($token) && strlen($token) < 4096
            ? \App\Services\FirebaseToken::verify(
                $token,
                (string) env("FIREBASE_PROJECT_ID", ""),
            )
            : null;
        $email = strtolower(trim((string) ($claims["email"] ?? "")));
        if (
            !$claims ||
            ($claims["email_verified"] ?? false) !== true ||
            !filter_var($email, FILTER_VALIDATE_EMAIL)
        ) {
            return $this->error(
                "LOGIN_FAILED",
                "Google sign-in could not be verified.",
                401,
            );
        }
        $u = $this->db()
            ->table("users")
            ->where("email", $email)
            ->get()
            ->getRowArray();
        if (!$u) {
            $name = mb_substr(
                trim((string) ($claims["name"] ?? "")) ?: strstr($email, "@", true),
                0,
                40,
            );
            $id = $this->createUser($email, "", $name);
            $u = $id
                ? $this->db()->table("users")->where("id", $id)->get()->getRowArray()
                : null;
        }
        if (!$u || $u["status"] !== "active") {
            return $this->error(
                "ACCOUNT_UNAVAILABLE",
                "Unable to sign in with this account.",
                403,
            );
        }
        session()->regenerate(true);
        session()->set("user_id", $u["id"]);
        return $this->respond(["user" => $this->publicUser($u)]);
    }
    public function login()
    {
        $b = $this->body();
        $email = strtolower(
            trim(is_string($b["email"] ?? null) ? $b["email"] : ""),
        );
        $password = is_string($b["password"] ?? null) ? $b["password"] : "";
        if (
            !service("throttler")->check(
                "login-" .
                    hash(
                        "sha256",
                        $email . "-" . $this->request->getIPAddress(),
                    ),
                10,
                900,
            )
        ) {
            return $this->error("RATE_LIMIT", "Too many login attempts.", 429);
        }
        $u = $this->db()
            ->table("users")
            ->where("email", $email)
            ->get()
            ->getRowArray();
        if (
            !$u ||
            !password_verify($password, $u["password_hash"]) ||
            $u["status"] !== "active"
        ) {
            return $this->error(
                "LOGIN_FAILED",
                "Email or password is incorrect.",
                401,
            );
        }
        session()->regenerate(true);
        session()->set("user_id", $u["id"]);
        return $this->respond(["user" => $this->publicUser($u)]);
    }
    public function logout()
    {
        session()->destroy();
        return $this->respond(["ok" => true]);
    }
    public function me()
    {
        return ($u = $this->user())
            ? $this->respond(["user" => $this->publicUser($u)])
            : $this->error("AUTH_REQUIRED", "Please sign in.", 401);
    }
    public function levels()
    {
        $cursor = max(0, (int) $this->request->getGet("cursor"));
        $items = $this->db()
            ->table("levels")
            ->select("id,level_number,layout_id,difficulty,puzzle_hash")
            ->where("status", "published")
            ->where("level_number <", 200000)
            ->where("level_number >", $cursor)
            ->orderBy("level_number")
            ->limit(25)
            ->get()
            ->getResultArray();
        return $this->respond([
            "items" => $items,
            "nextCursor" =>
                count($items) === 25 ? (int) end($items)["level_number"] : null,
        ]);
    }
    public function level($id)
    {
        $l = $this->db()
            ->table("levels")
            ->where(["id" => $id, "status" => "published"])
            ->get()
            ->getRowArray();
        return $l
            ? $this->respond([
                "puzzle" => json_decode($l["puzzle_json"], true),
                "hash" => $l["puzzle_hash"],
            ])
            : $this->error("NOT_FOUND", "Level unavailable.", 404);
    }
    public function layouts()
    {
        return $this->respond([
            "items" => $this->db()
                ->table("layouts")
                ->where("status", "published")
                ->get()
                ->getResultArray(),
        ]);
    }
    public function daily($date)
    {
        if (
            !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) ||
            date("Y-m-d", strtotime($date)) !== $date
        ) {
            return $this->error("VALIDATION", "Use a valid UTC date.");
        }
        $d = $this->db()
            ->table("daily_challenges")
            ->where(["challenge_date" => $date, "status" => "published"])
            ->get()
            ->getRowArray();
        if (!$d) {
            return $this->error(
                "NOT_PUBLISHED",
                "Daily challenge has not been published.",
                404,
            );
        }
        return $this->level($d["level_id"]);
    }
    public function progress()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        return $this->respond([
            "items" => $this->db()
                ->table("player_progress")
                ->where("user_id", $u["id"])
                ->get()
                ->getResultArray(),
            "serverVersion" =>
                (int) ($this->db()
                    ->table("wallets")
                    ->where("user_id", $u["id"])
                    ->get()
                    ->getRowArray()["version"] ?? 0),
        ]);
    }
    public function sync()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $events = $this->body()["events"] ?? null;
        if (!is_array($events) || count($events) > 100) {
            return $this->error("VALIDATION", "Send at most 100 events.");
        }
        foreach ($events as $e) {
            if (
                !is_array($e) ||
                !is_string($e["id"] ?? null) ||
                !preg_match('/^[a-zA-Z0-9:_-]{1,128}$/', $e["id"]) ||
                ($e["type"] ?? "") !== "completion" ||
                !is_array($e["payload"] ?? null) ||
                !is_string($e["payload"]["puzzleId"] ?? null) ||
                !is_int($e["payload"]["score"] ?? null) ||
                $e["payload"]["score"] < 0 ||
                $e["payload"]["score"] > 7200 ||
                !is_numeric($e["payload"]["elapsedMs"] ?? null) ||
                $e["payload"]["elapsedMs"] < 0 ||
                $e["payload"]["elapsedMs"] > 86400000
            ) {
                return $this->error("VALIDATION", "Invalid completion event.");
            }
        }
        $this->db()->transStart();
        $this->lockWallet($u["id"]);
        $ack = [];
        foreach ($events as $e) {
            $duplicate = $this->db()
                ->table("sync_events")
                ->where(["user_id" => $u["id"], "client_event_id" => $e["id"]])
                ->countAllResults();
            if ($duplicate) {
                $ack[] = $e["id"];
                continue;
            }
            $p = $e["payload"];
            $level = $this->db()
                ->table("levels")
                ->where(["id" => $p["puzzleId"], "status" => "published"])
                ->get()
                ->getRowArray();
            if (!$level) {
                continue;
            }
            $ack[] = $e["id"];
            $old = $this->db()
                ->table("player_progress")
                ->where(["user_id" => $u["id"], "level_id" => $p["puzzleId"]])
                ->get()
                ->getRowArray();
            $row = [
                "user_id" => $u["id"],
                "level_id" => $p["puzzleId"],
                "best_score" => max(
                    (int) ($old["best_score"] ?? 0),
                    $p["score"],
                ),
                "best_time_ms" => min(
                    (int) ($old["best_time_ms"] ?? 86400000),
                    (int) $p["elapsedMs"],
                ),
                "stars" => max(
                    (int) ($old["stars"] ?? 1),
                    min(3, max(1, (int) ($p["stars"] ?? 1))),
                ),
                "version" => (int) ($old["version"] ?? 0) + 1,
                "completed_at" => $this->now(),
            ];
            if ($old) {
                $this->db()
                    ->table("player_progress")
                    ->where("id", $old["id"])
                    ->update($row);
            } else {
                $this->db()
                    ->table("player_progress")
                    ->insert(
                        $row + [
                            "id" => $this->id(),
                            "created_at" => $this->now(),
                        ],
                    );
            }
            $this->db()
                ->table("sync_events")
                ->insert([
                    "id" => $this->id(),
                    "user_id" => $u["id"],
                    "client_event_id" => $e["id"],
                    "event_type" => "casual-completion",
                    "payload_json" => json_encode($p),
                    "server_version" => $row["version"],
                    "created_at" => $this->now(),
                ]);
        }
        $this->db()
            ->table("wallets")
            ->where("user_id", $u["id"])
            ->set("version", "version+1", false)
            ->update();
        $this->db()->transComplete();
        return $this->respond([
            "acknowledged" => $ack,
            "items" => $this->db()
                ->table("player_progress")
                ->where("user_id", $u["id"])
                ->get()
                ->getResultArray(),
            "activeRunPolicy" =>
                "Keep different active boards separate. This endpoint merges completed progress only.",
        ]);
    }
    private function signingKey(): string
    {
        return (string) env("RUN_SIGNING_KEY", "");
    }
    public function run()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        if (strlen($this->signingKey()) < 32) {
            return $this->error(
                "SERVICE_UNAVAILABLE",
                "Online run signing is not configured.",
                503,
            );
        }
        $id = $this->body()["puzzleId"] ?? "";
        if (!is_string($id)) {
            return $this->error("VALIDATION", "Invalid puzzle.");
        }
        $l = $this->db()
            ->table("levels")
            ->where(["id" => $id, "status" => "published"])
            ->get()
            ->getRowArray();
        if (!$l) {
            return $this->error("NOT_FOUND", "Puzzle unavailable.", 404);
        }
        $rid = $this->id();
        $nonce = $this->id();
        $expires = time() + 3600;
        $payload = base64_encode(
            json_encode(
                [
                    "run" => $rid,
                    "user" => $u["id"],
                    "hash" => $l["puzzle_hash"],
                    "rules" => "1",
                    "expires" => $expires,
                    "nonce" => $nonce,
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $ticket =
            $payload . "." . hash_hmac("sha256", $payload, $this->signingKey());
        $this->db()
            ->table("game_runs")
            ->insert([
                "id" => $rid,
                "user_id" => $u["id"],
                "level_id" => $id,
                "puzzle_hash" => $l["puzzle_hash"],
                "nonce_hash" => hash("sha256", $nonce),
                "expires_at" => $expires,
                "started_at" => time(),
                "completed_at" => 0,
                "elapsed_ms" => 0,
                "score" => 0,
                "moves_json" => "[]",
                "verification_status" => "pending",
                "created_at" => $this->now(),
            ]);
        return $this->respondCreated([
            "runId" => $rid,
            "ticket" => $ticket,
            "expiresAt" => gmdate("c", $expires),
        ]);
    }
    public function finish($id)
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $b = $this->body();
        $ticket = $b["ticket"] ?? "";
        if (!is_string($ticket) || strlen($ticket) > 4096) {
            return $this->error("INVALID_TICKET", "Invalid ticket.");
        }
        $parts = explode(".", $ticket);
        if (
            count($parts) !== 2 ||
            strlen($this->signingKey()) < 32 ||
            !hash_equals(
                hash_hmac("sha256", $parts[0], $this->signingKey()),
                $parts[1],
            )
        ) {
            return $this->error("INVALID_TICKET", "Invalid ticket.");
        }
        $p = json_decode(base64_decode($parts[0], true) ?: "", true);
        $r = $this->db()
            ->table("game_runs")
            ->where(["id" => $id, "user_id" => $u["id"]])
            ->get()
            ->getRowArray();
        if (
            !$r ||
            !is_array($p) ||
            ($p["run"] ?? "") !== $id ||
            ($p["user"] ?? "") !== $u["id"] ||
            ($p["hash"] ?? "") !== $r["puzzle_hash"] ||
            ($p["expires"] ?? 0) < time() ||
            !hash_equals($r["nonce_hash"], hash("sha256", $p["nonce"] ?? ""))
        ) {
            return $this->error("INVALID_TICKET", "Expired or invalid ticket.");
        }
        if ($r["verification_status"] === "verified") {
            return $this->respond([
                "runId" => $id,
                "score" => (int) $r["score"],
                "verified" => true,
            ]);
        }
        $l = $this->db()
            ->table("levels")
            ->where([
                "id" => $r["level_id"],
                "puzzle_hash" => $r["puzzle_hash"],
                "status" => "published",
            ])
            ->get()
            ->getRowArray();
        if (!$l) {
            return $this->error("STALE_CONTENT", "Puzzle version changed.");
        }
        if (!is_array($b["moves"] ?? null)) {
            return $this->error("VALIDATION", "A move log is required.");
        }
        try {
            $result = Rules::replay(
                json_decode($l["puzzle_json"], true)["tiles"],
                $b["moves"],
            );
        } catch (\InvalidArgumentException $e) {
            return $this->error("ILLEGAL_RUN", $e->getMessage());
        }
        $elapsed = (time() - (int) $r["started_at"]) * 1000;
        if ($elapsed < 1000 || $elapsed > 3600000) {
            return $this->error(
                "INVALID_TIMING",
                "Run timing is outside supported bounds.",
            );
        }
        if (isset($b["score"]) && $b["score"] !== $result["score"]) {
            return $this->error("FORGED_SCORE", "Score does not match replay.");
        }
        $this->db()
            ->table("game_runs")
            ->where(["id" => $id, "verification_status" => "pending"])
            ->update([
                "score" => $result["score"],
                "elapsed_ms" => $elapsed,
                "completed_at" => time(),
                "moves_json" => json_encode($b["moves"]),
                "verification_status" => "verified",
            ]);
        return $this->respond([
            "runId" => $id,
            "score" => $result["score"],
            "elapsedMs" => $elapsed,
            "verified" => true,
        ]);
    }
    /**
     * Player standings from synced campaign progress: levels cleared, then
     * stars, then best scores. Only display names leave the server; the
     * signed-in player's own row is flagged and their rank is always returned.
     */
    public function rankings()
    {
        $standings = fn() => $this->db()
            ->table("player_progress")
            ->select(
                "users.id AS uid, users.display_name, COUNT(*) AS levels, SUM(player_progress.stars) AS stars, SUM(player_progress.best_score) AS score",
            )
            ->join("users", "users.id=player_progress.user_id")
            ->where("users.status", "active")
            ->groupBy("users.id, users.display_name");
        $rows = $standings()
            ->orderBy("levels", "DESC")
            ->orderBy("stars", "DESC")
            ->orderBy("score", "DESC")
            ->orderBy("users.display_name", "ASC")
            ->limit(50)
            ->get()
            ->getResultArray();
        $me = $this->user();
        $shape = fn(array $r, int $rank) => [
            "rank" => $rank,
            "displayName" => (string) $r["display_name"],
            "levels" => (int) $r["levels"],
            "stars" => (int) $r["stars"],
            "score" => (int) $r["score"],
            "isMe" => $me !== null && $r["uid"] === $me["id"],
        ];
        $items = [];
        foreach ($rows as $i => $r) {
            $items[] = $shape($r, $i + 1);
        }
        $mine = null;
        if ($me) {
            $own = $standings()
                ->where("users.id", $me["id"])
                ->get()
                ->getRowArray();
            if ($own) {
                // Rank = 1 + players strictly ahead on (levels, stars, score).
                $ahead = 0;
                foreach (
                    $standings()->get()->getResultArray()
                    as $r
                ) {
                    $better =
                        [(int) $r["levels"], (int) $r["stars"], (int) $r["score"]] <=>
                        [(int) $own["levels"], (int) $own["stars"], (int) $own["score"]];
                    if ($better > 0) {
                        $ahead++;
                    }
                }
                $mine = $shape($own, $ahead + 1);
            }
        }
        return $this->respond([
            "items" => $items,
            "me" => $mine,
            "players" => (int) ($this->db()
                ->table("player_progress")
                ->join("users", "users.id=player_progress.user_id")
                ->where("users.status", "active")
                ->select("COUNT(DISTINCT player_progress.user_id) AS n")
                ->get()
                ->getRowArray()["n"] ?? 0),
        ]);
    }
    public function leaderboards()
    {
        $q = $this->db()
            ->table("game_runs")
            ->select(
                "game_runs.id,game_runs.level_id,game_runs.score,game_runs.elapsed_ms,users.display_name",
            )
            ->join("users", "users.id=game_runs.user_id")
            ->where([
                "verification_status" => "verified",
                "users.status" => "active",
            ]);
        $level = $this->request->getGet("levelId");
        if ($level !== null) {
            if (
                !is_string($level) ||
                !preg_match('/^[a-z0-9-]{1,64}$/', $level)
            ) {
                return $this->error("VALIDATION", "Invalid board ID.");
            }
            $q->where("level_id", $level);
        }
        $cursor = $this->request->getGet("cursor");
        if ($cursor !== null) {
            if (!is_string($cursor) || strlen($cursor) > 512) {
                return $this->error("VALIDATION", "Invalid cursor.");
            }
            $c = json_decode(base64_decode($cursor, true) ?: "", true);
            if (
                !is_array($c) ||
                !is_int($c["score"] ?? null) ||
                !is_int($c["elapsed"] ?? null) ||
                !is_string($c["id"] ?? null) ||
                !preg_match('/^[a-f0-9]{32}$/', $c["id"])
            ) {
                return $this->error("VALIDATION", "Invalid cursor.");
            }
            $q->groupStart()
                ->where("score <", $c["score"])
                ->orGroupStart()
                ->where("score", $c["score"])
                ->where("elapsed_ms >", $c["elapsed"])
                ->groupEnd()
                ->orGroupStart()
                ->where("score", $c["score"])
                ->where("elapsed_ms", $c["elapsed"])
                ->where("game_runs.id >", $c["id"])
                ->groupEnd()
                ->groupEnd();
        }
        $items = $q
            ->orderBy("score", "DESC")
            ->orderBy("elapsed_ms", "ASC")
            ->orderBy("game_runs.id", "ASC")
            ->limit(25)
            ->get()
            ->getResultArray();
        $next = null;
        if (count($items) === 25) {
            $last = end($items);
            $next = base64_encode(
                json_encode([
                    "score" => (int) $last["score"],
                    "elapsed" => (int) $last["elapsed_ms"],
                    "id" => $last["id"],
                ]),
            );
        }
        return $this->respond([
            "verification" =>
                "verified-online; elapsed time measured by server; automation cannot be fully prevented",
            "boardKey" => $level ?? "overall",
            "items" => $items,
            "nextCursor" => $next,
        ]);
    }
    public function achievements()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $count = $this->db()
            ->table("player_progress")
            ->where("user_id", $u["id"])
            ->countAllResults();
        $items = $this->db()
            ->table("achievements")
            ->where("active", 1)
            ->get()
            ->getResultArray();
        foreach ($items as &$a) {
            $a["earned"] =
                $count >= json_decode($a["criteria_json"], true)["completed"];
        }
        return $this->respond(["items" => $items]);
    }
    public function inventory()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        return $this->respond([
            "wallet" => $this->db()
                ->table("wallets")
                ->where("user_id", $u["id"])
                ->get()
                ->getRowArray(),
            "owned" => $this->db()
                ->table("player_cosmetics")
                ->where("user_id", $u["id"])
                ->get()
                ->getResultArray(),
            "catalog" => $this->db()
                ->table("cosmetics")
                ->where("active", 1)
                ->get()
                ->getResultArray(),
        ]);
    }
    public function claim()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $rid = $this->body()["runId"] ?? "";
        if (!is_string($rid)) {
            return $this->error("VALIDATION", "Invalid run.");
        }
        $r = $this->db()
            ->table("game_runs")
            ->where([
                "id" => $rid,
                "user_id" => $u["id"],
                "verification_status" => "verified",
            ])
            ->get()
            ->getRowArray();
        if (!$r) {
            return $this->error(
                "UNVERIFIED",
                "Only verified online runs earn server rewards.",
                403,
            );
        }
        $this->db()->transStart();
        $this->lockWallet($u["id"]);
        $ref = "level:" . $r["level_id"];
        $claimed = $this->db()
            ->table("wallet_ledger")
            ->where(["user_id" => $u["id"], "reference_id" => $ref])
            ->countAllResults();
        if (!$claimed) {
            $this->db()
                ->table("wallet_ledger")
                ->insert([
                    "id" => $this->id(),
                    "user_id" => $u["id"],
                    "amount" => 25,
                    "reason" => "level-completion",
                    "reference_id" => $ref,
                    "created_at" => $this->now(),
                ]);
            $this->db()
                ->table("wallets")
                ->where("user_id", $u["id"])
                ->set("coin_balance", "coin_balance+25", false)
                ->set("version", "version+1", false)
                ->update();
        }
        $this->db()->transComplete();
        return $this->respond([
            "awarded" => $claimed ? 0 : 25,
            "alreadyClaimed" => (bool) $claimed,
        ]);
    }
    public function purchase()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $b = $this->body();
        if (($b["provider"] ?? "") !== "coins") {
            return $this->error(
                "PROVIDER_DISABLED",
                "Real-money purchases are disabled; no payment was taken.",
                503,
            );
        }
        $id = $b["cosmeticId"] ?? "";
        if (!is_string($id)) {
            return $this->error("VALIDATION", "Invalid cosmetic.");
        }
        $c = $this->db()
            ->table("cosmetics")
            ->where(["id" => $id, "active" => 1])
            ->get()
            ->getRowArray();
        if (!$c) {
            return $this->error("NOT_FOUND", "Cosmetic unavailable.", 404);
        }
        $this->db()->transBegin();
        $this->lockWallet($u["id"]);
        $owned = $this->db()
            ->table("player_cosmetics")
            ->where(["user_id" => $u["id"], "cosmetic_id" => $id])
            ->countAllResults();
        if ($owned) {
            $this->db()->transRollback();
            return $this->respond(["owned" => true]);
        }
        $wallet = $this->db()
            ->table("wallets")
            ->where("user_id", $u["id"])
            ->get()
            ->getRowArray();
        if ((int) $wallet["coin_balance"] < (int) $c["price_coins"]) {
            $this->db()->transRollback();
            return $this->error("INSUFFICIENT_FUNDS", "Not enough coins.");
        }
        $this->db()
            ->table("wallets")
            ->where("user_id", $u["id"])
            ->set(
                "coin_balance",
                "coin_balance-" . (int) $c["price_coins"],
                false,
            )
            ->set("version", "version+1", false)
            ->update();
        $this->db()
            ->table("player_cosmetics")
            ->insert([
                "id" => $this->id(),
                "user_id" => $u["id"],
                "cosmetic_id" => $id,
                "created_at" => $this->now(),
            ]);
        $this->db()
            ->table("wallet_ledger")
            ->insert([
                "id" => $this->id(),
                "user_id" => $u["id"],
                "amount" => -(int) $c["price_coins"],
                "reason" => "cosmetic",
                "reference_id" => "cosmetic:" . $id,
                "created_at" => $this->now(),
            ]);
        $this->db()->transCommit();
        return $this->respond(["owned" => true]);
    }
    public function events()
    {
        return $this->respond([
            "accepted" => 0,
            "message" =>
                "Analytics disabled by default. No events were stored.",
        ]);
    }
    public function metrics()
    {
        if (!$this->admin()) {
            return $this->error(
                "FORBIDDEN",
                "Administrator access required.",
                403,
            );
        }
        return $this->respond([
            "users" => $this->db()->table("users")->countAllResults(),
            "verifiedRuns" => $this->db()
                ->table("game_runs")
                ->where("verification_status", "verified")
                ->countAllResults(),
            "levels" => $this->db()
                ->table("levels")
                ->where("status", "published")
                ->countAllResults(),
        ]);
    }
    public function adminList($type)
    {
        if (!$this->admin()) {
            return $this->error(
                "FORBIDDEN",
                "Administrator access required.",
                403,
            );
        }
        $table = $type === "daily" ? "daily_challenges" : $type;
        return $this->respond([
            "items" => $this->db()
                ->table($table)
                ->limit(100)
                ->get()
                ->getResultArray(),
        ]);
    }
    public function adminSave($type, $id = null)
    {
        if (!($u = $this->admin())) {
            return $this->error(
                "FORBIDDEN",
                "Administrator access required.",
                403,
            );
        }
        $b = $this->body();
        $id = $id ?? ($b["id"] ?? "");
        if (!is_string($id) || !preg_match('/^[a-z0-9-]{1,64}$/', $id)) {
            return $this->error("VALIDATION", "Use a stable lowercase ID.");
        }
        $table = $type === "daily" ? "daily_challenges" : $type;
        $old = $this->db()
            ->table($table)
            ->where("id", $id)
            ->get()
            ->getRowArray();
        if ($old && ($old["status"] ?? "") === "published") {
            return $this->error(
                "IMMUTABLE_CONTENT",
                "Published content is immutable. Create a new version with a new ID.",
                409,
            );
        }
        if ($type === "levels") {
            $p = $b["puzzle"] ?? null;
            if (!is_array($p) || ($p["id"] ?? "") !== $id) {
                return $this->error(
                    "VALIDATION",
                    "Puzzle and stable ID required.",
                );
            }
            try {
                Rules::validate($p);
            } catch (\InvalidArgumentException $e) {
                return $this->error("INVALID_PUZZLE", $e->getMessage());
            }
            if (!is_int($b["levelNumber"] ?? null) || $b["levelNumber"] < 1) {
                return $this->error(
                    "VALIDATION",
                    "Positive levelNumber required.",
                );
            }
            $row = [
                "id" => $id,
                "level_number" => $b["levelNumber"],
                "layout_id" => $p["layoutId"] ?? "custom",
                "seed" => $p["seed"] ?? "admin",
                "rules_version" => "1",
                "puzzle_hash" => hash("sha256", json_encode($p)),
                "difficulty" => $p["difficulty"] ?? "balanced",
                "puzzle_json" => json_encode($p),
                "status" => $b["publish"] ?? false ? "published" : "draft",
                "published_at" => $this->now(),
            ];
        } elseif ($type === "layouts") {
            $p = $b["puzzle"] ?? null;
            if (!is_array($p)) {
                return $this->error(
                    "VALIDATION",
                    "Provide a solved preview puzzle to validate the layout.",
                );
            }
            try {
                Rules::validate($p);
            } catch (\InvalidArgumentException $e) {
                return $this->error("INVALID_LAYOUT", $e->getMessage());
            }
            $row = [
                "id" => $id,
                "slug" => $id,
                "version" => 1,
                "geometry_json" => json_encode(
                    array_map(
                        fn($t) => array_intersect_key(
                            $t,
                            array_flip(["id", "x", "y", "z"]),
                        ),
                        $p["tiles"],
                    ),
                ),
                "status" => "published",
            ];
        } else {
            $date = $b["date"] ?? "";
            $level = $b["levelId"] ?? "";
            if (
                !is_string($date) ||
                !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) ||
                gmdate("Y-m-d", strtotime($date)) !== $date ||
                !is_string($level) ||
                !$this->db()
                    ->table("levels")
                    ->where(["id" => $level, "status" => "published"])
                    ->countAllResults()
            ) {
                return $this->error(
                    "VALIDATION",
                    "Valid UTC date and published level required.",
                );
            }
            $row = [
                "id" => $id,
                "challenge_date" => $date,
                "level_id" => $level,
                "status" => "published",
            ];
        }
        $conflict = $this->db()->table($table);
        if ($type === "levels") {
            $conflict->where("level_number", $row["level_number"]);
        } elseif ($type === "daily") {
            $conflict->where("challenge_date", $row["challenge_date"]);
        } else {
            $conflict->where("slug", $row["slug"]);
        }
        $existing = $conflict->get()->getRowArray();
        if ($existing && $existing["id"] !== $id) {
            return $this->error(
                "CONTENT_CONFLICT",
                "That published number, date or slug already exists.",
                409,
            );
        }
        $this->db()->transStart();
        if ($old) {
            $this->db()->table($table)->where("id", $id)->update($row);
        } else {
            $this->db()
                ->table($table)
                ->insert($row + ["created_at" => $this->now()]);
        }
        $this->db()
            ->table("admin_audit_logs")
            ->insert([
                "id" => $this->id(),
                "actor_id" => $u["id"],
                "action" => "publish-" . $type,
                "target_id" => $id,
                "before_json" => json_encode($old),
                "after_json" => json_encode($row),
                "created_at" => $this->now(),
            ]);
        $this->db()->transComplete();
        return $this->respond(["id" => $id, "status" => $row["status"]]);
    }
    public function moderate($id)
    {
        if (!($u = $this->admin())) {
            return $this->error(
                "FORBIDDEN",
                "Administrator access required.",
                403,
            );
        }
        if ($id === $u["id"]) {
            return $this->error(
                "VALIDATION",
                "Cannot moderate your own account.",
            );
        }
        $status = $this->body()["status"] ?? "";
        if (!in_array($status, ["active", "suspended"], true)) {
            return $this->error("VALIDATION", "Invalid status.");
        }
        $old = $this->db()
            ->table("users")
            ->where("id", $id)
            ->get()
            ->getRowArray();
        if (!$old) {
            return $this->error("NOT_FOUND", "User unavailable.", 404);
        }
        $this->db()->transStart();
        $this->db()
            ->table("users")
            ->where("id", $id)
            ->update(["status" => $status, "updated_at" => $this->now()]);
        $this->db()
            ->table("admin_audit_logs")
            ->insert([
                "id" => $this->id(),
                "actor_id" => $u["id"],
                "action" => "moderate",
                "target_id" => $id,
                "before_json" => json_encode(["status" => $old["status"]]),
                "after_json" => json_encode(["status" => $status]),
                "created_at" => $this->now(),
            ]);
        $this->db()->transComplete();
        return $this->respond(["status" => $status]);
    }
    public function export()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        $result = ["user" => $this->publicUser($u)];
        foreach (
            [
                "player_progress",
                "game_runs",
                "wallet_ledger",
                "player_cosmetics",
                "sync_events",
            ]
            as $t
        ) {
            $result[$t] = $this->db()
                ->table($t)
                ->where("user_id", $u["id"])
                ->get()
                ->getResultArray();
        }
        return $this->respond($result);
    }
    public function deleteMe()
    {
        if (!($u = $this->user())) {
            return $this->error("AUTH_REQUIRED", "Please sign in.", 401);
        }
        if (
            !is_string($this->body()["password"] ?? null) ||
            !password_verify($this->body()["password"], $u["password_hash"])
        ) {
            return $this->error(
                "CONFIRM_PASSWORD",
                "Password confirmation required.",
                403,
            );
        }
        $this->db()->table("users")->where("id", $u["id"])->delete();
        session()->destroy();
        return $this->respond(["deleted" => true]);
    }
}
