<?php
namespace App\Database\Migrations;
use CodeIgniter\Database\Migration;
class CreateGame extends Migration
{
    private function table(
        string $name,
        array $fields,
        array $unique = [],
        bool $user = false,
    ): void {
        $this->forge->addField(
            ["id" => ["type" => "VARCHAR", "constraint" => 64]] +
                $fields + [
                    "created_at" => ["type" => "VARCHAR", "constraint" => 32],
                ],
        );
        $this->forge->addKey("id", true);
        foreach ($unique as $columns) {
            $this->forge->addUniqueKey($columns);
        }
        if ($user) {
            $this->forge->addForeignKey(
                "user_id",
                "users",
                "id",
                "CASCADE",
                "CASCADE",
            );
        }
        $this->forge->createTable($name, true);
    }
    public function up()
    {
        $str = fn($n = 255) => ["type" => "VARCHAR", "constraint" => $n];
        $text = ["type" => "TEXT"];
        $int = ["type" => "INT", "default" => 0];
        $this->table(
            "users",
            [
                "email" => $str(),
                "password_hash" => $str(),
                "display_name" => $str(80),
                "role" => $str(16),
                "status" => $str(16),
                "updated_at" => $str(32),
            ],
            [["email"]],
        );
        $this->table(
            "layouts",
            [
                "slug" => $str(80),
                "version" => $int,
                "geometry_json" => $text,
                "status" => $str(16),
            ],
            [["slug"]],
        );
        $this->table(
            "levels",
            [
                "level_number" => $int,
                "layout_id" => $str(64),
                "seed" => $str(),
                "rules_version" => $str(16),
                "puzzle_hash" => $str(64),
                "difficulty" => $str(32),
                "puzzle_json" => $text,
                "status" => $str(16),
                "published_at" => $str(32),
            ],
            [["level_number"]],
        );
        $this->table(
            "player_progress",
            [
                "user_id" => $str(64),
                "level_id" => $str(64),
                "best_score" => $int,
                "best_time_ms" => $int,
                "stars" => $int,
                "version" => $int,
                "completed_at" => $str(32),
            ],
            [["user_id", "level_id"]],
            true,
        );
        $this->table(
            "game_runs",
            [
                "user_id" => $str(64),
                "level_id" => $str(64),
                "puzzle_hash" => $str(64),
                "nonce_hash" => $str(64),
                "expires_at" => $int,
                "started_at" => $int,
                "completed_at" => $int,
                "elapsed_ms" => $int,
                "score" => $int,
                "moves_json" => $text,
                "verification_status" => $str(24),
            ],
            [["nonce_hash"]],
            true,
        );
        $this->table(
            "daily_challenges",
            [
                "challenge_date" => $str(10),
                "level_id" => $str(64),
                "status" => $str(16),
            ],
            [["challenge_date"]],
        );
        $this->table(
            "daily_results",
            [
                "user_id" => $str(64),
                "challenge_id" => $str(64),
                "run_id" => $str(64),
                "score" => $int,
            ],
            [["user_id", "challenge_id"]],
            true,
        );
        $this->table(
            "wallets",
            ["user_id" => $str(64), "coin_balance" => $int, "version" => $int],
            [["user_id"]],
            true,
        );
        $this->table(
            "wallet_ledger",
            [
                "user_id" => $str(64),
                "amount" => $int,
                "reason" => $str(32),
                "reference_id" => $str(128),
            ],
            [["user_id", "reference_id"]],
            true,
        );
        $this->table(
            "sync_events",
            [
                "user_id" => $str(64),
                "client_event_id" => $str(128),
                "event_type" => $str(32),
                "payload_json" => $text,
                "server_version" => $int,
            ],
            [["user_id", "client_event_id"]],
            true,
        );
        $this->table(
            "cosmetics",
            ["asset_key" => $str(64), "price_coins" => $int, "active" => $int],
            [["asset_key"]],
        );
        $this->table(
            "player_cosmetics",
            ["user_id" => $str(64), "cosmetic_id" => $str(64)],
            [["user_id", "cosmetic_id"]],
            true,
        );
        $this->table(
            "entitlements",
            [
                "user_id" => $str(64),
                "provider" => $str(32),
                "provider_transaction_id" => $str(128),
                "product_id" => $str(64),
                "status" => $str(16),
            ],
            [["provider", "provider_transaction_id"]],
            true,
        );
        $this->table(
            "achievements",
            [
                "key_name" => $str(64),
                "criteria_json" => $text,
                "points" => $int,
                "active" => $int,
            ],
            [["key_name"]],
        );
        $this->table(
            "player_achievements",
            ["user_id" => $str(64), "achievement_id" => $str(64)],
            [["user_id", "achievement_id"]],
            true,
        );
        $this->table("admin_audit_logs", [
            "actor_id" => $str(64),
            "action" => $str(32),
            "target_id" => $str(64),
            "before_json" => $text,
            "after_json" => $text,
        ]);
        $this->table("analytics_events", [
            "anonymous_id" => $str(64),
            "event_type" => $str(32),
            "payload_json" => $text,
        ]);
    }
    public function down()
    {
        foreach (
            [
                "analytics_events",
                "admin_audit_logs",
                "player_achievements",
                "achievements",
                "entitlements",
                "player_cosmetics",
                "cosmetics",
                "sync_events",
                "wallet_ledger",
                "wallets",
                "daily_results",
                "daily_challenges",
                "game_runs",
                "player_progress",
                "levels",
                "layouts",
                "users",
            ]
            as $t
        ) {
            $this->forge->dropTable($t, true);
        }
    }
}
