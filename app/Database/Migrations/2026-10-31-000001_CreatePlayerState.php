<?php
namespace App\Database\Migrations;
use CodeIgniter\Database\Migration;
/**
 * Cross-device player wallet: coin and undo changes as an append-only ledger
 * (summed on read, deduplicated by the device's event id), plus a small state
 * row for owned themes and one-time claims (daily gift, missions, chests).
 */
class CreatePlayerState extends Migration
{
    public function up()
    {
        $str = fn($n = 255) => ["type" => "VARCHAR", "constraint" => $n];
        $this->forge->addField([
            "id" => $str(64),
            "user_id" => $str(64),
            "client_event_id" => $str(128),
            "kind" => $str(16),
            "delta" => ["type" => "INT"],
            "reason" => $str(64),
            "created_at" => $str(32),
        ]);
        $this->forge->addKey("id", true);
        $this->forge->addUniqueKey(["user_id", "client_event_id"]);
        $this->forge->addForeignKey("user_id", "users", "id", "CASCADE", "CASCADE");
        $this->forge->createTable("wallet_events", true);

        $this->forge->addField([
            "user_id" => $str(64),
            "purchases_json" => ["type" => "TEXT"],
            "claims_json" => ["type" => "MEDIUMTEXT"],
            "version" => ["type" => "INT", "default" => 0],
            "updated_at" => $str(32),
        ]);
        $this->forge->addKey("user_id", true);
        $this->forge->addForeignKey("user_id", "users", "id", "CASCADE", "CASCADE");
        $this->forge->createTable("player_state", true);
    }
    public function down()
    {
        $this->forge->dropTable("player_state", true);
        $this->forge->dropTable("wallet_events", true);
    }
}
