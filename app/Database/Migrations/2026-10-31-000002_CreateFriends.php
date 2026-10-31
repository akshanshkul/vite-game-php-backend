<?php
namespace App\Database\Migrations;
use CodeIgniter\Database\Migration;
/**
 * Friends: a short shareable code per player, and mutual friendships stored
 * as two rows (one per direction). Both go when either account is deleted.
 */
class CreateFriends extends Migration
{
    public function up()
    {
        $str = fn($n = 255) => ["type" => "VARCHAR", "constraint" => $n];
        $this->forge->addField([
            "user_id" => $str(64),
            "code" => $str(12),
            "created_at" => $str(32),
        ]);
        $this->forge->addKey("user_id", true);
        $this->forge->addUniqueKey("code");
        $this->forge->addForeignKey("user_id", "users", "id", "CASCADE", "CASCADE");
        $this->forge->createTable("friend_codes", true);

        $this->forge->addField([
            "user_id" => $str(64),
            "friend_id" => $str(64),
            "created_at" => $str(32),
        ]);
        $this->forge->addKey(["user_id", "friend_id"], true);
        $this->forge->addKey("friend_id");
        $this->forge->addForeignKey("user_id", "users", "id", "CASCADE", "CASCADE");
        $this->forge->addForeignKey("friend_id", "users", "id", "CASCADE", "CASCADE");
        $this->forge->createTable("friendships", true);
    }
    public function down()
    {
        $this->forge->dropTable("friendships", true);
        $this->forge->dropTable("friend_codes", true);
    }
}
