<?php
namespace App\Commands;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
class MakeAdmin extends BaseCommand
{
    protected $group = "Zen Tiles";
    protected $name = "zen:admin";
    protected $description = "Grant admin role to an existing account by email. Never creates a shared password.";
    public function run(array $params)
    {
        $email = $params[0] ?? "";
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            CLI::error("Usage: php spark zen:admin owner@example.com");
            return;
        }
        $db = db_connect();
        $u = $db
            ->table("users")
            ->where("email", strtolower($email))
            ->get()
            ->getRowArray();
        if (!$u) {
            CLI::error("Register the account first.");
            return;
        }
        $db->transStart();
        $db->table("users")
            ->where("id", $u["id"])
            ->update(["role" => "admin"]);
        $db->table("admin_audit_logs")->insert([
            "id" => bin2hex(random_bytes(16)),
            "actor_id" => "operator-cli",
            "action" => "grant-admin",
            "target_id" => $u["id"],
            "before_json" => json_encode(["role" => $u["role"]]),
            "after_json" => '{"role":"admin"}',
            "created_at" => gmdate("c"),
        ]);
        $db->transComplete();
        CLI::write("Administrator role granted.");
    }
}
