<?php
namespace App\Database\Seeds;
use CodeIgniter\Database\Seeder;
use App\Services\Rules;
class InitialSeeder extends Seeder
{
    public function run()
    {
        $content = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        foreach ($content["levels"] as $l) {
            $p = $l["puzzle"];
            Rules::validate($p);
            if (
                !$this->db
                    ->table("levels")
                    ->where("id", $p["id"])
                    ->countAllResults()
            ) {
                $this->db
                    ->table("levels")
                    ->insert([
                        "id" => $p["id"],
                        "level_number" => $l["number"],
                        "layout_id" => $p["layoutId"],
                        "seed" => $p["seed"],
                        "rules_version" => $p["rulesVersion"],
                        "puzzle_hash" => $l["hash"],
                        "difficulty" => $p["difficulty"],
                        "puzzle_json" => json_encode($p, JSON_THROW_ON_ERROR),
                        "status" => "published",
                        "published_at" => gmdate("c"),
                        "created_at" => gmdate("c"),
                    ]);
            }
            if (
                !$this->db
                    ->table("layouts")
                    ->where("id", $p["layoutId"])
                    ->countAllResults()
            ) {
                $this->db
                    ->table("layouts")
                    ->insert([
                        "id" => $p["layoutId"],
                        "slug" => $p["layoutId"],
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
                        "created_at" => gmdate("c"),
                    ]);
            }
        }
        $daily = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/daily.json",
            ),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        foreach ($daily["challenges"] as $d) {
            $p = $d["puzzle"];
            Rules::validate($p);
            if (
                !$this->db
                    ->table("levels")
                    ->where("id", $p["id"])
                    ->countAllResults()
            ) {
                $this->db
                    ->table("levels")
                    ->insert([
                        "id" => $p["id"],
                        "level_number" =>
                            200000 + (int) (strtotime($d["date"]) / 86400),
                        "layout_id" => $p["layoutId"],
                        "seed" => $p["seed"],
                        "rules_version" => "1",
                        "puzzle_hash" => $d["hash"],
                        "difficulty" => $p["difficulty"],
                        "puzzle_json" => json_encode($p),
                        "status" => "published",
                        "published_at" => gmdate("c"),
                        "created_at" => gmdate("c"),
                    ]);
            }
            if (
                !$this->db
                    ->table("daily_challenges")
                    ->where("id", $p["id"])
                    ->countAllResults()
            ) {
                $this->db
                    ->table("daily_challenges")
                    ->insert([
                        "id" => $p["id"],
                        "challenge_date" => $d["date"],
                        "level_id" => $p["id"],
                        "status" => "published",
                        "created_at" => gmdate("c"),
                    ]);
            }
        }
        foreach (["night", "sand"] as $id) {
            if (
                !$this->db
                    ->table("cosmetics")
                    ->where("id", $id)
                    ->countAllResults()
            ) {
                $this->db
                    ->table("cosmetics")
                    ->insert([
                        "id" => $id,
                        "asset_key" => $id,
                        "price_coins" => 100,
                        "active" => 1,
                        "created_at" => gmdate("c"),
                    ]);
            }
        }
        foreach (
            ["first-bloom" => 1, "gardener" => 10, "century" => 100]
            as $key => $count
        ) {
            if (
                !$this->db
                    ->table("achievements")
                    ->where("id", $key)
                    ->countAllResults()
            ) {
                $this->db
                    ->table("achievements")
                    ->insert([
                        "id" => $key,
                        "key_name" => $key,
                        "criteria_json" => json_encode(["completed" => $count]),
                        "points" => $count * 10,
                        "active" => 1,
                        "created_at" => gmdate("c"),
                    ]);
            }
        }
    }
}
