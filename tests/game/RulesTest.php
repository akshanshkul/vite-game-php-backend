<?php
namespace Tests\Game;
use App\Services\Rules;
use PHPUnit\Framework\TestCase;
final class RulesTest extends TestCase
{
    public function testEveryPublishedWitnessReplaysInPhp(): void
    {
        $catalog = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
        );
        $this->assertCount(100, $catalog["levels"]);
        foreach ($catalog["levels"] as $l) {
            Rules::validate($l["puzzle"]);
            $result = Rules::replay(
                $l["puzzle"]["tiles"],
                $l["puzzle"]["solution"],
            );
            $this->assertSame(
                count($l["puzzle"]["tiles"]) * 50,
                $result["score"],
            );
        }
    }
    public function testDuplicateTileSelectionRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $p = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
        )["levels"][0]["puzzle"];
        Rules::replay($p["tiles"], [
            [$p["tiles"][0]["id"], $p["tiles"][0]["id"]],
        ]);
    }
    public function testIncompleteRunRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $p = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
        )["levels"][0]["puzzle"];
        Rules::replay($p["tiles"], []);
    }
    public function testUpperLayerHalfGridBlocks(): void
    {
        $a = ["id" => "a", "x" => 0, "y" => 0, "z" => 0, "removed" => false];
        $b = ["id" => "b", "x" => 1, "y" => 1, "z" => 1, "removed" => false];
        $this->assertFalse(Rules::free([$a, $b], "a"));
        $this->assertTrue(Rules::free([$a, $b], "b"));
        $this->assertFalse(Rules::free([$a, $b], "missing"));
    }
    public function testCorruptPublishedGeometryRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $p = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
        )["levels"][0]["puzzle"];
        $p["tiles"][1]["id"] = $p["tiles"][0]["id"];
        Rules::validate($p);
    }
    public function testWrongFaceRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $p = json_decode(
            file_get_contents(
                ROOTPATH . "../web/packages/content/levels/campaign.json",
            ),
            true,
        )["levels"][0]["puzzle"];
        $p["tiles"][0]["matchGroup"] = "forged";
        Rules::validate($p);
    }
    public function testIntegerAndFloatLayersUseSameGeometry(): void
    {
        $a = ["id" => "a", "x" => 0, "y" => 0, "z" => 0, "removed" => false];
        $b = ["id" => "b", "x" => 2, "y" => 0, "z" => 0.0, "removed" => false];
        $c = ["id" => "c", "x" => 4, "y" => 0, "z" => 0, "removed" => false];
        $this->assertFalse(Rules::free([$a, $b, $c], "b"));
    }
    public function testMalformedTileIsValidationError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Rules::validate(["tiles" => [null, null], "solution" => []]);
    }
}
