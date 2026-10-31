<?php
use CodeIgniter\Router\RouteCollection;
/** @var RouteCollection $routes */
$routes->setAutoRoute(false);
$routes->group(
    "api/v1",
    ["namespace" => "App\Controllers\Api", "filter" => "apiGuard"],
    static function ($r) {
        $r->get("health", "Game::health");
        $r->get("auth/csrf", "Game::csrf");
        $r->post("auth/register", "Game::register");
        $r->post("auth/login", "Game::login");
        $r->post("auth/google", "Game::google");
        $r->post("auth/logout", "Game::logout");
        $r->get("me", "Game::me");
        $r->delete("me", "Game::deleteMe");
        $r->get("me/export", "Game::export");
        $r->get("catalog/layouts", "Game::layouts");
        $r->get("catalog/levels", "Game::levels");
        $r->get("catalog/levels/(:segment)", 'Game::level/$1');
        $r->get("daily/(:segment)", 'Game::daily/$1');
        $r->get("progress", "Game::progress");
        $r->post("progress/sync", "Game::sync");
        $r->get("me/state", "Game::state");
        $r->post("me/state/sync", "Game::stateSync");
        $r->post("runs", "Game::run");
        $r->post("runs/(:segment)/complete", 'Game::finish/$1');
        $r->get("leaderboards", "Game::leaderboards");
$r->get("rankings", "Game::rankings");
        $r->get("friends", "Game::friends");
        $r->post("friends", "Game::addFriend");
        $r->delete("friends/(:segment)", 'Game::removeFriend/$1');
        $r->get("achievements", "Game::achievements");
        $r->get("inventory", "Game::inventory");
        $r->post("rewards/claim", "Game::claim");
        $r->post("purchases/verify", "Game::purchase");
        $r->post("events/batch", "Game::events");
        $r->get("admin/metrics", "Game::metrics");
        foreach (["layouts", "levels", "daily"] as $type) {
            $r->get("admin/" . $type, "Game::adminList/" . $type);
            $r->post("admin/" . $type, "Game::adminSave/" . $type);
            $r->put(
                "admin/" . $type . "/(:segment)",
                "Game::adminSave/" . $type . '/$1',
            );
        }
        $r->post("admin/users/(:segment)/moderate", 'Game::moderate/$1');
    },
);
