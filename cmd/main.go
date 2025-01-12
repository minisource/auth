package main

import (
	"github.com/minisource/auth/api"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/db/cache"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
)

// @securityDefinitions.apikey AuthBearer
// @in header
// @name Authorization
func main() {
	cfg := config.GetConfig()
	logger := logging.NewLogger(&cfg.Logger)

	err := cache.InitRedis(&cfg.Redis)
	defer cache.CloseRedis()
	if err != nil {
		logger.Fatal(logging.Redis, logging.Startup, err.Error(), nil)
	}

	ory.InitHydra(&cfg.Hydra)

	api.InitServer(cfg)
}
