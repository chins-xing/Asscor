package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/engine"

	_ "github.com/argus-security/argus/internal/checks"
)

func main() {
	configPath := flag.String("config", "config.ini", "配置文件路径")
	jsonOutput := flag.Bool("json", false, "以JSON格式输出")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法加载配置文件 %s: %v\n使用默认配置\n", *configPath, err)
		cfg = config.Default()
	}

	assessor := engine.NewAssessor(cfg)
	result := assessor.Assess("", "")

	if *jsonOutput {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Print(assessor.PrintReport(result))
	}

	if !result.Acceptable {
		os.Exit(1)
	}
}
