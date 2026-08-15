package config

// UserCheck 定义用户通过配置文件添加的自定义检查项，无需编写Go代码。
type UserCheck struct {
	ID          string  `json:"id"`           // 检查ID, e.g. "CU-001"
	Domain      string  `json:"domain"`       // 归属域, e.g. "operation_trust"
	Name        string  `json:"name"`         // 检查名称
	Description string  `json:"description"`  // 检查描述
	Delta       float64 `json:"delta"`        // 失败扣分
	Command     string  `json:"command"`      // 要执行的命令 (exit 0=pass)
	OutputMatch string  `json:"output_match"` // 输出中出现此字符串=pass
	FilePath    string  `json:"file_path"`    // 要检查的文件路径
	FileRegex   string  `json:"file_regex"`   // 文件中匹配此正则=pass
}
