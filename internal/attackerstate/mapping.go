package attackerstate

// TTP → Intent 映射表（白皮书 §3.1 Intent 五类）。
// 基于 MITRE ATT&CK 战术的合理映射，仅作规则引擎的推断依据；不宣称
// 覆盖全部技术（白皮书 §3.5 原则：未知 TTP 保持 unknown，不臆测）。
var ttpIntent = map[string]Intent{
	// Recon（侦察）
	"T1595": IntentRecon, // Active Scanning
	"T1592": IntentRecon, // Gather Victim Host Information
	"T1590": IntentRecon, // Gather Victim Network Information
	"T1046": IntentRecon, // Network Service Discovery
	// Credential（凭据）
	"T1110": IntentCredential, // Brute Force
	"T1003": IntentCredential, // OS Credential Dumping
	"T1555": IntentCredential, // Credentials from Password Stores
	"T1078": IntentCredential, // Valid Accounts
	// Lateral（横向移动）
	"T1021": IntentLateral, // Remote Services
	"T1570": IntentLateral, // Lateral Tool Transfer
	"T1550": IntentLateral, // Use Alternate Authentication Material
	"T1028": IntentLateral, // Windows Remote Management
	// DataTheft（数据窃取）
	"T1567": IntentDataTheft, // Exfiltration Over Web Service
	"T1048": IntentDataTheft, // Exfiltration Over Alternative Protocol
	"T1030": IntentDataTheft, // Data Transfer Size Limits
	"T1537": IntentDataTheft, // Transfer Data to Cloud Account
	// WebAttack（Web 攻击）
	"T1190": IntentWebAttack, // Exploit Public-Facing Application
	"T1193": IntentWebAttack, // Spearphishing Attachment (social web entry)
	"T1566": IntentWebAttack, // Phishing
}

// TTP → 能力需求（规则 5：观测到的 TTP 计入攻击者能力集合）。
var ttpCapability = map[string]string{
	"T1595": "network_scanning",
	"T1592": "network_recon",
	"T1046": "network_scanning",
	"T1110": "credential_bruteforce",
	"T1003": "credential_dumping",
	"T1555": "credential_access",
	"T1078": "valid_accounts",
	"T1021": "remote_services",
	"T1570": "lateral_tool_transfer",
	"T1550": "auth_material_abuse",
	"T1567": "exfil_web",
	"T1048": "exfil_alt_protocol",
	"T1537": "exfil_cloud",
	"T1190": "web_exploit",
	"T1566": "phishing",
}
