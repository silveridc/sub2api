// Package setup provides CLI commands and application initialization helpers.
package setup

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"golang.org/x/term"
)

// CLI input validation functions (matching Web API validation)
func cliValidateHostname(host string) bool {
	validHost := regexp.MustCompile(`^[a-zA-Z0-9.\-:]+$`)
	return validHost.MatchString(host) && len(host) <= 253
}

func cliValidateDBName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	return validName.MatchString(name) && len(name) <= 63
}

func cliValidateUsername(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return validName.MatchString(name) && len(name) <= 63
}

func cliValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

func cliValidateSSLMode(mode string) bool {
	validModes := map[string]bool{
		"disable": true, "require": true, "verify-ca": true, "verify-full": true,
	}
	return validModes[mode]
}

// RunCLI runs the CLI setup wizard
func RunCLI() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║       Sub2API Installation Wizard         ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	cfg := &SetupConfig{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
			Mode: "release",
		},
		JWT: JWTConfig{
			ExpireHour: 24,
		},
	}

	// Database configuration with validation
	fmt.Println("── Database Configuration ──")

	isMySQL := promptDatabaseDriver(reader)
	if isMySQL {
		cfg.Database.Driver = "mysql"
	} else {
		cfg.Database.Driver = "postgres"
	}

	for {
		cfg.Database.Host = promptString(reader, "Database Host", "localhost")
		if cliValidateHostname(cfg.Database.Host) {
			break
		}
		fmt.Println("  Invalid hostname format. Use alphanumeric, dots, hyphens only.")
	}

	defaultPort := 5432
	defaultUser := "postgres"
	if isMySQL {
		defaultPort = 3306
		defaultUser = "root"
	}

	for {
		cfg.Database.Port = promptInt(reader, "Database Port", defaultPort)
		if cliValidatePort(cfg.Database.Port) {
			break
		}
		fmt.Println("  Invalid port. Must be between 1 and 65535.")
	}

	for {
		cfg.Database.User = promptString(reader, "Database User", defaultUser)
		if cliValidateUsername(cfg.Database.User) {
			break
		}
		fmt.Println("  Invalid username. Use alphanumeric and underscores only.")
	}

	cfg.Database.Password = promptPassword(reader, "Database Password")

	for {
		cfg.Database.DBName = promptString(reader, "Database Name", "sub2api")
		if cliValidateDBName(cfg.Database.DBName) {
			break
		}
		fmt.Println("  Invalid database name. Start with letter, use alphanumeric and underscores.")
	}

	if isMySQL {
		// MySQL 下 sslmode 字段承载 TLS 语义（取值→驱动 TLSConfig 的映射
		// 见 config.NormalizeMySQLTLSMode，与 Web 向导、config 校验共用一套）。
		for {
			cfg.Database.SSLMode = promptString(reader, "TLS Mode (disable/preferred/require/verify-ca/verify-full)", "disable")
			if _, valid := config.NormalizeMySQLTLSMode(cfg.Database.SSLMode); valid {
				break
			}
			fmt.Println("  Invalid TLS mode. Use: disable, preferred, require, verify-ca or verify-full.")
		}
	} else {
		for {
			cfg.Database.SSLMode = promptString(reader, "SSL Mode", "disable")
			if cliValidateSSLMode(cfg.Database.SSLMode) {
				break
			}
			fmt.Println("  Invalid SSL mode. Use: disable, require, verify-ca, or verify-full.")
		}
	}

	driverLabel := "PostgreSQL"
	if isMySQL {
		driverLabel = "MySQL"
	}

	fmt.Println()
	fmt.Print("Testing database connection... ")
	if err := TestDatabaseConnection(&cfg.Database); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("database connection failed: %w", err)
	}
	fmt.Println("OK")

	// Redis configuration with validation
	fmt.Println()
	fmt.Println("── Redis Configuration ──")

	for {
		cfg.Redis.Host = promptString(reader, "Redis Host", "localhost")
		if cliValidateHostname(cfg.Redis.Host) {
			break
		}
		fmt.Println("  Invalid hostname format. Use alphanumeric, dots, hyphens only.")
	}

	for {
		cfg.Redis.Port = promptInt(reader, "Redis Port", 6379)
		if cliValidatePort(cfg.Redis.Port) {
			break
		}
		fmt.Println("  Invalid port. Must be between 1 and 65535.")
	}

	cfg.Redis.Password = promptPassword(reader, "Redis Password (optional)")

	for {
		cfg.Redis.DB = promptInt(reader, "Redis DB", 0)
		if cfg.Redis.DB >= 0 && cfg.Redis.DB <= 15 {
			break
		}
		fmt.Println("  Invalid Redis DB. Must be between 0 and 15.")
	}

	cfg.Redis.EnableTLS = promptConfirm(reader, "Enable Redis TLS?")

	fmt.Println()
	fmt.Print("Testing Redis connection... ")
	if err := TestRedisConnection(&cfg.Redis); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("redis connection failed: %w", err)
	}
	fmt.Println("OK")

	// Admin configuration with validation
	fmt.Println()
	fmt.Println("── Admin Account ──")

	// 默认值使用随机邮箱，避免直接回车得到可被猜中的固定管理员用户名（issue #7850）。
	defaultAdminEmail, err := generateAdminEmail()
	if err != nil {
		return err
	}
	for {
		cfg.Admin.Email = promptString(reader, "Admin Email (login username)", defaultAdminEmail)
		if validateEmail(cfg.Admin.Email) {
			break
		}
		fmt.Println("  Invalid email format.")
	}

	for {
		cfg.Admin.Password = promptPassword(reader, "Admin Password")
		// SECURITY: Match Web API password requirements
		if err := validatePassword(cfg.Admin.Password); err != nil {
			fmt.Printf("  Invalid password: %v\n", err)
			continue
		}
		confirm := promptPassword(reader, "Confirm Password")
		if cfg.Admin.Password != confirm {
			fmt.Println("  Passwords do not match")
			continue
		}
		break
	}

	// Server configuration with validation
	fmt.Println()
	fmt.Println("── Server Configuration ──")

	for {
		cfg.Server.Port = promptInt(reader, "Server Port", 8080)
		if cliValidatePort(cfg.Server.Port) {
			break
		}
		fmt.Println("  Invalid port. Must be between 1 and 65535.")
	}

	// Confirm and install
	fmt.Println()
	fmt.Println("── Configuration Summary ──")
	fmt.Printf("Database: %s (%s@%s:%d/%s)\n", driverLabel, cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
	fmt.Printf("Redis: %s:%d\n", cfg.Redis.Host, cfg.Redis.Port)
	fmt.Printf("Redis TLS: %s\n", map[bool]string{true: "enabled", false: "disabled"}[cfg.Redis.EnableTLS])
	fmt.Printf("Admin: %s\n", cfg.Admin.Email)
	fmt.Printf("Server: :%d\n", cfg.Server.Port)
	fmt.Println()

	if !promptConfirm(reader, "Proceed with installation?") {
		fmt.Println("Installation cancelled")
		return nil
	}

	fmt.Println()
	fmt.Print("Installing... ")
	if err := Install(cfg); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║       Installation Complete!              ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Start the server with:")
	fmt.Println("  ./sub2api")
	fmt.Println()
	fmt.Printf("Admin panel: http://localhost:%d\n", cfg.Server.Port)
	fmt.Println()

	return nil
}

// readLine 从共享 reader 读一行；输入流关闭（EOF）时终止向导。
// 没有这个保护，EOF 会让「校验失败重试」循环变成死转
// （非交互 stdin 场景：`./sub2api -setup < responses.txt`）。
func readLine(reader *bufio.Reader) string {
	input, err := reader.ReadString('\n')
	if err != nil && input == "" {
		fmt.Println()
		fmt.Println("Input stream closed (EOF); aborting setup wizard.")
		os.Exit(1)
	}
	return strings.TrimSpace(input)
}

// promptDatabaseDriver 交互式选择数据库类型。返回 true 表示 MySQL。
// 输入 1/空 = PostgreSQL（默认），2 = mysql（大小写不敏感，也接受 "mysql"）。
func promptDatabaseDriver(reader *bufio.Reader) bool {
	for {
		fmt.Printf("  Database Type [1=PostgreSQL (default), 2=MySQL]: ")
		input := strings.ToLower(readLine(reader))
		switch input {
		case "", "1", "postgres", "postgresql", "pg":
			return false
		case "2", "mysql", "mariadb":
			return true
		default:
			fmt.Println("  Invalid choice. Enter 1 (PostgreSQL) or 2 (MySQL).")
		}
	}
}

func promptString(reader *bufio.Reader, prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("  %s: ", prompt)
	}

	input := readLine(reader)

	if input == "" {
		return defaultVal
	}
	return input
}

func promptInt(reader *bufio.Reader, prompt string, defaultVal int) int {
	fmt.Printf("  %s [%d]: ", prompt, defaultVal)

	input := readLine(reader)

	if input == "" {
		return defaultVal
	}

	val, err := strconv.Atoi(input)
	if err != nil {
		return defaultVal
	}
	return val
}

func promptPassword(reader *bufio.Reader, prompt string) string {
	fmt.Printf("  %s: ", prompt)

	// Try to read password without echo
	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return string(password)
		}
	}

	// Fallback to regular input：必须复用主 reader——新建 bufio.Reader 会与
	// 主 reader 的内部缓冲区争抢 os.Stdin（管道/重定向输入时主 reader 已把
	// 后续行缓冲进内存，新 reader 只会读到 EOF）。
	return readLine(reader)
}

func promptConfirm(reader *bufio.Reader, prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	input := strings.ToLower(readLine(reader))
	return input == "y" || input == "yes"
}
