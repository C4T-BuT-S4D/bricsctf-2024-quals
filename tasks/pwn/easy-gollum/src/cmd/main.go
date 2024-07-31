package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gollum/database"
	"gollum/models"
	"gollum/services"
)

type Context struct {
	db   *database.Database
	auth *services.AuthService

	user     models.User
	loggedIn bool
}

func NewContext() *Context {
	db := database.New()

	return &Context{
		db:   db,
		auth: services.NewAuthService(db),

		loggedIn: false,
	}
}

func input(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')

	return strings.TrimSpace(line)
}

func handleRegister(ctx *Context) {
	if ctx.loggedIn {
		fmt.Println("[-] You are logged in, you should log out first.")

		return
	}

	username := input("[?] Please, enter username: ")
	password := input("[?] Please, enter password: ")

	protection := input("[?] Please, enter password protection mode: ")

	var parsedProtection models.Protection
	switch strings.ToLower(protection) {
	case "full":
		parsedProtection = models.FullProtection
	case "md5":
		parsedProtection = models.MD5Protection
	case "sha1":
		parsedProtection = models.SHA1Protection
	case "sha256":
		parsedProtection = models.SHA256Protection
	default:
		fmt.Println("[-] Invalid protection mode, available modes: `Full`, `MD5`, `SHA1` and `SHA256`).")
		return
	}

	credential := models.NewCredential(password, parsedProtection)

	ctx.user.Name = username

	user, err := ctx.auth.Register(ctx.user, credential)
	if err != nil {
		fmt.Println("[-] Error:", err)
		return
	}

	fmt.Println("[+] Registered successfully.")

	ctx.user = user
	ctx.loggedIn = true
}

func handleLogin(ctx *Context) {
	if ctx.loggedIn {
		fmt.Println("[-] You are logged in, you should log out first.")

		return
	}

	username := input("[?] Please, enter username: ")
	password := input("[?] Please, enter password: ")

	user, err := ctx.auth.Login(username, password)
	if err != nil {
		fmt.Println("[-] Error:", err)
		return
	}

	fmt.Println("[+] Logged in successfully.")

	ctx.user = user
	ctx.loggedIn = true
}

func handleInfo(ctx *Context) {
	if !ctx.loggedIn {
		fmt.Println("[-] You are not logged in, you should log in first.")

		return
	}

	user, err := ctx.db.GetUser(ctx.user.Id)
	if err != nil {
		fmt.Println("[-] Error:", err)
	}

	fmt.Printf("[*] User: %s\n", user)
}

func handleUpdate(ctx *Context) {
	if !ctx.loggedIn {
		fmt.Println("[-] You are not logged in, you should log in first.")

		return
	}

	description := input("[?] Please, enter description: ")

	user := models.User{
		Name:        ctx.user.Name,
		Description: description,
	}

	ctx.db.UpdateUser(user)

	fmt.Println("[+] Description updated.")
}

func handleLogout(ctx *Context) {
	if !ctx.loggedIn {
		fmt.Println("[-] You are not logged in, you should log in first.")

		return
	}

	ctx.loggedIn = false
}

func handleHelp(ctx *Context) {
	if ctx.loggedIn {
		fmt.Println("[*] Use `INFO`, `UPDATE`, `LOGOUT` or `EXIT` commands.")
	} else {
		fmt.Println("[*] Use `LOGIN`, `REGISTER` or `EXIT` commands.")
	}
}

func main() {
	ctx := NewContext()

	fmt.Println("[!] Hello! Please, use `HELP` for available commands.")

	for {
		command := input("> ")

		switch strings.ToLower(command) {
		case "register":
			handleRegister(ctx)

		case "login":
			handleLogin(ctx)

		case "info":
			handleInfo(ctx)

		case "update":
			handleUpdate(ctx)

		case "logout":
			handleLogout(ctx)

		case "exit":
			fmt.Println("[!] Bye.")

			return

		case "help":
			fallthrough

		default:
			handleHelp(ctx)
		}
	}
}
