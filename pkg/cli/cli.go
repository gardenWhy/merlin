// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package cli

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	uuid "github.com/satori/go.uuid"
	"gopkg.in/yaml.v3"

	// Merlin
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/menu"
)

// Global Variables
var clientID = uuid.NewV4()

var shellListener listener
var shellListenerOptions map[string]string

type listener struct {
	id     uuid.UUID // Listener unique identifier
	name   string    // Listener unique name
	status string    // Listener server status
}

type YamListener struct {
	Name      string `yaml:"Name"`
	Protocol  string `yaml:"Protocol"`
	Interface string `yaml:"Interface"`
	Port      string `yaml:"Port"`
	PSK       string `yaml:"PSK"`
}

type YamlConfig struct {
	AutoStart        string        `yaml:"AutoStart"`
	AutoSetAllAgents string        `yaml:"AutoSetAllAgents"`
	Listeners        []YamListener `yaml:"Listeners"`
}

var GlobalYamlConfig YamlConfig

const DefaultYamlFile = "./config.yaml"

func initializeYamlFile() error {
	yamlFile := DefaultYamlFile

	yamlFileBytes, err := ioutil.ReadFile(yamlFile)
	//fmt.Printf("[*] Read YAML file\n")
	m := fmt.Sprintf("Reading config YAML file")
	um := messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: m,
		Error:   false,
	}

	core.MessageChannel <- um

	if err != nil {
		//fmt.Printf("[*] Failed to read YAML file: %s\n", err)
		m := fmt.Sprintf("Failed to read YAML file: %s\n", err)
		messages.SendBroadcastMessage(messages.UserMessage{
			Level:   messages.Note,
			Message: m,
			Time:    time.Now().UTC(),
			Error:   false,
		})

	} else {
		//fmt.Printf("[*] Parsing YAML file\n")
		m := fmt.Sprintf("Parsing config YAML file")
		um := messages.UserMessage{
			Level:   messages.Success,
			Time:    time.Now().UTC(),
			Message: m,
			Error:   false,
		}

		core.MessageChannel <- um
		err = yaml.Unmarshal(yamlFileBytes, &GlobalYamlConfig)
		if err != nil {
			//fmt.Printf("[*] Failed to parse YAML file: %s\n", err)
			m := fmt.Sprintf("Failed to parse YAML file: %s\n", err)
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.Note,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   false,
			})
		}
	}

	return err
}

func loadYamlConfigFile() {
	err := initializeYamlFile()
	if err == nil {
		if strings.ToLower(GlobalYamlConfig.AutoStart) == "true" {
			for _, yamlListener := range GlobalYamlConfig.Listeners {
				shellListenerOptions = listenerAPI.GetListenerOptions(yamlListener.Protocol)
				shellListenerOptions["Protocol"] = yamlListener.Protocol
				shellListenerOptions["Interface"] = yamlListener.Interface
				shellListenerOptions["Port"] = yamlListener.Port
				shellListenerOptions["Name"] = yamlListener.Name
				shellListenerOptions["PSK"] = yamlListener.PSK

				um, id := listenerAPI.NewListener(shellListenerOptions)
				core.MessageChannel <- um
				if um.Error {
					return
				}
				if id == uuid.Nil {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: "a nil Listener UUID was returned",
						Time:    time.Time{},
						Error:   true,
					}
					return
				}

				shellListener = listener{id: id, name: shellListenerOptions["Name"]}
				startMessage := listenerAPI.Start(shellListener.name)
				shellListener.status = listenerAPI.GetListenerStatus(id).Message
				core.MessageChannel <- startMessage
				um, shellListenerOptions = listenerAPI.GetListenerConfiguredOptions(shellListener.id)
				if um.Error {
					core.MessageChannel <- um
					break
				}
			}
		}
	}
}

// Shell is the exported function to start the command line interface
func Shell() {
	osSignalHandler()
	printUserMessage()
	registerMessageChannel()
	getUserMessages()

	var err error
	core.Prompt, err = readline.NewEx(&readline.Config{
		Prompt:              "\033[31mMerlin»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error creating the CLI prompt: %s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		core.Exit()
	}

	defer func() {
		err := core.Prompt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	loadYamlConfigFile()
	log.SetOutput(core.Prompt.Stderr())
	menu.Set(menu.MAIN)

	for {
		// Read command line input
		line, err := core.Prompt.Readline()

		// Handle Ctrl+C
		if err == readline.ErrInterrupt {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		} else if err == io.EOF {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		}

		line = strings.TrimSpace(line)
		cmd, err := shellwords.Parse(line)
		if err != nil {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing command line arguments:\r\n%s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}

		if len(cmd) > 0 {
			menu.Handle(cmd)
		}
	}
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func registerMessageChannel() {
	um := messages.Register(clientID)
	if um.Error {
		core.MessageChannel <- um
		return
	}
	if core.Debug {
		core.MessageChannel <- um
	}
}

func getUserMessages() {
	go func() {
		for {
			core.MessageChannel <- messages.GetMessageForClient(clientID)
		}
	}()
}

// printUserMessage is used to print all messages to STDOUT for command line clients
func printUserMessage() {
	go func() {
		for {
			m := <-core.MessageChannel
			switch m.Level {
			case messages.Info:
				fmt.Println(color.CyanString("\n[i] %s", m.Message))
			case messages.Note:
				fmt.Println(color.YellowString("\n[-] %s", m.Message))
			case messages.Warn:
				fmt.Println(color.RedString("\n[!] %s", m.Message))
			case messages.Debug:
				if core.Debug {
					fmt.Println(color.RedString("\n[DEBUG] %s", m.Message))
				}
			case messages.Success:
				fmt.Println(color.GreenString("\n[+] %s", m.Message))
			case messages.Plain:
				fmt.Println("\n" + m.Message)
			default:
				fmt.Println(color.RedString("\n[_-_] Invalid message level: %d\r\n%s", m.Level, m.Message))
			}
		}
	}()
}

// osSignalHandler catches SIGINT and SIGTERM signals to prevent accidentally quitting the server when Ctrl-C is pressed
func osSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	}()
}
