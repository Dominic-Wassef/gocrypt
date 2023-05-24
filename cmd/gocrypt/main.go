package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	gocrypt "github.com/dominic-wassef/gocrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// Interface that commands should satisfy
type command interface {
	Name() string           // "foobar"
	Args() string           // "<baz> [quux...]"
	ShortHelp() string      // "Foo the first bar"
	LongHelp() string       // "Foo the first bar meeting the following conditions..."
	Register(*flag.FlagSet) // command-specific flags
	Run([]string) error
}

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to get working directory", err)
		os.Exit(1)
	}
	c := &Config{
		Args:       os.Args,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		WorkingDir: wd,
		Env:        os.Environ(),
	}
	os.Exit(c.Run())
}

// A Config specifies a full configuration for a dep execution.
type Config struct {
	WorkingDir     string    // Where to execute
	Args           []string  // Command-line arguments, starting with the program name.
	Env            []string  // Environment variables
	Stdout, Stderr io.Writer // Log output
}

func (c *Config) Run() int {
	// Build the list of available commands.
	commands := [...]command{
		&encryptCommand{},
		//&decryptCommand{},
		//&versionCommand{},
	}
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "gocrypt tries to do your life easy")
	}

	cmdName, printCmdUsage, exit := parseArgs(c.Args)
	if exit {
		usage(c.Stderr)
		return 1
	}
	if printCmdUsage {
		fmt.Println("Hi! i'm printing a command help")
	}
	outLogger := log.New(c.Stdout, "", 0)
	_ = outLogger

	errLogger := log.New(c.Stderr, "", 0)
	// iterate over commands
	for _, cmd := range commands {
		if cmd.Name() == cmdName {
			// Build flag set with global flags in there.
			fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
			fs.SetOutput(c.Stderr)
			verbose := fs.Bool("v", false, "enable verbose logging")
			_ = verbose

			// Register the subcommand flags in there, too.
			cmd.Register(fs)

			if printCmdUsage {
				fs.Usage()
				return 1
			}
			// Parse the flags the user gave us.
			// flag package automatically prints usage and error message in err != nil
			if err := fs.Parse(c.Args[2:]); err != nil {
				panic(err)
			}

			if err := cmd.Run(fs.Args()); err != nil {
				errLogger.Printf("%v\n", err)
				return 1
			}

		}
	}
	return 0
}

// Parses args
func parseArgs(args []string) (cmdName string, printCmdUsage bool, exit bool) {
	isHelpArg := func() bool {
		return strings.Contains(strings.ToLower(args[1]), "help") || strings.ToLower(args[1]) == "-h"
	}

	switch len(args) {
	// No arguments provided
	case 0, 1:
		exit = true
	case 2:
		if isHelpArg() {
			exit = true
		} else {
			cmdName = args[1]
			exit = false
		}
	default:
		if isHelpArg() {
			cmdName = args[2]
			printCmdUsage = true
		} else {
			cmdName = args[1]
		}
	}
	return cmdName, printCmdUsage, exit
}

// type that includes basic info of command
type encryptCommand struct {
	fromFile string
	password string
	outFile  string
}

func (cmd *encryptCommand) Name() string { return "cipher" }
func (cmd *encryptCommand) Args() string { return "" }

const encryptShortHelp = `Encrypts from files or stdin.`
const encryptLongHelp = ""

func (cmd *encryptCommand) ShortHelp() string { return encryptShortHelp }
func (cmd *encryptCommand) LongHelp() string  { return encryptLongHelp }

// Register command-specific flags
func (cmd *encryptCommand) Register(fs *flag.FlagSet) {
	fs.StringVar(&cmd.fromFile, "f", "", "reads text from file")
	fs.StringVar(&cmd.password, "p", "", "password")
	fs.StringVar(&cmd.outFile, "o", "", "writes to file")
}

func (cmd *encryptCommand) Run(args []string) error {
	if len(args) > 2 {
		return fmt.Errorf("too many args (%d)", len(args))
	}
	fmt.Println("I'm running an encrypt command")
	// empty input file: Read from stdin
	var text string
	if cmd.fromFile == "" {
		fmt.Print("Enter text to encrypt: ")
		reader := bufio.NewReader(os.Stdin)
		var err error
		text, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
	}
	// no password provided
	var strPass string
	if cmd.password == "" {
		fmt.Print("Enter Password: \n")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		strPass = string(bytePassword)
	} else {
		strPass = cmd.password
	}
	encr := gocrypt.NewEncryptedObject()
	err := encr.Encrypt([]byte(text), strPass)
	if err != nil {
		return err
	}
	fmt.Println("file", cmd.outFile)
	if cmd.outFile != "" {
		err = encr.WriteToFile(cmd.outFile)
		if err != nil {
			return err
		}
	}

	packed := encr.PackMessage()
	fmt.Println("packed message", packed)
	//TODO MOVE THIS TO decipher
	unp, _ := gocrypt.UnpackMessage(packed)
	_ = unp
	res, err := encr.Decrypt(strPass)
	_ = res
	if err != nil {
		panic(err.Error())
	}
	return nil
}

func (cmd *encryptCommand) Runner(args []string) error {
	if len(args) > 2 {
		return fmt.Errorf("too many args (%d)", len(args))
	}
	_, err := fmt.Println("I'm running a decrypt command")
	return err
}
