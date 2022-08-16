package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "strings"
    "errors"
    "bytes"
    "fmt"
    "os"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
    privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
    return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
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
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
            return pub, nil
    default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}

func main() {
        var sure string

        fmt.Print("you sure u want overwrite?: ")
        fmt.Scanf("%s", &sure)
        if sure != "yes" && sure != "y" {
                fmt.Println("Aborted.")
                os.Exit(0)
        }
        
        priv, pub := GenerateRsaKeyPair()
        priv_pem := strings.TrimSpace(ExportRsaPrivateKeyAsPemStr(priv))
        pub_pemR, _ := ExportRsaPublicKeyAsPemStr(pub)
        pub_pem := strings.TrimSpace(pub_pemR)
        f, _ := os.Create("OPER_PrivateKey.pitraix")
        f.WriteString(priv_pem)
        f.Close()

        f, _ = os.Create("OPER_PublicKey.pitraix")
        f.WriteString(pub_pem)
        f.Close()

        for _, v := range []string{"lyst_windows.go", "OPER.go", "lyst_windows.exe", "OPER.exe", "OPER", "lyst_linux.go", "lyst_liux"} {       
                file, err := os.Open(v)
                if err != nil {
                        fmt.Println("[WARNING] Make sure you have `" + v + "` in same folder!")
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

                        nb := bytes.Replace(b, []byte("~~YOUR RSA PUBLIC KEY - RUN SETUPCRYPTO.GO~~"), []byte(pub_pem), 1)
                        nb = bytes.Replace(b, []byte("~~YOUR RSA PRIVATE KEY - RUN SETUPCRYPTO.GO~~"), []byte(priv_pem), 1)

                        // fmt.Println(nb)

                        f, _ := os.Create(v)
                        f.Write(nb)
                        f.Close()
                }
                        
        }

        
}
