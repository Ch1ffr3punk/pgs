package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

type ecSignature struct{ R, S *big.Int }

func main() {
	sign := flag.Bool("s", false, "sign input")
	verify := flag.Bool("v", false, "verify input")
	analyze := flag.Bool("a", false, "analyze signature and compare with provided certificate")
	certFile := flag.String("c", "", "certificate file for analysis (PEM format)")
	pin := flag.String("p", "", "YubiKey PIN (required for signing)")
	flag.CommandLine.SetOutput(io.Discard)
	flag.Parse()

	if (!*sign && !*verify && !*analyze) || (*sign && *verify) || (*sign && *analyze) || (*verify && *analyze) {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
                fmt.Fprintln(os.Stderr, "Options:")
                fmt.Fprintln(os.Stderr, "  -s -p PIN          Sign message using the provided PIN")
                fmt.Fprintln(os.Stderr, "  -v                 Verify a signature")
                fmt.Fprintln(os.Stderr, "  -a -c certificate  Analyze signed message with certificate file\n")
                fmt.Fprintln(os.Stderr, "Examples:")
                fmt.Fprintf(os.Stderr, "  %s -s -p 12345678 < msg.txt > signed.txt\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "  %s -v < signed.txt\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "  %s -a < signed.txt -c cert.pem\n", os.Args[0])
                os.Exit(1)
        }

	if *sign && *pin == "" {
		fmt.Fprintf(os.Stderr, "Error: PIN required for signing. Use -p PIN\n")
		os.Exit(1)
	}

	if *analyze && *certFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Certificate file required for analysis. Use -c certificate.pem\n")
		os.Exit(1)
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		exit("read stdin failed: %v", err)
	}

	data := normalizeCRLF(input)

	if *sign {
		sig, err := signData(*pin, data)
		if err != nil {
			exit("signing failed: %v", err)
		}
		os.Stdout.Write(data)
		fmt.Println("\r\n-----BEGIN PGS SIGNATURE-----")
		for i := 0; i < len(sig); i += 64 {
			end := i + 64
			if end > len(sig) {
				end = len(sig)
			}
			fmt.Printf("%s\r\n", sig[i:end])
		}
		fmt.Println("-----END PGS SIGNATURE-----")
	} else if *verify {
		if err := verifyData(data); err != nil {
			exit("%v", err)
		}
		fmt.Println("Signature is valid.")
	} else if *analyze {
		if err := analyzeSignature(data, *certFile); err != nil {
			exit("analysis failed: %v", err)
		}
	}
}

func normalizeCRLF(data []byte) []byte {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

func signData(pin string, data []byte) (string, error) {
	yk, err := openYubiKey(0)
	if err != nil {
		return "", err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", err
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not ECDSA")
	}

	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", err
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("key does not implement crypto.Signer")
	}

	digest := sha256.Sum256(data)
	asn1sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", err
	}

	pad32 := func(b []byte) []byte {
		if len(b) > 32 {
			b = b[len(b)-32:]
		}
		return append(make([]byte, 32-len(b)), b...)
	}

	var raw []byte
	raw = append(raw, pad32(pubKey.X.Bytes())...)
	raw = append(raw, pad32(pubKey.Y.Bytes())...)
	raw = append(raw, pad32(sig.R.Bytes())...)
	raw = append(raw, pad32(sig.S.Bytes())...)

	return hex.EncodeToString(raw), nil
}

func verifyData(data []byte) error {
	s := string(data)
	beg := "\r\n-----BEGIN PGS SIGNATURE-----\r\n"
	end := "-----END PGS SIGNATURE-----\r\n"

	i := strings.Index(s, beg)
	j := strings.Index(s, end)

	if i == -1 {
		return fmt.Errorf("signature begin delimiter not found")
	}
	if j == -1 {
		return fmt.Errorf("signature end delimiter not found")
	}
	if j < i {
		return fmt.Errorf("invalid signature block: end before begin")
	}

	original := s[:i]
	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	if len(hexPart) != 256 {
		return fmt.Errorf("expected 256 hex chars, got %d", len(hexPart))
	}

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}
	if len(combined) != 128 {
		return fmt.Errorf("decoded block must be 128 bytes, got %d", len(combined))
	}

	x := new(big.Int).SetBytes(combined[0:32])
	y := new(big.Int).SetBytes(combined[32:64])
	r := new(big.Int).SetBytes(combined[64:96])
	sVal := new(big.Int).SetBytes(combined[96:128])

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	digest := sha256.Sum256([]byte(original))

	if !ecdsa.Verify(pub, digest[:], r, sVal) {
		return fmt.Errorf("signature is not valid")
	}

	return nil
}

func analyzeSignature(data []byte, certFilename string) error {
	s := string(data)
	beg := "\r\n-----BEGIN PGS SIGNATURE-----\r\n"
	end := "-----END PGS SIGNATURE-----\r\n"

	i := strings.Index(s, beg)
	j := strings.Index(s, end)

	if i == -1 || j == -1 {
		return fmt.Errorf("signature block not found")
	}

	original := s[:i]
	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	if len(hexPart) != 256 {
		return fmt.Errorf("expected 256 hex chars, got %d", len(hexPart))
	}

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}
	if len(combined) != 128 {
		return fmt.Errorf("decoded block must be 128 bytes, got %d", len(combined))
	}

	xSig := new(big.Int).SetBytes(combined[0:32])
	ySig := new(big.Int).SetBytes(combined[32:64])

	_ = &ecdsa.PublicKey{Curve: elliptic.P256(), X: xSig, Y: ySig}

	certData, err := os.ReadFile(certFilename)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no valid PEM certificate found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain ECDSA public key")
	}

	fmt.Println("=== PGS SIGNATURE ANALYSIS ===")

	signatureIsValid := verifyData(data) == nil

	fmt.Println("--- SIGNATURE VALIDATION ---")
	if signatureIsValid {
		fmt.Println("✅ Signature is VALID!")
		fmt.Printf("Data SHA-256 hash: %x\n", sha256.Sum256([]byte(original)))
	} else {
		fmt.Println("❌ WARNING: Signature is NOT VALID!")
		fmt.Println("The data has been tampered with or the signature is corrupt.")
	}

	fmt.Println("\n--- PUBLIC KEY FROM SIGNATURE ---")
	fmt.Printf("Curve: P-256 (secp256r1)\n")
	fmt.Printf("X: %x\n", xSig.Bytes())
	fmt.Printf("Y: %x\n", ySig.Bytes())

	fmt.Println("\n--- PUBLIC KEY FROM CERTIFICATE ---")
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("X: %x\n", certPubKey.X.Bytes())
	fmt.Printf("Y: %x\n", certPubKey.Y.Bytes())

	fmt.Println("\n--- PUBLIC KEY COMPARISON ---")
	if xSig.Cmp(certPubKey.X) == 0 && ySig.Cmp(certPubKey.Y) == 0 {
		fmt.Println("✅ SUCCESS: Public keys MATCH!")
		fmt.Println("The signature was created with the private key corresponding to the provided certificate.")
	} else {
		fmt.Println("❌ WARNING: Public keys DO NOT MATCH!")
		fmt.Println("The signature was NOT created with the private key corresponding to the provided certificate.")
	}

	return nil
}

func openYubiKey(index int) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list cards: %v", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no smart card found")
	}

	count := 0
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if count == index {
				return piv.Open(card)
			}
			count++
		}
	}
	return nil, fmt.Errorf("no YubiKey found at index %d", index)
}

func exit(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}