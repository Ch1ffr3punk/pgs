package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
	"time"

	"github.com/go-piv/piv-go/piv"
)

type ecSignature struct{ R, S *big.Int }

// Supported ECC curves
var supportedCurves = map[elliptic.Curve]string{
	elliptic.P256(): "ECCP256",
	elliptic.P384(): "ECCP384",
	elliptic.P521(): "ECCP521",
}

var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
	elliptic.P521(): crypto.SHA512,
}

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
		sig, curveType, err := signData(*pin, data)
		if err != nil {
			exit("signing failed: %v", err)
		}
		os.Stdout.Write(data)
		fmt.Printf("\r\n-----BEGIN %s SIGNATURE-----\r\n", curveType)
		for i := 0; i < len(sig); i += 64 {
			end := i + 64
			if end > len(sig) {
				end = len(sig)
			}
			fmt.Printf("%s\r\n", sig[i:end])
		}
		fmt.Printf("-----END %s SIGNATURE-----\r\n", curveType)
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

func signData(pin string, data []byte) (string, string, error) {
	yk, err := openYubiKey(0)
	if err != nil {
		return "", "", err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", "", err
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not ECDSA")
	}

	// Determine curve type
	curveType, exists := supportedCurves[pubKey.Curve]
	if !exists {
		return "", "", fmt.Errorf("unsupported curve: %v", pubKey.Curve)
	}

	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", "", err
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	// Use appropriate hash for the curve
	hashFunc := curveToHash[pubKey.Curve]
	var digest []byte

	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		digest = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		digest = h[:]
	default:
		return "", "", fmt.Errorf("unsupported hash algorithm for curve")
	}

	asn1sig, err := signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return "", "", err
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", "", err
	}

	// Calculate appropriate padding based on curve
	curveSize := (pubKey.Curve.Params().BitSize + 7) / 8
	pad := func(b []byte) []byte {
		if len(b) > curveSize {
			b = b[len(b)-curveSize:]
		}
		return append(make([]byte, curveSize-len(b)), b...)
	}

	var raw []byte
	raw = append(raw, pad(pubKey.X.Bytes())...)
	raw = append(raw, pad(pubKey.Y.Bytes())...)
	raw = append(raw, pad(sig.R.Bytes())...)
	raw = append(raw, pad(sig.S.Bytes())...)

	return hex.EncodeToString(raw), curveType, nil
}

func verifyData(data []byte) error {
	s := string(data)
	
	// Try to find signature block for any supported curve
	var curveType string
	var beg, end string
	
	for _, ct := range supportedCurves {
		begTest := fmt.Sprintf("\r\n-----BEGIN %s SIGNATURE-----\r\n", ct)
		endTest := fmt.Sprintf("-----END %s SIGNATURE-----\r\n", ct)
		
		if strings.Contains(s, begTest) && strings.Contains(s, endTest) {
			curveType = ct
			beg = begTest
			end = endTest
			break
		}
	}
	
	if curveType == "" {
		return fmt.Errorf("no supported signature block found")
	}

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

	// Determine curve and expected size
	var curve elliptic.Curve
	for c, ct := range supportedCurves {
		if ct == curveType {
			curve = c
			break
		}
	}
	if curve == nil {
		return fmt.Errorf("unsupported curve type: %s", curveType)
	}

	// Calculate expected hex length (4 components: X, Y, R, S)
	curveSize := (curve.Params().BitSize + 7) / 8
	expectedHexLength := curveSize * 4 * 2 // 4 components * curveSize bytes * 2 hex chars per byte

	if len(hexPart) != expectedHexLength {
		return fmt.Errorf("expected %d hex chars for %s, got %d", expectedHexLength, curveType, len(hexPart))
	}

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}
	
	expectedBytes := curveSize * 4
	if len(combined) != expectedBytes {
		return fmt.Errorf("decoded block must be %d bytes for %s, got %d", expectedBytes, curveType, len(combined))
	}

	x := new(big.Int).SetBytes(combined[0:curveSize])
	y := new(big.Int).SetBytes(combined[curveSize:curveSize*2])
	r := new(big.Int).SetBytes(combined[curveSize*2:curveSize*3])
	sVal := new(big.Int).SetBytes(combined[curveSize*3:curveSize*4])

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	
	// Use appropriate hash for verification
	hashFunc := curveToHash[curve]
	var digest []byte

	switch hashFunc {
	case crypto.SHA256:
		h := sha256.Sum256([]byte(original))
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384([]byte(original))
		digest = h[:]
	case crypto.SHA512:
		h := sha512.Sum512([]byte(original))
		digest = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm for curve")
	}

	if !ecdsa.Verify(pub, digest, r, sVal) {
		return fmt.Errorf("signature is not valid")
	}

	return nil
}

func analyzeSignature(data []byte, certFilename string) error {
	s := string(data)
	
	// Find signature block
	var curveType string
	var beg, end string
	
	for _, ct := range supportedCurves {
		begTest := fmt.Sprintf("\r\n-----BEGIN %s SIGNATURE-----\r\n", ct)
		endTest := fmt.Sprintf("-----END %s SIGNATURE-----\r\n", ct)
		
		if strings.Contains(s, begTest) && strings.Contains(s, endTest) {
			curveType = ct
			beg = begTest
			end = endTest
			break
		}
	}
	
	if curveType == "" {
		return fmt.Errorf("no supported signature block found")
	}

	i := strings.Index(s, beg)
	j := strings.Index(s, end)

	if i == -1 || j == -1 {
		return fmt.Errorf("signature block not found")
	}

	original := s[:i]
	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	// Determine curve
	var curve elliptic.Curve
	for c, ct := range supportedCurves {
		if ct == curveType {
			curve = c
			break
		}
	}
	if curve == nil {
		return fmt.Errorf("unsupported curve type: %s", curveType)
	}

	curveSize := (curve.Params().BitSize + 7) / 8
	expectedHexLength := curveSize * 4 * 2

	if len(hexPart) != expectedHexLength {
		return fmt.Errorf("expected %d hex chars for %s, got %d", expectedHexLength, curveType, len(hexPart))
	}

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}
	
	expectedBytes := curveSize * 4
	if len(combined) != expectedBytes {
		return fmt.Errorf("decoded block must be %d bytes for %s, got %d", expectedBytes, curveType, len(combined))
	}

	xSig := new(big.Int).SetBytes(combined[0:curveSize])
	ySig := new(big.Int).SetBytes(combined[curveSize:curveSize*2])

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

	fmt.Printf("=== PGS SIGNATURE ANALYSIS (%s) ===\n", curveType)

	signatureIsValid := verifyData(data) == nil

	fmt.Println("--- SIGNATURE VALIDATION ---")
	if signatureIsValid {
		fmt.Println("✅ Signature is VALID!")
		// Show appropriate hash based on curve
		hashFunc := curveToHash[curve]
		switch hashFunc {
		case crypto.SHA256:
			fmt.Printf("Data SHA-256 hash: %x\n", sha256.Sum256([]byte(original)))
		case crypto.SHA384:
			fmt.Printf("Data SHA-384 hash: %x\n", sha512.Sum384([]byte(original)))
		case crypto.SHA512:
			fmt.Printf("Data SHA-512 hash: %x\n", sha512.Sum512([]byte(original)))
		}
	} else {
		fmt.Println("❌ WARNING: Signature is NOT VALID!")
		fmt.Println("The data has been tampered with or the signature is corrupt.")
	}

	fmt.Println("\n--- PUBLIC KEY FROM SIGNATURE ---")
	fmt.Printf("Curve: %s\n", curveType)
	fmt.Printf("X: %x\n", xSig.Bytes())
	fmt.Printf("Y: %x\n", ySig.Bytes())

	fmt.Println("\n--- PUBLIC KEY FROM CERTIFICATE ---")
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	
	fmt.Printf("Valid from: %s to %s\n", cert.NotBefore.Format("02.01.2006"), cert.NotAfter.Format("02.01.2006"))
	currentTime := time.Now()
	if currentTime.Before(cert.NotBefore) {
		fmt.Printf("⚠️ Certificate is NOT YET valid (starts on %s)\n", cert.NotBefore.Format("02.01.2006"))
	} else if currentTime.After(cert.NotAfter) {
		fmt.Printf("❌ Certificate has EXPIRED (since %s)\n", cert.NotAfter.Format("02.01.2006"))
	} else {
		remaining := cert.NotAfter.Sub(currentTime)
		days := int(remaining.Hours() / 24)
		fmt.Printf("✅ Certificate is valid (valid for %d more days)\n", days)
	}
	
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