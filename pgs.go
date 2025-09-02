package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	"github.com/go-piv/piv-go/v2/piv"
)

type ecSignature struct{ R, S *big.Int }

// Supported ECC curves including Ed25519
var supportedCurves = map[elliptic.Curve]string{
	elliptic.P256(): "ECCP256",
	elliptic.P384(): "ECCP384",
	nil:             "ED25519", // Ed25519 uses a different curve representation
}

var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
	nil:             crypto.Hash(0), // Ed25519 doesn't use pre-hashing
}

func main() {
	sign := flag.Bool("s", false, "sign input")
	verify := flag.Bool("v", false, "verify input")
	analyze := flag.Bool("a", false, "analyze signature and compare with provided certificate")
	detached := flag.Bool("d", false, "use detached signature mode (read signature from file for verify, write to file for sign)")
	certFile := flag.String("c", "", "certificate file for analysis (PEM format)")
	pin := flag.String("p", "", "YubiKey PIN (required for signing)")
	flag.CommandLine.SetOutput(io.Discard)
	flag.Parse()

	if (!*sign && !*verify && !*analyze) || (*sign && *verify) || (*sign && *analyze) || (*verify && *analyze) {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -s -p PIN          Sign message using the provided PIN")
		fmt.Fprintln(os.Stderr, "  -v                 Verify a signature")
		fmt.Fprintln(os.Stderr, "  -a -c certificate  Analyze signed message with certificate file")
		fmt.Fprintln(os.Stderr, "  -d                 Use detached signature mode\n")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintf(os.Stderr, "  %s -s -p 12345678 < msg.txt > signed.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -v < signed.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -a < signed.txt -c cert.pem\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s -p 12345678 -d signature.sig < binary_file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -v -d signature.sig < binary_file\n", os.Args[0])
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

	// Get signature file from arguments if using detached mode
	var sigFile string
	if *detached {
		if flag.NArg() != 1 {
			fmt.Fprintf(os.Stderr, "Error: Signature file required for detached mode. Usage: %s -d signature_file\n", os.Args[0])
			os.Exit(1)
		}
		sigFile = flag.Arg(0)
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		exit("read stdin failed: %v", err)
	}

	data := input // Use raw data for all operations

	if *sign {
		if *detached {
			// Detached signing: write signature to file, nothing to stdout
			sig, curveType, err := signData(*pin, data)
			if err != nil {
				exit("signing failed: %v", err)
			}
			
			// Write signature to file
			sigContent := fmt.Sprintf("-----BEGIN %s SIGNATURE-----\r\n", curveType)
			for i := 0; i < len(sig); i += 64 {
				end := i + 64
				if end > len(sig) {
					end = len(sig)
				}
				sigContent += fmt.Sprintf("%s\r\n", sig[i:end])
			}
			sigContent += fmt.Sprintf("-----END %s SIGNATURE-----\r\n", curveType)
			
			err = os.WriteFile(sigFile, []byte(sigContent), 0644)
			if err != nil {
				exit("failed to write signature file: %v", err)
			}
			
			// No output to stdout for detached signing
		} else {
			// Normal signing: embed signature with data
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
		}
	} else if *verify {
		if *detached {
			// Detached verification: read signature from file and verify against stdin data
			sigData, err := os.ReadFile(sigFile)
			if err != nil {
				exit("failed to read signature file: %v", err)
			}
			
			// Parse the signature file
			sigHex, curveType, err := parseSignatureFile(sigData)
			if err != nil {
				exit("failed to parse signature file: %v", err)
			}
			
			// Verify the signature
			if err := verifyDetachedSignature(data, sigHex, curveType); err != nil {
				exit("%v", err)
			}
			fmt.Println("Signature is valid.")
		} else {
			// Normal verification
			if err := verifyData(data); err != nil {
				exit("%v", err)
			}
			fmt.Println("Signature is valid.")
		}
	} else if *analyze {
		if *detached {
			// Detached analysis: read signature from file
			sigData, err := os.ReadFile(sigFile)
			if err != nil {
				exit("failed to read signature file: %v", err)
			}
			
			// Parse the signature file
			sigHex, curveType, err := parseSignatureFile(sigData)
			if err != nil {
				exit("failed to parse signature file: %v", err)
			}
			
			// Analyze detached signature
			if err := analyzeDetachedSignature(data, sigHex, curveType, *certFile); err != nil {
				exit("analysis failed: %v", err)
			}
		} else {
			// Normal analysis
			if err := analyzeSignature(data, *certFile); err != nil {
				exit("analysis failed: %v", err)
			}
		}
	}
}

func parseSignatureFile(sigData []byte) (string, string, error) {
	s := string(sigData)
	
	// Try to find signature block for any supported curve
	var curveType string
	var beg, end string
	
	for _, ct := range supportedCurves {
		begTest := fmt.Sprintf("-----BEGIN %s SIGNATURE-----\r\n", ct)
		endTest := fmt.Sprintf("-----END %s SIGNATURE-----\r\n", ct)
		
		if strings.Contains(s, begTest) && strings.Contains(s, endTest) {
			curveType = ct
			beg = begTest
			end = endTest
			break
		}
	}
	
	if curveType == "" {
		return "", "", fmt.Errorf("no supported signature block found in signature file")
	}

	i := strings.Index(s, beg)
	j := strings.Index(s, end)

	if i == -1 {
		return "", "", fmt.Errorf("signature begin delimiter not found")
	}
	if j == -1 {
		return "", "", fmt.Errorf("signature end delimiter not found")
	}
	if j < i {
		return "", "", fmt.Errorf("invalid signature block: end before begin")
	}

	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	return hexPart, curveType, nil
}

func verifyDetachedSignature(data []byte, sigHex, curveType string) error {
	combined, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}

	if curveType == "ED25519" {
		return verifyEd25519Data(data, combined)
	}

	// ECDSA verification
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
		h := sha256.Sum256(data)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm for curve")
	}

	if !ecdsa.Verify(pub, digest, r, sVal) {
		return fmt.Errorf("signature is not valid")
	}

	return nil
}

func analyzeDetachedSignature(data []byte, sigHex, curveType, certFilename string) error {
	combined, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}

	if curveType == "ED25519" {
		return analyzeEd25519Signature(data, combined, certFilename)
	}

	// ECDSA analysis
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

	// Verify the signature first
	signatureIsValid := verifyDetachedSignature(data, sigHex, curveType) == nil

	fmt.Println("--- SIGNATURE VALIDATION ---")
	if signatureIsValid {
		fmt.Println("✅ Signature is VALID!")
		hashFunc := curveToHash[curve]
		switch hashFunc {
		case crypto.SHA256:
			fmt.Printf("Data SHA-256 hash: %x\n", sha256.Sum256(data))
		case crypto.SHA384:
			fmt.Printf("Data SHA-384 hash: %x\n", sha512.Sum384(data))
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

// ... (rest of the functions remain similar to previous version, but with improved error handling)

func signData(pin string, data []byte) (string, string, error) {
	yk, err := openYubiKey(0)
	if err != nil {
		return "", "", err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", "", fmt.Errorf("failed to get certificate: %v", err)
	}

	// Check if it's Ed25519
	if isEd25519Certificate(cert) {
		return signEd25519Data(yk, pin, cert, data)
	}

	// ECDSA handling
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not ECDSA or Ed25519")
	}

	// Determine curve type
	curveType, exists := supportedCurves[pubKey.Curve]
	if !exists {
		return "", "", fmt.Errorf("unsupported curve: %v", pubKey.Curve)
	}

	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
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
	default:
		return "", "", fmt.Errorf("unsupported hash algorithm for curve")
	}

	asn1sig, err := signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return "", "", fmt.Errorf("signing failed: %v", err)
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", "", fmt.Errorf("ASN.1 unmarshal failed: %v", err)
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

func signEd25519Data(yk *piv.YubiKey, pin string, cert *x509.Certificate, data []byte) (string, string, error) {
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not Ed25519")
	}

	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	// For large data, hash it first for Ed25519
	hash := sha256.Sum256(data)
	data = hash[:]

	// Ed25519 signs the data
	signature, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return "", "", fmt.Errorf("Ed25519 signing failed: %v", err)
	}

	// For Ed25519, we include the public key and signature
	var raw []byte
	raw = append(raw, pubKey...)
	raw = append(raw, signature...)

	return hex.EncodeToString(raw), "ED25519", nil
}

func isEd25519Certificate(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(ed25519.PublicKey)
	return ok
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

	original := []byte(s[:i])
	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	return verifyDetachedSignature(original, hexPart, curveType)
}

func verifyEd25519Data(data, combined []byte) error {
	// Ed25519: public key (32 bytes) + signature (64 bytes)
	if len(combined) != 96 {
		return fmt.Errorf("invalid Ed25519 signature block: expected 96 bytes, got %d", len(combined))
	}

	publicKey := combined[:32]
	signature := combined[32:96]

	// Data should be a hash (32 bytes) for Ed25519 verification
	if len(data) != 32 {
		hash := sha256.Sum256(data)
		data = hash[:]
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), data, signature) {
		return fmt.Errorf("Ed25519 signature is not valid")
	}

	return nil
}

func analyzeSignature(data []byte, certFilename string) error {
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

	if i == -1 || j == -1 {
		return fmt.Errorf("signature block not found")
	}

	original := []byte(s[:i])
	hexPart := s[i+len(beg):j]
	hexPart = strings.ReplaceAll(hexPart, "\r\n", "")
	hexPart = strings.ReplaceAll(hexPart, " ", "")

	if curveType == "ED25519" {
		combined, err := hex.DecodeString(hexPart)
		if err != nil {
			return fmt.Errorf("hex decode failed: %v", err)
		}
		return analyzeEd25519Signature(original, combined, certFilename)
	}

	// ECDSA analysis
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
	expectedBytes := curveSize * 4

	combined, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("hex decode failed: %v", err)
	}

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
		hashFunc := curveToHash[curve]
		switch hashFunc {
		case crypto.SHA256:
			fmt.Printf("Data SHA-256 hash: %x\n", sha256.Sum256(original))
		case crypto.SHA384:
			fmt.Printf("Data SHA-384 hash: %x\n", sha512.Sum384(original))
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

func analyzeEd25519Signature(data, combined []byte, certFilename string) error {
	if len(combined) != 96 {
		return fmt.Errorf("invalid Ed25519 signature block: expected 96 bytes, got %d", len(combined))
	}

	publicKeySig := combined[:32]

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

	certPubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain Ed25519 public key")
	}

	fmt.Printf("=== PGS SIGNATURE ANALYSIS (ED25519) ===\n")

	signatureIsValid := verifyEd25519Data(data, combined) == nil

	fmt.Println("--- SIGNATURE VALIDATION ---")
	if signatureIsValid {
		fmt.Println("✅ Signature is VALID!")
		fmt.Printf("Data hash (first 32 bytes): %x\n", sha256.Sum256(data))
	} else {
		fmt.Println("❌ WARNING: Signature is NOT VALID!")
		fmt.Println("The data has been tampered with or the signature is corrupt.")
	}

	fmt.Println("\n--- PUBLIC KEY FROM SIGNATURE ---")
	fmt.Printf("Public Key: %x\n", publicKeySig)

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
	
	fmt.Printf("Public Key: %x\n", certPubKey)

	fmt.Println("\n--- PUBLIC KEY COMPARISON ---")
	if string(publicKeySig) == string(certPubKey) {
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