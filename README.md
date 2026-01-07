# goxades

Implementation of XAdES signature in golang. Improvement of the original [goxades](https://github.com/artemkunich/goxades) library by adding customizable serialization of issuer signature and customizable hash of signed properties.

## Improvements

### Issuer serialization

Previously, the issuer signature was serialized using the default serialization method `pkix.Name.String()`, which is not compatible with [Polish KSeF API](https://github.com/CIRFMF/ksef-docs/blob/main/auth/podpis-xades.md). The API requires the issuer signature to be serialized in the format [returned by C# built-in `X509Certificate2.Issuer` property](https://github.com/CIRFMF/ksef-client-csharp/blob/main/KSeF.Client/Api/Services/SignatureService.cs#L150).

Format returned by `pkix.Name.String()`:
```
SERIALNUMBER=TINPL-8126178616,CN=A R,C=PL,2.5.4.42=#130141,2.5.4.4=#130152
```

Format returned by the official C# client:
```
G=A, SN=R, SERIALNUMBER=TINPL-1192154885, CN=A R, C=PL
```

The modification to `goxades` allows adding a custom serialization method for the issuer signature.

### Hash of signed properties

Previously, the hash of signed properties was always calculated using SHA-1 algorithm, which is not compatible with [Polish KSeF API](https://github.com/CIRFMF/ksef-docs/blob/main/auth/podpis-xades.md). The API requires the hash of signed properties to be calculated using SHA-256.

The modification to `goxades` is to allow user to configure the function to hash the signed properties by `ctx.SignedPropertiesHash` option, and if it's unspecified, use the hash function from `ctx.Hash`. This way, if the user uses SHA-256 for other parts of the signature, SHA-256 will be used for the signed properties too.

## Installation

Install `goxades` using `go get`:

```
$ go get github.com/artemkunich/goxades
```

## Usage

### Creating signature

```go
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	xades "github.com/artemkunich/goxades"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

var sampleXml = `<element id="signedData" xmlns="namespace">text</element>`

func main() {

	doc := etree.NewDocument()
	err := doc.ReadFromString(strings.ReplaceAll(sampleXml, "\n", ""))
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}

	keyStore, err := loadCert("key.pem", "cert.crt")
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}

	root := removeComments(doc.Root())
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signContext := xades.SigningContext{
		DataContext: xades.SignedDataContext{
			Canonicalizer: canonicalizer,
			Hash:          crypto.SHA256,
			ReferenceURI:  "#signedData",
			IsEnveloped:   true,
		},
		PropertiesContext: xades.SignedPropertiesContext{
			Canonicalizer: canonicalizer,
			Hash:          crypto.SHA256,
		},
		Canonicalizer:        canonicalizer,
		Hash:                 crypto.SHA256,
		KeyStore:             *keyStore,
		IssuerSerializer:     xades.IssuerSerializerKSeF, // <- custom issuer serialization (optional)
		SignedPropertiesHash: crypto.SHA256,              // <- custom hash function for signed properties (optional)
		SigningTimeFormat:    "2006-01-02T15:04:05.0000000+00:00", // <- custom signing time format (optional)
	}
	signature, err := xades.CreateSignature(root, &signContext)
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}

	b, err := canonicalSerialize(signature)
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}
	fmt.Println(string(b))
}

func removeComments(elem *etree.Element) *etree.Element {
	copy := elem.Copy()
	for _, token := range copy.Child {
		_, ok := token.(*etree.Comment)
		if ok {
			copy.RemoveChild(token)
		}
	}
	for i, child := range elem.ChildElements() {
		copy.ChildElements()[i] = removeComments(child)
	}
	return copy
}

func canonicalSerialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: false,
		CanonicalText:    true,
	}

	return doc.WriteToBytes()
}

func loadCert(keyPath string, certPath string) (*xades.MemoryX509KeyStore, error) {
	buffer, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	blockc, _ := pem.Decode(buffer)
	cert, err := x509.ParseCertificate(blockc.Bytes)

	buffer, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	blockp, _ := pem.Decode(buffer)
	key, err := x509.ParsePKCS1PrivateKey(blockp.Bytes)

	return &xades.MemoryX509KeyStore{
		PrivateKey: key,
		Cert:       cert,
		CertBinary: blockc.Bytes,
	}, nil
}

