package xades

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type IssuerSerializer func(pkix.Name) string

// DefaultIssuerSerializer is the default serializer that uses pkix.Name.String()
func DefaultIssuerSerializer(name pkix.Name) string {
	return name.String()
}

var (
	oidGivenName = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname   = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// IssuerSerializerKSeF serializes the issuer name in the format compatible with C# X509Certificate2.Issuer property, used by the official KSeF client
func IssuerSerializerKSeF(name pkix.Name) string {
	given := attributeValue(name, oidGivenName)
	surname := attributeValue(name, oidSurname)
	return fmt.Sprintf(
		"G=%s, SN=%s, SERIALNUMBER=%s, CN=%s, C=%s",
		given,
		surname,
		name.SerialNumber,
		name.CommonName,
		firstOrEmpty(name.Country),
	)
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func attributeValue(name pkix.Name, oid asn1.ObjectIdentifier) string {
	for _, atv := range name.Names {
		if atv.Type.Equal(oid) {
			if str, ok := atv.Value.(string); ok {
				return str
			}
			return fmt.Sprint(atv.Value)
		}
	}
	for _, atv := range name.ExtraNames {
		if atv.Type.Equal(oid) {
			if str, ok := atv.Value.(string); ok {
				return str
			}
			return fmt.Sprint(atv.Value)
		}
	}
	return ""
}
