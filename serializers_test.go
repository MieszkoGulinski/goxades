package xades

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIssuerSerializerKSeF_FormatsExpected(t *testing.T) {
	name := pkix.Name{
		SerialNumber: "TINPL-1192154885",
		CommonName:   "A R",
		Country:      []string{"PL"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidGivenName, Value: "A"},
			{Type: oidSurname, Value: "R"},
		},
	}

	result := IssuerSerializerKSeF(name)

	require.Equal(t, "G=A, SN=R, SERIALNUMBER=TINPL-1192154885, CN=A R, C=PL", result)
}
