package goproxy

import (
	"crypto/tls"
	"crypto/x509"
)

var GoproxyCa tls.Certificate

func init() {
	// When we included the embedded certificate inside this file, we made
	// sure that it was valid.
	// If there is an error here, this is a really exceptional case that requires
	// a panic. It should NEVER happen!
	var err error
	GoproxyCa, err = tls.X509KeyPair(CA_CERT, CA_KEY)
	if err != nil {
		panic("Error parsing builtin CA: " + err.Error())
	}

	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA leaf: " + err.Error())
	}
}

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUHVCPJULTuVnzeZ2pAWFzEjoLj2owDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUxvY2FsMQ4wDAYDVQQHDAVMb2Nh
bDEOMAwGA1UECgwFRGV2Q0ExDDAKBgNVBAsMA0RldjEUMBIGA1UEAwwLRGV2IFJv
b3QgQ0EwHhcNMjUwNzA0MDMzOTUzWhcNMzUwNzAyMDMzOTUzWjBhMQswCQYDVQQG
EwJDTjEOMAwGA1UECAwFTG9jYWwxDjAMBgNVBAcMBUxvY2FsMQ4wDAYDVQQKDAVE
ZXZDQTEMMAoGA1UECwwDRGV2MRQwEgYDVQQDDAtEZXYgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOq2Rf8MlIc6WhmWw1GxT+RxvzZCZukY
Dg1oG1ktWCaCk0dgx40qB6/pPjjYb4Igy6iqMy353kaV6KqWju1NSA/M8p2sqccw
xxSr0wI9ib0he4+taE7GaTprKHRRREVDH8WZr35zo0uxI88ID9Dq9FLh7RTk7aB2
szMlHUkEbg70WdbnYCXTaKdMxRMNqmEMD0GUvCWGObL32YN+IVrNC7ZElchIsO/y
rDFjjyg9NBTvfNL6HbQhNHNUGh6nUfIMGD1R+gTB/DsD2OweHOmN6DO3ZFoo3wwi
2ZefSCkrzhfiaiIMO6Ry2y25tFk+mr0JTYO9NmwMmZLpX/yd8VCQxw8CAwEAAaNT
MFEwHQYDVR0OBBYEFAmf8UFAX2ZdWWyudGec4pO+WSYEMB8GA1UdIwQYMBaAFAmf
8UFAX2ZdWWyudGec4pO+WSYEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMljtFCx4RUrG2Y1C4rTEgKMagUIxVAIL7ovWaMO6n1anhXep/ecmn3B
T6y7Io2QDjeMFwbU400Sk3pjUjqZK/yi0BOQ9w/mOXvQ5gBw49K+eUAldz8rsanp
bxIe4nts3K6/N8ocdwX9GcvfjIENJ0SUZSx88ZA+UcL5AsG8GKhEhjtdB7m9hH+4
nhz0NRcXv/XBFMl07NrBqmEWjoiFBUOIA6qDC5DqCrPTDJlaL+6NyxyHdjuVDX3l
ZHSHgLDbkzQvaCplYbs/15QWeVgyvf6TK5qdHuZdzkMYET1XU3UmpkZlhuQjDd/A
zbRJgiTCeNJys3IACwIYzkfBF6/QrBo=
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6rZF/wyUhzpaGZbDUbFP5HG/NkJm6RgODWgbWS1YJoKTR2DH
jSoHr+k+ONhvgiDLqKozLfneRpXoqpaO7U1ID8zynaypxzDHFKvTAj2JvSF7j61o
TsZpOmsodFFERUMfxZmvfnOjS7EjzwgP0Or0UuHtFOTtoHazMyUdSQRuDvRZ1udg
JdNop0zFEw2qYQwPQZS8JYY5svfZg34hWs0LtkSVyEiw7/KsMWOPKD00FO980vod
tCE0c1QaHqdR8gwYPVH6BMH8OwPY7B4c6Y3oM7dkWijfDCLZl59IKSvOF+JqIgw7
pHLbLbm0WT6avQlNg702bAyZkulf/J3xUJDHDwIDAQABAoIBAQDP2Ddl4wsIMQkm
jdZK2lyoLH4qG2UsVwvinWVSdBASkiC/3Zj4jdae1UovZqJgNpCCvK1zskg+c3PE
1GyfAYelzlSugf8akDxLNtk1q670l9jmY6Xx1EvM2qXJU0nEl+tjvXOl49sgJS5T
oIz48YcIel7K2OsA5PxNdzlWtqCLhe5Nn/DIfQmZKCDH31TXdSDzR22gJJNOtqdx
RQl3fpzSlahyVRHGA3eLcIl8WMEHV8ND08O5midj8PsXFZqRg0D+Kivbjyx7uXlI
nIEVEQ0cUHN2OPa+xrH9Pix4gpmWWfvD9bfzJjbqOhw2a7TWYmklgy3UZkYAg1AV
xStlIM8RAoGBAPy3Ina6Ko3r9lNHQRgoXU6x6Zaa4K6Fr9LOrKYsYA2jdrhkS756
KtmZTQ6fMmEqoJPSEvgabJDOzJ2syBM1K20W8Rmbwj83eMQq9FktgGDGrdLssyXO
YYoxPAX/ssMUyodqQw/tMdOqo1TwRrYalHxs8QRwOuGUkpJTDrcN/YdXAoGBAO3D
PF4rBimmhdMi8wdXoHi4P9C/kOyOROFgEKrZoDVuqfHgO/AGV1GVB9b+dy1g2XhO
KwylIGc39fnaXUFGEIgQ+9SqHI5adLv3iAFeaar9w5zpQ+QlIVdtsRychy4lnwHC
YRTqT+hl/dBhlH3VMSpRWFuAytTIECkvIuBQ1wMJAoGALWDVF2ymZ4WPXbTVw3i8
CH157EkzPyNSRxBFgDFHritEDig0UaeuOhSE+bMsYLY+z0xRi6tzAy2fIFD+PDS3
74bHFEobvy4+yTrNVZYOD1Kds9o88PT2HtJobMtVViJNm7NBB4MYB2IEoiPjDqAH
ObB2Ns3QROFg0FWJtuUUOVECgYEAyCURLDQLfAQxowpIimW5L+Xp0k9wL7GTSiUT
4r5PnqsJZBLeYa700jgh4VlT+V8NsbgbhQl7vWfeJ/Upi0jvoZqqYtrQLwT2P0Sf
uIdBbC8x+2RhQiv/ZRlxfiRFpxMERvbZwkF8AqXYgxGhbkuIl5biSiSgmX3QHNsR
AMMMPAECgYAdD7LSdtaNA/3v/j98L8cM94gAFUqn9/hbpUdZIRSQ6q+2HT3E7QS1
f1jS3/T53h5mJ27BgO341Knc0fIgT97VnMNmOfHioygd0eQWCcIFGdR3/GjVVIHL
1zbb0QnkAhBosX2mrkba7Quvn8hqIwskeCt9g2er1xesXUF0Dj9zfg==
-----END RSA PRIVATE KEY-----`)
