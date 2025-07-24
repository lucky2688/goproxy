package util

import (
	"encoding/base32"
	"errors"
	"strings"
)

func DecodeUrl(host string) (string, string, string, error) {
	realHost := strings.Replace(host, ".com", "", 1)
	originHost := host
	port := realHost[strings.LastIndex(realHost, ":")+1:]
	realHost = strings.Replace(realHost, ":"+port, "", 1)
	realHost = strings.ReplaceAll(realHost, ".-", "=")
	realHost = strings.ToUpper(realHost)
	//ctx.Logf("处理后地址 " + realHost)
	decodedBytes, err := base32.StdEncoding.DecodeString(realHost)
	if err != nil {
		return "", "", "", errors.New("解码失败!")
	}
	decodedUrl := string(decodedBytes)
	hostName := decodedUrl
	decodedUrl += ":" + port

	return decodedUrl, originHost, hostName, nil
}
