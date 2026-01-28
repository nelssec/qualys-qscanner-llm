package credentials

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

const serviceName = "qscanner-agent"

type KeyType string

const (
	KeyAnthropic    KeyType = "anthropic_api_key"
	KeyQualysToken  KeyType = "qualys_bearer_token"
	KeyQualysPOD    KeyType = "qualys_pod"
)

func Set(key KeyType, value string) error {
	return keyring.Set(serviceName, string(key), value)
}

func Get(key KeyType) (string, error) {
	return keyring.Get(serviceName, string(key))
}

func Delete(key KeyType) error {
	return keyring.Delete(serviceName, string(key))
}

func GetOrEnv(key KeyType, envValue string) string {
	if envValue != "" {
		return envValue
	}
	val, err := Get(key)
	if err != nil {
		return ""
	}
	return val
}

func IsConfigured() bool {
	_, err1 := Get(KeyQualysToken)
	return err1 == nil
}

func ListConfigured() map[KeyType]bool {
	result := make(map[KeyType]bool)

	keys := []KeyType{KeyAnthropic, KeyQualysToken, KeyQualysPOD}
	for _, k := range keys {
		_, err := Get(k)
		result[k] = err == nil
	}

	return result
}

func ClearAll() error {
	var lastErr error
	keys := []KeyType{KeyAnthropic, KeyQualysToken, KeyQualysPOD}
	for _, k := range keys {
		if err := Delete(k); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func Setup(anthropicKey, qualysToken, qualysPOD string) error {
	if anthropicKey != "" {
		if err := Set(KeyAnthropic, anthropicKey); err != nil {
			return fmt.Errorf("failed to store Anthropic key: %w", err)
		}
	}

	if qualysToken != "" {
		if err := Set(KeyQualysToken, qualysToken); err != nil {
			return fmt.Errorf("failed to store Qualys token: %w", err)
		}
	}

	if qualysPOD != "" {
		if err := Set(KeyQualysPOD, qualysPOD); err != nil {
			return fmt.Errorf("failed to store Qualys POD: %w", err)
		}
	}

	return nil
}
