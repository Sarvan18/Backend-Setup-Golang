package helpers

import "encoding/json"

func Marshal(data interface{}) ([]byte, error) {
	marshallData, err := json.Marshal(data)

	if err != nil {
		return nil, err
	}

	return marshallData, nil
}
