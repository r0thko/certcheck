package notifications

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type TelegramConfig struct {
	Token  string
	ChatID string
}

func ParseTelegramArg(value string) (TelegramConfig, error) {
	parts := strings.SplitN(value, "@", 2)

	if len(parts) != 2 {
		return TelegramConfig{}, fmt.Errorf(
			"invalid telegram format, expected TOKEN@CHATID",
		)
	}

	return TelegramConfig{
		Token:  parts[0],
		ChatID: parts[1],
	}, nil
}

func SendTelegramMessage(
	token string,
	chatID string,
	message string,
) error {
	endpoint := fmt.Sprintf(
		"https://api.telegram.org/bot%s/sendMessage",
		token,
	)
	resp, err := http.PostForm(
		endpoint,
		url.Values{
			"chat_id": {chatID},
			"text":    {message},
		},
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"telegram api returned status %d",
			resp.StatusCode,
		)
	}
	return nil
}
