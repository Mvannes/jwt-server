package two_factor

type TwoFactorType string

const (
	TwoFactorDisabled      TwoFactorType = "disabled"
	TwoFactorAuthenticator               = "authenticator"
)
