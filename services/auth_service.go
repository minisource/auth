package services

import (
	"github.com/minisource/apiclients/notifier"
	"github.com/minisource/apiclients/notifier/models"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/http/services"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
	hydra "github.com/ory/hydra-client-go"
)

type AuthService struct {
	logger           logging.Logger
	cfg              *config.Config
	otpService       *OtpService
	notifier         *notifier.NotifierService
	hydra            *hydra.APIClient
	userService      *UserService
	UserTokenService *services.TokenService
}

func NewAuthService(cfg *config.Config) *AuthService {
	logger := logging.NewLogger(&cfg.Logger)
	notifierService := notifier.GetNotifierService()
	otpService := NewOtpService(cfg)
	hydraClient := ory.GetHydra()
	userService := NewUserService(cfg)
	userTokenService := services.NewTokenService(&cfg.UserJWT)

	return &AuthService{
		cfg:              cfg,
		logger:           logger,
		otpService:       otpService,
		notifier:         notifierService,
		hydra:            hydraClient,
		userService:      userService,
		UserTokenService: userTokenService,
	}
}

func (s *AuthService) SendOtp(req *dto.GetOtpRequest) (error) {
	otp := s.cfg.Otp.GenerateOtp()

	err := s.notifier.SendSMS(models.SMSRequest{To: req.PhoneNumber, Template: s.cfg.NotificationConfig.TemplateOTP, Body: otp})
	if err != nil {
		return err
	}

	_, isExist, err := s.userService.CheckUserExists(map[string]interface{}{"phone_number": req.PhoneNumber})
	if err != nil {
		return err
	}
	if !isExist {
		_, err = s.userService.CreateInactiveUserWithMobile(req.PhoneNumber)
		if err != nil {
			return err
		}
	}

	err = s.otpService.SetOtp(req.PhoneNumber, otp)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthService) LoginByPhoneNumber(req *dto.VerifyOtpRequest) (*services.TokenDetail, error) {
	err := s.otpService.ValidateOtp(req.PhoneNumber, req.Otp)
	if err != nil {
		return nil, err
	}

	err = s.userService.ActiveUser(req.PhoneNumber)
	if err != nil {
		return nil, err
	}

	tdto := services.TokenDto{PhoneNumber: req.PhoneNumber}
	token, err := s.UserTokenService.GenerateToken(tdto)
	if err != nil {
		return nil, err
	}
	return token, nil
}
