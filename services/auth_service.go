package services

import (
	"github.com/minisource/apiclients/notifier"
	"github.com/minisource/apiclients/notifier/models"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
	hydra "github.com/ory/hydra-client-go"
)

type AuthService struct {
	logger     logging.Logger
	cfg        *config.Config
	otpService *OtpService
	notifier   *notifier.NotifierService
	hydra      *hydra.APIClient
}

func NewAuthService(cfg *config.Config) *AuthService {
	logger := logging.NewLogger(&cfg.Logger)
	notifierService := notifier.GetNotifierService()
	otpService := NewOtpService(cfg)
	hydraClient := ory.GetHydra()

	return &AuthService{
		cfg:        cfg,
		logger:     logger,
		otpService: otpService,
		notifier:   notifierService,
		hydra:      hydraClient,
	}
}


func (s *AuthService) SendOtp(req *dto.GetOtpRequest) error {
	otp := s.cfg.Otp.GenerateOtp()

	go s.notifier.SendSMS(models.SMSRequest{To: req.MobileNumber, Template: s.cfg.NotificationConfig.TemplateOTP, Body: otp})

	err := s.otpService.SetOtp(req.MobileNumber, otp)
	if err != nil {
		return err
	}

	return nil
}

// // Register/login by mobile number
// func (s *UserService) RegisterLoginByMobileNumber(req *dto.RegisterLoginByMobileRequest) (*dto.TokenDetail, error) {
// 	err := s.otpService.ValidateOtp(req.MobileNumber, req.Otp)
// 	if err != nil {
// 		return nil, err
// 	}
// 	exists, err := s.existsByMobileNumber(req.MobileNumber)
// 	if err != nil {
// 		return nil, err
// 	}

// 	u := models.User{MobileNumber: req.MobileNumber, Username: req.MobileNumber}

// 	if exists {
// 		var user models.User
// 		err = s.database.
// 			Model(&models.User{}).
// 			Where("username = ?", u.Username).
// 			Preload("UserRoles", func(tx *gorm.DB) *gorm.DB {
// 				return tx.Preload("Role")
// 			}).
// 			Find(&user).Error
// 		if err != nil {
// 			return nil, err
// 		}
// 		tdto := tokenDto{UserId: user.Id, FirstName: user.FirstName, LastName: user.LastName,
// 			Email: user.Email, MobileNumber: user.MobileNumber}

// 		if len(*user.UserRoles) > 0 {
// 			for _, ur := range *user.UserRoles {
// 				tdto.Roles = append(tdto.Roles, ur.Role.Name)
// 			}
// 		}

// 		token, err := s.tokenService.GenerateToken(&tdto)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return token, nil

// 	}

// 	bp := []byte(common.GeneratePassword())
// 	hp, err := bcrypt.GenerateFromPassword(bp, bcrypt.DefaultCost)
// 	if err != nil {
// 		s.logger.Error(logging.General, logging.HashPassword, err.Error(), nil)
// 		return nil, err
// 	}
// 	u.Password = string(hp)
// 	roleId, err := s.getDefaultRole()
// 	if err != nil {
// 		s.logger.Error(logging.Postgres, logging.DefaultRoleNotFound, err.Error(), nil)
// 		return nil, err
// 	}

// 	tx := s.database.Begin()
// 	err = tx.Create(&u).Error
// 	if err != nil {
// 		tx.Rollback()
// 		s.logger.Error(logging.Postgres, logging.Rollback, err.Error(), nil)
// 		return nil, err
// 	}
// 	err = tx.Create(&models.UserRole{RoleId: roleId, UserId: u.Id}).Error
// 	if err != nil {
// 		tx.Rollback()
// 		s.logger.Error(logging.Postgres, logging.Rollback, err.Error(), nil)
// 		return nil, err
// 	}
// 	tx.Commit()

// 	var user models.User
// 	err = s.database.
// 		Model(&models.User{}).
// 		Where("username = ?", u.Username).
// 		Preload("UserRoles", func(tx *gorm.DB) *gorm.DB {
// 			return tx.Preload("Role")
// 		}).
// 		Find(&user).Error
// 	if err != nil {
// 		return nil, err
// 	}
// 	tdto := tokenDto{UserId: user.Id, FirstName: user.FirstName, LastName: user.LastName,
// 		Email: user.Email, MobileNumber: user.MobileNumber}

// 	if len(*user.UserRoles) > 0 {
// 		for _, ur := range *user.UserRoles {
// 			tdto.Roles = append(tdto.Roles, ur.Role.Name)
// 		}
// 	}

// 	token, err := s.tokenService.GenerateToken(&tdto)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return token, nil

// }
