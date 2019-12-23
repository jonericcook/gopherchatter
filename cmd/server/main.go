package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ardanlabs/conf"
	"github.com/dgrijalva/jwt-go"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/jonericcook/gopherchatter/internal/chat"
	"github.com/jonericcook/gopherchatter/internal/contact"

	"github.com/jonericcook/gopherchatter/internal/message"
	"github.com/jonericcook/gopherchatter/internal/middleware"
	"github.com/jonericcook/gopherchatter/internal/platform/database"
	gopherchatterv0 "github.com/jonericcook/gopherchatter/internal/platform/protobuf/v0"
	"github.com/jonericcook/gopherchatter/internal/user"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ========================================================================================
// Authentication

func (gcs *gopherChatterServer) Authenticate(ctx context.Context, req *gopherchatterv0.AuthenticateRequest) (*gopherchatterv0.AuthenticateResponse, error) {
	uc := user.Credentials{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}
	ua, err := user.Authenticate(ctx, gcs.db, uc)
	if err != nil {
		return nil, err
	}
	signingKey := []byte("gopherchatter super secret")
	expiresAt := time.Now().Add(12 * time.Hour).Unix()
	claims := &jwt.StandardClaims{
		Subject:   ua.ID.Hex(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	log.Println(token)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "signing token",
		)
	}
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.AuthenticateResponse{
		Token:     ss,
		ExpiresAt: expiresAt,
	}, nil
}

// ========================================================================================
// User

func (gcs *gopherChatterServer) CreateUser(ctx context.Context, req *gopherchatterv0.CreateUserRequest) (*gopherchatterv0.CreateUserResponse, error) {
	unu := user.NewUser{
		Username:        req.GetUsername(),
		Password:        req.GetPassword(),
		PasswordConfirm: req.GetPasswordConfirm(),
	}
	if err := user.CheckFormat(ctx, gcs.db, unu); err != nil {
		return nil, err
	}
	if user.NameExists(ctx, gcs.db, req.GetUsername()) {
		return nil, status.Errorf(
			codes.AlreadyExists, "username already exists",
		)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "hashing password",
		)
	}
	uu := user.User{
		Username:     req.GetUsername(),
		PasswordHash: string(hash),
	}
	uc, err := user.Create(ctx, gcs.db, uu)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.CreateUserResponse{
		UserId:       uc.ID.Hex(),
		Username:     uc.Username,
		PasswordHash: uc.PasswordHash,
	}, nil
}

func (gcs *gopherChatterServer) SearchUsername(ctx context.Context, req *gopherchatterv0.SearchUsernameRequest) (*gopherchatterv0.SearchUsernameResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	u, err := user.GetUsername(ctx, gcs.db, req.GetUsername())
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.SearchUsernameResponse{
		UserId:   u.ID.Hex(),
		Username: u.Username,
	}, nil
}

func (gcs *gopherChatterServer) GetUsers(ctx context.Context, req *gopherchatterv0.GetUsersRequest) (*gopherchatterv0.GetUsersResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	var users []*gopherchatterv0.User
	for _, e := range req.GetUserIds() {
		userID, err := primitive.ObjectIDFromHex(e)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal, "converting to ObjectID",
			)
		}
		u, err := user.GetUserID(ctx, gcs.db, userID)
		if err != nil {
			return nil, err
		}
		users = append(users, &gopherchatterv0.User{
			UserId:   u.ID.Hex(),
			Username: u.Username,
		})
	}
	return &gopherchatterv0.GetUsersResponse{
		Users: users,
	}, nil
}

// ========================================================================================
// Contact

func (gcs *gopherChatterServer) AddContact(ctx context.Context, req *gopherchatterv0.AddContactRequest) (*gopherchatterv0.AddContactResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	if authUserID == userID {
		return nil, status.Errorf(
			codes.InvalidArgument, "cannot make yourself a contact",
		)
	}
	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.AlreadyExists, "already a contact",
		)
	}
	err = contact.Add(ctx, gcs.db, c)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.AddContactResponse{}, nil
}

func (gcs *gopherChatterServer) RemoveContact(ctx context.Context, req *gopherchatterv0.RemoveContactRequest) (*gopherchatterv0.RemoveContactResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}

	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if !contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.AlreadyExists, "contact does not exist",
		)
	}
	err = contact.Remove(ctx, gcs.db, c)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.RemoveContactResponse{}, nil
}

func (gcs *gopherChatterServer) GetContacts(ctx context.Context, req *gopherchatterv0.GetContactsRequest) (*gopherchatterv0.GetContactsResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	cga, err := contact.GetAll(ctx, gcs.db, authUserID)
	if err != nil {
		return nil, err
	}
	var users []*gopherchatterv0.User
	for _, e := range cga {
		u, err := user.GetUserID(ctx, gcs.db, e.User)
		if err != nil {
			return nil, err
		}
		users = append(users, &gopherchatterv0.User{UserId: u.ID.Hex(), Username: u.Username})
	}
	return &gopherchatterv0.GetContactsResponse{
		Users: users,
	}, nil
}

// ========================================================================================
// Group Chat

func (gcs *gopherChatterServer) CreateGroupChat(ctx context.Context, req *gopherchatterv0.CreateGroupChatRequest) (*gopherchatterv0.CreateGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	if req.GetChatName() == "" {
		return nil, status.Errorf(
			codes.InvalidArgument, "chat name must not be blank",
		)
	}
	if len(req.GetChatMembers()) < 1 ||
		len(req.GetChatMembers()) > (chat.GroupMemberLimit-1) {
		message := fmt.Sprintf("chat members must contain at least 1 user and at most %v users", chat.GroupMemberLimit-1)
		return nil, status.Errorf(
			codes.InvalidArgument, message,
		)
	}
	var members []primitive.ObjectID
	for _, e := range req.GetChatMembers() {
		userID, err := primitive.ObjectIDFromHex(e)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal, "converting to ObjectID",
			)
		}
		if !user.IDExists(ctx, gcs.db, userID) {
			return nil, status.Errorf(
				codes.NotFound, "user id does not exist",
			)
		}
		c := contact.Contact{
			Owner: authUserID,
			User:  userID,
		}
		if !contact.Exists(ctx, gcs.db, c) {
			return nil, status.Errorf(
				codes.NotFound, "contact does not exist",
			)
		}
		members = append(members, userID)
	}
	members = append(members, authUserID)
	cg := chat.Group{
		Name:    req.GetChatName(),
		Type:    chat.GroupLabel,
		Admin:   authUserID,
		Members: members,
	}
	ccg, err := chat.CreateGroup(ctx, gcs.db, cg)
	if err != nil {
		return nil, err
	}
	var chatMembers []string
	for _, e := range ccg.Members {
		chatMembers = append(chatMembers, e.Hex())
	}
	return &gopherchatterv0.CreateGroupChatResponse{
		ChatId:      ccg.ID.Hex(),
		ChatName:    ccg.Name,
		ChatType:    ccg.Type,
		ChatAdmin:   authUserID.Hex(),
		ChatMembers: chatMembers,
	}, nil
}

func (gcs *gopherChatterServer) GetGroupChats(ctx context.Context, req *gopherchatterv0.GetGroupChatsRequest) (*gopherchatterv0.GetGroupChatsResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	groupChats, err := chat.GetGroups(ctx, gcs.db, authUserID)
	if err != nil {
		return nil, err
	}
	var gc []*gopherchatterv0.GroupChat
	for _, e := range groupChats {
		var cm []string
		for _, e := range e.Members {
			cm = append(cm, e.Hex())
		}
		gc = append(gc, &gopherchatterv0.GroupChat{
			ChatId:      e.ID.Hex(),
			ChatName:    e.Name,
			ChatType:    e.Type,
			ChatAdmin:   e.Admin.Hex(),
			ChatMembers: cm,
		})
	}
	return &gopherchatterv0.GetGroupChatsResponse{
		GroupChats: gc,
	}, nil
}

func (gcs *gopherChatterServer) LeaveGroupChat(ctx context.Context, req *gopherchatterv0.LeaveGroupChatRequest) (*gopherchatterv0.LeaveGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetGroup(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if !chat.IsMember(cg.Members, authUserID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "member not in chat",
		)
	}
	if len(cg.Members) == 1 {
		err = chat.DeleteGroup(ctx, gcs.db, chatID)
		if err != nil {
			return nil, err
		}
		err = message.DeleteChatMessages(ctx, gcs.db, chatID)
		if err != nil {
			return nil, err
		}
	} else {
		for _, e := range cg.Members {
			if e != authUserID {
				chat.UpdateGroupChatAdmin(ctx, gcs.db, chatID, e)
				break
			}
		}
		err = chat.RemoveGroupChatMember(ctx, gcs.db, chatID, authUserID)
	}
	return &gopherchatterv0.LeaveGroupChatResponse{}, nil
}

func (gcs *gopherChatterServer) AddMemberToGroupChat(ctx context.Context, req *gopherchatterv0.AddMemberToGroupChatRequest) (*gopherchatterv0.AddMemberToGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if !contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.NotFound, "contact does not exist",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetGroup(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if cg.Admin != authUserID {
		return nil, status.Errorf(
			codes.PermissionDenied, "not authorized to add a member",
		)
	}
	if chat.IsMember(cg.Members, userID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "member is already in chat",
		)
	}
	err = chat.AddGroupChatMember(ctx, gcs.db, chatID, userID)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range cg.Members {
		cm = append(cm, e.Hex())
	}
	cm = append(cm, userID.Hex())
	return &gopherchatterv0.AddMemberToGroupChatResponse{
		ChatId:      cg.ID.Hex(),
		ChatName:    cg.Name,
		ChatType:    cg.Type,
		ChatAdmin:   authUserID.Hex(),
		ChatMembers: cm,
	}, nil
}

func (gcs *gopherChatterServer) RemoveMemberFromGroupChat(ctx context.Context, req *gopherchatterv0.RemoveMemberFromGroupChatRequest) (*gopherchatterv0.RemoveMemberFromGroupChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	userID, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	if authUserID == userID {
		return nil, status.Errorf(
			codes.InvalidArgument, "cannot remove yourself",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetGroup(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if cg.Admin != authUserID {
		return nil, status.Errorf(
			codes.PermissionDenied, "not authorized to remove a member",
		)
	}
	if !chat.IsMember(cg.Members, userID) {
		return nil, status.Errorf(
			codes.NotFound, "member not in chat",
		)
	}
	err = chat.RemoveGroupChatMember(ctx, gcs.db, chatID, userID)
	if err != nil {
		return nil, err
	}
	var cm []string
	for _, e := range cg.Members {
		if e != userID {
			cm = append(cm, e.Hex())
		}
	}
	return &gopherchatterv0.RemoveMemberFromGroupChatResponse{
		ChatId:      cg.ID.Hex(),
		ChatName:    cg.Name,
		ChatType:    cg.Type,
		ChatAdmin:   cg.Admin.Hex(),
		ChatMembers: cm,
	}, nil
}

// ========================================================================================
// Individual Chat

func (gcs *gopherChatterServer) CreateIndividualChat(ctx context.Context, req *gopherchatterv0.CreateIndividualChatRequest) (*gopherchatterv0.CreateIndividualChatResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}

	userID, err := primitive.ObjectIDFromHex(req.GetChatMember())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, userID) {
		return nil, status.Errorf(
			codes.NotFound, "user id does not exist",
		)
	}
	c := contact.Contact{
		Owner: authUserID,
		User:  userID,
	}
	if !contact.Exists(ctx, gcs.db, c) {
		return nil, status.Errorf(
			codes.NotFound, "contact does not exist",
		)
	}
	ci := chat.Individual{
		Type:    chat.IndividualLabel,
		Members: []primitive.ObjectID{authUserID, userID},
	}
	if chat.IndividualChatExists(ctx, gcs.db, ci.Members[0], ci.Members[1]) {
		return nil, status.Errorf(
			codes.AlreadyExists, "individual chat already exists",
		)
	}
	cci, err := chat.CreateIndividual(ctx, gcs.db, ci)
	if err != nil {
		return nil, err
	}
	var chatMembers []string
	for _, e := range cci.Members {
		chatMembers = append(chatMembers, e.Hex())
	}
	return &gopherchatterv0.CreateIndividualChatResponse{
		ChatId:      cci.ID.Hex(),
		ChatType:    cci.Type,
		ChatMembers: chatMembers,
	}, nil
}

func (gcs *gopherChatterServer) GetIndividualChats(ctx context.Context, req *gopherchatterv0.GetIndividualChatsRequest) (*gopherchatterv0.GetIndividualChatsResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	individualChats, err := chat.GetIndividuals(ctx, gcs.db, authUserID)
	if err != nil {
		return nil, err
	}
	var ic []*gopherchatterv0.IndividualChat
	for _, e := range individualChats {
		var cm []string
		for _, e := range e.Members {
			cm = append(cm, e.Hex())
		}
		ic = append(ic, &gopherchatterv0.IndividualChat{
			ChatId:      e.ID.Hex(),
			ChatType:    e.Type,
			ChatMembers: cm,
		})
	}

	return &gopherchatterv0.GetIndividualChatsResponse{
		IndividualChats: ic,
	}, nil
}

// ========================================================================================
// Message

func (gcs *gopherChatterServer) SendGroupMessage(ctx context.Context, req *gopherchatterv0.SendGroupMessageRequest) (*gopherchatterv0.SendGroupMessageResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	if req.GetContents() == "" {
		return nil, status.Errorf(
			codes.InvalidArgument, "message cannot be blank",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetGroup(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if !chat.IsMember(cg.Members, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "not a chat member",
		)
	}
	m := message.Message{
		ChatID:   chatID,
		AuthorID: authUserID,
		Contents: req.GetContents(),
		Created:  time.Now().UTC(),
	}
	mc, err := message.Create(ctx, gcs.db, m)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.SendGroupMessageResponse{
		MessageId: mc.ID.Hex(),
		ChatId:    chatID.Hex(),
		AuthorId:  authUserID.Hex(),
		Contents:  req.GetContents(),
		Created:   mc.Created.UTC().String(),
	}, nil
}

func (gcs *gopherChatterServer) SendIndividualMessage(ctx context.Context, req *gopherchatterv0.SendIndividualMessageRequest) (*gopherchatterv0.SendIndividualMessageResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	if req.GetContents() == "" {
		return nil, status.Errorf(
			codes.InvalidArgument, "message cannot be blank",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetIndividual(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if !chat.IsMember(cg.Members, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "not a chat member",
		)
	}
	m := message.Message{
		ChatID:   chatID,
		AuthorID: authUserID,
		Contents: req.GetContents(),
		Created:  time.Now().UTC(),
	}
	mc, err := message.Create(ctx, gcs.db, m)
	if err != nil {
		return nil, err
	}
	return &gopherchatterv0.SendIndividualMessageResponse{
		MessageId: mc.ID.Hex(),
		ChatId:    chatID.Hex(),
		AuthorId:  authUserID.Hex(),
		Contents:  req.GetContents(),
		Created:   mc.Created.UTC().String(),
	}, nil
}

func (gcs *gopherChatterServer) GetGroupChatMessages(ctx context.Context, req *gopherchatterv0.GetGroupChatMessagesRequest) (*gopherchatterv0.GetGroupChatMessagesResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	cg, err := chat.GetGroup(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if !chat.IsMember(cg.Members, authUserID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "member not in chat",
		)
	}
	messages, err := message.GetMessages(ctx, gcs.db, chatID)
	var m []*gopherchatterv0.Message
	for _, e := range messages {
		m = append(m, &gopherchatterv0.Message{
			MessageId: e.ID.Hex(),
			ChatId:    e.ChatID.Hex(),
			AuthorId:  e.AuthorID.Hex(),
			Contents:  e.Contents,
			Created:   e.Created.UTC().String(),
		})
	}
	return &gopherchatterv0.GetGroupChatMessagesResponse{
		Messages: m,
	}, nil
}

func (gcs *gopherChatterServer) GetIndividualChatMessages(ctx context.Context, req *gopherchatterv0.GetIndividualChatMessagesRequest) (*gopherchatterv0.GetIndividualChatMessagesResponse, error) {
	authUserID, err := primitive.ObjectIDFromHex(grpc_ctxtags.Extract(ctx).Values()["auth.sub"].(string))
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	if !user.IDExists(ctx, gcs.db, authUserID) {
		return nil, status.Errorf(
			codes.NotFound, "user id in token does not exist",
		)
	}
	chatID, err := primitive.ObjectIDFromHex(req.GetChatId())
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "converting to ObjectID",
		)
	}
	ci, err := chat.GetIndividual(ctx, gcs.db, chatID)
	if err != nil {
		return nil, err
	}
	if !chat.IsMember(ci.Members, authUserID) {
		return nil, status.Errorf(
			codes.AlreadyExists, "member not in chat",
		)
	}
	messages, err := message.GetMessages(ctx, gcs.db, chatID)
	var m []*gopherchatterv0.Message
	for _, e := range messages {
		m = append(m, &gopherchatterv0.Message{
			MessageId: e.ID.Hex(),
			ChatId:    e.ChatID.Hex(),
			AuthorId:  e.AuthorID.Hex(),
			Contents:  e.Contents,
			Created:   e.Created.UTC().String(),
		})
	}
	return &gopherchatterv0.GetIndividualChatMessagesResponse{
		Messages: m,
	}, nil
}

type gopherChatterServer struct {
	db *mongo.Database
}

func run() error {

	// ========================================================================================
	// Configuration

	var cfg struct {
		DB struct {
			Host string `conf:"default:localhost:27017"`
			Name string `conf:"default:gopherchatter"`
		}
		GRPC struct {
			Host string `conf:"default:localhost:50051"`
		}
	}
	if err := conf.Parse(os.Args[1:], "SALES", &cfg); err != nil {
		if err == conf.ErrHelpWanted {
			usage, err := conf.Usage("SALES", &cfg)
			if err != nil {
				return errors.Wrap(err, "generating config usage")
			}
			fmt.Println(usage)
			return nil
		}
		return errors.Wrap(err, "parsing config")
	}

	// ========================================================================================
	// App Starting

	log.Println("main : Started : Application initializing")
	defer log.Println("main : Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return errors.Wrap(err, "generating config for output")
	}
	log.Printf("main : Config :\n%v\n", out)

	// ========================================================================================
	// Start Database

	log.Println("main : Started : Initializing database support")

	db, err := database.Open(database.Config{
		Host: cfg.DB.Host,
		Name: cfg.DB.Name,
	})
	if err != nil {
		return errors.Wrap(err, "connecting to db")
	}
	defer func() {
		log.Printf("main : Database Stopping : %s", cfg.DB.Host)
		db.Client().Disconnect(context.Background())
	}()

	// ========================================================================================
	// Start GRPC Service

	log.Println("main : Started : Initializing GRPC support")

	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	listener, err := net.Listen("tcp", cfg.GRPC.Host)
	if err != nil {
		return errors.Wrap(err, "listening on network")
	}

	grpcs := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				middleware.AddContextTags(),
				middleware.AddLogging(),
				middleware.AddAuthentication(),
			),
		),
	)
	gcs := gopherChatterServer{
		db: db,
	}
	gopherchatterv0.RegisterGopherChatterServer(grpcs, &gcs)

	// Start the service listening for requests.
	go func() {
		log.Printf("main : GRPC service listening on %s", cfg.GRPC.Host)
		serverErrors <- grpcs.Serve(listener)
	}()

	// ========================================================================================
	// Shutdown

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		return errors.Wrap(err, "server error")
	case sig := <-shutdown:
		log.Printf("main : %v : Start shutdown", sig)

		grpcs.Stop()
		listener.Close()

		// Log the status of this shutdown.
		switch {
		case sig == syscall.SIGSTOP:
			return errors.New("integrity issue caused shutdown")
		case err != nil:
			return errors.Wrap(err, "could not stop server gracefully")
		}

	}
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Println("error :", err)
		os.Exit(1)
	}
}
