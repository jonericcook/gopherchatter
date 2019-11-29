// Code generated by protoc-gen-go. DO NOT EDIT.
// source: v0/gopherchatter.proto

package gopherchatterv0

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type AuthenticateRequest struct {
	Username             string   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthenticateRequest) Reset()         { *m = AuthenticateRequest{} }
func (m *AuthenticateRequest) String() string { return proto.CompactTextString(m) }
func (*AuthenticateRequest) ProtoMessage()    {}
func (*AuthenticateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{0}
}

func (m *AuthenticateRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthenticateRequest.Unmarshal(m, b)
}
func (m *AuthenticateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthenticateRequest.Marshal(b, m, deterministic)
}
func (m *AuthenticateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthenticateRequest.Merge(m, src)
}
func (m *AuthenticateRequest) XXX_Size() int {
	return xxx_messageInfo_AuthenticateRequest.Size(m)
}
func (m *AuthenticateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthenticateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AuthenticateRequest proto.InternalMessageInfo

func (m *AuthenticateRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *AuthenticateRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type AuthenticateResponse struct {
	UserId               string   `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Username             string   `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
	Token                string   `protobuf:"bytes,3,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthenticateResponse) Reset()         { *m = AuthenticateResponse{} }
func (m *AuthenticateResponse) String() string { return proto.CompactTextString(m) }
func (*AuthenticateResponse) ProtoMessage()    {}
func (*AuthenticateResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{1}
}

func (m *AuthenticateResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthenticateResponse.Unmarshal(m, b)
}
func (m *AuthenticateResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthenticateResponse.Marshal(b, m, deterministic)
}
func (m *AuthenticateResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthenticateResponse.Merge(m, src)
}
func (m *AuthenticateResponse) XXX_Size() int {
	return xxx_messageInfo_AuthenticateResponse.Size(m)
}
func (m *AuthenticateResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthenticateResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AuthenticateResponse proto.InternalMessageInfo

func (m *AuthenticateResponse) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *AuthenticateResponse) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *AuthenticateResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type CreateUserRequest struct {
	Username             string   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateUserRequest) Reset()         { *m = CreateUserRequest{} }
func (m *CreateUserRequest) String() string { return proto.CompactTextString(m) }
func (*CreateUserRequest) ProtoMessage()    {}
func (*CreateUserRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{2}
}

func (m *CreateUserRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateUserRequest.Unmarshal(m, b)
}
func (m *CreateUserRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateUserRequest.Marshal(b, m, deterministic)
}
func (m *CreateUserRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateUserRequest.Merge(m, src)
}
func (m *CreateUserRequest) XXX_Size() int {
	return xxx_messageInfo_CreateUserRequest.Size(m)
}
func (m *CreateUserRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateUserRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateUserRequest proto.InternalMessageInfo

func (m *CreateUserRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *CreateUserRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type CreateGroupChatRequest struct {
	ChatName             string   `protobuf:"bytes,1,opt,name=chat_name,json=chatName,proto3" json:"chat_name,omitempty"`
	CreatorId            string   `protobuf:"bytes,2,opt,name=creator_id,json=creatorId,proto3" json:"creator_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateGroupChatRequest) Reset()         { *m = CreateGroupChatRequest{} }
func (m *CreateGroupChatRequest) String() string { return proto.CompactTextString(m) }
func (*CreateGroupChatRequest) ProtoMessage()    {}
func (*CreateGroupChatRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{3}
}

func (m *CreateGroupChatRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateGroupChatRequest.Unmarshal(m, b)
}
func (m *CreateGroupChatRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateGroupChatRequest.Marshal(b, m, deterministic)
}
func (m *CreateGroupChatRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateGroupChatRequest.Merge(m, src)
}
func (m *CreateGroupChatRequest) XXX_Size() int {
	return xxx_messageInfo_CreateGroupChatRequest.Size(m)
}
func (m *CreateGroupChatRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateGroupChatRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateGroupChatRequest proto.InternalMessageInfo

func (m *CreateGroupChatRequest) GetChatName() string {
	if m != nil {
		return m.ChatName
	}
	return ""
}

func (m *CreateGroupChatRequest) GetCreatorId() string {
	if m != nil {
		return m.CreatorId
	}
	return ""
}

type CreateGroupChatResponse struct {
	ChatId               string   `protobuf:"bytes,1,opt,name=chat_id,json=chatId,proto3" json:"chat_id,omitempty"`
	ChatName             string   `protobuf:"bytes,2,opt,name=chat_name,json=chatName,proto3" json:"chat_name,omitempty"`
	CreatorId            string   `protobuf:"bytes,3,opt,name=creator_id,json=creatorId,proto3" json:"creator_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateGroupChatResponse) Reset()         { *m = CreateGroupChatResponse{} }
func (m *CreateGroupChatResponse) String() string { return proto.CompactTextString(m) }
func (*CreateGroupChatResponse) ProtoMessage()    {}
func (*CreateGroupChatResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{4}
}

func (m *CreateGroupChatResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateGroupChatResponse.Unmarshal(m, b)
}
func (m *CreateGroupChatResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateGroupChatResponse.Marshal(b, m, deterministic)
}
func (m *CreateGroupChatResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateGroupChatResponse.Merge(m, src)
}
func (m *CreateGroupChatResponse) XXX_Size() int {
	return xxx_messageInfo_CreateGroupChatResponse.Size(m)
}
func (m *CreateGroupChatResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateGroupChatResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CreateGroupChatResponse proto.InternalMessageInfo

func (m *CreateGroupChatResponse) GetChatId() string {
	if m != nil {
		return m.ChatId
	}
	return ""
}

func (m *CreateGroupChatResponse) GetChatName() string {
	if m != nil {
		return m.ChatName
	}
	return ""
}

func (m *CreateGroupChatResponse) GetCreatorId() string {
	if m != nil {
		return m.CreatorId
	}
	return ""
}

type AddContactRequest struct {
	UserId               string   `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	ContactId            string   `protobuf:"bytes,2,opt,name=contact_id,json=contactId,proto3" json:"contact_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AddContactRequest) Reset()         { *m = AddContactRequest{} }
func (m *AddContactRequest) String() string { return proto.CompactTextString(m) }
func (*AddContactRequest) ProtoMessage()    {}
func (*AddContactRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{5}
}

func (m *AddContactRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddContactRequest.Unmarshal(m, b)
}
func (m *AddContactRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddContactRequest.Marshal(b, m, deterministic)
}
func (m *AddContactRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddContactRequest.Merge(m, src)
}
func (m *AddContactRequest) XXX_Size() int {
	return xxx_messageInfo_AddContactRequest.Size(m)
}
func (m *AddContactRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AddContactRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AddContactRequest proto.InternalMessageInfo

func (m *AddContactRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *AddContactRequest) GetContactId() string {
	if m != nil {
		return m.ContactId
	}
	return ""
}

type RemoveContactRequest struct {
	UserId               string   `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	ContactId            string   `protobuf:"bytes,2,opt,name=contact_id,json=contactId,proto3" json:"contact_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RemoveContactRequest) Reset()         { *m = RemoveContactRequest{} }
func (m *RemoveContactRequest) String() string { return proto.CompactTextString(m) }
func (*RemoveContactRequest) ProtoMessage()    {}
func (*RemoveContactRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f52cf33cfe78713c, []int{6}
}

func (m *RemoveContactRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RemoveContactRequest.Unmarshal(m, b)
}
func (m *RemoveContactRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RemoveContactRequest.Marshal(b, m, deterministic)
}
func (m *RemoveContactRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RemoveContactRequest.Merge(m, src)
}
func (m *RemoveContactRequest) XXX_Size() int {
	return xxx_messageInfo_RemoveContactRequest.Size(m)
}
func (m *RemoveContactRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_RemoveContactRequest.DiscardUnknown(m)
}

var xxx_messageInfo_RemoveContactRequest proto.InternalMessageInfo

func (m *RemoveContactRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *RemoveContactRequest) GetContactId() string {
	if m != nil {
		return m.ContactId
	}
	return ""
}

func init() {
	proto.RegisterType((*AuthenticateRequest)(nil), "gopherchatter.v0.AuthenticateRequest")
	proto.RegisterType((*AuthenticateResponse)(nil), "gopherchatter.v0.AuthenticateResponse")
	proto.RegisterType((*CreateUserRequest)(nil), "gopherchatter.v0.CreateUserRequest")
	proto.RegisterType((*CreateGroupChatRequest)(nil), "gopherchatter.v0.CreateGroupChatRequest")
	proto.RegisterType((*CreateGroupChatResponse)(nil), "gopherchatter.v0.CreateGroupChatResponse")
	proto.RegisterType((*AddContactRequest)(nil), "gopherchatter.v0.AddContactRequest")
	proto.RegisterType((*RemoveContactRequest)(nil), "gopherchatter.v0.RemoveContactRequest")
}

func init() { proto.RegisterFile("v0/gopherchatter.proto", fileDescriptor_f52cf33cfe78713c) }

var fileDescriptor_f52cf33cfe78713c = []byte{
	// 411 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x93, 0x6d, 0x8b, 0xda, 0x40,
	0x10, 0xc7, 0x51, 0xa9, 0xad, 0x43, 0xc5, 0xba, 0x15, 0x95, 0x48, 0xa1, 0xa4, 0xb4, 0xd8, 0x37,
	0x51, 0xda, 0x4f, 0x60, 0x43, 0x91, 0x20, 0xb5, 0x20, 0xed, 0x9b, 0x42, 0x91, 0x35, 0x3b, 0x1a,
	0x69, 0xcd, 0xe6, 0x36, 0x9b, 0x1c, 0xf7, 0xe1, 0xee, 0xbb, 0x1d, 0x9b, 0x55, 0x63, 0x9e, 0xee,
	0x0e, 0xee, 0x5e, 0xce, 0xc3, 0xfe, 0x66, 0x76, 0xe6, 0x3f, 0xd0, 0x8f, 0xa7, 0x93, 0x1d, 0x0f,
	0x3c, 0x14, 0xae, 0x47, 0xa5, 0x44, 0x61, 0x05, 0x82, 0x4b, 0x4e, 0xde, 0x64, 0x9d, 0xf1, 0xd4,
	0x18, 0xed, 0x38, 0xdf, 0xfd, 0xc7, 0x49, 0x12, 0xdf, 0x44, 0xdb, 0x09, 0x1e, 0x02, 0x79, 0xa3,
	0xd3, 0xcd, 0x1f, 0xf0, 0x76, 0x16, 0x49, 0x0f, 0x7d, 0xb9, 0x77, 0xa9, 0xc4, 0x15, 0x5e, 0x45,
	0x18, 0x4a, 0x62, 0xc0, 0xab, 0x28, 0x44, 0xe1, 0xd3, 0x03, 0x0e, 0x6b, 0xef, 0x6b, 0xe3, 0xd6,
	0xea, 0x6c, 0xab, 0x58, 0x40, 0xc3, 0xf0, 0x9a, 0x0b, 0x36, 0xac, 0xeb, 0xd8, 0xc9, 0x36, 0x29,
	0xf4, 0xb2, 0xb8, 0x30, 0xe0, 0x7e, 0x88, 0x64, 0x00, 0x2f, 0xd5, 0xfb, 0xf5, 0x9e, 0x1d, 0x71,
	0x4d, 0x65, 0x3a, 0x2c, 0x53, 0xa8, 0x9e, 0x2b, 0xd4, 0x83, 0x17, 0x92, 0xff, 0x43, 0x7f, 0xd8,
	0x48, 0x02, 0xda, 0x30, 0x17, 0xd0, 0xb5, 0x05, 0x52, 0x89, 0xbf, 0x43, 0x14, 0x4f, 0xed, 0xf7,
	0x17, 0xf4, 0x35, 0x6c, 0x2e, 0x78, 0x14, 0xd8, 0x1e, 0x95, 0x27, 0xe2, 0x08, 0x5a, 0x6a, 0x86,
	0xeb, 0x4b, 0xa4, 0x72, 0x2c, 0x15, 0xf2, 0x1d, 0x80, 0xab, 0x9e, 0xf1, 0xe4, 0x47, 0x1a, 0xda,
	0x3a, 0x7a, 0x1c, 0x66, 0xfa, 0x30, 0x28, 0x50, 0xd3, 0x41, 0x24, 0xd8, 0x74, 0x10, 0xca, 0x74,
	0x58, 0xb6, 0x5e, 0xfd, 0xde, 0x7a, 0x8d, 0x7c, 0xbd, 0x05, 0x74, 0x67, 0x8c, 0xd9, 0xdc, 0x97,
	0xd4, 0x3d, 0x7f, 0xa0, 0x72, 0xe4, 0x0a, 0xa6, 0x53, 0x2f, 0x9b, 0xd7, 0x1e, 0x87, 0x99, 0x4b,
	0xe8, 0xad, 0xf0, 0xc0, 0x63, 0x7c, 0x1e, 0xde, 0x97, 0xdb, 0x06, 0xb4, 0xe7, 0x89, 0x26, 0x6d,
	0xad, 0x49, 0xf2, 0x17, 0x5e, 0x5f, 0x8a, 0x84, 0x7c, 0xb4, 0xf2, 0x9a, 0xb5, 0x4a, 0x34, 0x69,
	0x7c, 0x7a, 0x28, 0xed, 0x38, 0x62, 0x07, 0x20, 0x15, 0x08, 0xf9, 0x50, 0x7c, 0x55, 0x90, 0x8f,
	0xd1, 0xb7, 0xf4, 0x8d, 0x58, 0xa7, 0x1b, 0xb1, 0xbe, 0xab, 0x1b, 0x21, 0x5b, 0xe8, 0xe4, 0x16,
	0x49, 0xc6, 0x55, 0xbc, 0xbc, 0x82, 0x8c, 0xcf, 0x8f, 0xc8, 0x4c, 0x5b, 0x4e, 0x17, 0x58, 0xd6,
	0x72, 0x61, 0xbd, 0x95, 0x2d, 0xff, 0x84, 0x76, 0x66, 0x7d, 0xa4, 0x64, 0x6c, 0x65, 0xfb, 0xad,
	0x02, 0x7e, 0xeb, 0xfe, 0xe9, 0x64, 0x00, 0xf1, 0x74, 0xd3, 0x4c, 0x52, 0xbe, 0xde, 0x05, 0x00,
	0x00, 0xff, 0xff, 0x3a, 0x6d, 0xeb, 0x9f, 0x84, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// GopherChatterClient is the client API for GopherChatter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GopherChatterClient interface {
	Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error)
	CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	CreateGroupChat(ctx context.Context, in *CreateGroupChatRequest, opts ...grpc.CallOption) (*CreateGroupChatResponse, error)
	AddContact(ctx context.Context, in *AddContactRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	RemoveContact(ctx context.Context, in *RemoveContactRequest, opts ...grpc.CallOption) (*empty.Empty, error)
}

type gopherChatterClient struct {
	cc *grpc.ClientConn
}

func NewGopherChatterClient(cc *grpc.ClientConn) GopherChatterClient {
	return &gopherChatterClient{cc}
}

func (c *gopherChatterClient) Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error) {
	out := new(AuthenticateResponse)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/Authenticate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/CreateUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) CreateGroupChat(ctx context.Context, in *CreateGroupChatRequest, opts ...grpc.CallOption) (*CreateGroupChatResponse, error) {
	out := new(CreateGroupChatResponse)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/CreateGroupChat", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) AddContact(ctx context.Context, in *AddContactRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/AddContact", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gopherChatterClient) RemoveContact(ctx context.Context, in *RemoveContactRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/gopherchatter.v0.GopherChatter/RemoveContact", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GopherChatterServer is the server API for GopherChatter service.
type GopherChatterServer interface {
	Authenticate(context.Context, *AuthenticateRequest) (*AuthenticateResponse, error)
	CreateUser(context.Context, *CreateUserRequest) (*empty.Empty, error)
	CreateGroupChat(context.Context, *CreateGroupChatRequest) (*CreateGroupChatResponse, error)
	AddContact(context.Context, *AddContactRequest) (*empty.Empty, error)
	RemoveContact(context.Context, *RemoveContactRequest) (*empty.Empty, error)
}

// UnimplementedGopherChatterServer can be embedded to have forward compatible implementations.
type UnimplementedGopherChatterServer struct {
}

func (*UnimplementedGopherChatterServer) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authenticate not implemented")
}
func (*UnimplementedGopherChatterServer) CreateUser(ctx context.Context, req *CreateUserRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser not implemented")
}
func (*UnimplementedGopherChatterServer) CreateGroupChat(ctx context.Context, req *CreateGroupChatRequest) (*CreateGroupChatResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateGroupChat not implemented")
}
func (*UnimplementedGopherChatterServer) AddContact(ctx context.Context, req *AddContactRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddContact not implemented")
}
func (*UnimplementedGopherChatterServer) RemoveContact(ctx context.Context, req *RemoveContactRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveContact not implemented")
}

func RegisterGopherChatterServer(s *grpc.Server, srv GopherChatterServer) {
	s.RegisterService(&_GopherChatter_serviceDesc, srv)
}

func _GopherChatter_Authenticate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).Authenticate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/Authenticate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).Authenticate(ctx, req.(*AuthenticateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_CreateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).CreateUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/CreateUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).CreateUser(ctx, req.(*CreateUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_CreateGroupChat_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGroupChatRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).CreateGroupChat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/CreateGroupChat",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).CreateGroupChat(ctx, req.(*CreateGroupChatRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_AddContact_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddContactRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).AddContact(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/AddContact",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).AddContact(ctx, req.(*AddContactRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GopherChatter_RemoveContact_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveContactRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GopherChatterServer).RemoveContact(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gopherchatter.v0.GopherChatter/RemoveContact",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GopherChatterServer).RemoveContact(ctx, req.(*RemoveContactRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _GopherChatter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gopherchatter.v0.GopherChatter",
	HandlerType: (*GopherChatterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Authenticate",
			Handler:    _GopherChatter_Authenticate_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _GopherChatter_CreateUser_Handler,
		},
		{
			MethodName: "CreateGroupChat",
			Handler:    _GopherChatter_CreateGroupChat_Handler,
		},
		{
			MethodName: "AddContact",
			Handler:    _GopherChatter_AddContact_Handler,
		},
		{
			MethodName: "RemoveContact",
			Handler:    _GopherChatter_RemoveContact_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v0/gopherchatter.proto",
}
