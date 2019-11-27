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

func init() {
	proto.RegisterType((*AuthenticateRequest)(nil), "gopherchatter.v0.AuthenticateRequest")
	proto.RegisterType((*AuthenticateResponse)(nil), "gopherchatter.v0.AuthenticateResponse")
	proto.RegisterType((*CreateUserRequest)(nil), "gopherchatter.v0.CreateUserRequest")
	proto.RegisterType((*CreateGroupChatRequest)(nil), "gopherchatter.v0.CreateGroupChatRequest")
	proto.RegisterType((*CreateGroupChatResponse)(nil), "gopherchatter.v0.CreateGroupChatResponse")
}

func init() { proto.RegisterFile("v0/gopherchatter.proto", fileDescriptor_f52cf33cfe78713c) }

var fileDescriptor_f52cf33cfe78713c = []byte{
	// 354 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x92, 0x6f, 0x4b, 0x3a, 0x41,
	0x10, 0xc7, 0xf1, 0xe4, 0xe7, 0x2f, 0x87, 0xc2, 0xdc, 0x44, 0xe5, 0x24, 0x88, 0x8b, 0xc2, 0x9e,
	0x9c, 0x52, 0xaf, 0xa0, 0x24, 0xe4, 0x88, 0x7a, 0x20, 0xf5, 0x24, 0x08, 0x59, 0xbd, 0xd1, 0x93,
	0xf2, 0x76, 0xdb, 0xdd, 0x33, 0x7a, 0x39, 0xbd, 0xd3, 0xd8, 0x5d, 0x4d, 0xef, 0xae, 0x7f, 0xd0,
	0xc3, 0xd9, 0x99, 0xf9, 0x7c, 0x67, 0xe7, 0x3b, 0x50, 0x5f, 0x74, 0x3b, 0x53, 0xc6, 0x23, 0x14,
	0xe3, 0x88, 0x2a, 0x85, 0xc2, 0xe7, 0x82, 0x29, 0x46, 0x76, 0xd3, 0x8f, 0x8b, 0xae, 0xdb, 0x9a,
	0x32, 0x36, 0x7d, 0xc2, 0x8e, 0xc9, 0x8f, 0x92, 0x49, 0x07, 0xe7, 0x5c, 0xbd, 0xda, 0x72, 0xef,
	0x1a, 0xf6, 0xce, 0x13, 0x15, 0x61, 0xac, 0x66, 0x63, 0xaa, 0x70, 0x80, 0xcf, 0x09, 0x4a, 0x45,
	0x5c, 0xd8, 0x4a, 0x24, 0x8a, 0x98, 0xce, 0xb1, 0x59, 0x38, 0x28, 0xb4, 0xcb, 0x83, 0x8f, 0x58,
	0xe7, 0x38, 0x95, 0xf2, 0x85, 0x89, 0xb0, 0xe9, 0xd8, 0xdc, 0x2a, 0xf6, 0x28, 0xd4, 0xd2, 0x38,
	0xc9, 0x59, 0x2c, 0x91, 0x34, 0xe0, 0xbf, 0xee, 0x1f, 0xce, 0xc2, 0x25, 0xae, 0xa4, 0xc3, 0x20,
	0x4c, 0x09, 0x39, 0x19, 0xa1, 0x1a, 0xfc, 0x53, 0xec, 0x11, 0xe3, 0x66, 0xd1, 0x24, 0x6c, 0xe0,
	0x5d, 0x41, 0xb5, 0x27, 0x90, 0x2a, 0xbc, 0x93, 0x28, 0xfe, 0x3a, 0xef, 0x2d, 0xd4, 0x2d, 0xac,
	0x2f, 0x58, 0xc2, 0x7b, 0x11, 0x55, 0x2b, 0x62, 0x0b, 0xca, 0x7a, 0x87, 0xc3, 0x4d, 0xa4, 0x7e,
	0xb8, 0xd1, 0xc8, 0x7d, 0x80, 0xb1, 0x6e, 0x63, 0xe6, 0x47, 0x16, 0x5a, 0x5e, 0xbe, 0x04, 0xa1,
	0x17, 0x43, 0x23, 0x47, 0x5d, 0x2f, 0xc2, 0x60, 0xd7, 0x8b, 0xd0, 0x61, 0x10, 0xa6, 0xf5, 0x9c,
	0x6f, 0xf5, 0x8a, 0x19, 0xbd, 0xd3, 0x37, 0x07, 0x76, 0xfa, 0xc6, 0xf6, 0x9e, 0xb5, 0x9d, 0x3c,
	0xc0, 0xf6, 0xa6, 0x0f, 0xe4, 0xc8, 0xcf, 0x9e, 0x85, 0xff, 0x89, 0xed, 0xee, 0xf1, 0x4f, 0x65,
	0xcb, 0x5f, 0x04, 0x00, 0x6b, 0x0f, 0xc8, 0x61, 0xbe, 0x2b, 0xe7, 0x90, 0x5b, 0xf7, 0xed, 0x19,
	0xfa, 0xab, 0x33, 0xf4, 0x2f, 0xf5, 0x19, 0x92, 0x09, 0x54, 0x32, 0xbb, 0x22, 0xed, 0xaf, 0x78,
	0x59, 0x93, 0xdc, 0x93, 0x5f, 0x54, 0xda, 0x91, 0x2f, 0xaa, 0xf7, 0x95, 0x54, 0xed, 0xa2, 0x3b,
	0x2a, 0x99, 0x51, 0xce, 0xde, 0x03, 0x00, 0x00, 0xff, 0xff, 0x98, 0x58, 0xd4, 0x89, 0x4b, 0x03,
	0x00, 0x00,
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

// GopherChatterServer is the server API for GopherChatter service.
type GopherChatterServer interface {
	Authenticate(context.Context, *AuthenticateRequest) (*AuthenticateResponse, error)
	CreateUser(context.Context, *CreateUserRequest) (*empty.Empty, error)
	CreateGroupChat(context.Context, *CreateGroupChatRequest) (*CreateGroupChatResponse, error)
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
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v0/gopherchatter.proto",
}
